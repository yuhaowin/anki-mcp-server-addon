// Command anki-mcp-relay is a self-hosted drop-in replacement for the
// AnkiMCP tunnel relay (wss://tunnel.ankimcp.ai). Point the addon's
// "tunnel_server_url" config at it; no addon code changes are needed.
package main

import (
	"context"
	"crypto/subtle"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	Listen         string
	PublicURL      string // e.g. https://relay.example.com ; empty = derive from request
	Password       string
	DataFile       string
	DefaultEmail   string
	Tier           string
	ClientIDs      []string
	AccessTokenTTL time.Duration
	RequestTimeout time.Duration
	CORSOrigins    []string
	PublicAPIKey   string
	TrustProxy     bool
	TLSCert        string
	TLSKey         string
}

// publicBase is the externally visible https:// origin of the relay.
func (c *Config) publicBase(r *http.Request) string {
	if c.PublicURL != "" {
		return strings.TrimRight(c.PublicURL, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if c.TrustProxy {
		if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
			scheme = strings.TrimSpace(strings.Split(p, ",")[0])
		}
		if hh := r.Header.Get("X-Forwarded-Host"); hh != "" {
			host = strings.TrimSpace(strings.Split(hh, ",")[0])
		}
	}
	return scheme + "://" + host
}

func (c *Config) clientIP(r *http.Request) string {
	if c.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	return hostOnly(r.RemoteAddr)
}

func constantTimeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func main() {
	cfg := &Config{}
	var clientIDs, cors string
	var ttl, reqTimeout time.Duration

	flag.StringVar(&cfg.Listen, "listen", env("RELAY_LISTEN", ":8080"), "listen address")
	flag.StringVar(&cfg.PublicURL, "public-url", env("RELAY_PUBLIC_URL", ""), "public https origin, e.g. https://relay.example.com (default: derived from request)")
	flag.StringVar(&cfg.Password, "password", env("RELAY_PASSWORD", ""), "password required to approve a device login (required)")
	flag.StringVar(&cfg.DataFile, "data", env("RELAY_DATA", "relay-data.json"), "state file (users, refresh tokens, signing secret)")
	flag.StringVar(&cfg.DefaultEmail, "default-email", env("RELAY_DEFAULT_EMAIL", "me@anki-relay"), "pre-filled account name on the approval page")
	flag.StringVar(&cfg.Tier, "tier", env("RELAY_TIER", "self-hosted"), `tier shown in Anki ("free" hides the "Permanent URL" hint)`)
	flag.StringVar(&clientIDs, "client-ids", env("RELAY_CLIENT_IDS", "ankimcp-cli"), "comma-separated accepted OAuth client_ids (empty = any)")
	flag.DurationVar(&ttl, "access-token-ttl", mustDur(env("RELAY_ACCESS_TOKEN_TTL", "24h")), "access token lifetime")
	flag.DurationVar(&reqTimeout, "request-timeout", mustDur(env("RELAY_REQUEST_TIMEOUT", "30s")), "max wait for Anki to answer one MCP request")
	flag.StringVar(&cors, "cors-origins", env("RELAY_CORS_ORIGINS", "*"), "comma-separated CORS origins for the public MCP endpoint (empty = no CORS)")
	flag.StringVar(&cfg.PublicAPIKey, "public-api-key", env("RELAY_PUBLIC_API_KEY", ""), "if set, MCP clients must send Authorization: Bearer <key>")
	flag.BoolVar(&cfg.TrustProxy, "trust-proxy", env("RELAY_TRUST_PROXY", "") == "1", "trust X-Forwarded-* headers (set when behind a reverse proxy)")
	flag.StringVar(&cfg.TLSCert, "tls-cert", env("RELAY_TLS_CERT", ""), "TLS certificate file (optional; else terminate TLS in a proxy)")
	flag.StringVar(&cfg.TLSKey, "tls-key", env("RELAY_TLS_KEY", ""), "TLS key file")
	flag.Parse()

	cfg.ClientIDs = splitList(clientIDs)
	cfg.CORSOrigins = splitList(cors)
	cfg.AccessTokenTTL = ttl
	cfg.RequestTimeout = reqTimeout

	if cfg.Password == "" {
		fmt.Fprintln(os.Stderr, "error: -password (or RELAY_PASSWORD) is required")
		os.Exit(2)
	}

	store, err := OpenStore(cfg.DataFile)
	if err != nil {
		log.Fatalf("open data file: %v", err)
	}
	auth := NewAuth(cfg, store)
	hub := NewHub(cfg, store)

	mux := http.NewServeMux()
	auth.Register(mux)
	mux.HandleFunc("/t/", hub.ServePublic)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})
	tunnelOrIndex := func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			hub.ServeTunnel(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "AnkiMCP self-hosted relay. Set the addon's tunnel_server_url to this host with ws:// or wss://.")
	}
	// The addon connects to tunnel_server_url verbatim, so accept the upgrade
	// on the root and on /ws.
	mux.HandleFunc("GET /{$}", tunnelOrIndex)
	mux.HandleFunc("GET /ws", tunnelOrIndex)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		var err error
		log.Printf("relay listening on %s (public url: %s)", cfg.Listen, orDerived(cfg.PublicURL))
		if cfg.TLSCert != "" {
			err = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down")
	hub.CloseAll()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

func mustDur(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		log.Fatalf("bad duration %q: %v", s, err)
	}
	return d
}

func orDerived(s string) string {
	if s == "" {
		return "(derived from Host header)"
	}
	return s
}
