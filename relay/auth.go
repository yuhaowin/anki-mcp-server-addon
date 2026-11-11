package main

import (
	"crypto/subtle"
	"encoding/json"
	"html/template"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// OAuth 2.0 Device Authorization Grant (RFC 8628), the subset the addon's
// tunnel/auth.py speaks:
//
//	POST /auth/device  client_id, scope            -> device_code, user_code, ...
//	POST /auth/token   grant_type=device_code      -> tokens | authorization_pending
//	POST /auth/token   grant_type=refresh_token    -> tokens | invalid_grant
//
// The token response must carry expires_in and a "user" object
// ({id, email, tier}); the addon stores it verbatim in credentials.json.
//
// Instead of an identity provider, the user approves a device code on
// /device by typing the relay's admin password.

const (
	deviceCodeTTL   = 10 * time.Minute
	devicePollEvery = 5                      // seconds
	userCodeChars   = "BCDFGHJKLMNPQRSTVWXZ" // no vowels, no look-alikes
	maxFailedLogins = 5
	failWindow      = 15 * time.Minute
)

type deviceGrant struct {
	userCode  string
	clientID  string
	expiresAt time.Time
	userID    string // set once approved
}

type Auth struct {
	cfg   *Config
	store *Store

	mu       sync.Mutex
	byDevice map[string]*deviceGrant // device_code -> grant
	byUser   map[string]string       // user_code -> device_code
	failures map[string][]time.Time  // client IP -> failed approval attempts
}

func NewAuth(cfg *Config, store *Store) *Auth {
	a := &Auth{
		cfg:      cfg,
		store:    store,
		byDevice: map[string]*deviceGrant{},
		byUser:   map[string]string{},
		failures: map[string][]time.Time{},
	}
	go a.gcLoop()
	return a
}

func (a *Auth) gcLoop() {
	for range time.Tick(time.Minute) {
		now := time.Now()
		a.mu.Lock()
		for dc, g := range a.byDevice {
			if now.After(g.expiresAt) {
				delete(a.byDevice, dc)
				delete(a.byUser, g.userCode)
			}
		}
		for ip, ts := range a.failures {
			if len(pruneOld(ts, now)) == 0 {
				delete(a.failures, ip)
			}
		}
		a.mu.Unlock()
	}
}

func (a *Auth) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/device", a.handleDevice)
	mux.HandleFunc("POST /auth/token", a.handleToken)
	mux.HandleFunc("GET /device", a.handleVerifyPage)
	mux.HandleFunc("POST /device", a.handleVerifySubmit)
}

// --- /auth/device ------------------------------------------------------------

func (a *Auth) handleDevice(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	clientID := r.PostForm.Get("client_id")
	if !a.clientAllowed(clientID) {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "unknown client_id")
		return
	}

	deviceCode := randB64(32)
	userCode := newUserCode()

	a.mu.Lock()
	for a.byUser[userCode] != "" {
		userCode = newUserCode()
	}
	a.byDevice[deviceCode] = &deviceGrant{
		userCode:  userCode,
		clientID:  clientID,
		expiresAt: time.Now().Add(deviceCodeTTL),
	}
	a.byUser[userCode] = deviceCode
	a.mu.Unlock()

	base := a.cfg.publicBase(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          base + "/device",
		"verification_uri_complete": base + "/device?user_code=" + userCode,
		"expires_in":                int(deviceCodeTTL.Seconds()),
		"interval":                  devicePollEvery,
	})
}

// --- /auth/token ---------------------------------------------------------------

func (a *Auth) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	if !a.clientAllowed(r.PostForm.Get("client_id")) {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "unknown client_id")
		return
	}

	switch r.PostForm.Get("grant_type") {
	case "urn:ietf:params:oauth:grant-type:device_code":
		a.deviceCodeGrant(w, r.PostForm.Get("device_code"))
	case "refresh_token":
		uid, ok := a.store.LookupRefreshToken(r.PostForm.Get("refresh_token"))
		if !ok {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid or revoked")
			return
		}
		// The refresh token is not rotated: it behaves like Keycloak's offline
		// token. A lost response therefore never strands the client.
		a.writeTokens(w, uid, r.PostForm.Get("refresh_token"))
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (a *Auth) deviceCodeGrant(w http.ResponseWriter, deviceCode string) {
	a.mu.Lock()
	g, ok := a.byDevice[deviceCode]
	if ok && time.Now().After(g.expiresAt) {
		delete(a.byDevice, deviceCode)
		delete(a.byUser, g.userCode)
		a.mu.Unlock()
		oauthError(w, http.StatusBadRequest, "expired_token", "device code expired")
		return
	}
	if !ok {
		a.mu.Unlock()
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown device code")
		return
	}
	if g.userID == "" {
		a.mu.Unlock()
		oauthError(w, http.StatusBadRequest, "authorization_pending", "waiting for user approval")
		return
	}
	// Approved: single use.
	delete(a.byDevice, deviceCode)
	delete(a.byUser, g.userCode)
	uid := g.userID
	a.mu.Unlock()

	refresh, err := a.store.IssueRefreshToken(uid)
	if err != nil {
		log.Printf("auth: persist refresh token: %v", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "could not persist token")
		return
	}
	a.writeTokens(w, uid, refresh)
}

func (a *Auth) writeTokens(w http.ResponseWriter, uid, refresh string) {
	u, ok := a.store.User(uid)
	if !ok {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "user no longer exists")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  a.store.IssueAccessToken(uid, a.cfg.AccessTokenTTL),
		"refresh_token": refresh,
		"token_type":    "Bearer",
		"expires_in":    int(a.cfg.AccessTokenTTL.Seconds()),
		"user":          map[string]string{"id": u.ID, "email": u.Email, "tier": u.Tier},
	})
}

func (a *Auth) clientAllowed(id string) bool {
	if len(a.cfg.ClientIDs) == 0 {
		return id != ""
	}
	return slices.Contains(a.cfg.ClientIDs, id)
}

// --- /device verification page -------------------------------------------------

var verifyTmpl = template.Must(template.New("v").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AnkiMCP Relay – Authorize device</title>
<style>
body{font-family:system-ui,sans-serif;max-width:420px;margin:60px auto;padding:0 16px;color:#222}
input{width:100%;padding:8px;margin:4px 0 14px;box-sizing:border-box;font-size:16px}
button{padding:10px 18px;font-size:16px}.err{color:#b00}.ok{color:#080}
</style></head><body>
<h2>Authorize Anki</h2>
{{if .Done}}<p class="ok">Approved. You can return to Anki — the tunnel will connect in a few seconds.</p>
{{else}}
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<form method="post" action="device">
<label>Code shown in Anki</label><input name="user_code" value="{{.UserCode}}" autocomplete="off" required>
<label>Account (email or any name)</label><input name="email" value="{{.Email}}" required>
<label>Relay password</label><input name="password" type="password" required autofocus>
<button type="submit">Approve</button>
</form>{{end}}
</body></html>`))

type verifyView struct {
	UserCode, Email, Error string
	Done                   bool
}

func (a *Auth) handleVerifyPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	verifyTmpl.Execute(w, verifyView{
		UserCode: normalizeUserCode(r.URL.Query().Get("user_code")),
		Email:    a.cfg.DefaultEmail,
	})
}

func (a *Auth) handleVerifySubmit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	view := verifyView{
		UserCode: normalizeUserCode(r.PostForm.Get("user_code")),
		Email:    strings.TrimSpace(r.PostForm.Get("email")),
	}
	ip := a.cfg.clientIP(r)

	a.mu.Lock()
	now := time.Now()
	a.failures[ip] = pruneOld(a.failures[ip], now)
	locked := len(a.failures[ip]) >= maxFailedLogins
	a.mu.Unlock()
	if locked {
		w.WriteHeader(http.StatusTooManyRequests)
		view.Error = "Too many failed attempts. Try again later."
		verifyTmpl.Execute(w, view)
		return
	}

	pw := r.PostForm.Get("password")
	if subtle.ConstantTimeCompare([]byte(pw), []byte(a.cfg.Password)) != 1 {
		a.recordFailure(ip)
		log.Printf("auth: wrong relay password from %s", ip)
		w.WriteHeader(http.StatusUnauthorized)
		view.Error = "Wrong password."
		verifyTmpl.Execute(w, view)
		return
	}
	if view.Email == "" || len(view.Email) > 254 {
		w.WriteHeader(http.StatusBadRequest)
		view.Error = "Account name is required."
		verifyTmpl.Execute(w, view)
		return
	}

	a.mu.Lock()
	dc := a.byUser[view.UserCode]
	g := a.byDevice[dc]
	if g == nil || time.Now().After(g.expiresAt) {
		a.mu.Unlock()
		a.recordFailure(ip) // guessing user codes also counts
		w.WriteHeader(http.StatusBadRequest)
		view.Error = "Unknown or expired code. Click Connect in Anki again."
		verifyTmpl.Execute(w, view)
		return
	}
	a.mu.Unlock()

	u, err := a.store.UserByEmail(view.Email, a.cfg.Tier)
	if err != nil {
		log.Printf("auth: persist user: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		view.Error = "Internal error."
		verifyTmpl.Execute(w, view)
		return
	}

	a.mu.Lock()
	if g2 := a.byDevice[dc]; g2 != nil {
		g2.userID = u.ID
	}
	a.mu.Unlock()

	log.Printf("auth: device %s approved for %s (%s) from %s", view.UserCode, u.Email, u.ID, ip)
	view.Done = true
	verifyTmpl.Execute(w, view)
}

func (a *Auth) recordFailure(ip string) {
	a.mu.Lock()
	a.failures[ip] = append(a.failures[ip], time.Now())
	a.mu.Unlock()
}

func pruneOld(ts []time.Time, now time.Time) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < failWindow {
			out = append(out, t)
		}
	}
	return out
}

func newUserCode() string {
	b := randBytes(8)
	out := make([]byte, 0, 9)
	for i, v := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, userCodeChars[int(v)%len(userCodeChars)])
	}
	return string(out)
}

func normalizeUserCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	if len(s) == 8 && !strings.Contains(s, "-") {
		s = s[:4] + "-" + s[4:]
	}
	return s
}

// --- shared HTTP helpers ---------------------------------------------------------

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
