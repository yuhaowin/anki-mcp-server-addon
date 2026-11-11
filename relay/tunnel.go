package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocket protocol, mirroring anki_mcp_server/tunnel/protocol.py.
//
// relay -> addon: tunnel_established{url} | request{...} | ping{timestamp} | error{code,message}
// addon -> relay: response{requestId,statusCode,headers,body?} | pong{timestamp}
const (
	closeNormal         = 1000
	closeGoingAway      = 1001
	closeTokenRevoked   = 4002
	closeSessionReplace = 4005
	closeShutdown       = 4009

	pingInterval = 30 * time.Second // addon drops the link after 60s without a ping
	pongTimeout  = 90 * time.Second
	writeTimeout = 10 * time.Second

	// The addon's websockets client keeps the library default max_size of
	// 1 MiB for incoming frames; a bigger frame kills the whole tunnel
	// (close 1009). Requests that would not fit are refused with 413.
	addonMaxFrame = 1 << 20
	// Responses travel addon -> relay, where we choose the limit.
	relayMaxFrame = 64 << 20
)

type wsMessage struct {
	Type       string            `json:"type"`
	URL        string            `json:"url,omitempty"`
	RequestID  string            `json:"requestId,omitempty"`
	Method     string            `json:"method,omitempty"`
	Path       string            `json:"path,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       *string           `json:"body,omitempty"`
	StatusCode int               `json:"statusCode,omitempty"`
	Timestamp  int64             `json:"timestamp,omitempty"`
	Code       string            `json:"code,omitempty"`
	Message    string            `json:"message,omitempty"`
}

// session is one connected addon.
type session struct {
	user *User
	conn *websocket.Conn

	writeMu sync.Mutex

	mu       sync.Mutex
	pending  map[string]chan *wsMessage
	lastPong time.Time
	closed   bool
	done     chan struct{}
}

func (s *session) send(m *wsMessage) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return s.sendRaw(raw)
}

func (s *session) sendRaw(raw []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return s.conn.WriteMessage(websocket.TextMessage, raw)
}

// close sends a close frame with code/reason and tears the session down.
func (s *session) close(code int, reason string) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	pending := s.pending
	s.pending = map[string]chan *wsMessage{}
	s.mu.Unlock()

	s.writeMu.Lock()
	s.conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second))
	s.writeMu.Unlock()
	s.conn.Close()
	close(s.done)
	for _, ch := range pending {
		close(ch) // waiters treat a closed channel as "tunnel went away"
	}
}

// Hub tracks connected addons by tunnel ID.
type Hub struct {
	cfg      *Config
	store    *Store
	upgrader websocket.Upgrader

	mu       sync.Mutex
	sessions map[string]*session // tunnel ID -> session
}

func NewHub(cfg *Config, store *Store) *Hub {
	return &Hub{
		cfg:   cfg,
		store: store,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  32 << 10,
			WriteBufferSize: 32 << 10,
			// The addon is not a browser; auth is the bearer token.
			CheckOrigin: func(*http.Request) bool { return true },
		},
		sessions: map[string]*session{},
	}
}

// ServeTunnel handles the addon's WebSocket upgrade.
func (h *Hub) ServeTunnel(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	user, err := h.store.VerifyAccessToken(strings.TrimSpace(tok))
	if err != nil {
		log.Printf("tunnel: rejected connection from %s: %v", h.cfg.clientIP(r), err)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade already wrote the error
	}
	conn.SetReadLimit(relayMaxFrame)

	s := &session{
		user:     user,
		conn:     conn,
		pending:  map[string]chan *wsMessage{},
		lastPong: time.Now(),
		done:     make(chan struct{}),
	}

	h.mu.Lock()
	old := h.sessions[user.TunnelID]
	h.sessions[user.TunnelID] = s
	h.mu.Unlock()
	if old != nil {
		old.close(closeSessionReplace, "Session replaced by a new connection")
	}

	url := h.cfg.publicBase(r) + "/t/" + user.TunnelID
	if err := s.send(&wsMessage{Type: "tunnel_established", URL: url}); err != nil {
		h.drop(s, closeGoingAway, "handshake write failed")
		return
	}
	log.Printf("tunnel: %s connected (client=%s/%s) url=%s", user.Email,
		r.Header.Get("x-ankimcp-client-type"), r.Header.Get("x-ankimcp-client-version"), url)

	go h.pingLoop(s)
	h.readLoop(s)
}

func (h *Hub) drop(s *session, code int, reason string) {
	h.mu.Lock()
	if h.sessions[s.user.TunnelID] == s {
		delete(h.sessions, s.user.TunnelID)
	}
	h.mu.Unlock()
	s.close(code, reason)
}

func (h *Hub) readLoop(s *session) {
	defer func() {
		h.drop(s, closeGoingAway, "connection lost")
		log.Printf("tunnel: %s disconnected", s.user.Email)
	}()
	for {
		_, raw, err := s.conn.ReadMessage()
		if err != nil {
			return
		}
		var m wsMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			log.Printf("tunnel: %s sent malformed message: %v", s.user.Email, err)
			continue
		}
		switch m.Type {
		case "response":
			s.mu.Lock()
			ch := s.pending[m.RequestID]
			delete(s.pending, m.RequestID)
			s.mu.Unlock()
			if ch != nil {
				ch <- &m // buffered(1)
			}
		case "pong":
			s.mu.Lock()
			s.lastPong = time.Now()
			s.mu.Unlock()
		default:
			log.Printf("tunnel: %s sent unknown message type %q", s.user.Email, m.Type)
		}
	}
}

func (h *Hub) pingLoop(s *session) {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
		}
		s.mu.Lock()
		stale := time.Since(s.lastPong) > pongTimeout
		s.mu.Unlock()
		if stale {
			h.drop(s, closeGoingAway, "pong timeout")
			return
		}
		// Revoked (refresh tokens removed from the data file) -> tell the
		// addon not to reconnect.
		if !h.store.HasRefreshToken(s.user.ID) {
			h.drop(s, closeTokenRevoked, "Token revoked")
			return
		}
		if err := s.send(&wsMessage{Type: "ping", Timestamp: time.Now().UnixMilli()}); err != nil {
			h.drop(s, closeGoingAway, "ping write failed")
			return
		}
	}
}

// CloseAll is called on shutdown. 4009 makes the addon retry with backoff,
// so it comes back on its own after a relay restart.
func (h *Hub) CloseAll() {
	h.mu.Lock()
	all := make([]*session, 0, len(h.sessions))
	for _, s := range h.sessions {
		all = append(all, s)
	}
	h.sessions = map[string]*session{}
	h.mu.Unlock()
	for _, s := range all {
		s.close(closeShutdown, "Relay shutting down")
	}
}

// --- public side: https://<relay>/t/<tunnelID>[/...] ---------------------------

// hop-by-hop / credential headers never forwarded to the addon.
var dropHeaders = map[string]bool{
	"authorization": true, "cookie": true, "connection": true, "keep-alive": true,
	"proxy-authorization": true, "proxy-connection": true, "te": true, "trailer": true,
	"transfer-encoding": true, "upgrade": true,
}

func (h *Hub) ServePublic(w http.ResponseWriter, r *http.Request) {
	h.setCORS(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/t/")
	tunnelID, subPath, _ := strings.Cut(rest, "/")
	subPath = "/" + subPath
	if r.URL.RawQuery != "" {
		subPath += "?" + r.URL.RawQuery
	}

	if h.cfg.PublicAPIKey != "" {
		got, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !constantTimeEq(got, h.cfg.PublicAPIKey) {
			jsonRPCError(w, http.StatusForbidden, nil, -32001, "Forbidden")
			return
		}
	}

	h.mu.Lock()
	s := h.sessions[tunnelID]
	h.mu.Unlock()
	if s == nil {
		// Same answer for "unknown ID" and "addon offline": no ID oracle.
		jsonRPCError(w, http.StatusServiceUnavailable, nil, -32000,
			"Anki is not connected to the relay (open Anki and click Connect Tunnel)")
		return
	}

	switch r.Method {
	case http.MethodPost:
	case http.MethodGet, http.MethodDelete:
		// The addon runs MCP statelessly: no standalone SSE stream and no
		// session to delete. 405 is the spec-sanctioned answer to both.
		w.Header().Set("Allow", "POST, OPTIONS")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	default:
		w.Header().Set("Allow", "POST, OPTIONS")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(http.MaxBytesReader(w, r.Body, addonMaxFrame))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			jsonRPCError(w, http.StatusRequestEntityTooLarge, nil, -32600, "Request body too large for the tunnel (max ~1 MiB)")
			return
		}
		jsonRPCError(w, http.StatusBadRequest, nil, -32700, "Could not read request body")
		return
	}
	body := string(bodyBytes)
	rpcID := extractRPCID(bodyBytes)

	headers := map[string]string{}
	for k, v := range r.Header {
		lk := strings.ToLower(k)
		if dropHeaders[lk] {
			continue
		}
		headers[lk] = strings.Join(v, ", ")
	}

	reqID := randHex(12)
	msg := &wsMessage{
		Type:      "request",
		RequestID: reqID,
		Method:    r.Method,
		Path:      subPath,
		Headers:   headers,
	}
	if len(bodyBytes) > 0 {
		msg.Body = &body
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		jsonRPCError(w, http.StatusInternalServerError, rpcID, -32603, "Internal relay error")
		return
	}
	if len(raw) > addonMaxFrame {
		jsonRPCError(w, http.StatusRequestEntityTooLarge, rpcID, -32600, "Request too large for the tunnel (max ~1 MiB after encoding)")
		return
	}

	ch := make(chan *wsMessage, 1)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		jsonRPCError(w, http.StatusServiceUnavailable, rpcID, -32000, "Anki tunnel disconnected")
		return
	}
	s.pending[reqID] = ch
	s.mu.Unlock()

	cleanup := func() {
		s.mu.Lock()
		delete(s.pending, reqID)
		s.mu.Unlock()
	}

	start := time.Now()
	if err := s.sendRaw(raw); err != nil {
		cleanup()
		h.drop(s, closeGoingAway, "write failed")
		jsonRPCError(w, http.StatusBadGateway, rpcID, -32000, "Anki tunnel disconnected")
		return
	}

	timer := time.NewTimer(h.cfg.RequestTimeout)
	defer timer.Stop()
	select {
	case resp, ok := <-ch:
		if !ok {
			jsonRPCError(w, http.StatusBadGateway, rpcID, -32000, "Anki tunnel disconnected while handling the request")
			return
		}
		for k, v := range resp.Headers {
			if !dropHeaders[strings.ToLower(k)] && !strings.EqualFold(k, "content-length") {
				w.Header().Set(k, v)
			}
		}
		status := resp.StatusCode
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		if resp.Body != nil {
			io.WriteString(w, *resp.Body)
		}
		log.Printf("proxy: %s POST %s -> %d (%s)", s.user.Email, subPath, status, time.Since(start).Round(time.Millisecond))
	case <-timer.C:
		cleanup()
		jsonRPCError(w, http.StatusGatewayTimeout, rpcID, -32004, "Request timed out")
	case <-r.Context().Done():
		cleanup()
	}
}

func (h *Hub) setCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" || len(h.cfg.CORSOrigins) == 0 {
		return
	}
	allowed := ""
	for _, o := range h.cfg.CORSOrigins {
		if o == "*" || o == origin {
			allowed = origin
			break
		}
	}
	if allowed == "" {
		return
	}
	hd := w.Header()
	hd.Set("Access-Control-Allow-Origin", allowed)
	hd.Add("Vary", "Origin")
	hd.Set("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS")
	hd.Set("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID")
	hd.Set("Access-Control-Expose-Headers", "Mcp-Session-Id, Mcp-Protocol-Version")
	hd.Set("Access-Control-Max-Age", "600")
}

func extractRPCID(body []byte) json.RawMessage {
	var probe struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(body, &probe) != nil || len(probe.ID) == 0 {
		return nil
	}
	return probe.ID
}

func jsonRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, msg string) {
	if id == nil {
		id = json.RawMessage("null")
	}
	writeJSON(w, status, map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": msg},
	})
}
