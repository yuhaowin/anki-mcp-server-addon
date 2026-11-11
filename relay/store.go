package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// User is one account that may open a tunnel. Each user owns exactly one
// stable tunnel ID, so its public URL survives reconnects and relay restarts.
type User struct {
	ID       string    `json:"id"`
	Email    string    `json:"email"`
	Tier     string    `json:"tier"`
	TunnelID string    `json:"tunnel_id"`
	Created  time.Time `json:"created"`
}

// persisted is the on-disk layout of the data file.
type persisted struct {
	// Secret signs access tokens. Deleting the data file rotates it, which
	// invalidates every outstanding token and forces every client to log in.
	Secret string           `json:"secret"`
	Users  map[string]*User `json:"users"` // keyed by user ID
	// RefreshTokens maps sha256(refresh_token) -> user ID. Only hashes are
	// stored so a leaked data file does not leak usable refresh tokens.
	RefreshTokens map[string]string `json:"refresh_tokens"`
}

// Store is the relay's persistent state, saved as JSON after every mutation.
type Store struct {
	mu     sync.Mutex
	path   string
	data   persisted
	secret []byte
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		s.data = persisted{
			Secret:        randHex(32),
			Users:         map[string]*User{},
			RefreshTokens: map[string]string{},
		}
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(raw, &s.data); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if s.data.Users == nil {
			s.data.Users = map[string]*User{}
		}
		if s.data.RefreshTokens == nil {
			s.data.RefreshTokens = map[string]string{}
		}
		if s.data.Secret == "" {
			s.data.Secret = randHex(32)
			if err := s.saveLocked(); err != nil {
				return nil, err
			}
		}
	}
	s.secret = []byte(s.data.Secret)
	return s, nil
}

func (s *Store) saveLocked() error {
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// UserByEmail returns the user with this email, creating it if needed.
func (s *Store) UserByEmail(email, tier string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.data.Users {
		if strings.EqualFold(u.Email, email) {
			c := *u
			return &c, nil
		}
	}
	u := &User{
		ID:       "usr_" + randHex(8),
		Email:    email,
		Tier:     tier,
		TunnelID: randHex(16), // 128 bits: the public URL is the capability
		Created:  time.Now().UTC(),
	}
	s.data.Users[u.ID] = u
	if err := s.saveLocked(); err != nil {
		delete(s.data.Users, u.ID)
		return nil, err
	}
	c := *u
	return &c, nil
}

func (s *Store) User(id string) (*User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.data.Users[id]
	if !ok {
		return nil, false
	}
	c := *u
	return &c, true
}

// HasRefreshToken reports whether the user still holds at least one refresh
// token. Used to notice revocation of a user whose tunnel is connected.
func (s *Store) HasRefreshToken(userID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, uid := range s.data.RefreshTokens {
		if uid == userID {
			return true
		}
	}
	return false
}

func (s *Store) IssueRefreshToken(userID string) (string, error) {
	tok := randB64(32)
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashToken(tok)
	s.data.RefreshTokens[h] = userID
	if err := s.saveLocked(); err != nil {
		delete(s.data.RefreshTokens, h)
		return "", err
	}
	return tok, nil
}

func (s *Store) LookupRefreshToken(tok string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	uid, ok := s.data.RefreshTokens[hashToken(tok)]
	if !ok {
		return "", false
	}
	if _, exists := s.data.Users[uid]; !exists {
		return "", false
	}
	return uid, true
}

// --- access tokens -----------------------------------------------------------
//
// Access tokens are stateless: base64url(payload) "." base64url(HMAC-SHA256).
// They only need to survive until expiry; revocation happens through the
// refresh token, which the client must present again once this expires.

type accessClaims struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
}

func (s *Store) IssueAccessToken(userID string, ttl time.Duration) string {
	payload, _ := json.Marshal(accessClaims{Sub: userID, Exp: time.Now().Add(ttl).Unix()})
	p := base64.RawURLEncoding.EncodeToString(payload)
	return p + "." + s.sign(p)
}

func (s *Store) VerifyAccessToken(tok string) (*User, error) {
	p, sig, ok := strings.Cut(tok, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(s.sign(p))) {
		return nil, errors.New("bad signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return nil, err
	}
	var c accessClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if time.Now().Unix() >= c.Exp {
		return nil, errors.New("token expired")
	}
	u, ok := s.User(c.Sub)
	if !ok {
		return nil, errors.New("unknown user")
	}
	return u, nil
}

func (s *Store) sign(p string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(p))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// --- helpers -------------------------------------------------------------------

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func randHex(n int) string { return hex.EncodeToString(randBytes(n)) }
func randB64(n int) string { return base64.RawURLEncoding.EncodeToString(randBytes(n)) }
