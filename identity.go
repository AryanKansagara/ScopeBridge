package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const exchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"
const accessTokenType = "urn:ietf:params:oauth:token-type:access_token"

type Client struct {
	SecretHash   [32]byte
	Scopes       []string
	Audiences    []string
	DelegatesFor []string
}
type Actor struct {
	Subject string `json:"sub"`
}
type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ClientID  string `json:"client_id"`
	Scope     string `json:"scope"`
	ID        string `json:"jti"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	Expires   int64  `json:"exp"`
	Actor     *Actor `json:"act,omitempty"`
}
type AuditEvent struct {
	Time      int64  `json:"time"`
	RequestID string `json:"request_id"`
	Action    string `json:"action"`
	Outcome   string `json:"outcome"`
	Subject   string `json:"subject,omitempty"`
	Actor     string `json:"actor,omitempty"`
	Audience  string `json:"audience,omitempty"`
	Scope     string `json:"scope,omitempty"`
}
type Service struct {
	issuer   string
	key      ed25519.PrivateKey
	clients  map[string]Client
	now      func() time.Time
	ttl      time.Duration
	mu       sync.Mutex
	revoked  map[string]int64
	audit    io.Writer
	requests atomic.Uint64
	denied   atomic.Uint64
	issued   atomic.Uint64
}

func newService(issuer string, clients map[string]Client, audit io.Writer) (*Service, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Service{issuer: issuer, key: key, clients: clients, now: time.Now,
		ttl: 2 * time.Minute, revoked: map[string]int64{}, audit: audit}, nil
}
func client(secret string, scopes, audiences, delegates []string) Client {
	return Client{sha256.Sum256([]byte(secret)), scopes, audiences, delegates}
}
func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func allowed(requested []string, permitted []string) bool {
	if len(requested) == 0 {
		return false
	}
	for _, s := range requested {
		if !contains(permitted, s) {
			return false
		}
	}
	return true
}
func canonicalScope(raw string) string {
	fields := strings.Fields(raw)
	sort.Strings(fields)
	result := []string{}
	for _, s := range fields {
		if !contains(result, s) {
			result = append(result, s)
		}
	}
	return strings.Join(result, " ")
}
func encode(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
func (s *Service) sign(c Claims) string {
	payload := encode(map[string]string{"alg": "EdDSA", "typ": "at+jwt", "kid": "local-1"}) + "." + encode(c)
	return payload + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.key, []byte(payload)))
}
func (s *Service) verify(token, audience string) (Claims, error) {
	fail := errors.New("invalid access token")
	var c Claims
	if len(token) > 8192 {
		return c, fail
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, fail
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return c, fail
	}
	var h struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
		KeyID     string `json:"kid"`
	}
	if json.Unmarshal(header, &h) != nil || h.Algorithm != "EdDSA" || h.Type != "at+jwt" || h.KeyID != "local-1" {
		return c, fail
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return c, fail
	}
	if !ed25519.Verify(s.key.Public().(ed25519.PublicKey), []byte(parts[0]+"."+parts[1]), signature) {
		return c, fail
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(payload, &c) != nil {
		return c, fail
	}
	now := s.now().Unix()
	if c.Issuer != s.issuer || c.Audience != audience || c.Subject == "" || c.ClientID == "" || c.ID == "" || c.Scope == "" || c.IssuedAt <= 0 || c.IssuedAt > now || c.NotBefore > now || c.Expires <= now || c.Expires <= c.IssuedAt || c.Expires-c.IssuedAt > int64(s.ttl.Seconds()) {
		return c, fail
	}
	s.mu.Lock()
	_, revoked := s.revoked[c.ID]
	s.mu.Unlock()
	if revoked {
		return c, fail
	}
	return c, nil
}
func (s *Service) record(event AuditEvent) error {
	event.Time = s.now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.NewEncoder(s.audit).Encode(event)
}
func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func (s *Service) reject(w http.ResponseWriter, id string, status int, code string) {
	s.denied.Add(1)
	_ = s.record(AuditEvent{RequestID: id, Action: "request", Outcome: code})
	if status == 401 {
		challenge := `Basic realm="ScopeBridge"`
		if code == "invalid_token" {
			challenge = `Bearer error="invalid_token"`
		}
		w.Header().Set("WWW-Authenticate", challenge)
	}
	jsonResponse(w, status, map[string]string{"error": code})
}
func (s *Service) authenticate(r *http.Request) (string, Client, bool) {
	id, secret, ok := r.BasicAuth()
	config, exists := s.clients[id]
	hash := sha256.Sum256([]byte(secret))
	valid := subtle.ConstantTimeCompare(hash[:], config.SecretHash[:]) == 1
	return id, config, ok && exists && valid
}
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("POST /oauth/revoke", s.revoke)
	mux.HandleFunc("GET /api/secret", s.secret)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, map[string]any{"issuer": s.issuer, "token_endpoint": s.issuer + "/oauth/token", "jwks_uri": s.issuer + "/jwks.json", "revocation_endpoint": s.issuer + "/oauth/revoke", "grant_types_supported": []string{"client_credentials", exchangeGrant}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"}})
	})
	mux.HandleFunc("GET /jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, map[string]any{"keys": []any{map[string]string{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": "local-1", "x": base64.RawURLEncoding.EncodeToString(s.key.Public().(ed25519.PublicKey))}}})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { jsonResponse(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, map[string]uint64{"requests": s.requests.Load(), "denied": s.denied.Load(), "tokens_issued": s.issued.Load()})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := randomID()
		w.Header().Set("X-Request-ID", id)
		s.requests.Add(1)
		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		mux.ServeHTTP(w, r)
		slog.Debug("request completed", "request_id", id, "elapsed_us", time.Since(start).Microseconds())
	})
}
func (s *Service) token(w http.ResponseWriter, r *http.Request) {
	id := w.Header().Get("X-Request-ID")
	name, config, ok := s.authenticate(r)
	if !ok {
		s.reject(w, id, 401, "invalid_client")
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") || r.ParseForm() != nil {
		s.reject(w, id, 400, "invalid_request")
		return
	}
	scope := canonicalScope(r.PostForm.Get("scope"))
	audience := r.PostForm.Get("audience")
	if !allowed(strings.Fields(scope), config.Scopes) || !contains(config.Audiences, audience) {
		s.reject(w, id, 400, "invalid_scope")
		return
	}
	now := s.now().Unix()
	c := Claims{Issuer: s.issuer, Subject: name, Audience: audience, ClientID: name, Scope: scope, ID: randomID(), IssuedAt: now, NotBefore: now, Expires: now + int64(s.ttl.Seconds())}
	grant := r.PostForm.Get("grant_type")
	switch grant {
	case "client_credentials":
	case exchangeGrant:
		if r.PostForm.Get("subject_token_type") != accessTokenType {
			s.reject(w, id, 400, "invalid_request")
			return
		}
		parent, err := s.verify(r.PostForm.Get("subject_token"), "scopebridge")
		if err != nil || parent.Actor != nil || !contains(config.DelegatesFor, parent.Subject) || !allowed(strings.Fields(scope), strings.Fields(parent.Scope)) {
			s.reject(w, id, 400, "invalid_grant")
			return
		}
		c.Subject = parent.Subject
		c.Actor = &Actor{Subject: name}
		if c.Expires > parent.Expires {
			c.Expires = parent.Expires
		}
	default:
		s.reject(w, id, 400, "unsupported_grant_type")
		return
	}
	actor := name
	if s.record(AuditEvent{RequestID: id, Action: grant, Outcome: "allowed", Subject: c.Subject, Actor: actor, Audience: audience, Scope: scope}) != nil {
		jsonResponse(w, 503, map[string]string{"error": "audit_unavailable"})
		return
	}
	s.issued.Add(1)
	result := map[string]any{"access_token": s.sign(c), "token_type": "Bearer", "expires_in": c.Expires - now, "scope": scope}
	if grant == exchangeGrant {
		result["issued_token_type"] = accessTokenType
	}
	jsonResponse(w, 200, result)
}
func (s *Service) secret(w http.ResponseWriter, r *http.Request) {
	id := w.Header().Get("X-Request-ID")
	authorization := strings.Fields(r.Header.Get("Authorization"))
	if len(authorization) != 2 || !strings.EqualFold(authorization[0], "Bearer") {
		s.reject(w, id, 401, "invalid_token")
		return
	}
	c, err := s.verify(authorization[1], "secrets-api")
	if err != nil {
		s.reject(w, id, 401, "invalid_token")
		return
	}
	if !contains(strings.Fields(c.Scope), "secrets:read") {
		s.reject(w, id, 403, "insufficient_scope")
		return
	}
	actor := c.ClientID
	if c.Actor != nil {
		actor = c.Actor.Subject
	}
	if s.record(AuditEvent{RequestID: id, Action: "secret.read", Outcome: "allowed", Subject: c.Subject, Actor: actor, Audience: c.Audience, Scope: c.Scope}) != nil {
		jsonResponse(w, 503, map[string]string{"error": "audit_unavailable"})
		return
	}
	jsonResponse(w, 200, map[string]string{"value": "synthetic-demo-value", "subject": c.Subject, "actor": actor})
}
func (s *Service) revoke(w http.ResponseWriter, r *http.Request) {
	id := w.Header().Get("X-Request-ID")
	name, config, ok := s.authenticate(r)
	if !ok {
		s.reject(w, id, 401, "invalid_client")
		return
	}
	if r.ParseForm() != nil {
		s.reject(w, id, 400, "invalid_request")
		return
	}
	// The issuer only revokes tokens issued to the authenticated client. Invalid
	// tokens still return 200 to avoid disclosing another client's token state.
	for _, audience := range config.Audiences {
		c, err := s.verify(r.PostForm.Get("token"), audience)
		if err == nil && c.ClientID == name {
			s.mu.Lock()
			for jti, expiry := range s.revoked {
				if expiry <= s.now().Unix() {
					delete(s.revoked, jti)
				}
			}
			s.revoked[c.ID] = c.Expires
			s.mu.Unlock()
			if s.record(AuditEvent{RequestID: id, Action: "token.revoke", Outcome: "allowed", Subject: c.Subject, Actor: name}) != nil {
				jsonResponse(w, 503, map[string]string{"error": "audit_unavailable"})
				return
			}
			break
		}
	}
	jsonResponse(w, 200, map[string]string{"status": "processed"})
}
