package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const testPlanner = "test-fixture-planner-not-a-real-credential"
const testWorker = "test-fixture-worker-not-a-real-credential"

func setup(t *testing.T) (*Service, *bytes.Buffer) {
	t.Helper()
	audit := &bytes.Buffer{}
	s, err := newService("http://issuer.local", policies(testPlanner, testWorker), audit)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Unix(1800000000, 0) }
	return s, audit
}
func post(s *Service, path, name, secret string, values url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(values.Encode()))
	r.SetBasicAuth(name, secret)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func grant(scope, audience string) url.Values {
	return url.Values{"grant_type": {"client_credentials"}, "scope": {scope}, "audience": {audience}}
}
func get(s *Service, path, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func issuedToken(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("unexpected response %d: %s", w.Code, w.Body.String())
	}
	var result struct {
		Token string `json:"access_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Token == "" {
		t.Fatal("missing token")
	}
	return result.Token
}
func workerToken(t *testing.T, s *Service, scope string) string {
	return issuedToken(t, post(s, "/oauth/token", "worker", testWorker, grant(scope, "secrets-api")))
}

func TestClientCredentialsAndProtectedResource(t *testing.T) {
	s, _ := setup(t)
	token := workerToken(t, s, "secrets:read")
	c, err := s.verify(token, "secrets-api")
	if err != nil {
		t.Fatal(err)
	}
	if c.Expires-c.IssuedAt != 120 || c.Subject != "worker" || c.ClientID != "worker" {
		t.Fatalf("bad claims: %+v", c)
	}
	w := get(s, "/api/secret", token)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing response controls")
	}
}
func TestGrantRejections(t *testing.T) {
	cases := []struct {
		name, client, secret string
		form                 url.Values
		status               int
	}{
		{"bad secret", "worker", "wrong", grant("secrets:read", "secrets-api"), 401},
		{"unknown client", "missing", testWorker, grant("secrets:read", "secrets-api"), 401},
		{"scope escalation", "worker", testWorker, grant("secrets:write", "secrets-api"), 400},
		{"empty scope", "worker", testWorker, grant("", "secrets-api"), 400},
		{"wrong audience", "worker", testWorker, grant("secrets:read", "external-api"), 400},
		{"unsupported grant", "worker", testWorker, url.Values{"grant_type": {"password"}, "scope": {"secrets:read"}, "audience": {"secrets-api"}}, 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := setup(t)
			w := post(s, "/oauth/token", tc.client, tc.secret, tc.form)
			if w.Code != tc.status {
				t.Fatalf("got %d", w.Code)
			}
		})
	}
}
func exchange(parent, scope string) url.Values {
	return url.Values{"grant_type": {exchangeGrant}, "subject_token_type": {accessTokenType}, "subject_token": {parent}, "scope": {scope}, "audience": {"secrets-api"}}
}
func TestDelegatedExchange(t *testing.T) {
	s, audit := setup(t)
	parent := issuedToken(t, post(s, "/oauth/token", "planner", testPlanner, grant("secrets:read repo:read", "scopebridge")))
	s.now = func() time.Time { return time.Unix(1800000050, 0) }
	token := issuedToken(t, post(s, "/oauth/token", "worker", testWorker, exchange(parent, "secrets:read")))
	c, err := s.verify(token, "secrets-api")
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "planner" || c.Actor == nil || c.Actor.Subject != "worker" || c.Scope != "secrets:read" || c.Expires != 1800000120 {
		t.Fatalf("incorrect delegation: %+v", c)
	}
	if get(s, "/api/secret", token).Code != 200 {
		t.Fatal("delegation failed")
	}
	if !strings.Contains(audit.String(), `"subject":"planner","actor":"worker"`) {
		t.Fatal("missing actor attribution")
	}
}
func TestExchangeBoundaries(t *testing.T) {
	for _, mode := range []string{"scope escalation", "untrusted subject", "invalid token", "wrong type", "already delegated", "revoked parent"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := setup(t)
			parent := issuedToken(t, post(s, "/oauth/token", "planner", testPlanner, grant("secrets:read", "scopebridge")))
			form := exchange(parent, "secrets:read")
			switch mode {
			case "scope escalation":
				form.Set("scope", "repo:read")
			case "untrusted subject":
				c, _ := s.verify(parent, "scopebridge")
				c.Subject = "outsider"
				form.Set("subject_token", s.sign(c))
			case "invalid token":
				form.Set("subject_token", "malformed")
			case "wrong type":
				form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:id_token")
			case "already delegated":
				c, _ := s.verify(parent, "scopebridge")
				c.Actor = &Actor{Subject: "other"}
				form.Set("subject_token", s.sign(c))
			case "revoked parent":
				post(s, "/oauth/revoke", "planner", testPlanner, url.Values{"token": {parent}})
			}
			if w := post(s, "/oauth/token", "worker", testWorker, form); w.Code != 400 {
				t.Fatalf("accepted %s: %d", mode, w.Code)
			}
		})
	}
}
func TestTokenValidation(t *testing.T) {
	cases := []string{"expired", "future nbf", "future iat", "wrong issuer", "wrong audience", "empty subject", "missing id", "missing client", "empty scope", "excess lifetime", "reversed expiry", "bad signature", "none algorithm", "id token type", "wrong key id", "malformed", "oversized"}
	for _, mode := range cases {
		t.Run(mode, func(t *testing.T) {
			s, _ := setup(t)
			token := workerToken(t, s, "secrets:read")
			c, _ := s.verify(token, "secrets-api")
			switch mode {
			case "expired":
				c.Expires = c.IssuedAt
			case "future nbf":
				c.NotBefore += 5
			case "future iat":
				c.IssuedAt += 5
			case "wrong issuer":
				c.Issuer = "http://attacker.local"
			case "wrong audience":
				c.Audience = "other"
			case "empty subject":
				c.Subject = ""
			case "missing id":
				c.ID = ""
			case "missing client":
				c.ClientID = ""
			case "empty scope":
				c.Scope = ""
			case "excess lifetime":
				c.Expires += 1
			case "reversed expiry":
				c.Expires = c.IssuedAt - 1
			}
			token = s.sign(c)
			switch mode {
			case "bad signature":
				parts := strings.Split(token, ".")
				signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
				signature[0] ^= 1
				parts[2] = base64.RawURLEncoding.EncodeToString(signature)
				token = strings.Join(parts, ".")
			case "none algorithm", "id token type", "wrong key id":
				h := map[string]string{"alg": "EdDSA", "typ": "at+jwt", "kid": "local-1"}
				if mode == "none algorithm" {
					h["alg"] = "none"
				}
				if mode == "id token type" {
					h["typ"] = "JWT"
				}
				if mode == "wrong key id" {
					h["kid"] = "untrusted"
				}
				payload := encode(h) + "." + encode(c)
				token = payload + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.key, []byte(payload)))
			case "malformed":
				token = "invalid"
			case "oversized":
				token = strings.Repeat("x", 8193)
			}
			if get(s, "/api/secret", token).Code != 401 {
				t.Fatalf("accepted %s", mode)
			}
		})
	}
}
func TestMissingAndInsufficientAuthorization(t *testing.T) {
	s, _ := setup(t)
	if get(s, "/api/secret", "").Code != 401 {
		t.Fatal("accepted anonymous")
	}
	if get(s, "/api/secret", workerToken(t, s, "repo:read")).Code != 403 {
		t.Fatal("accepted wrong scope")
	}
}
func TestRevocationIsClientScoped(t *testing.T) {
	s, _ := setup(t)
	token := workerToken(t, s, "secrets:read")
	post(s, "/oauth/revoke", "planner", testPlanner, url.Values{"token": {token}})
	if get(s, "/api/secret", token).Code != 200 {
		t.Fatal("other client revoked token")
	}
	post(s, "/oauth/revoke", "worker", testWorker, url.Values{"token": {token}})
	if get(s, "/api/secret", token).Code != 401 {
		t.Fatal("revocation ignored")
	}
	if post(s, "/oauth/revoke", "worker", testWorker, url.Values{"token": {"invalid"}}).Code != 200 {
		t.Fatal("invalid token state disclosed")
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("audit unavailable") }
func TestAuditFailureIsClosed(t *testing.T) {
	s, _ := setup(t)
	token := workerToken(t, s, "secrets:read")
	s.audit = brokenWriter{}
	if post(s, "/oauth/token", "worker", testWorker, grant("secrets:read", "secrets-api")).Code != 503 {
		t.Fatal("issued without audit")
	}
	if get(s, "/api/secret", token).Code != 503 {
		t.Fatal("served without audit")
	}
}
func TestAuditDoesNotLogCredentials(t *testing.T) {
	s, audit := setup(t)
	token := workerToken(t, s, "secrets:read")
	get(s, "/api/secret", token)
	if strings.Contains(audit.String(), testWorker) || strings.Contains(audit.String(), token) || strings.Contains(audit.String(), "synthetic-demo-value") {
		t.Fatal("sensitive value in audit")
	}
}
func TestMetadataAndMetrics(t *testing.T) {
	s, _ := setup(t)
	for _, path := range []string{"/healthz", "/.well-known/oauth-authorization-server", "/jwks.json", "/metrics"} {
		w := get(s, path, "")
		if w.Code != 200 || !json.Valid(w.Body.Bytes()) {
			t.Fatalf("bad %s", path)
		}
	}
	if strings.Contains(get(s, "/jwks.json", "").Body.String(), `"d":`) {
		t.Fatal("private key exposed")
	}
}
func TestBadContentAndOversizedInput(t *testing.T) {
	s, _ := setup(t)
	r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("{}"))
	r.SetBasicAuth("worker", testWorker)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("accepted JSON grant")
	}
	if post(s, "/oauth/token", "worker", testWorker, grant(strings.Repeat("x", 20000), "secrets-api")).Code != 400 {
		t.Fatal("accepted oversized body")
	}
}
func TestParallelHTTPRequests(t *testing.T) {
	s, _ := setup(t)
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, _ := http.NewRequest("POST", server.URL+"/oauth/token", strings.NewReader(grant("secrets:read", "secrets-api").Encode()))
			r.SetBasicAuth("worker", testWorker)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response, err := server.Client().Do(r)
			if err != nil {
				t.Error(err)
				return
			}
			defer response.Body.Close()
			_, _ = io.Copy(io.Discard, response.Body)
			if response.StatusCode != 200 {
				t.Errorf("status %d", response.StatusCode)
			}
		}()
	}
	wg.Wait()
	if s.issued.Load() != 24 {
		t.Fatalf("lost requests: %d", s.issued.Load())
	}
}
func TestCanonicalScope(t *testing.T) {
	if canonicalScope("secrets:read repo:read secrets:read") != "repo:read secrets:read" {
		t.Fatal("scope normalization failed")
	}
}
func TestDemo(t *testing.T) {
	if err := demo(); err != nil {
		t.Fatal(err)
	}
}
func BenchmarkTokenVerify(b *testing.B) {
	s, _ := newService("http://issuer.local", policies(testPlanner, testWorker), io.Discard)
	now := time.Now().Unix()
	token := s.sign(Claims{Issuer: s.issuer, Subject: "worker", Audience: "secrets-api", ClientID: "worker", Scope: "secrets:read", ID: "benchmark", IssuedAt: now, NotBefore: now, Expires: now + 120})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.verify(token, "secrets-api"); err != nil {
			b.Fatal(err)
		}
	}
}
