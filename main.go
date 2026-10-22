package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func policies(planner, worker string) map[string]Client {
	return map[string]Client{
		"planner": client(planner, []string{"secrets:read", "repo:read"}, []string{"scopebridge"}, nil),
		"worker":  client(worker, []string{"secrets:read", "repo:read"}, []string{"secrets-api"}, []string{"planner"}),
	}
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "demo" {
		if err := demo(); err != nil {
			log.Fatal(err)
		}
		return
	}
	planner, worker := os.Getenv("SCOPEBRIDGE_PLANNER_SECRET"), os.Getenv("SCOPEBRIDGE_WORKER_SECRET")
	if len(planner) < 24 || len(worker) < 24 || sha256.Sum256([]byte(planner)) == sha256.Sum256([]byte(worker)) {
		log.Fatal("set two distinct client secrets of at least 24 characters; use `go run . demo` for an ephemeral demonstration")
	}
	audit, err := os.OpenFile("audit.jsonl", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer audit.Close()
	service, err := newService("http://127.0.0.1:8080", policies(planner, worker), audit)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: "127.0.0.1:8080", Handler: service.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Print("ScopeBridge listening on loopback port 8080; development only, not a production identity provider")
	if err = server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func demo() error {
	planner, worker := randomID()+randomID(), randomID()+randomID()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	origin := "http://" + listener.Addr().String()
	var audit bytes.Buffer
	service, err := newService(origin, policies(planner, worker), &audit)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: service.Handler(), ReadHeaderTimeout: 3 * time.Second}
	go server.Serve(listener)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	post := func(path, name, secret string, form url.Values) (map[string]any, error) {
		req, _ := http.NewRequest("POST", origin+path, bytes.NewBufferString(form.Encode()))
		req.SetBasicAuth(name, secret)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		var value map[string]any
		err = json.NewDecoder(response.Body).Decode(&value)
		if response.StatusCode != 200 {
			return nil, fmt.Errorf("%s returned %d", path, response.StatusCode)
		}
		return value, err
	}
	initial, err := post("/oauth/token", "planner", planner, url.Values{"grant_type": {"client_credentials"}, "scope": {"secrets:read repo:read"}, "audience": {"scopebridge"}})
	if err != nil {
		return err
	}
	delegated, err := post("/oauth/token", "worker", worker, url.Values{"grant_type": {exchangeGrant}, "subject_token_type": {accessTokenType}, "subject_token": {initial["access_token"].(string)}, "scope": {"secrets:read"}, "audience": {"secrets-api"}})
	if err != nil {
		return err
	}
	token := delegated["access_token"].(string)
	access := func() (int, error) {
		req, _ := http.NewRequest("GET", origin+"/api/secret", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, nil
	}
	before, err := access()
	if err != nil {
		return err
	}
	if _, err = post("/oauth/revoke", "worker", worker, url.Values{"token": {token}}); err != nil {
		return err
	}
	after, err := access()
	if err != nil {
		return err
	}
	if before != 200 || after != 401 {
		return fmt.Errorf("unexpected access results: %d/%d", before, after)
	}
	for _, credential := range []string{planner, worker, token, initial["access_token"].(string)} {
		if bytes.Contains(audit.Bytes(), []byte(credential)) {
			return fmt.Errorf("credential detected in audit output")
		}
	}
	summary := map[string]any{"delegated_access_status": before, "revoked_access_status": after, "tokens_issued": service.issued.Load(), "audit_events": bytes.Count(audit.Bytes(), []byte("\n")), "scope": "secrets:read", "subject": "planner", "actor": "worker", "credentials_logged": false}
	return json.NewEncoder(os.Stdout).Encode(summary)
}
