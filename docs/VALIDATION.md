# Local verification record

Validated on 2026-10-22 with Go 1.27.1, macOS ARM64.

- `go test -race -cover ./...`: passed, 81.3% statement coverage.
- `go vet ./...`: passed.
- `go run . demo`: passed against a real loopback HTTP listener.
- Concurrency test: 24 simultaneous HTTP grant requests, all successful with no
  race detector findings in this run.

Demo summary:

```json
{
  "actor": "worker",
  "audit_events": 5,
  "credentials_logged": false,
  "delegated_access_status": 200,
  "revoked_access_status": 401,
  "scope": "secrets:read",
  "subject": "planner",
  "tokens_issued": 2
}
```

The demo explicitly checks audit output for bootstrap secrets and access tokens
before reporting `credentials_logged: false`. Test fixtures are synthetic. These
results are a local functional check, not an independent security audit or a
production reliability/throughput benchmark. The CI template is inactive.
