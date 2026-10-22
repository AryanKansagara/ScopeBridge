# ScopeBridge

An end-to-end Go machine-identity project for scoped, auditable AI-agent and
workload access. A planner obtains a short-lived access token; an authorized worker
exchanges it for narrower downstream access, calls a protected resource, and
revokes its credential. Audit events retain both the original subject and actor.
All resources and identities in the demonstration are synthetic.

## Run locally

Requires Go 1.24+. No third-party modules or external accounts are needed.

```sh
go test -race -cover ./...
go vet ./...
go run . demo
```

The demo runs an ephemeral loopback HTTP server and real HTTP client. It creates
random bootstrap credentials in memory, exercises client credentials → token
exchange → protected resource → revocation → rejection, then shuts down. Its JSON
summary reports status codes and attribution, never bearer tokens or secrets.

For an interactive server, set two distinct secrets (24+ characters) in
`SCOPEBRIDGE_PLANNER_SECRET` and `SCOPEBRIDGE_WORKER_SECRET`, then `go run .`.
Use randomly generated values from your secret manager; never commit them.
The server listens only on `127.0.0.1:8080` and writes `audit.jsonl` with mode 0600.
Do not expose this development server or use real credentials.

## Flow and API

1. POST `/oauth/token` with HTTP Basic client authentication and URL-encoded
   `grant_type=client_credentials`, `scope=secrets:read repo:read`,
   `audience=scopebridge`, authenticating as planner.
2. POST `/oauth/token` as worker with grant type
   `urn:ietf:params:oauth:grant-type:token-exchange`, the first `subject_token`,
   `subject_token_type=urn:ietf:params:oauth:token-type:access_token`,
   `scope=secrets:read`, and `audience=secrets-api`.
3. GET `/api/secret` with the exchanged Bearer token. Response is a synthetic
   value and subject/actor attribution, not an actual secret-manager integration.
4. POST `/oauth/revoke` as worker with `token=<exchanged access token>`.
   Subsequent access fails with 401.
5. Inspect `/metrics`, `/healthz`, `/jwks.json`, and
   `/.well-known/oauth-authorization-server` for operational metadata.

Policy is deny-by-default: requested scopes and audience must be allowlisted for
the authenticated client; exchange scopes must also be a subset of the source
token. Only an explicitly trusted actor may delegate for a given subject. Exchange
rejects chained delegation and caps child expiry at the parent's remaining life.
Revoking a parent prevents further exchanges but does not cascade to already
issued children; revoke children separately or wait for their bounded expiry.

## Authentication, authorization and identity

- Authentication: per-client bootstrap secrets, stored as SHA-256 digests in memory
  and compared in constant time. Each workload has its own identity, not a shared
  downstream bearer credential. Bootstrap secret provisioning/rotation is external.
- Authorization: explicit scope, audience and delegation policy checks.
- Access tokens: Ed25519 signatures; pinned algorithm, key ID and `at+jwt` type;
  issuer, audience, expiry, issuance, not-before, lifetime and revocation validation.
- Delegation: `sub` preserves the original workload; `act.sub` identifies the worker.
  This represents workload-to-workload delegation, not verified human consent.
- OAuth/OIDC distinction: OAuth access tokens authorize API access. OIDC ID tokens
  authenticate users; this service is not an OIDC provider and does not implement
  interactive login, ID tokens, external federation or OIDC discovery. JWTs with
  the wrong token type are rejected at protected-resource boundaries.

Protocol design references: [OAuth client credentials, RFC 6749](https://www.rfc-editor.org/rfc/rfc6749),
[token exchange and actor attribution, RFC 8693](https://www.rfc-editor.org/rfc/rfc8693),
[access-token validation concepts, RFC 9068](https://www.rfc-editor.org/rfc/rfc9068).
This is a deliberately limited implementation, not a certified OAuth server or a
claim of full conformance to these specifications.

## Reliability and observability

Structured JSON audit events contain random request IDs, decisions, subject,
actor, audience and scope; tokens, client secrets and resource values are excluded.
Issuance and resource access fail closed if the audit writer fails. Atomic counters
track requests, denials and issued tokens. Mutexes protect revocation and audit
writes; race-enabled HTTP concurrency tests exercise 24 simultaneous grants.
The interactive server uses body/header limits, request deadlines and graceful
shutdown. Debug logs record request duration without query strings or credentials.

## Verification and delivery

Tests cover positive flows, authentication failures, scope escalation, audience and
issuer mismatches, expiry, algorithm/type confusion, signatures, delegation policy,
client-scoped revocation, audit failure, oversized requests, and parallel clients.
Run `go test -bench=. -benchmem ./...` for a local verification microbenchmark;
results are machine-specific, not a distributed-system throughput claim.

`ci/github-actions.yml` is an inactive CI template. A repository owner with workflow
permissions can copy it into `.github/workflows/ci.yml` to enable automated checks.
See [engineering notes](docs/ENGINEERING.md) for the work breakdown and limitations.
See [local validation results](docs/VALIDATION.md) for the executed checks.

## Security boundary

Educational local implementation, not production identity infrastructure. Signing
keys and revocations are in memory and reset on restart. Restart invalidates all
old tokens. No durable database, rate limiter, TLS, key rotation, external trust,
tenant isolation or distributed revocation exists. Use a maintained identity
provider and vetted JOSE/OIDC library for production, durable audit storage and
KMS-managed keys. A synthetic resource avoids granting access to real systems.
