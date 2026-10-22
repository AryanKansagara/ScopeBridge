# Engineering notes

## Work breakdown

1. Policy and threat model: identify principals, downstream audiences, scopes,
   permitted delegation pairs and credential boundaries.
2. Token core: typed claims, signing, strict validation and short lifetimes.
3. HTTP services: authentication, grant parsing, exchange, protected resource and
   revocation; explicit error paths and bounded inputs.
4. Quality: table-driven rejection tests, end-to-end HTTP scenario and concurrent
   requests under the Go race detector.
5. Operations: structured audits, counters, shutdown, runbook and CI template.

Relative planning estimates: policy/token core medium, HTTP flow medium,
observability small, negative-path tests medium. These are planning examples, not
claims about a team delivery timeline.

## Threats and tradeoffs

- Token theft: short expiry and explicit revocation bound exposure, but bearer
  tokens are replayable until expiry/revocation. Sender-constrained tokens remain
  future work. A source token is reusable for authorized exchanges by design.
- Confused deputy: both original subject and actor must satisfy delegation policy;
  exchanged scopes cannot exceed either party's scope. Audiences are pinned.
- Forged identity: strict signature/issuer/type checks; no user-controlled subject
  or actor field is copied from an unauthenticated request.
- Lost audit storage: issue/access operations fail closed. For production, an
  append-only durable audit transaction must precede release of credentials/data.
- Restart/scaleout: process-local state keeps the demo dependency-free but cannot
  coordinate distributed revocation or persistence. Multiple replicas would need
  shared policy/revocation storage, external keys and cache consistency decisions.
- Revocation is checked per request under a lock. This is correct locally but adds
  contention; benchmark before replacing with caches that could delay revocation.
- Authentication failures log a reason and request ID, not attacker-supplied names
  or credential material. Allowed events contain subject and actor identifiers.

## Review checklist

Trace all denied paths. Check scope subset and audience handling, claim validation,
logs for credentials, test determinism and race results. Review generated code with
the same scrutiny as manual changes. Document limitations before expanding scope.

## Manual runbook

Run `go run . demo` and expect access status 200 then revoked access status 401.
For failures, run `go test -race -v ./...`, inspect JSON audit decisions and request
IDs, and verify the client policy and audience before changing permissions. Never
"fix" a denial by disabling signature checks or widening every client's scopes.
