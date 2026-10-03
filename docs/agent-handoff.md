# qWDTT Project Handoff

Last updated: 2026-10-03

This document is a continuation brief for another coding agent. Read it together with the current Git status and the source files named below. Do not assume the checked-in commits describe every current file: the quick-link/QR work described in **Current Uncommitted Work** is not committed yet.

## Executive Summary

qWDTT is an Android VPN client and self-hosted Go server. The client transports encrypted traffic through VK WebRTC/TURN call infrastructure to a user-controlled VPS, where the server exits traffic to the Internet. The user is scaling the server to roughly 100 access keys and at most 4 devices per key, building an external web control panel and a sales bot against the server API, and planning to distribute traffic over multiple nodes.

The user explicitly asked not to change Android client code for the current server/API/panel work. A per-key device limit remains configurable; do not add a hard global maximum of four. The old global maximum of 10 generated passwords has been removed. Telegram bot management is not a priority, but its source code has not been removed.

## Product Background

- Repository: `proxy-turn-vk-android`; current product name is qWDTT.
- qWDTT began from Android and server-side technical foundations in the archived original project `amurcanov/proxy-turn-vk-android` (WDTT). qWDTT is an independently developed codebase and is not an official continuation or release of that original project.
- The repository is GPL v3. See `LICENSE` and the root `README.md`.
- User-facing flow: add a VPS, provision server software, create/import a profile, provide a VK call hash, connect the Android system VPN, and let the VPS forward traffic.
- Do not describe the product as a generic direct VPN tunnel: its transport intentionally uses VK TURN/WebRTC media infrastructure, while the VPS runs userspace WireGuard and NAT.

## User Goals and Preferences

- Target capacity: approximately 100 keys and up to 4 devices per key. The configured `max_devices` value may be higher where desired; there must not be a fixed global cap of four devices.
- Do not modify the Android client unless the user later explicitly authorizes it. The current task was deliberately implemented server-side and in the embedded web panel.
- The user is building an API-driven management panel and an automated sales bot. Create-key retries must therefore be idempotent when the caller supplies an order ID.
- Multi-node deployment/load balancing is planned. Shared credentials, device slot reservations, challenges, and presence must not be treated as process-local in PostgreSQL mode.
- Telegram bot is low priority. In PostgreSQL cluster mode, polling is disabled by default to avoid every replica polling the same bot token; exactly one node may enable it with `-bot-node-id`.
- The user asked that technical reasoning be done in English. User-facing conversation so far is Russian; the requested handoff itself is English.
- The user requested a local branch and one descriptive commit per feature/fix. Do not commit unless the user has requested commits (they did); keep feature commits focused.
- Before editing any UI file, re-read it: the user has explicitly warned that an automated formatter or they may have changed the embedded UI files.

## Repository Map

- `app/`: Android/Kotlin app, Compose UI, tunnel manager, profile import/export, server provisioning and existing Admin API client.
- `go_client/`: separate Go module compiled to Android shared libraries; do not confuse this with server code.
- `server/`: Go server package (`package main`) inside the root Go module. `server/main.go` starts the service.
- `server/web/admin/`: embedded HTML/CSS/JS admin UI served by the HTTPS admin listener.
- `scripts/`: build tooling and the API load driver `profile-api-loadtest.go`.
- `docs/server-api.md`: HTTP contract and deployment docs.
- `docs/server-load-testing.md`: test plan for API and full tunnel data plane.

## Server Architecture

### Listeners

- `-listen`, default `0.0.0.0:56000`: DTLS over UDP and profile/device REST API over TCP on the same port.
- `-wg-port`, default `56001`: userspace WireGuard UDP endpoint, bound internally to loopback by design.
- `-admin-listen`: optional HTTPS admin listener; default installation uses `56002/tcp`. It hosts `/`, `/healthz`, `/metrics`, `/admin/*`, and `/admin/qrcode`.
- Optional `-listen-direct` and `-listen-raw` enable alternative transports; they are not required for the default path.
- The admin listener requires `-admin-token-file`, `-admin-cert`, and `-admin-key`. TLS minimum is 1.2. The Android admin client pins the HTTPS certificate fingerprint.

### Credentials and Devices

- `Database.Passwords` maps generated passwords to `PasswordEntry` records. `Database.Devices` stores per-device WG keys, addresses, and traffic.
- Each `PasswordEntry.MaxDevices` controls its own device slot limit. `canConnectAndBind` performs binding while the shared DB lock is held.
- Generated credentials are installed into the in-memory WRAP key store; peers are added dynamically to userspace WireGuard on first device provisioning.
- `server/database_bot.go` persists the legacy single-node database as an atomic JSON file (`passwords.json`). In PostgreSQL mode the authoritative state is a singleton JSONB snapshot.
- `server/connections.go`, `server/raw.go`, `server/profile_api.go`, and `server/admin_api.go` all mutate or inspect this state; preserve the existing lock boundary unless deliberately refactoring the repository abstraction.

## HTTP API Contract

### Admin API

Base URL: `https://<host>:<admin-port>`.

All admin API operations require `Authorization: Bearer <admin-token>`, except the static admin UI root and `GET /healthz`. `/metrics` requires the token. HTML UI, API, health, and metrics are served from the HTTPS admin mux (same origin).

Important routes:

- `GET /admin/passwords`: returns `{ "passwords": [...] }` with password, label, VK hash, legacy ports string, max device count, bound device IDs, expiration, active/deactivated flags, and traffic counters.
- `POST /admin/passwords`: creates an access key. Form fields: `vk_hash` required; `days` 1..365 (default 30); `max_devices` positive integer (default 1); optional `label` and `ports`. No fixed global key count cap.
- `POST /admin/passwords/update`: partial update of label/hash/max_devices/days.
- `POST /admin/passwords/activate`, `/deactivate`, `/delete`.
- `POST /admin/passwords/unbind-device`: required `password`; nonempty `device_id` removes one device; empty `device_id` removes all devices.
- `GET /healthz`: 200 JSON ready only when WireGuard and WRAP keys are ready and PostgreSQL responds in cluster mode; otherwise 503.
- `GET /metrics`: Prometheus exposition, Bearer protected, per-node metrics and PostgreSQL pool gauges.
- `POST /admin/qrcode`: Bearer protected form field `payload` (up to 3000 bytes), returns a locally generated `image/png`. Do not place profile password data in its URL; call with HTTPS POST body.

Create calls support optional `Idempotency-Key` (up to 200 bytes). The request fingerprint and password fingerprint are persisted for seven days; a repeated key with the same parameters returns the same key. Reusing it with different parameters, or retrying after the created key has been deleted/expired, returns 409. Old clients can omit the header.

Admin API mutation handlers are intended to report persistence failures and roll back in-memory mutation before returning 500. Preserve and extend those tests whenever changing CRUD behavior.

### Profile API

Base URL: `http://<host>:<listen-port>` (TCP, same numeric port as DTLS UDP). Routes:

- `POST /api/profile/challenge` -> `{ "nonce": "..." }`.
- `POST /api/profile/status` -> device count/status and `expires_at`.
- `POST /api/profile/unbind` -> unbind one device, or all devices when the signed `device_id` is empty.

Requests use application/x-www-form-urlencoded fields `device_id`, `nonce`, `key_id`, `proof`. `key_id = hex(SHA-256("WDTT-PROFILE-ID-v1\0" + password))`; proof is hex HMAC-SHA-256 keyed with the profile password over `action + "\n" + device_id + "\n" + nonce`. The nonce is single-use and expires after one minute. HMAC authenticates but does not encrypt; profile API still uses HTTP. TLS for this endpoint would require client changes, which the user has not authorized.

Per-IP token bucket: burst 1000, refill 250/sec; cluster mode stores the shared bucket in PostgreSQL. It keys on the TCP peer IP and intentionally does not trust forwarded headers. Outstanding nonce cap is 32768. Storage unavailable is reported as 503; rate/capacity rejection is 429.

## Scale Work Already Committed

Current branch: `feat/server-api-scale`. Base was `master` at tag `v1.4.4` (`a296c57`). Existing commits on the branch (oldest first):

1. `9c76e59 feat(server): remove generated key limit`
   - Removed the global 10-key limit from HTTP and Telegram creation flows; adjusted Telegram count text and API docs.
2. `0b26258 fix(server): handle profile challenge bursts behind NAT`
   - Replaced 30/min IP limit with token bucket (1000 burst, 250/sec), bounded maps, nonce cleanup, and 400-client/concurrency tests.
3. `d7e1f47 perf(server): index profile lookups and reduce disk writes`
   - Indexed active profile credentials, optimized WireGuard traffic stat peer mapping, removed unnecessary list/auth fsyncs, and added tests.
4. `f088967 fix(server): allow profile unbind all devices`
   - Allows correctly signed empty device ID for profile unbind-all, fixes legacy device cleanup, and adds tests.
5. `1dcfd2d feat(server): add retry-safe API and node metrics`
   - Persisted idempotency ledger, CRUD rollback/error handling, health endpoint, Prometheus metrics, and tests.
6. `b28a2a9 fix(server): remove duplicate create request init`
   - Removed a duplicated map initialization.
7. `0483cc7 feat(server): add PostgreSQL multi-node mode`
   - Added optional pgx-backed shared snapshot, shared challenges/rate bucket/active presence, cluster flags, and integration tests; added a 400-client API load driver and runbook.
8. `b4f7c34 feat(server): add embedded admin dashboard`
   - Embedded same-origin admin UI, CSP/security headers, UI route tests, and server-side unbind-all support for the panel.

Previously verified before current uncommitted QR work: `go test -race ./...`, `go vet ./...`, PostgreSQL 16 integration tests, 400 concurrent shared challenge operations across two stores, and Linux/amd64 static build.

## Current Uncommitted Work: Quick Link and QR

The user's latest feature request is to clean the local test DB, explain the `ports` field, and expose the generated access credential as both qWDTT quick-link URI and QR code.

Already done in this working tree:

- Cleared generated records from the temporary local runtime DB through the admin API, then removed `/tmp/qwdtt-local-runtime/config/passwords.json` before restarting. The running DB is clean; owner password and WG keypair remain in `/tmp`.
- Confirmed Android parser `SubscriptionImport.parseQwdttUri`: qwdtt URI fields are `name`, `peer`, `hashes`, `workers`, `port`, `pass` (also accepts `password`). Existing client admin UI uses 18 workers and local app port 9000.
- Confirmed legacy `PasswordEntry.Ports` is a three-number CSV tuple: DTLS server port, WG port, app/local port, conventionally `56000,56001,9000`; it is not a dtls/wg/tun mode selector. The current web form explains this and uses defaults when blank.
- Added `github.com/skip2/go-qrcode` and Bearer-protected `POST /admin/qrcode`. It accepts form payload (<=3000 bytes), returns PNG with `Cache-Control: no-store`, and does not log the URI.
- The embedded details dialog now has buttons for a visible `qwdtt://config?...` URI, copy-link, QR display, and PNG download. Creating a key opens its details immediately. QR requests send payload in same-origin HTTPS POST body.
- URI builder uses current page hostname plus DTLS port from `ports` (default 56000), VK hashes, workers=18, app port from tuple (default 9000), and password. It matches Android `parseQwdttUri` fields.
- Added API PNG test (`TestAdminQRCodeReturnsPNG`) and ran `go test -race ./...`, `go vet ./...`, `node --check server/web/admin/app.js` before the last URI wiring change. Re-run all before committing.

**Important: these changes are not committed yet.** `git status --short` currently shows modified `docs/server-api.md`, `go.mod`, `go.sum`, `server/admin_api.go`, `server/admin_api_test.go`, `server/admin_ui.go`, `server/web/admin/app.css`, `server/web/admin/app.js`, and `server/web/admin/index.html`. Re-read those files before editing; the user has warned that they may apply formatter/UI changes.

## Local Runtime Currently Running

The user asked to launch the actual server. Full `wdtt-server` is running as root in the Codespace:

- Profile HTTP + DTLS UDP: port 56000.
- Internal WG UDP: port 56001.
- HTTPS admin listener: port 56002.
- Temporary Codespaces HTTP->HTTPS bridge: port 56003, forwards to `https://127.0.0.1:56002` with local self-signed cert verification disabled only inside this local bridge.
- User-facing local panel link: `https://jubilant-system-97xr759pqxqqfxxxw-56003.app.github.dev/`.
- The plain Codespaces forward to 56002 caused `Client sent an HTTP request to an HTTPS server`; bridge 56003 fixed that protocol mismatch.
- Temp config/certs/token: `/tmp/qwdtt-local-runtime/`. Admin token file is `/tmp/qwdtt-local-runtime/admin.token`; do not paste the token into committed docs or source. The local test owner password is `/tmp/qwdtt-local-runtime/main.password`.
- Temporary local DB is `/tmp/qwdtt-local-runtime/config/passwords.json`; it should currently contain no generated keys.
- Original admin cert is self-signed for localhost. The bridge handles backend TLS locally; external Codespaces URL uses the VS Code tunnel. The forwarded endpoint may require normal GitHub/Codespaces auth in the user's browser.
- Server terminal process PID observed: `89910` was the current full server at last check; bridge PID observed: `77994`. These may change. Prefer `ps` and `ss` scoped to ports/config path before stopping anything.
- Do not kill/restart blindly: sudo child processes can outlive terminal teardown. Gracefully signal only the process whose args include `/tmp/qwdtt-local-runtime/config`; SIGTERM flushes/saves and removes WG interface.
- For the currently running binary, static source edits are not live until rebuilding `app/src/main/assets/server` and restarting this instance.

## Test Commands and Workflow

From repository root:

```sh
gofmt -w server/*.go
go test -race ./...
go vet ./...
node --check server/web/admin/app.js
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o app/src/main/assets/server ./server
git diff --check
```

For PostgreSQL integration tests, start PostgreSQL 16 and set `WDTT_TEST_DATABASE_URL`; tests create isolated schemas and drop them on completion:

```sh
WDTT_TEST_DATABASE_URL='postgres://user:password@127.0.0.1:5432/testdb?sslmode=disable' \
  go test -race ./server -run TestPostgres -count=1 -v
```

The HTTP API load generator is `scripts/profile-api-loadtest.go`; details and full tunnel failover test plan are in `docs/server-load-testing.md`.

## Architecture Decisions and Caveats

- Single-node mode remains JSON-backed if `-database-url` / `WDTT_DATABASE_URL` is empty.
- PostgreSQL mode uses a singleton JSONB state plus a global session advisory lock and revision polling. It is correctness-oriented for a small cluster; the lock/snapshot is a write serialization point. Normalize passwords/devices/idempotency into tables only after measuring a bottleneck.
- Challenges and rate limits are shared in PostgreSQL. Active device status uses per-node leases (45s TTL, 10s heartbeat). Existing UDP sessions stay on their original node; failover means client reconnect, not session migration.
- All nodes must use the same DB and compatible owner/admin secrets and binaries. Only one Telegram polling node is allowed via `-bot-node-id`; in cluster mode the bot is otherwise disabled.
- Load balancer must preserve UDP flow affinity and probe `/healthz` on the admin HTTPS listener. Do not run independent JSON-mode replicas behind a load balancer.
- Admin HTTPS certificate pinning means admin TLS certificates must match the host/client pin. `/api/profile/*` remains plaintext HTTP; changing that needs Android client changes and is out of current scope.
- The panel uses same-origin fetch, `sessionStorage` for token, strict CSP, and textContent for API data. Do not introduce `innerHTML`, external QR services, or localStorage for the admin token.

## Roadmap / Next Steps

1. Finish and review the in-progress qwdtt link/QR flow. Verify generated link with `SubscriptionImport.parseQwdttUri` semantics; inspect `ports` defaults/custom ports and IPv6 host formatting.
2. Rebuild the embedded server binary and restart the local full server so the QR endpoint and current UI are actually served.
3. Run an end-to-end local create -> quick link display -> QR PNG -> delete test; confirm temporary DB returns to empty.
4. Run `go test -race ./...`, `go vet ./...`, `node --check`, and Linux/amd64 build.
5. Inspect git diff/status, preserve any new user UI edits, then commit the QR/quick-link feature separately (user requested descriptive per-feature commits).
6. Leave the actual server and bridge running unless the user asks to stop them; report the admin URL and token-file path, never commit local secrets.
7. Longer term, add pagination to GET `/admin/passwords` if list sizes grow; instrument full tunnel load on staging (400 active tunnels, reconnect storm, node loss); consider normalized DB only if measurements justify it.

## Agent Working Rules for This Repository

- Stay on `feat/server-api-scale` unless asked to switch/merge/push.
- Do not modify Android source for this work.
- Check `git status` before each commit and include only intended files.
- The user's current `server/web/admin/*` may have external formatter/user edits. Read latest content before touching it and preserve those edits.
- Never put temporary owner/admin/database credentials in commits or handoff text. The token is only in `/tmp/qwdtt-local-runtime/admin.token`.
- User prefers brief Russian collaboration messages; source-level technical docs requested in this handoff are English.
