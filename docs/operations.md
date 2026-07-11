# Operations guide

## Probes and metrics

- `GET /healthz`: process liveness; does not inspect credentials.
- `GET /readyz`: storage and usable credential readiness. Returns 503 when no
  enabled, non-cooling credential with token material is available.
- `GET /metrics`: low-cardinality Prometheus counters for request count,
  failures, inflight requests, response bytes, and total latency.

The Admin System page/API includes aggregate pool health. It never exposes
plaintext OAuth or client secrets.

## Logs

Logs are JSON on stdout. Request records include request ID, method, route
template, status, latency, and response size. Upstream retry records include the
credential record ID, attempt, status, and Retry-After duration.

Request bodies, prompts, OAuth tokens, client keys, and admin keys are never
logged. Send `X-Request-Id` with a safe value to correlate a client request; the
proxy generates one otherwise and returns it in the response header.

## Backup and restore

Stop the process before copying or restoring `data_dir`. The store holds
`.instance.lock` for its lifetime and rejects a second process using the same
directory.

Docker Compose uses the `grokbuild-data` named volume. Stop the service before
backing that volume up with your normal Docker volume backup tooling.

Back up the entire directory, including:

- `credentials.json`: OAuth tokens and persisted health;
- `clients.json`: hashed client keys and revocation state;
- `meta.json`: bootstrap key material;
- `*.bak`: previous valid snapshots.

Files contain secrets and must remain mode `0600`; the dedicated directory
should be accessible only to the service account. To restore, stop the process,
replace the whole directory from one consistent backup, verify ownership and
permissions, then start and check `/readyz`.

If a primary JSON file is truncated or corrupt, the proxy reads its `.bak`
snapshot. Investigate disk or filesystem health before continuing.

## Upgrade and rollback

1. Back up `data_dir`.
2. Read `CHANGELOG.md` and the GitHub release notes.
3. Verify `checksums.txt` and its Sigstore bundle.
4. Replace the binary or image, preserving configuration and data.
5. Check `/healthz`, `/readyz`, Admin pool summary, and one synthetic request.

For rollback, stop the new process and restore both the prior executable/image
and the pre-upgrade data backup. Never run two versions against one data
directory.

## Public deployment

Loopback is the default. A non-loopback bind requires
`allow_public_listen: true` or `ALLOW_PUBLIC_LISTEN=true`. If remote access is
required, place the proxy behind a trusted TLS reverse proxy, restrict source
networks, protect `/admin`, `/metrics`, and all `/v1` endpoints, and rotate any
key exposed to browsers or logs.

## Credential imports

Use the Admin UI or `POST /admin/credential-imports`; the legacy
`/admin/import-jobs` route remains available. Configure `import.max_files`,
`max_file_bytes`, `max_total_bytes`, `max_entries`, `max_queued_jobs`,
`max_queued_bytes`, `max_retained_jobs`, `max_retained_bytes`, and `job_ttl_min`
before accepting operator uploads. Queue
overload returns HTTP 429 with `Retry-After`; jobs report per-file/per-account
outcomes without returning SSO cookies or OAuth tokens.

Imported `oidc_issuer` values must resolve exactly to `https://auth.x.ai`.
Credentials naming another issuer are rejected before persistence, preventing
refresh tokens from being sent to imported or discovered third-party hosts.

SSO conversion is optional. Keep it disabled unless required. With Compose,
set one strong `SSO_CONVERTER_API_TOKEN`, copy it to
`sso_converter.api_key`, configure `http://sso-import:8090`, and start
`docker compose --profile sso-import up -d`. The sidecar is internal-only;
`SSO_CONVERTER_PROXY` controls its x.ai egress route.
Keep `sso_converter.max_batch` at or below 100 and `timeout_sec` at or below
300 seconds. x.ai responses are capped at 1 MiB, and item deadlines
cooperatively stop semaphore waits, retries, backoff, and polling.

## Proxy changes

Global proxy settings can be changed in Admin. Credential `direct` or URL mode
overrides the global route; `inherit` follows it. Stored and returned URLs are
redacted in read APIs. A malformed or unavailable configured proxy is treated
as an error and never falls back silently to direct access.

After changing a route, run a manual inspection or billing refresh to verify it.
HTTP 407 indicates proxy authentication failure and must not be treated as an
invalid Grok credential.

## Inspection and quarantine

Inspection is disabled by default. Start with low concurrency and retain the
mass-failure guard. Quarantine requires repeated 401 probes plus a terminal
refresh failure; a successful refresh followed by another 401 is retained for
later inspection. A 429 only sets cooldown, and transport/5xx errors are
retained. Manual disables are never automatically reversed.

Keep `inspection.purge_after_sec: 0` unless physical deletion is explicitly
required. When enabled, cleanup occurs only after the retention deadline, an
unchanged token fingerprint, and another confirmed terminal-auth failure.
Always back up `data_dir` before enabling cleanup.

## Billing interpretation

The primary Admin card is Grok Build's shared weekly usage. Product-level
GrokBuild usage is a contribution to that shared pool, not an independent
quota. “Not reported” means the upstream omitted the value; it is distinct from
a real zero. Monthly/API payloads and one-sided request errors remain available
in the folded diagnostics view.
