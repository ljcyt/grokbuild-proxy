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

## Multi-account failover

`lb.max_attempts` limits how many distinct credentials one request may try
after a retryable upstream failure. The default is 10 and the accepted range is
1 through 20. Increase it only when the account pool is independent enough to
justify the extra latency and upstream requests during an outage; it is not a
quota-bypass setting. `lb.quota_cooldown_sec` defaults to seven days and only
applies when a Responses account reports zero remaining quota or returns the
known chat-endpoint quota denial; ordinary 403/402 failures keep using
`lb.cooldown.max_sec`. `lb.quota_reserve_requests` reserves request capacity
for concurrent work, so accounts with a tight advertised budget yield to other
accounts before they hit the quota boundary. The Admin credential list filters accounts locally and
loads billing only when an operator selects **Billing**, so opening a large
pool does not fan out one upstream billing request per account. The credential
list is server-paginated: `page`, `page_size` (1-100), `q`, and `status`
(`all`, `available`, `cooling`, `healthy`, `rate_limited`, `quota_exhausted`,
`unauthorized`, `quarantined`, `uninspected`, `inspection_error`, `expired`,
or `disabled`) are accepted by
`GET /admin/credentials`; the Admin UI requests 24 accounts per page.

## Sub2API migration export

`POST /admin/credentials/export-sub2api` returns a Sub2API Grok OAuth batch
payload. It accepts only the existing Admin key (`Authorization: Bearer
<admin_key>` or `X-Admin-Key`), never a client API key. The response includes
OAuth secrets, has `Cache-Control: no-store`, and only contains enabled,
non-quarantined, non-cooling accounts with recorded positive remaining quota.
Accounts with unknown quota are intentionally excluded.

## Request raw path overrides

`request_patch` rewrites the upstream Responses JSON body after Anthropic/OpenAI
translation and before the Grok request is sent. Values are raw JSON fragments
as strings (not YAML objects), which is useful for complex fields such as tools
entries, `text.format`, or schemas.

Example: always append Grok built-in web search for matching models:

```yaml
request_patch:
  enabled: true
  rules:
    - name: force-web-search
      models: ["default", "grok-4.5"]
      set:
        tools.-1: '{"type":"web_search"}'
```

Path notes:

- dotted object paths, for example `text.format`
- numeric array indexes, for example `tools.0`
- `tools.-1` appends one item; if a tool with the same `type` already exists, the
  append is skipped
- empty `models`, `*`, or `default` matches every model

Keep this off unless you need operator-side injection. It does not bypass
upstream policy, quotas, or authentication.

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

The selector keeps an in-memory count of in-flight requests and, within the
same priority, selects the least-loaded credential before round-robin tie
breaking. A probe validates both `/models` and the weekly-credit endpoint. A
reported usage of 100%, or an HTTP 402 response, is recorded as
`quota_exhausted` and uses the configured maximum cooldown; this avoids
repeatedly selecting an authenticated account whose upstream quota is
unavailable. HTTP 402 and 429 never quarantine or delete credentials.

Successful `POST /v1/responses` responses may include free-tier chat headers
`X-Ratelimit-Limit-Requests`, `X-Ratelimit-Remaining-Requests`,
`X-Ratelimit-Limit-Tokens`, and `X-Ratelimit-Remaining-Tokens`. The proxy stores
those counters on the credential. When either remaining value reaches 0, the
account enters the configured maximum cooldown, sticky bindings are cleared, and
later turns pick another account. The current successful response is still
returned so the turn is not aborted mid-stream. This reduces the free-tier
follow-up error `Forbidden: Access to the chat endpoint is denied`.

Each generation request snapshots only a lightweight credential candidate list
once, then reloads the selected full credential before it uses a token. This
keeps failover from repeatedly cloning the entire token and billing pool while
preserving the revision and enabled-state checks around each upstream call.

Keep `inspection.purge_after_sec: 0` unless physical deletion is explicitly
required. When enabled, cleanup occurs only after the retention deadline, an
unchanged token fingerprint, and another confirmed terminal-auth failure.
Always back up `data_dir` before enabling cleanup.

## Feishu notifications

Set `notifications.feishu_webhook_url` to a Feishu custom-bot webhook URL to
receive a compact summary after every scheduled or manually started inspection.
Webhook delivery is bounded and failures are logged without changing the
inspection result. Treat the URL as a secret and keep it only in private
`config.yaml`, never in source control.

## Billing interpretation

The primary Admin card is Grok Build's shared weekly usage. Product-level
GrokBuild usage is a contribution to that shared pool, not an independent
quota. “Not reported” means the upstream omitted the value; it is distinct from
a real zero. Monthly/API payloads and one-sided request errors remain available
in the folded diagnostics view.
