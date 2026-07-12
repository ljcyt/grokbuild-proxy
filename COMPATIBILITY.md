# API compatibility

grokbuild-proxy translates supported Anthropic and OpenAI requests to the Grok
Build Responses upstream. It is a compatibility subset, not an implementation
of every provider API.

## Anthropic Messages

| Capability | Status |
|---|---|
| `POST /v1/messages`, text, system, streaming | Supported |
| Client function tools and tool results | Supported |
| Parallel client tool calls | Supported |
| URL/base64 image input | Supported |
| `temperature`, `top_p`, `max_tokens` | Supported |
| Anthropic `metadata` | Consumed locally; not forwarded because Grok rejects it |
| Correct completed/incomplete/failed stream termination | Supported |
| Prompt-cache token details | Best effort |
| `thinking` / `output_config.effort` request controls | Supported with coarse mapping |
| Thinking summary / omitted blocks and signature SSE | CPA-style bridge |
| Encrypted reasoning replay through tool turns | Supported when upstream returns it |
| `output_config.format` JSON Schema | Mapped to Responses `text.format` |
| `top_k`, `stop_sequences` | Consumed but not forwarded because Grok reasoning rejects them |
| Anthropic `web_search_*` server tools | Mapped to Grok built-in `web_search`; forced selection degrades to `auto` |
| Other server tools, MCP, rich citations, PDF/document | Not supported |
| `POST /v1/messages/count_tokens` | Not supported; returns 404 |

Thinking strength maps to the upstream Responses `reasoning.effort` field:

| Anthropic input | Grok input |
|---|---|
| `output_config.effort: low / medium / high` | Same effort |
| `output_config.effort: xhigh / max` | `high` on `grok-4.5`; `xhigh` on multi-agent models |
| `thinking.type: enabled`, valid budget `1024..3999 / 4000..15999 / >=16000` | `low / medium / high` |
| `thinking.type: adaptive` without explicit effort | `high` |
| `thinking.type: disabled` without effort | `low` on `grok-4.5` (reasoning cannot be disabled); `none` on `grok-4.3` |
| `thinking.type: disabled` with effort | Preserve the requested effort as Grok's closest compatible control |

Manual budgets must also be below `max_tokens` unless tools are present for an
interleaved tool loop.

For enabled/adaptive thinking, the proxy requests
`reasoning.encrypted_content`. Following CPA's Responses-to-Claude bridge:

- Grok reasoning summaries become Anthropic `thinking` text.
- `display: omitted` emits an empty thinking block without exposing the summary.
- Grok `encrypted_content` is carried as the block's opaque `signature`, and
  streaming emits it through `signature_delta`.
- On the next Claude Code tool turn, that signature is restored as the original
  Grok `reasoning.encrypted_content` item before the matching function call and
  tool result.

This is a proxy-scoped compatibility signature, not a portable Anthropic
signature. It must remain opaque and is only expected to replay through this
proxy to the same upstream model/account. If upstream omits encrypted content,
the summary can still be displayed but hidden reasoning continuity is
unavailable for that turn.

Reference semantics reviewed for this mapping:

- [Claude adaptive thinking and effort](https://platform.claude.com/docs/en/build-with-claude/adaptive-thinking)
- [Claude Code model and effort configuration](https://code.claude.com/docs/en/model-config)
- [xAI reasoning effort and encrypted reasoning](https://docs.x.ai/developers/model-capabilities/text/reasoning)

## OpenAI

| Capability | Status |
|---|---|
| `POST /v1/responses`, JSON and SSE | Supported passthrough/sanitize subset |
| `POST /v1/chat/completions`, text and stream | Supported for `n=1` |
| Chat client function tools and parallel tool stream | Supported |
| Chat image content | Supported |
| Chat `stream_options.include_usage` | Supported |
| Structured output JSON schema | Supported |
| Native Grok `reasoning.encrypted_content` replay | Preserved verbatim |
| `GET /v1/models` | Supported |
| Chat audio, logprobs, `n>1` | Not supported |
| Responses retrieve/delete/cancel/background/conversation APIs | Not supported |

Unsupported fields are rejected when silently discarding them could change
request semantics. Provider-specific response metadata and token detail fields
may be reduced to the common subset documented above.

Native Responses preserves encrypted reasoning verbatim. The Anthropic surface
wraps the same Grok blob as a CPA-style opaque signature and unwraps it on
replay; it does not decrypt or reinterpret the content.

## Admin and credential operations

| Capability | Status |
|---|---|
| Grok CLI auth JSON import | Supported |
| Repeated files, raw JSON/text, duplicate top-level JSON keys | Supported |
| CPA credential JSON (`type=xai`) | Supported |
| Optional SSO text conversion | Supported through protected sidecar |
| Atomic stable-identity bulk upsert | Supported |
| Global and credential-specific direct/HTTP(S)/SOCKS routing | Supported |
| Scheduled/manual inspection with 401 confirmation | Supported |
| 429 cooldown without quarantine | Supported |
| Quota exhausted (`100%` weekly usage or HTTP 402) max cooldown | Supported; not OAuth quarantine |
| Free-tier `X-Ratelimit-*` snapshot and exhausted cooldown | Supported on Responses responses |
| Configurable multi-credential failover depth (`lb.max_attempts`) | Supported (1-20, default 3) |
| Least-inflight selection within the same priority | Supported |
| Lightweight candidate-pool selection per generation request | Supported |
| Admin credential list pagination/filter (`page`, `page_size`, `q`, `status`) | Supported |
| On-demand Admin billing load | Supported |
| Operator raw JSON path overrides (`request_patch`) | Supported when enabled |
| Quarantine recovery after token rotation | Supported |
| Automatic physical cleanup | Optional; disabled by default |
| Grok Build shared weekly quota view | Supported when upstream reports it |
| Monthly/API billing diagnostics | Preserved as diagnostic data |

Upstream quota fields are not guaranteed for every account. Missing values are
reported as “not reported” and are not converted to numeric zero. A GrokBuild
product percentage is its contribution to the shared pool, not a separate cap.

## Upstream and terms

This project is unofficial and is not affiliated with xAI, Grok, Anthropic, or
OpenAI. It uses the Grok CLI OAuth client and `cli-chat-proxy.grok.com` behavior
observed for accounts controlled by the operator. Upstream protocols can change
without notice.

Operators and distributors are responsible for confirming that their use,
automation, credential handling, and redistribution comply with all applicable
terms, policies, rate limits, and laws. The MIT license covers this
repository's code only; it does not grant rights to upstream services,
trademarks, accounts, quotas, or third-party APIs.
