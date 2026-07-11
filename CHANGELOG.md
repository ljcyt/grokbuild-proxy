# Changelog / 变更日志

All notable changes are documented here. The project follows Semantic
Versioning and keeps the latest release under GitHub Releases.

所有重要变更均记录于此。项目遵循语义化版本规范，最新版本以 GitHub
Releases 为准。

## [Unreleased] / 未发布

## [0.2.0] - 2026-07-11

### 简体中文

#### 新增

- 新增异步多格式凭据导入，支持稳定账号身份、重复 JSON 顶层键、多文件、
  有界上传、逐项结果，以及可选的内部 Bearer 鉴权 SSO 转换 sidecar。
- 新增全局及每凭据出站代理，覆盖生成请求、OAuth 刷新、模型、额度和巡检。
- 新增定时及手动凭据巡检，包含确认 401 后隔离、批量异常熔断、429 冷却、
  自动恢复和受保护的延迟清理。
- 新增 Grok Build 共享周额度规范化视图，并保留原始账单诊断信息。

#### 变更

- 凭据来源键仅作为溯源信息，不再定义账号身份；成功导入项通过一次原子批量
  Upsert 写入。
- 未返回的额度字段与真实数值 0 保持可区分。
- 重复凭据校验改用带版本失效的内存快照，避免巡检每个账号时重复解析完整
  凭据文件。

#### 修复

- 凭据卡片现在会显示最近巡检时间、结果和脱敏诊断详情。
- 嵌套账单响应会在折叠诊断区保留完整外层结构及未知字段。

#### 安全

- SSO 服务模式不落盘输入 Cookie，也不会向浏览器返回转换后的 Token；同时
  限制请求/响应大小、并发和绝对处理时限，仅允许可信私网明文端点，并在
  跟随重定向前验证每个 x.ai 地址。
- 自动物理删除凭据必须同时满足保留期到期、Token 指纹未变化和最新终止型
  认证错误确认。
- 导入的 OAuth issuer 以及最终 Token/设备端点必须属于可信 xAI origin，
  才会发送刷新 Token 或设备码。
- 凭据路由变更会使进行中的刷新 epoch 失效，旧刷新不得写回存储或重新填充
  Token 缓存。
- 隔离和延迟删除使用原子 Token 版本比较，待清理凭据也受同一批量 401
  熔断保护。

### English

#### Added

- Asynchronous multi-format credential imports with stable identity, duplicate
  JSON-key preservation, bounded uploads, per-item results, and optional SSO
  conversion through an internal Bearer-protected sidecar.
- Global and per-credential outbound proxy routing for generation, OAuth
  refresh, models, billing, and inspection.
- Scheduled/manual credential inspection with confirmed-401 quarantine,
  mass-failure protection, 429 cooldown, recovery, and guarded delayed cleanup.
- A normalized Grok Build shared-weekly-quota view with raw billing diagnostics.

#### Changed

- Credential source keys are provenance only and no longer define account
  identity; successful imports use one atomic bulk upsert.
- Missing quota fields remain distinguishable from a real numeric zero.
- Repeated credential guards use a versioned in-memory snapshot instead of
  reparsing the complete credential document for every inspection probe.

#### Fixed

- Credential cards now show the latest inspection time, result, and redacted
  diagnostic details.
- Nested billing responses retain their complete wrapper and unknown fields in
  the collapsed Admin diagnostics.

#### Security

- SSO service mode does not persist input cookies or return converted tokens to
  browsers, limits request/response sizes, restricts plaintext endpoints to
  trusted private routes, and validates every x.ai redirect before following it.
- Automatic credential deletion now requires retention expiry, an unchanged
  token fingerprint, and a fresh terminal-auth confirmation.
- Imported OAuth issuers and final token/device endpoints are restricted to the
  trusted xAI origin before refresh tokens or device codes are transmitted.
- Credential-route changes invalidate in-flight refresh epochs; stale refreshes
  cannot persist or repopulate the token cache.
- Quarantine and delayed deletion use atomic token-version comparisons, and
  purge candidates participate in the same mass-401 circuit breaker.

## [0.1.0] - 2026-07-10

### 简体中文

#### 新增

- 新增官方 OpenAI 与 Anthropic Go SDK 契约测试。
- 新增持久化凭据健康状态、402/429 故障切换、幂等导入和进程生命周期存储锁。
- 新增就绪探针、指标、JSON 请求日志、Request ID、凭据池摘要和浏览器 OAuth
  设备登录。
- 新增多平台归档、校验和、SBOM、校验和签名及容器发布自动化。
- 新增需显式启用的 CPA Thinking Block、签名回放及摘要/省略流在线探针。

#### 变更

- Anthropic 与 Chat Completions 流式响应改用逐项状态机，失败或截断的流会
  明确返回错误。
- Claude Code adaptive/manual thinking 强度映射为 Grok Responses reasoning
  effort；CPA 风格 Thinking Block 会跨工具回合保留 Grok 摘要和加密推理。
- 原生 Responses 加密推理项可在无状态工具循环中回放；冲突的 effort 拼写会
  直接校验失败。
- 转发至 Grok Build 前移除 Anthropic attribution 元数据，避免被上游拒绝。
- Anthropic 结构化输出 schema 映射至 Responses `text.format`；不兼容的
  `top_k`/stop 提示会被消费，Claude Code 显式关闭 thinking 时仍可使用 effort。
- Anthropic 版本化 `web_search_*` Server Tool 改用 Grok 内置网页搜索，强制
  Server Tool 选择会规范化为 xAI 兼容的自动选择。
- 运行时监听地址环境变量会在配置校验前应用，允许安全地将公开配置收窄至
  loopback。
- 公开监听必须显式开启。
- 启动生成的密钥不再输出到日志。

#### 安全

- 增加严格 YAML 字段校验、外部请求截止时间、可撤销启动客户端密钥、数据
  目录安全校验、备份和持久化写入保护。

### English

#### Added

- Official OpenAI and Anthropic Go SDK contract tests.
- Persistent credential health, 402/429 failover, idempotent imports, and
  process lifetime storage locking.
- Readiness and metrics endpoints, JSON request logs, request IDs, pool
  summaries, and browser-based OAuth device login.
- Multi-platform archive, checksum, SBOM, checksum signature, and container
  release automation.
- Opt-in credentialed live probe for CPA thinking blocks, signature replay, and
  summarized/omitted streams.

#### Changed

- Anthropic and Chat Completions streaming now use per-item state machines and
  surface failed or truncated streams as errors.
- Claude Code adaptive/manual thinking strength now maps to Grok Responses
  reasoning effort, while CPA-style thinking blocks preserve Grok summaries and
  encrypted reasoning through Claude Code tool turns.
- Native Responses encrypted-reasoning items now survive stateless tool-loop
  replay, and conflicting effort spellings fail validation.
- Anthropic attribution metadata is stripped before Grok Build requests because
  the upstream rejects that field.
- Anthropic structured-output schemas now map to Responses `text.format`;
  incompatible `top_k`/stop hints are consumed, and effort remains usable when
  Claude Code explicitly disables thinking.
- Anthropic versioned `web_search_*` server tools now use Grok's built-in web
  search instead of being returned as unexecutable client tool calls; forced
  server-tool choices are normalized to xAI-compatible automatic selection.
- Runtime listen environment overrides are applied before configuration
  validation, allowing a public config bind to be safely narrowed to loopback.
- Public listeners require explicit opt-in.
- Bootstrap secrets are no longer printed to logs.

#### Security

- Strict YAML field validation, external request deadlines, revocable bootstrap
  client keys, safe data-directory validation, backups, and durable writes.

[Unreleased]: https://github.com/GreyGunG/grokbuild-proxy/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/GreyGunG/grokbuild-proxy/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/GreyGunG/grokbuild-proxy/releases/tag/v0.1.0
