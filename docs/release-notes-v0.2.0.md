# grokbuild-proxy v0.2.0

[简体中文](#简体中文) | [English](#english)

## 简体中文

`v0.2.0` 聚焦批量凭据导入、出站代理和凭据生命周期治理，并进一步
加固发布流程。

### 主要更新

- 支持 Grok CLI、CPA xAI JSON、重复顶层 JSON 键、多文件和 SSO 文本的
  异步批量导入，提供逐文件、逐账号结果和有界任务队列。
- 新增可选的 SSO 转换 sidecar；服务端受 Bearer Key 保护，限制并发、
  请求体、响应体和绝对处理时限，不向浏览器返回转换后的 Token。
- 新增全局及每凭据出站代理，覆盖生成请求、模型、额度、OAuth 刷新和巡检。
- 新增定时和手动凭据巡检：确认 401 后隔离，429 仅冷却，并提供批量 401
  熔断、恢复和受保护的延迟清理。
- Admin UI 新增批量导入、代理、巡检状态和 Grok Build 共享周额度视图。
- 发布流程新增双镜像多架构构建、精确不可变标签、六平台归档、SBOM、
  严格权限/内容校验和 Sigstore checksum bundle。

### 升级提示

升级前请备份 `data_dir`。旧版 `credentials.json` 可直接读取；首次启动后，
新增字段会在后续持久化操作中按兼容默认值补齐。不要让两个版本同时使用
同一个数据目录。

预构建镜像：

```text
ghcr.io/greygung/grokbuild-proxy:0.2.0
ghcr.io/greygung/grokbuild-proxy-sso-import:0.2.0
```

## English

`v0.2.0` adds bulk credential imports, unified outbound proxy routing,
credential lifecycle governance, and a hardened release pipeline.

### Highlights

- Asynchronous imports for Grok CLI, CPA xAI JSON, duplicate top-level JSON
  keys, multiple files, and SSO text, with bounded queues and per-item results.
- An optional Bearer-protected SSO conversion sidecar with strict concurrency,
  body, response, and absolute-deadline limits; converted tokens never reach
  the browser.
- Global and per-credential proxy routing across generation, model discovery,
  billing, OAuth refresh, and inspection.
- Scheduled and manual inspection with confirmed-401 quarantine, 429 cooldown,
  mass-401 protection, recovery, and guarded delayed cleanup.
- Admin UI controls for imports, proxy settings, inspection evidence, and the
  Grok Build shared weekly quota view.
- Multi-architecture proxy and sidecar images, immutable exact tags, six-platform
  archives, SBOMs, strict payload/mode verification, and a Sigstore checksum
  bundle.

### Upgrade notes

Back up `data_dir` before upgrading. Existing `credentials.json` files remain
readable; compatibility defaults are applied when records are next persisted.
Never run two versions against the same data directory.

Images:

```text
ghcr.io/greygung/grokbuild-proxy:0.2.0
ghcr.io/greygung/grokbuild-proxy-sso-import:0.2.0
```
