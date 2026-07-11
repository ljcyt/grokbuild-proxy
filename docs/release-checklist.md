# Release checklist

## Automated gates

- [ ] `gofmt` clean
- [ ] `go vet ./...`
- [ ] `go test -race ./...`
- [ ] official OpenAI and Anthropic SDK contract tests pass
- [ ] `govulncheck ./...`
- [ ] Docker build and `/healthz` smoke pass
- [ ] GoReleaser snapshot succeeds for every target
- [ ] no secrets or generated runtime data in the diff

## Compatibility and operations

- [ ] `COMPATIBILITY.md` matches accepted/rejected fields and stream behavior
- [ ] configuration changes are documented and strict parsing tested
- [ ] backup/restore and upgrade notes are current
- [ ] migration from the previous release is tested against a copied data dir
- [ ] 401 refresh, 402/429 failover, cooldown restart, and truncated SSE tests pass
- [ ] Admin device login, key revocation, readiness, and pool summary tests pass

## Optional live gate

With an operator-owned test account and explicit consent:

```bash
GROKBUILD_LIVE_SMOKE=1 \
GROKBUILD_API_KEY=... \
GROKBUILD_LIVE_MODEL=grok-4.5 \
bash scripts/live-smoke.sh
```

For Claude Code thinking/signature compatibility:

```bash
GROKBUILD_LIVE_SMOKE=1 \
GROKBUILD_API_KEY=... \
GROKBUILD_LIVE_MODEL=claude-opus-4-6 \
go run ./scripts/live-thinking-probe.go
```

Never run live smoke in pull requests or with production credentials.

## Publishing

- [ ] update `CHANGELOG.md`
- [ ] create a signed `vMAJOR.MINOR.PATCH` tag
- [ ] confirm the release `validate` job passed Go race/vet/build, sidecar tests, both image builds, Compose validation, and the six-platform snapshot
- [ ] run `REQUIRE_SBOM=1 sh scripts/verify-release-archive.sh dist` against a snapshot with Syft available; confirm the exact payload, canonical checksums, and all six checksummed SBOMs pass
- [ ] verify both SHA-staged GHCR manifests were checked before the immutable exact tags were promoted
- [ ] verify archives, checksums, SBOMs, Sigstore bundle, and both exact GHCR manifests
- [ ] test one downloaded archive and `docker-compose.release.yml` SSO profile on a clean host with an exact `GROKBUILD_CONTAINER_TAG`
- [ ] confirm moving tags were promoted only after both exact images and the GitHub release succeeded
- [ ] publish upgrade and rollback notes
