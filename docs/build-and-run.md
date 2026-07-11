# Build and run guide

This guide covers local development builds, production binaries, Docker,
cross-compilation, release validation, and common startup failures.

## Prerequisites

### Source build

- Go 1.26.5 or newer
- Git
- A POSIX shell for the provided scripts

### Container build

- Docker 24 or newer
- Docker Compose v2

Verify the toolchain:

```bash
go version
docker version
docker compose version
```

## Install a release

Linux / macOS:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/GreyGunG/grokbuild-proxy/main/scripts/install.sh \
  | sh
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/GreyGunG/grokbuild-proxy/main/scripts/install.ps1 | iex
```

Install a specific version:

```bash
GROKBUILD_VERSION=v0.2.0 sh -c \
  'curl -fsSL https://raw.githubusercontent.com/GreyGunG/grokbuild-proxy/main/scripts/install.sh | sh'
```

## Clone and configure

```bash
git clone https://github.com/GreyGunG/grokbuild-proxy.git
cd grokbuild-proxy
cp config.example.yaml config.yaml
```

The example configuration is loopback-first and safe for local development.
Review at least:

- `listen`
- `data_dir`
- `anthropic.model_aliases`
- `limits.request_timeout_sec`

Leave `api_key` and `admin_key` empty to generate local bootstrap keys on first
start. They are written to `data/meta.json`.

## Run from source

```bash
go run ./cmd/grokbuild-proxy -config config.yaml
```

Override the listener without editing the file:

```bash
LISTEN=127.0.0.1:9090 go run ./cmd/grokbuild-proxy -config config.yaml
```

Environment listen overrides are applied before configuration validation.

## Build a local binary

Using Make:

```bash
make build VERSION=v0.2.0
make check
make docker-build VERSION=v0.2.0
make release-snapshot
```

Using Go directly:

```bash
mkdir -p bin
go build -trimpath -o bin/grokbuild-proxy ./cmd/grokbuild-proxy
./bin/grokbuild-proxy -config config.yaml
```

Embed a version:

```bash
VERSION=v0.2.0
go build -trimpath \
  -ldflags="-s -w -X main.version=${VERSION}" \
  -o bin/grokbuild-proxy \
  ./cmd/grokbuild-proxy

./bin/grokbuild-proxy --version
```

## Platform-specific builds

### Linux

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -o bin/grokbuild-proxy-linux-amd64 \
  ./cmd/grokbuild-proxy
```

### macOS

Apple Silicon:

```bash
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
  go build -trimpath -o bin/grokbuild-proxy-darwin-arm64 \
  ./cmd/grokbuild-proxy
```

Intel:

```bash
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 \
  go build -trimpath -o bin/grokbuild-proxy-darwin-amd64 \
  ./cmd/grokbuild-proxy
```

### Windows

```powershell
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -trimpath -o bin/grokbuild-proxy-windows-amd64.exe ./cmd/grokbuild-proxy
```

The storage lock implementation has separate Unix and Windows backends.

## Docker image

Build:

```bash
docker build \
  --build-arg VERSION=dev \
  -t grokbuild-proxy:local \
  .
```

Run with a named volume:

```bash
docker volume create grokbuild-data

docker run --rm \
  --name grokbuild-proxy \
  -p 127.0.0.1:8080:8080 \
  -e LISTEN=0.0.0.0:8080 \
  -e ALLOW_PUBLIC_LISTEN=true \
  -v "$(pwd)/config.yaml:/app/config.yaml:ro" \
  -v grokbuild-data:/app/data \
  grokbuild-proxy:local
```

The container binds all interfaces internally, but the host publishes only
loopback.

## Docker Compose

```bash
docker compose up --build -d
docker compose ps
docker compose logs -f grokbuild-proxy
```

Read generated bootstrap keys:

```bash
docker compose exec grokbuild-proxy sh -c 'cat /app/data/meta.json'
```

Stop:

```bash
docker compose down
```

Remove runtime data only when you intentionally want to delete credentials and
keys:

```bash
docker compose down -v
```

## First-run setup

1. Start the proxy.
2. Open `http://127.0.0.1:8080/admin`.
3. Read `admin_key` from `data/meta.json`.
4. Complete browser device login or import an existing Grok CLI credential.
5. Create or retrieve a client API key.
6. Verify `/readyz`.

Prefer browser device login. Importing `~/.grok/auth.json` can copy an already
rotated or revoked refresh token when another process owns the credential
lifecycle.

## Client configuration

### Claude Code

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080
export ANTHROPIC_AUTH_TOKEN="$(jq -r .api_key data/meta.json)"
export ANTHROPIC_MODEL=grok-4.5

claude --effort high
```

### OpenAI SDKs

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
export OPENAI_API_KEY="$(jq -r .api_key data/meta.json)"
```

## Validation

Format:

```bash
gofmt -w ./cmd ./internal
```

Static analysis:

```bash
go vet ./...
```

Unit and contract tests:

```bash
go test ./...
go test -race ./...
```

Build:

```bash
go build ./cmd/grokbuild-proxy
```

Docker smoke:

```bash
docker build -t grokbuild-proxy:smoke .
docker run --rm -d \
  --name grokbuild-proxy-smoke \
  -p 127.0.0.1:18080:8080 \
  -e LISTEN=0.0.0.0:8080 \
  -e ALLOW_PUBLIC_LISTEN=true \
  grokbuild-proxy:smoke

curl --fail http://127.0.0.1:18080/healthz
docker rm -f grokbuild-proxy-smoke
```

Credentialed live smoke is never run by normal tests:

```bash
GROKBUILD_LIVE_SMOKE=1 \
GROKBUILD_BASE_URL=http://127.0.0.1:8080 \
GROKBUILD_API_KEY=... \
GROKBUILD_LIVE_MODEL=claude-opus-4-6 \
go run ./scripts/live-thinking-probe.go
```

## GoReleaser snapshot

Validate release archives without publishing:

```bash
go run github.com/goreleaser/goreleaser/v2@latest \
  release --snapshot --clean
```

Artifacts are written to `dist/` and include:

- Linux, macOS, and Windows binaries
- amd64 and arm64 archives
- `checksums.txt`
- archive SBOMs
- project documentation and example configuration
- source-build and image-only Compose files
- the SSO import sidecar Dockerfile, runtime sources, and dependency manifest

Verify the deployable payload after a snapshot build:

```bash
REQUIRE_SBOM=1 sh scripts/verify-release-archive.sh dist
```

The verifier requires the exact archive payload, regular-file entries, Unix
execute bits on Linux/macOS binaries, canonical checksum syntax, and one
checksummed SBOM for each of the six archives.

Downloaded binary archives can start the published proxy and optional sidecar
images without a source tree:

```bash
cp config.example.yaml config.yaml
export SSO_CONVERTER_API_TOKEN="$(openssl rand -hex 32)"
export GROKBUILD_CONTAINER_TAG=0.1.1
docker compose -f docker-compose.release.yml --profile sso-import pull
docker compose -f docker-compose.release.yml --profile sso-import up -d
```

Set the required `GROKBUILD_CONTAINER_TAG` to the exact downloaded release before `pull` and `up`; both containers always use that same immutable version.

## Release process

Releases are automated by `.github/workflows/release.yml`.

1. Update `CHANGELOG.md`.
2. Run all validation commands.
3. Create and push a semantic-version tag:

   ```bash
   git tag -a v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```

4. GitHub Actions builds both images under a revision-scoped staging tag,
   verifies both multi-platform manifests, and then promotes immutable exact
   version tags. Archives, SBOMs, and checksums are built and verified locally
   before the checksum is signed and the GitHub Release is published.
5. Verify the GitHub Release and install one downloaded artifact on a clean
   machine.

## Troubleshooting

### Public-listen validation failure

Use a loopback address:

```bash
LISTEN=127.0.0.1:8080 ./grokbuild-proxy
```

For a container whose host port remains loopback-only:

```bash
LISTEN=0.0.0.0:8080 ALLOW_PUBLIC_LISTEN=true ./grokbuild-proxy
```

### Data directory is locked

Only one proxy process may use a data directory. Stop the other process or
select a different `data_dir`.

### `invalid_grant` / revoked refresh token

The copied refresh token is no longer valid. Complete browser device login
again. Retrying refresh cannot revive a revoked token.

### HTTP 402

The selected account has no available Grok Build balance. Add another
operator-owned account or wait for quota reset.

### Claude Code receives HTTP 400

Check [COMPATIBILITY.md](../COMPATIBILITY.md), then inspect the proxy's
structured logs using the request ID. Do not attach prompts, tokens, or thinking
signatures to public issues.
