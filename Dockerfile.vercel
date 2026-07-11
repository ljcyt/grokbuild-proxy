# syntax=docker/dockerfile:1

FROM golang:1.26.5-alpine AS builder
WORKDIR /src

RUN apk add --no-cache ca-certificates git

ARG VERSION=dev

COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/grokbuild-proxy ./cmd/grokbuild-proxy

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -H -u 10001 appuser

WORKDIR /app
COPY --from=builder /out/grokbuild-proxy /app/grokbuild-proxy
COPY config.example.yaml /app/config.example.yaml

RUN mkdir -p /app/data && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080
VOLUME ["/app/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/app/grokbuild-proxy"]
