# ── Build stage ──────────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS builder

ARG TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/single-pane-of-glass ./spog

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.19

COPY --from=builder /out/single-pane-of-glass /usr/local/bin/single-pane-of-glass

RUN addgroup -S -g 65532 spog && adduser -S -u 65532 -G spog spog
USER 65532

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/single-pane-of-glass"]
