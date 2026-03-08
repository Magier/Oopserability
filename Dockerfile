# ── Build stage ──────────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS builder

# TARGETARCH is injected by BuildKit (amd64, arm64, etc.)
ARG TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the agent
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/ooopservability .

# Build the demo payload separately so it can be bundled or distributed
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/payload ./payload

# ── Runtime stage ─────────────────────────────────────────────────────────────
# Using alpine (not distroless) so the container has a shell —
# which makes the RCE exercises more interesting.
FROM alpine:3.19

RUN apk add --no-cache \
      bash \
      curl \
      grep \
      procps \
      util-linux

COPY --from=builder /out/ooopservability /usr/local/bin/ooopservability
COPY --from=builder /out/payload      /usr/local/bin/ooopservability-payload

# Non-root user — note that memfd_create does NOT require root.
# This reinforces the point: fileless execution works as any UID.
RUN addgroup -S oops && adduser -S oops -G oops
USER oops

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/ooopservability"]
