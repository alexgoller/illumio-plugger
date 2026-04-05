# Multi-stage build for a Go-based plugger plugin.
# Produces a minimal scratch-based image.

# ---- Build stage ----
FROM golang:1.21-alpine AS builder

WORKDIR /build
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /plugin .

# ---- Runtime stage ----
FROM alpine:3.19

# Install ca-certificates for TLS connections to PCE
RUN apk add --no-cache ca-certificates

# Create non-root user
RUN adduser -D -u 1000 plugin
USER plugin

# Copy the binary
COPY --from=builder /plugin /usr/local/bin/plugin

# Copy in-container metadata for plugger discovery.
# Plugger reads /.plugger/metadata.yaml to discover ports, config, volumes.
COPY .plugger/metadata.yaml /.plugger/metadata.yaml

# Create data directory (matches volumes in metadata.yaml)
RUN mkdir -p /data

# Expose ports declared in metadata.yaml
EXPOSE 8080 9090

ENTRYPOINT ["plugin"]
