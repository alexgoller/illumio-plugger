# Shell-based plugger plugin.
# Lightweight image with curl and jq for PCE API calls.

FROM alpine:3.19

# Install tools for API calls and JSON processing
RUN apk add --no-cache ca-certificates curl jq

# Create non-root user
RUN adduser -D -u 1000 plugin
USER plugin

# Copy entrypoint script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

# Copy in-container metadata for plugger discovery
COPY .plugger/metadata.yaml /.plugger/metadata.yaml

# Create data directory (matches volumes in metadata.yaml)
RUN mkdir -p /data

ENTRYPOINT ["sh", "/usr/local/bin/entrypoint.sh"]
