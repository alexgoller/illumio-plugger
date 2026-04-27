FROM ghcr.io/alexgoller/illumio-pretty-cool-events:latest

# Copy plugger metadata for discovery
COPY .plugger/metadata.yaml /.plugger/metadata.yaml
ARG VERSION=0.1.0
RUN sed -i "s/^  version: .*/  version: \"${VERSION}\"/" /.plugger/metadata.yaml || true

# Default config location — mount or override via env
VOLUME /config

EXPOSE 8443

ENTRYPOINT ["pce-events", "run", "--config", "/config/config.yaml"]
