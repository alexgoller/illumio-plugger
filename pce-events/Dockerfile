FROM ghcr.io/alexgoller/illumio-pretty-cool-events:latest

# Copy plugger metadata for discovery
COPY .plugger/metadata.yaml /.plugger/metadata.yaml

# Default config location — mount or override via env
VOLUME /config

EXPOSE 8443

ENTRYPOINT ["pce-events", "run", "--config", "/config/config.yaml"]
