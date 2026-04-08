FROM python:3.12-slim

# Install dependencies first for layer caching
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Create non-root user
RUN useradd -m -u 1000 plugin
USER plugin

# Copy plugin code
COPY main.py /app/main.py

# Copy in-container metadata for plugger discovery
COPY .plugger/metadata.yaml /.plugger/metadata.yaml

# Create data directory (matches volumes in metadata.yaml)
RUN mkdir -p /data

WORKDIR /app
ENTRYPOINT ["python3", "main.py"]
