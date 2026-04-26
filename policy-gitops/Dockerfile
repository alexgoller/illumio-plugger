FROM python:3.12-slim

# Install git (required for GitPython and repo operations)
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

RUN useradd -m -u 1000 plugin

COPY main.py /app/main.py
COPY .plugger/metadata.yaml /.plugger/metadata.yaml

# Persistent data: git clone target, state
RUN mkdir -p /data/repo && chown -R plugin:plugin /data

USER plugin
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["python3", "main.py"]
