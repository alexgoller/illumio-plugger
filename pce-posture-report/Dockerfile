FROM python:3.12-slim
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
RUN useradd -m -u 1000 plugin
COPY main.py /app/main.py
COPY .plugger/metadata.yaml /.plugger/metadata.yaml
ARG VERSION=0.1.0
RUN sed -i "s/^  version: .*/  version: \"${VERSION}\"/" /.plugger/metadata.yaml || true
RUN mkdir -p /data && chown plugin:plugin /data
USER plugin
WORKDIR /app
ENTRYPOINT ["python3", "main.py"]
