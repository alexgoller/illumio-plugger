FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY plugger_sdk.py .

ARG VERSION=0.1.0
COPY plugin.yaml /.plugger/plugin.yaml
COPY .plugger/metadata.yaml /.plugger/metadata.yaml
RUN sed -i "s/^  version: .*/  version: \"${VERSION}\"/" /.plugger/metadata.yaml || true

EXPOSE 8080
CMD ["python3", "main.py"]
