FROM python:3.12-slim

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

RUN useradd -m -u 1000 plugin

COPY main.py /app/main.py
COPY .plugger/metadata.yaml /.plugger/metadata.yaml

USER plugin
WORKDIR /app

EXPOSE 8080

ENTRYPOINT ["python3", "main.py"]
