FROM python:3.10-slim

RUN apt-get update && apt-get install -y wget curl unzip && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app

RUN pip install -r requirements.txt && python -m playwright install chromium

ENTRYPOINT ["python3", "auto_run.py"]
