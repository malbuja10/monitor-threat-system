FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TZ=America/Guayaquil

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    tzdata \
    wget \
    ca-certificates \
    && wget https://dl.step.sm/gh-release/cli/gh-release-header/v0.24.4/step_linux_0.24.4_arm64.tar.gz -O step.tar.gz \
    && tar -xf step.tar.gz \
    && cp step_0.24.4/bin/step /usr/local/bin/ \
    && rm -rf step.tar.gz step_0.24.4 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
#COPY alembic.ini /app/alembic.ini
#COPY alembic /app/alembic

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . /app

CMD ["python3", "main.py"]
