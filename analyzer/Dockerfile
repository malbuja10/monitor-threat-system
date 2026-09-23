# Usar imagen base ligera
FROM python:3.11-slim

# Evitar basura temporal y asegurar salida inmediata de logs
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TZ=America/Guayaquil

# Instalar dependencias del sistema necesarias para audio, compilación y OpenCV
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libasound2-dev \
    libportaudio2 \
    portaudio19-dev \
    libasound2 \
    libgl1 \
    libglib2.0-0 \
    libxcb1 \
    libx11-6 \
    libsm6 \
    libxext6 \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copiar requerimientos primero para aprovechar el caché de Docker
COPY requirements.txt .

# 1. Actualizar pip
# 2. Instalar versiones de CPU para ARM64
# 3. Instalar el resto filtrando SOLO los paquetes exactos ya instalados
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir tensorflow tensorflow-hub && \
    grep -vE "^torch$|^tensorflow$|^numpy$|^tensorflow-hub$" requirements.txt > req_lite.txt && \
    pip install --no-cache-dir -r req_lite.txt && \
    rm req_lite.txt && \
    rm -rf /root/.cache/pip

# Copiar el resto del código y los modelos
COPY . .

# Comando por defecto
ENTRYPOINT ["python3", "realtime_analyzer.py", "detect"]

#CMD ["detect"]
