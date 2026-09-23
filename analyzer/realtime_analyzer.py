import os
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import joblib
import pyaudio
import tensorflow as tf
import tensorflow_hub as hub
from scipy.signal import resample_poly
from datetime import datetime
import time
import threading
import argparse
from pathlib import Path
import ctypes
from queue import Queue, Full
import gc
import psutil
from collections import deque

# ===================================================================
# 0. CONFIGURACIÓN Y SILENCIO DE ALSA
# ===================================================================
# OPTIMIZACIÓN: Limitar a 1 solo núcleo para evitar sobrecalentamiento
tf.config.threading.set_inter_op_parallelism_threads(1)
tf.config.threading.set_intra_op_parallelism_threads(1)
torch.set_num_threads(1)

def py_error_handler(filename, line, function, err, fmt): pass
ERROR_HANDLER_FUNC = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p)
c_error_handler = ERROR_HANDLER_FUNC(py_error_handler)
try:
    asound = ctypes.cdll.LoadLibrary('libasound.so.2')
    asound.snd_lib_error_set_handler(c_error_handler)
except: pass

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
PERCH_LOCAL_PATH = os.path.join(SCRIPT_DIR, "perch2") 
MODEL_CLASSIFIER_PATH = os.path.join(SCRIPT_DIR, "models_assets/model_swa_perch.pth")
LABEL_ENCODER_PATH = os.path.join(SCRIPT_DIR, "models_assets/label_encoder_perch2.pkl")
LOG_FILE_PATH = os.path.join(SCRIPT_DIR, "logits_log.txt")
THREAT_CONFIG_PATH = os.path.join(SCRIPT_DIR, "threat_config.yaml")
THREAT_DIR = os.path.join('EVIDENCE_DIR', "/var/log/threat_evidence")
PIPE_PATH = os.path.join('FIFO_PIPE_PATH', "/var/lib/threat_system/pipe_monitor")

TARGET_SR = 32000
PERCH_DURATION_S = 5.0
DETECTION_INTERVAL_S = 4.0  # Antes 2.0. Menos inferencias = menos calor.

raw_audio_buffer = deque(maxlen=100)
current_streaks = {}

# ===================================================================
# 1. UTILIDADES DE AMENAZAS (Imports internos para evitar Segfault)
# ===================================================================
def load_threat_config():
    import yaml
    try:
        if os.path.exists(THREAT_CONFIG_PATH):
            with open(THREAT_CONFIG_PATH, 'r') as f:
                return yaml.safe_load(f)
    except: pass
    return {"threats": {}, "default": {"threshold": 0.5, "min_streak": 5}}

def save_threat_audio(label, audio_np):
    from scipy.io.wavfile import write as wav_write
    import glob
    os.makedirs(THREAT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.abspath(os.path.join(THREAT_DIR, f"AMENAZA_{label}_{timestamp}.wav"))
    audio_int16 = (audio_np * 32767).astype(np.int16)
    wav_write(filename, TARGET_SR, audio_int16)
    
    # Mantener solo 10 archivos
    files = sorted(glob.glob(os.path.join(THREAT_DIR, "AMENAZA_*.wav")), key=os.path.getmtime)
    while len(files) > 10:
        try: os.remove(files.pop(0))
        except: pass
    return filename

def send_to_pipe(payload):
    import json
    try:
        # Ensure the pipe exists before writing
        if not os.path.exists(PIPE_PATH):
            print("Receiver is not running yet.")
        else:
            # Open the pipe and write the JSON message
            with open(PIPE_PATH, "w") as fifo:
                fifo.write(json.dumps(payload) + "\n")
                print("JSON Message sent!")
    except Exception as e:
        print(f"Error sending to pipe: {e}")

# ===================================================================
# 2. MODELO CLASIFICADOR (n=256)
# ===================================================================
class NeuralNetwork(nn.Module):
    def __init__(self, input_dim, num_classes, n=256):
        super().__init__()
        self.layer1 = nn.Linear(input_dim, n); self.bn1 = nn.BatchNorm1d(n)
        self.layer2 = nn.Linear(n, n); self.bn2 = nn.BatchNorm1d(n)
        self.layer3 = nn.Linear(n, n); self.bn3 = nn.BatchNorm1d(n)
        self.layer4 = nn.Linear(n, n); self.bn4 = nn.BatchNorm1d(n)
        self.layer5 = nn.Linear(n, n); self.bn5 = nn.BatchNorm1d(n)
        self.output = nn.Linear(n, num_classes)
    def forward(self, x):
        if x.dim() == 1: x = x.unsqueeze(0)
        x = torch.relu(self.bn1(self.layer1(x)))
        x = torch.relu(self.bn2(self.layer2(x)))
        x = torch.relu(self.bn3(self.layer3(x)))
        x = torch.relu(self.bn4(self.layer4(x)))
        x = torch.relu(self.bn5(self.layer5(x)))
        return self.output(x)

# ===================================================================
# 3. CAPTURA DE AUDIO
# ===================================================================
def audio_capture_thread(p, mic_idx, rate):
    global raw_audio_buffer
    
    # Intentar abrir con 1 canal, si falla intentar con 2 (común en RPi/Docker)
    try:
        stream = p.open(format=pyaudio.paInt16, channels=1, rate=rate, input=True, input_device_index=mic_idx, frames_per_buffer=4096)
        ch_count = 1
    except Exception as e:
        print(f"⚠️ Falló apertura con 1 canal, intentando con 2... (Error: {e})", flush=True)
        try:
            stream = p.open(format=pyaudio.paInt16, channels=2, rate=rate, input=True, input_device_index=mic_idx, frames_per_buffer=4096)
            ch_count = 2
        except Exception as e2:
            print(f"❌ Error fatal: No se pudo abrir el micrófono en ningún modo: {e2}", flush=True)
            return

    chunk_samples = int(rate * 0.5)
    print(f"🎤 Captura activa ({rate}Hz, {'Mono' if ch_count==1 else 'Stereo'}) en dispositivo {mic_idx}", flush=True)
    
    while True:
        try:
            data = stream.read(chunk_samples, exception_on_overflow=False)
            audio_np = np.frombuffer(data, dtype=np.int16)
            
            # Si es estéreo, convertir a mono promediando los dos canales
            if ch_count == 2:
                audio_np = audio_np.reshape(-1, 2).mean(axis=1).astype(np.int16)
            
            raw_audio_buffer.append(audio_np)
        except Exception as e:
            print(f"⚠️ Error en captura de audio: {e}", flush=True)
            time.sleep(0.1)

# ===================================================================
# 4. FLUJO PRINCIPAL (VERSION TURN 104)
# ===================================================================
def run_detection_mode():
    global raw_audio_buffer, current_streaks
    
    # --- 1. AUDIO PRIMERO ---
    p = pyaudio.PyAudio()
    mic_idx = None
    
    # Escaneo exhaustivo de dispositivos de entrada
    print("🔍 Escaneando dispositivos de audio...", flush=True)
    for i in range(p.get_device_count()):
        dev_info = p.get_device_info_by_index(i)
        name = dev_info.get("name")
        max_in = dev_info.get("maxInputChannels", 0)
        
        if max_in > 0:
            print(f"   [ID {i}] {name} (Inputs: {max_in})", flush=True)
            # Preferir dispositivos que digan USB o Microphone
            if "USB" in name.upper() or "MICROPHONE" in name.upper():
                mic_idx = i
                print(f"✅ Micrófono USB detectado y seleccionado: {name}", flush=True)
                break
    
    # Si no se encontró uno con nombre específico, usar el primer ID con entrada
    if mic_idx is None:
        for i in range(p.get_device_count()):
            if p.get_device_info_by_index(i).get("maxInputChannels", 0) > 0:
                mic_idx = i
                print(f"⚠️ Usando dispositivo genérico con entrada: {p.get_device_info_by_index(i)['name']}", flush=True)
                break

    if mic_idx is None:
        print("❌ ERROR: No se encontró ningún dispositivo con capacidad de entrada.", flush=True)
        return

    rate = 44100
    try:
        if not p.is_format_supported(rate, input_device=mic_idx, input_channels=1, input_format=pyaudio.paInt16):
            rate = 48000
    except: pass

    # --- 2. IA DESPUÉS ---
    print("🚀 Cargando modelos...")
    le = joblib.load(LABEL_ENCODER_PATH)
    perch = hub.load(PERCH_LOCAL_PATH)
    perch_sigs = perch.signatures
    classifier = NeuralNetwork(input_dim=1536, num_classes=len(le.classes_), n=256)
    classifier.load_state_dict(torch.load(MODEL_CLASSIFIER_PATH, map_location="cpu"))
    classifier.eval()
    
    for clase in le.classes_: current_streaks[clase] = 0
    threat_config = load_threat_config()

    # Lanzar captura
    threading.Thread(target=audio_capture_thread, args=(p, mic_idx, rate), daemon=True).start()
    process = psutil.Process(os.getpid())

    print("⏳ Llenando buffer inicial...")
    while len(raw_audio_buffer) < 10: time.sleep(0.5)
    print(f"🔥 Monitor activo cada {DETECTION_INTERVAL_S}s.")
    
    while True:
        try:
            start_time = time.time()
            now = datetime.now()
            
            # Preparar audio
            audio_full = np.concatenate(list(raw_audio_buffer))
            needed = int(rate * PERCH_DURATION_S)
            audio_chunk = audio_full[-needed:]
            audio_resampled = resample_poly(audio_chunk, TARGET_SR, rate).astype(np.float32) / 32768.0
            if len(audio_resampled) < 160000: audio_resampled = np.pad(audio_resampled, (0, 160000 - len(audio_resampled)))
            else: audio_resampled = audio_resampled[:160000]
            
            # Inferencia Directa
            inputs = tf.constant(audio_resampled.reshape(1, -1), dtype=tf.float32)
            outputs = perch_sigs["serving_default"](inputs)
            embedding = outputs["embedding"].numpy()
            
            with torch.no_grad():
                logits = classifier(torch.from_numpy(embedding).float())
                probs = F.softmax(logits, dim=1)
                val, idx = torch.max(probs, dim=1)
                label = le.inverse_transform([idx.item()])[0]
            
            prob_val = val.item()
            
            # Lógica de amenazas
            conf = threat_config["threats"].get(label, {"threshold": 1.0, "min_streak": 999})
            if label in threat_config["threats"] and prob_val >= conf["threshold"]:
                current_streaks[label] += 1
                streak = current_streaks[label]
                for c in current_streaks: 
                    if c != label: current_streaks[c] = 0
                
                if streak == conf["min_streak"]:
                    # EVENTO AMENAZA INICIAL
                    ev_file = save_threat_audio(label, audio_resampled)
                    send_to_pipe({"event": "THREAT", "label": label, "prob": round(prob_val, 4), "file": ev_file, "time": now.isoformat()})
                    status = "🚨 ALERTA"
                elif streak in [conf["min_streak"] * 3, conf["min_streak"] * 6, conf["min_streak"] * 9]:
                    # EVENTO CONTINUO (Múltiplos 3x, 6x, 9x)
                    ev_file = save_threat_audio(label, audio_resampled)
                    send_to_pipe({"event": "CONTINUOUS", "label": label, "prob": round(prob_val, 4), "file": ev_file, "time": now.isoformat(), "streak": streak})
                    status = f"🚨 CONT_{streak}"
                elif streak > conf["min_streak"]: 
                    status = "AMENAZA_CONT"
                else: 
                    status = f"Racha:{streak}"
            else:
                for c in current_streaks: current_streaks[c] = 0
                status = "OK"

            # Stats y Print
            ia_dur = (time.time() - start_time) * 1000
            ram = process.memory_info().rss / 1024 / 1024
            print(f"[{now.strftime('%H:%M:%S')}] 🦜 {label:20} ({prob_val:6.2%}) | {status:15} | RAM:{ram:.0f}MB", flush=True)
            
            time.sleep(max(0.1, DETECTION_INTERVAL_S - (time.time() - start_time)))
            
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["detect", "monitor"])
    args = parser.parse_args()
    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
    if args.mode == "detect": run_detection_mode()
