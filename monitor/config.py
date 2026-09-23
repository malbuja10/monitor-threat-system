from pathlib import Path
import socket
import os

SERIAL_PORT = '/dev/ttyAMA0'
BAUD_RATE = 9600

TIME_ANTENNA_POWER_ON_MINUTES = 5  # minutes
ANTENNA_REST_TIME_MINUTES = 5      # minutes
REPORTING_TIME_ON_MINUTES = 10
REPORTING_TIMES = ['12:48', '14:00', '18:00']
VOLTAGE_TURN_OFF = 11.8            # V

API_URL = 'https://192.168.1.88:8444/api/sincronizar'
VOLTAGE_API_URL = 'https://192.168.1.88:8444/api/telemetry/voltage'
TEMP_API_URL = 'https://192.168.1.88:8444/api/telemetry/temperature'
GET_TOKEN = 'https://192.168.1.88:8444/v1/inscripcion'

def get_device_serial():
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if line.startswith('Serial'):
                    return line.split(':')[1].strip()
    except Exception:
        pass
    return socket.gethostname()

DEVICE_ID = get_device_serial()
MAIN_DIR = Path(__file__).resolve().parent

CERTS_DIR = Path("/var/lib/threat_system/certs")
CERT_FILES = (
    str(CERTS_DIR / f"{DEVICE_ID}.crt"),
    str(CERTS_DIR / f"{DEVICE_ID}.key")
)
#CERT_FILES = (f'/var/lib/threat_system/certs/{DEVICE_ID}.crt'), ( f'/var/lib/threat_system/certs/{DEVICE_ID}.key')
#CA_CERT = Path('/home/rpi/.step/certs/root_ca.crt')
CA_CERT = os.getenv("STEP_CA_CERT", "/app/certs/root_ca.crt")

LOG_PATH = Path(os.getenv('LOG_PATH', '/var/lib/threat_system/system.log'))
LOCAL_DB_PATH = Path(os.getenv('LOCAL_DB_PATH', '/var/lib/threat_system/threats.db'))
PIPE_PATH = Path(os.getenv('FIFO_PIPE_PATH', '/var/lib/threat_system/pipe_monitor'))
EVIDENCE_DIR = Path(os.getenv('EVIDENCE_DIR', '/var/log/threat_evidence'))
