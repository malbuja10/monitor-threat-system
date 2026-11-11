from pathlib import Path
import socket
import os
import math
import json
import time
import re
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


DEVICE_CONFIG_PATH = Path(os.getenv(
    'DEVICE_CONFIG_PATH', '/var/lib/threat_system/device_config.json'
))


def _load_remote_settings() -> dict:
    if not DEVICE_CONFIG_PATH.exists():
        return {}
    try:
        document = json.loads(DEVICE_CONFIG_PATH.read_text(encoding='utf-8'))
        settings = document['settings']
        if not isinstance(settings, dict):
            raise ValueError('settings must be a JSON object')
        return settings
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f'Cannot read remote device configuration: {exc}') from exc


REMOTE_SETTINGS = _load_remote_settings()


def _raw_setting(env_name: str, default):
    setting_name = env_name.lower()
    if setting_name in REMOTE_SETTINGS:
        return REMOTE_SETTINGS[setting_name]
    return os.getenv(env_name, str(default))


if 'timezone' in REMOTE_SETTINGS:
    try:
        ZoneInfo(REMOTE_SETTINGS['timezone'])
        os.environ['TZ'] = REMOTE_SETTINGS['timezone']
        if hasattr(time, 'tzset'):
            time.tzset()
    except (ZoneInfoNotFoundError, TypeError) as exc:
        raise ValueError('Invalid timezone in remote device configuration') from exc


def _positive_int_env(name: str, default: int, *, allow_zero: bool = False) -> int:
    """Read and validate a duration from the environment."""
    raw_value = _raw_setting(name, default)
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f'{name} must be an integer; got {raw_value!r}') from exc

    minimum = 0 if allow_zero else 1
    if value < minimum:
        raise ValueError(f'{name} must be >= {minimum}; got {value}')
    return value


def _reporting_times_env() -> list[str]:
    """Read comma-separated local 24-hour report times (HH:MM)."""
    raw_value = _raw_setting('REPORTING_TIMES', '10:00,14:00,18:00')
    if isinstance(raw_value, list):
        times = [str(item).strip() for item in raw_value]
    else:
        times = [item.strip() for item in str(raw_value).split(',') if item.strip()]
    if not times:
        raise ValueError('REPORTING_TIMES must contain at least one HH:MM time')

    for value in times:
        try:
            if not re.fullmatch(r'\d{2}:\d{2}', value):
                raise ValueError
            datetime.strptime(value, '%H:%M')
        except ValueError as exc:
            raise ValueError(
                f'Invalid REPORTING_TIMES entry {value!r}; expected 24-hour HH:MM'
            ) from exc

    if len(times) != len(set(times)):
        raise ValueError('REPORTING_TIMES must not contain duplicate times')
    return times


def _positive_voltage_env(name: str, default: float) -> float:
    raw_value = _raw_setting(name, default)
    try:
        value = float(raw_value)
    except ValueError as exc:
        raise ValueError(f'{name} must be a number; got {raw_value!r}') from exc
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f'{name} must be a finite positive voltage; got {raw_value!r}')
    return value

SERIAL_PORT = '/dev/ttyAMA0'
BAUD_RATE = 9600

ANTENNA_TYPE = str(_raw_setting('ANTENNA_TYPE', 'starlink')).strip().lower()
if ANTENNA_TYPE not in {'starlink', 'ubiquiti'}:
    raise ValueError("ANTENNA_TYPE must be either 'starlink' or 'ubiquiti'")

TIME_ANTENNA_POWER_ON_MINUTES = _positive_int_env('TIME_ANTENNA_POWER_ON_MINUTES', 10)
ANTENNA_REST_TIME_MINUTES = _positive_int_env('ANTENNA_REST_TIME_MINUTES', 5, allow_zero=True)
REPORTING_TIME_ON_MINUTES = _positive_int_env('REPORTING_TIME_ON_MINUTES', 10)
REPORTING_TIMES = _reporting_times_env()
VOLTAGE_TURN_OFF = _positive_voltage_env('VOLTAGE_TURN_OFF', 11.8)  # V
STARLINK_CONNECTION_TIMEOUT_SECONDS = _positive_int_env(
    'STARLINK_CONNECTION_TIMEOUT_SECONDS', 420
)
STARLINK_CONNECTION_CHECK_INTERVAL_SECONDS = _positive_int_env(
    'STARLINK_CONNECTION_CHECK_INTERVAL_SECONDS', 60
)

API_URL = os.getenv('THREAT_API_URL', 'https://192.168.1.88:8444/api/sincronizar')
VOLTAGE_API_URL = os.getenv('VOLTAGE_API_URL', 'https://192.168.1.88:8444/api/telemetry/voltage')
TEMP_API_URL = os.getenv('DEVICE_TELEMETRY_API_URL', 'https://192.168.1.88:8444/api/telemetry/status')
GET_TOKEN = os.getenv('DEVICE_ENROLLMENT_URL', 'https://192.168.1.88:8444/v1/inscripcion')
FACTORY_CLAIM_SECRET = os.getenv('FACTORY_CLAIM_SECRET', '')
STEP_CA_URL = os.getenv('STEP_CA_URL', 'https://dev.minkafab.com:8443')

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
STARLINK_STATE_PATH = Path(os.getenv(
    'STARLINK_STATE_PATH', '/var/lib/threat_system/starlink_power_state'
))
