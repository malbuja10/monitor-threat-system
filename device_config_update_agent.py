#!/usr/bin/env python3
"""Fetch, validate and safely apply a remote monitor configuration over mTLS."""
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


PROJECT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get(
    "DEVICE_CONFIG_PATH", "/var/lib/threat_system/device_config.json"
))
STARLINK_STATE_PATH = Path(os.environ.get(
    "STARLINK_STATE_PATH", "/var/lib/threat_system/starlink_power_state"
))
CONFIG_API_URL = os.environ.get("DEVICE_CONFIG_API_URL", "").strip()
CA_CERT = Path(os.environ.get(
    "DEVICE_CONFIG_CA_CERT", str(PROJECT_DIR / "monitor/certs/root_ca.crt")
))
DEVICE_CERT_DIR = Path(os.environ.get("DEVICE_CERT_DIR", "/var/lib/threat_system/certs"))
STATUS_QUEUE_PATH = Path(os.environ.get(
    "DEVICE_CONFIG_STATUS_QUEUE", "/var/lib/threat_system/device_config_status_queue.json"
))
LAST_STATUS_PATH = Path(os.environ.get(
    "DEVICE_CONFIG_LAST_STATUS", "/var/lib/threat_system/device_config_last_status.json"
))
STATUS_PATH = CONFIG_API_URL.rstrip("/") + "/status" if CONFIG_API_URL else ""
MAX_DOCUMENT_BYTES = 16 * 1024
MAX_API_RESPONSE_BYTES = 32 * 1024
SETTINGS_KEYS = {
    "timezone", "reporting_times", "time_antenna_power_on_minutes",
    "antenna_rest_time_minutes", "reporting_time_on_minutes",
    "voltage_turn_off", "starlink_connection_timeout_seconds",
    "starlink_connection_check_interval_seconds",
}


def api_request(url, method="GET", body=None, active_revision_value=0, active_version=""):
    if not url.startswith("https://"):
        raise ValueError("DEVICE_CONFIG_API_URL must use HTTPS")
    serial = device_id()
    cert_path = DEVICE_CERT_DIR / f"{serial}.crt"
    key_path = DEVICE_CERT_DIR / f"{serial}.key"
    if not cert_path.is_file() or not key_path.is_file() or not CA_CERT.is_file():
        raise FileNotFoundError("Device mTLS certificate, key, or trusted CA certificate is missing")
    context = ssl.create_default_context(cafile=str(CA_CERT))
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "User-Agent": "jocotoco-device-config/1",
            "Accept": "application/json",
            "Cache-Control": "no-cache",
            "X-Active-Config-Revision": str(active_revision_value),
            "X-Active-Config-Version": active_version,
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
    )
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
    with opener.open(request, timeout=20) as response:
        data = response.read(MAX_API_RESPONSE_BYTES + 1)
    if len(data) > MAX_API_RESPONSE_BYTES:
        raise ValueError("Configuration API response is too large")
    return response.status, data


def device_id():
    certificates = list(DEVICE_CERT_DIR.glob("*.crt"))
    if len(certificates) == 1:
        return certificates[0].stem
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("Serial"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return socket.gethostname()


def validate_document(document):
    required = {"schema_version", "config_revision", "config_version", "settings"}
    if not isinstance(document, dict) or set(document) != required:
        raise ValueError(f"Configuration must contain exactly: {sorted(required)}")
    if isinstance(document["schema_version"], bool) or document["schema_version"] != 1:
        raise ValueError("Unsupported configuration schema_version")
    revision = document["config_revision"]
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise ValueError("config_revision must be a positive integer")
    version = document["config_version"]
    if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", version):
        raise ValueError("Invalid config_version")
    settings = document["settings"]
    if not isinstance(settings, dict) or set(settings) != SETTINGS_KEYS:
        raise ValueError(f"settings must contain exactly: {sorted(SETTINGS_KEYS)}")
    times = settings["reporting_times"]
    if not isinstance(times, list) or not times or not all(isinstance(item, str) for item in times):
        raise ValueError("reporting_times must be a non-empty array of HH:MM strings")
    for value in times:
        try:
            if not re.fullmatch(r"\d{2}:\d{2}", value):
                raise ValueError
            datetime.strptime(value, "%H:%M")
        except ValueError as exc:
            raise ValueError(f"Invalid reporting time {value!r}; expected HH:MM") from exc
    if len(times) != len(set(times)):
        raise ValueError("reporting_times contains duplicates")

    ranges = {
        "time_antenna_power_on_minutes": (1, 1440),
        "antenna_rest_time_minutes": (0, 1440),
        "reporting_time_on_minutes": (1, 1440),
        "starlink_connection_timeout_seconds": (10, 7200),
        "starlink_connection_check_interval_seconds": (1, 600),
    }
    for key, (minimum, maximum) in ranges.items():
        value = settings[key]
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ValueError(f"{key} must be an integer from {minimum} to {maximum}")
    if settings["starlink_connection_check_interval_seconds"] > settings["starlink_connection_timeout_seconds"]:
        raise ValueError("Connection check interval cannot exceed connection timeout")
    voltage = settings["voltage_turn_off"]
    if isinstance(voltage, bool) or not isinstance(voltage, (int, float)) or not 1 <= voltage <= 60:
        raise ValueError("voltage_turn_off must be a number from 1 to 60 volts")
    if not isinstance(settings["timezone"], str) or not settings["timezone"]:
        raise ValueError("timezone must be a non-empty IANA timezone name")
    try:
        ZoneInfo(settings["timezone"])
    except ZoneInfoNotFoundError as exc:
        raise ValueError("timezone must be a valid IANA timezone name") from exc
    return document


def active_revision():
    try:
        current = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        return int(current.get("config_revision", 0))
    except (OSError, ValueError, TypeError, AttributeError):
        return 0


def active_version():
    try:
        current = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        return str(current.get("config_version", ""))
    except (OSError, ValueError, TypeError, AttributeError):
        return ""


def antenna_commanded_off():
    try:
        return STARLINK_STATE_PATH.read_text(encoding="utf-8").strip() == "0"
    except OSError:
        return False


def compose(*args, check=True):
    return subprocess.run(
        ["docker", "compose", "--project-directory", str(PROJECT_DIR),
         "-f", str(PROJECT_DIR / "docker-compose.yml"), *args],
        check=check, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=180,
    )


def monitor_state():
    result = compose("ps", "-q", "monitor")
    container_id = result.stdout.strip().splitlines()
    if not container_id:
        return None
    inspected = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}} {{.RestartCount}}", container_id[0]],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    return container_id[0], inspected[0] == "true", int(inspected[1])


def restart_and_check_monitor():
    try:
        output = compose("up", "-d", "--force-recreate", "monitor", check=False)
    except subprocess.TimeoutExpired:
        print("Timed out recreating monitor container", file=sys.stderr)
        return False
    if output.returncode:
        print(output.stdout, file=sys.stderr)
        return False
    deadline = time.monotonic() + 35
    initial = None
    while time.monotonic() < deadline:
        try:
            state = monitor_state()
        except (subprocess.CalledProcessError, ValueError, IndexError):
            state = None
        if state and state[1]:
            if initial is None:
                initial = state
            elif state[0] != initial[0] or state[2] > initial[2]:
                return False
        else:
            return False
        time.sleep(5)
    return initial is not None


def write_atomically(data):
    atomic_write(CONFIG_PATH, data, ".device-config-")


def atomic_write(path, data, prefix):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=prefix, dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def read_status_queue():
    try:
        entries = json.loads(STATUS_QUEUE_PATH.read_text(encoding="utf-8"))
        return entries if isinstance(entries, list) else []
    except (OSError, ValueError):
        return []


def queue_status(revision, version, status, detail=""):
    entries = read_status_queue()
    if any(item.get("config_revision") == revision and item.get("status") == status for item in entries):
        return
    try:
        last = json.loads(LAST_STATUS_PATH.read_text(encoding="utf-8"))
        if last.get("config_revision") == revision and last.get("status") == status:
            return
    except (OSError, ValueError, AttributeError):
        pass
    event = {
        "status_id": str(uuid.uuid4()),
        "config_revision": revision,
        "config_version": version,
        "status": status,
        "active_config_revision": active_revision(),
        "active_config_version": active_version(),
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "detail": detail[:500],6
    }
    entries.append(event)
    atomic_write(STATUS_QUEUE_PATH, json.dumps(entries[-100:], separators=(",", ":")).encode(), ".config-status-")


def flush_status_queue():
    entries = read_status_queue()
    if not entries or not STATUS_PATH:
        return
    pending = list(entries)
    for event in entries:
        try:
            code, _ = api_request(
                STATUS_PATH,
                method="POST",
                body=json.dumps(event).encode(),
                active_revision_value=active_revision(),
                active_version=active_version(),
            )
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            print(f"Could not report configuration status yet: {exc}")
            break
        if code not in (200, 201, 202, 204):
            break
        pending.remove(event)
        atomic_write(STATUS_QUEUE_PATH, json.dumps(pending, separators=(",", ":")).encode(), ".config-status-")
        atomic_write(LAST_STATUS_PATH, json.dumps({
            "config_revision": event["config_revision"], "status": event["status"]
        }).encode(), ".config-last-status-")


def apply_configuration(document_bytes):
    try:
        old_data = CONFIG_PATH.read_bytes()
    except FileNotFoundError:
        old_data = None
    write_atomically(document_bytes)
    if restart_and_check_monitor():
        return
    if old_data is None:
        CONFIG_PATH.unlink(missing_ok=True)
    else:
        write_atomically(old_data)
    if not restart_and_check_monitor():
        raise RuntimeError("New config failed; old config restored, but monitor restart also failed")
    raise RuntimeError("New config failed monitor health check; previous config restored")


def main():
    if not CONFIG_API_URL:
        print("DEVICE_CONFIG_API_URL is not configured; skipping remote configuration check")
        return 0
    revision = active_revision()
    version = active_version()
    try:
        flush_status_queue()
        code, response_bytes = api_request(
            CONFIG_API_URL, active_revision_value=revision, active_version=version
        )
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Configuration API returned HTTP {exc.code}: {exc.reason}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"Configuration API unavailable; will retry on next connection: {exc}")
        return 0
    if code == 204:
        print("No configuration update assigned")
        flush_status_queue()
        return 0
    if code != 200:
        raise ValueError(f"Unexpected configuration API response: HTTP {code}")
    if not response_bytes or len(response_bytes) > MAX_DOCUMENT_BYTES:
        raise ValueError("Configuration document is empty or too large")
    untrusted_document = json.loads(response_bytes)
    raw_revision = untrusted_document.get("config_revision", 0) if isinstance(untrusted_document, dict) else 0
    revision = raw_revision if isinstance(raw_revision, int) and not isinstance(raw_revision, bool) else 0
    raw_version = untrusted_document.get("config_version", "") if isinstance(untrusted_document, dict) else ""
    version = raw_version if isinstance(raw_version, str) else ""
    try:
        document = validate_document(untrusted_document)
    except Exception as exc:
        queue_status(revision, version, "rejected", str(exc))
        flush_status_queue()
        raise
    if document["config_revision"] <= active_revision():
        if document["config_revision"] < active_revision():
            queue_status(document["config_revision"], document["config_version"], "rejected", "Assignment revision is older than the active revision")
            flush_status_queue()
        else:
            print(f"Configuration revision {document['config_revision']} is already active")
        return 0
    if not antenna_commanded_off():
        print("Configuration validated; application is deferred until Starlink is commanded off")
        queue_status(document["config_revision"], document["config_version"], "deferred", "Starlink is still commanded on")
        flush_status_queue()
        return 0
    had_previous = CONFIG_PATH.exists()
    try:
        apply_configuration(response_bytes)
    except Exception as exc:
        result = "rolled_back" if had_previous and "previous config restored" in str(exc) else "failed"
        queue_status(document["config_revision"], document["config_version"], result, str(exc))
        flush_status_queue()
        raise
    queue_status(document["config_revision"], document["config_version"], "applied")
    flush_status_queue()
    print(f"Applied device configuration {document['config_version']} (revision {document['config_revision']})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"Configuration update rejected: {error}", file=sys.stderr)
        sys.exit(1)
