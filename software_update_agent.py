#!/usr/bin/env python3
"""Install an approved software-image manifest on a field Raspberry Pi.

Model artifacts are updated by model_update_agent.py. This agent only changes
the monitor and analyzer container image references in the project's .env.
"""
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse


PROJECT_DIR = Path(os.environ.get("SOFTWARE_PROJECT_DIR", "/home/rpi/client"))
STATE_DIR = Path(os.environ.get("SOFTWARE_STATE_DIR", "/var/lib/threat_system/software"))
MANIFEST_URL = os.environ.get(
    "SOFTWARE_UPDATE_MANIFEST_URL",
    "https://raw.githubusercontent.com/malbuja10/monitor-threat-system/main/software-update.json",
)
ENV_FILE = PROJECT_DIR / ".env"
DEFAULT_IMAGES = {
    "monitor": "ghcr.io/malbuja10/monitor-threat-system/monitor:latest",
    "analyzer": "ghcr.io/malbuja10/monitor-threat-system/analyzer:latest",
}
IMAGE_KEYS = {"monitor": "MONITOR_IMAGE_REF", "analyzer": "ANALYZER_IMAGE_REF"}
IMAGE_RE = re.compile(
    r"^ghcr\.io/malbuja10/monitor-threat-system/(monitor|analyzer)@sha256:[0-9a-f]{64}$"
)
READY_TEXT = "Monitor activo cada"
POLL_SECONDS = 5
HEALTH_TIMEOUT = int(os.environ.get("SOFTWARE_HEALTH_TIMEOUT_SECONDS", "240"))


def log(message):
    print(f"[SOFTWARE_OTA] {message}", flush=True)


def run(args, *, capture=False):
    return subprocess.run(
        args, cwd=PROJECT_DIR, check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )


def compose(*args, capture=False):
    return run(
        ["docker", "compose", "--project-directory", str(PROJECT_DIR),
         "-f", str(PROJECT_DIR / "docker-compose.yml"), *args],
        capture=capture,
    )


def load_manifest():
    request = urllib.request.Request(
        MANIFEST_URL,
        headers={"User-Agent": "jocotoco-software-updater/1", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=25) as response:
        raw = response.read(16 * 1024 + 1)
    if len(raw) > 16 * 1024:
        raise ValueError("Software manifest is too large")
    return validate_manifest(json.loads(raw))


def internet_available():
    host = urlparse(MANIFEST_URL).hostname
    if not host:
        raise ValueError("Software manifest URL has no hostname")
    try:
        with socket.create_connection((host, 443), timeout=3):
            return True
    except OSError:
        return False


def validate_manifest(data):
    if not isinstance(data, dict):
        raise ValueError("Software manifest must be a JSON object")
    if data.get("schema_version") != 1:
        raise ValueError("Unsupported software manifest schema_version")
    release_id = data.get("release_id")
    if not isinstance(release_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", release_id):
        raise ValueError("Invalid release_id in software manifest")
    images = data.get("images")
    if not isinstance(images, dict):
        raise ValueError("Manifest images must be an object")
    validated = {}
    for service in ("monitor", "analyzer"):
        reference = images.get(service)
        match = IMAGE_RE.fullmatch(reference or "") if isinstance(reference, str) else None
        if not match or match.group(1) != service:
            raise ValueError(f"{service} must use its GHCR image pinned by sha256 digest")
        validated[service] = reference
    return release_id, validated


def read_env():
    if not ENV_FILE.exists():
        return None, {}, 0o600
    original = ENV_FILE.read_text()
    mode = ENV_FILE.stat().st_mode & 0o777
    values = {}
    for line in original.splitlines():
        match = re.match(r"^\s*(MONITOR_IMAGE_REF|ANALYZER_IMAGE_REF)\s*=\s*(.*?)\s*$", line)
        if match:
            values[match.group(1)] = match.group(2).strip("'\"")
    return original, values, mode


def write_env(original, replacements, mode):
    lines = (original or "").splitlines()
    found = set()
    output = []
    for line in lines:
        match = re.match(r"^\s*(MONITOR_IMAGE_REF|ANALYZER_IMAGE_REF)\s*=", line)
        if match:
            key = match.group(1)
            if key not in found:
                output.append(f"{key}={replacements[key]}")
                found.add(key)
        else:
            output.append(line)
    for key, value in replacements.items():
        if key not in found:
            output.append(f"{key}={value}")
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".env.software-", dir=PROJECT_DIR, text=True)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write("\n".join(output).rstrip() + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, ENV_FILE)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def current_references(values):
    return {service: values.get(IMAGE_KEYS[service], DEFAULT_IMAGES[service]) for service in IMAGE_KEYS}


def running_image_digest(service):
    """Return the immutable GHCR digest for the image currently used by Compose."""
    container_ids = compose("ps", "-a", "-q", service, capture=True).stdout.splitlines()
    if not container_ids:
        raise RuntimeError(f"Cannot establish a safe rollback image: no {service} container exists")
    image_id = run(
        ["docker", "inspect", "--format", "{{.Image}}", container_ids[0]], capture=True
    ).stdout.strip()
    repo_digests = json.loads(run(
        ["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image_id],
        capture=True,
    ).stdout)
    prefix = f"ghcr.io/malbuja10/monitor-threat-system/{service}@sha256:"
    for reference in repo_digests or []:
        if isinstance(reference, str) and reference.startswith(prefix) and IMAGE_RE.fullmatch(reference):
            return reference
    raise RuntimeError(
        f"Cannot establish a safe rollback image for {service}; its running image has no matching GHCR digest"
    )


def pin_previous_images(original, values, mode):
    """Persist immutable references to the currently deployed pair before updating."""
    current = current_references(values)
    previous = {}
    for service, reference in current.items():
        match = IMAGE_RE.fullmatch(reference)
        previous[service] = (
            reference if match and match.group(1) == service
            else running_image_digest(service)
        )

    pinned_values = {IMAGE_KEYS[service]: previous[service] for service in previous}
    if original is None or any(values.get(key) != value for key, value in pinned_values.items()):
        write_env(original, pinned_values, mode)
        original = ENV_FILE.read_text()
        mode = ENV_FILE.stat().st_mode & 0o777
        log("Saved digest-pinned references to the currently running images for rollback")
    return original, previous, mode


def compose_services():
    raw = compose("ps", "--format", "json", capture=True).stdout.strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        pass
    services = []
    for line in raw.splitlines():
        try:
            services.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return services


def wait_healthy(started_at):
    deadline = time.monotonic() + HEALTH_TIMEOUT
    while time.monotonic() < deadline:
        services = {item.get("Service"): item for item in compose_services()}
        monitor = services.get("monitor", {})
        analyzer = services.get("analyzer", {})
        running = lambda item: str(item.get("State", "")).lower() == "running"
        if monitor and analyzer and running(monitor) and running(analyzer):
            logs = compose("logs", "--since", started_at, "--no-color", "analyzer", capture=True).stdout
            if READY_TEXT in logs:
                return
        time.sleep(POLL_SECONDS)
    raise TimeoutError("Monitor and analyzer did not pass the startup health check")


def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def cleanup_old_images(keep_references):
    """Remove obsolete local images for these services, preserving active/rollback refs.

    This deliberately does not run a global Docker prune and does not touch
    images outside the Jocotoco monitor/analyzer GHCR repositories.
    """
    keep = {reference for reference in keep_references if IMAGE_RE.fullmatch(reference)}
    try:
        output = run(
            ["docker", "image", "ls", "--digests", "--no-trunc", "--format",
             "{{.Repository}}@{{.Digest}}"],
            capture=True,
        ).stdout
    except Exception as error:
        log(f"Could not list local release images; skipping cleanup: {error}")
        return

    candidates = set()
    for reference in output.splitlines():
        reference = reference.strip()
        if IMAGE_RE.fullmatch(reference):
            candidates.add(reference)

    for reference in sorted(candidates - keep):
        try:
            run(["docker", "image", "rm", reference], capture=True)
            log(f"Removed obsolete local image {reference}")
        except Exception as error:
            # Cleanup is best-effort; it must not invalidate a healthy release.
            log(f"Could not remove obsolete image {reference}; leaving it in place: {error}")


def restore_env(original, mode):
    if original is None:
        ENV_FILE.unlink(missing_ok=True)
        return
    fd, temporary = tempfile.mkstemp(prefix=".env.rollback-", dir=PROJECT_DIR, text=True)
    with os.fdopen(fd, "w") as handle:
        handle.write(original)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, ENV_FILE)


def update():
    if not (PROJECT_DIR / "docker-compose.yml").is_file():
        raise FileNotFoundError(f"Compose project not found: {PROJECT_DIR}")
    if not internet_available():
        log("No internet connection; the next timer check will retry")
        return
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    release_id, candidate = load_manifest()
    active_state = STATE_DIR / "active.json"
    failed_state = STATE_DIR / "failed.json"
    if failed_state.exists() and json.loads(failed_state.read_text()).get("release_id") == release_id:
        log(f"Release {release_id} previously failed; waiting for a different manifest target")
        return

    original, values, mode = read_env()
    original, previous, mode = pin_previous_images(original, values, mode)
    if previous == candidate:
        log(f"Software release {release_id} is already active")
        previous_images = {}
        if active_state.exists():
            try:
                saved_state = json.loads(active_state.read_text())
                if saved_state.get("images") == candidate:
                    saved_previous = saved_state.get("previous_images", {})
                    if isinstance(saved_previous, dict):
                        previous_images = {
                            service: reference
                            for service, reference in saved_previous.items()
                            if service in IMAGE_KEYS
                            and isinstance(reference, str)
                            and IMAGE_RE.fullmatch(reference)
                            and IMAGE_RE.fullmatch(reference).group(1) == service
                        }
            except (OSError, json.JSONDecodeError):
                pass
        atomic_json(active_state, {
            "release_id": release_id,
            "images": candidate,
            "previous_images": previous_images,
        })
        cleanup_old_images(list(candidate.values()) + list(previous_images.values()))
        return

    log(f"Pulling approved software release {release_id}")
    for service in ("monitor", "analyzer"):
        run(["docker", "pull", candidate[service]])

    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        write_env(original, {IMAGE_KEYS[s]: candidate[s] for s in candidate}, mode)
        compose("up", "-d", "--no-build", "--force-recreate", "monitor", "analyzer")
        wait_healthy(started_at)
    except Exception as error:
        log(f"Candidate failed health check: {error}; restoring the previous image references")
        restore_env(original, mode)
        try:
            compose("up", "-d", "--no-build", "--force-recreate", "monitor", "analyzer")
        except Exception as rollback_error:
            log(f"AUTOMATIC ROLLBACK COMMAND FAILED: {rollback_error}")
        atomic_json(failed_state, {"release_id": release_id, "error": str(error)[:500]})
        raise

    failed_state.unlink(missing_ok=True)
    atomic_json(active_state, {"release_id": release_id, "images": candidate, "previous_images": previous})
    log(f"Software release {release_id} is active")
    cleanup_old_images(list(candidate.values()) + list(previous.values()))


if __name__ == "__main__":
    try:
        update()
    except Exception as exc:
        log(f"Update not applied: {exc}")
        sys.exit(1)
