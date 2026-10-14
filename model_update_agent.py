#!/usr/bin/env python3
"""Fetch and safely stage the latest signed GitHub model release.

This runs on the Raspberry Pi host (not in the analyzer container). Re-running
it resumes an interrupted HTTP download, which suits short Starlink windows.
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath


MODEL_ROOT = Path(os.environ.get("MODEL_ROOT", "/var/lib/threat_system/models"))
API_URL = os.environ.get(
    "MODEL_RELEASE_API_URL",
    "https://api.github.com/repos/malbuja10/monitor-threat-system/releases/latest",
)
PUBLIC_KEY = Path(os.environ.get(
    "MODEL_RELEASE_PUBLIC_KEY", "/etc/threat_system/model-release-public.pem"
))
ASSET_NAME = os.environ.get("MODEL_RELEASE_ASSET", "model-release.tar.gz")
USER_AGENT = "jocotoco-model-updater/1"


def request(url, headers=None, timeout=25):
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    request_headers.update(headers or {})
    return urllib.request.urlopen(urllib.request.Request(url, headers=request_headers), timeout=timeout)


def latest_release():
    with request(API_URL) as response:
        release = json.load(response)
    if release.get("draft") or release.get("prerelease"):
        raise ValueError("The latest GitHub release must be published and stable")
    tag = str(release.get("tag_name", ""))
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", tag):
        raise ValueError("Invalid release tag")
    assets = {asset.get("name"): asset for asset in release.get("assets", [])}
    asset = assets.get(ASSET_NAME)
    if not asset or not asset.get("browser_download_url"):
        raise ValueError(f"Release {tag} has no {ASSET_NAME} asset")
    size = int(asset.get("size", 0))
    if size <= 0:
        raise ValueError("Release asset has an invalid size")
    return tag, asset["browser_download_url"], size


def current_release_id():
    link = MODEL_ROOT / "current"
    try:
        manifest = json.loads((link.resolve() / "release.json").read_text())
        return str(manifest.get("release_id", ""))
    except (OSError, ValueError, TypeError):
        return ""


def download_resumable(url, destination, expected_size):
    destination.parent.mkdir(parents=True, exist_ok=True)
    offset = destination.stat().st_size if destination.exists() else 0
    if offset > expected_size:
        destination.unlink()
        offset = 0
    headers = {"Range": f"bytes={offset}-"} if offset else {}
    try:
        response = request(url, headers=headers, timeout=30)
    except urllib.error.HTTPError as exc:
        if offset and exc.code == 416 and offset == expected_size:
            return
        raise
    with response:
        append = offset > 0 and response.status == 206
        if append:
            content_range = response.headers.get("Content-Range", "")
            match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", content_range)
            if not match or int(match.group(1)) != offset or int(match.group(3)) != expected_size:
                raise ValueError("Server returned an invalid Content-Range for the resumed download")
        if offset and not append:
            offset = 0
        mode = "ab" if append else "wb"
        with destination.open(mode) as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                output.write(chunk)
                output.flush()
                if output.tell() > expected_size:
                    raise ValueError("Downloaded release exceeds its published size")
    if destination.stat().st_size != expected_size:
        raise ConnectionError("Release download is incomplete; it will resume next time")


def safe_extract(archive, destination):
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if not members or len(members) > 100000:
            raise ValueError("Release archive has an invalid number of entries")
        uncompressed_size = sum(member.size for member in members if member.isfile())
        available = shutil.disk_usage(destination.parent).free
        if uncompressed_size > available - 512 * 1024 * 1024:
            raise OSError("Not enough free disk space to extract release and preserve the safety reserve")
        for member in members:
            name = member.name.removeprefix("./")
            if name in ("", ".") and member.isdir():
                continue
            path = PurePosixPath(name)
            if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
                raise ValueError(f"Unsafe path in archive: {member.name}")
            if not (member.isdir() or member.isfile()):
                raise ValueError(f"Unsupported archive entry: {member.name}")
            target = destination.joinpath(*path.parts)
            if not target.resolve().is_relative_to(destination.resolve()):
                raise ValueError(f"Archive path escapes staging directory: {member.name}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                if source is None:
                    raise ValueError(f"Unreadable archive file: {member.name}")
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o644)


def verify_manifest_signature(release_dir):
    manifest = release_dir / "release.json"
    signature = release_dir / "release.json.sig"
    if not manifest.is_file() or not signature.is_file() or not PUBLIC_KEY.is_file():
        raise ValueError("release.json, release.json.sig, and the trusted public key are required")
    subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(PUBLIC_KEY),
         "-rawin", "-in", str(manifest), "-sigfile", str(signature)],
        check=True, stdout=subprocess.DEVNULL,
    )
    data = json.loads(manifest.read_text())
    if data.get("release_id") != release_dir.name:
        raise ValueError("Manifest release_id does not match its staged directory")
    return data


def main():
    if not PUBLIC_KEY.is_file():
        raise RuntimeError(f"Trusted model signing key is missing: {PUBLIC_KEY}")
    try:
        with socket.create_connection(("api.github.com", 443), timeout=3):
            pass
    except OSError:
        print("No internet connection; the next timer check will retry")
        return 0
    tag, url, size = latest_release()
    active = current_release_id()
    if active == tag:
        print(f"Model release {tag} is already active")
        return 0

    failed_marker = MODEL_ROOT / "failed_release"
    if failed_marker.is_file() and failed_marker.read_text().strip() == tag:
        print(f"Release {tag} previously failed; waiting for a newly published release")
        return 0

    downloads = MODEL_ROOT / "downloads"
    archive = downloads / f"{tag}.tar.gz.part"
    partial_size = archive.stat().st_size if archive.exists() else 0
    if partial_size > size:
        archive.unlink()
        partial_size = 0
    free = shutil.disk_usage(MODEL_ROOT.parent).free
    remaining_download = max(size - partial_size, 0)
    if free < (remaining_download + size + 512 * 1024 * 1024):
        raise OSError("Insufficient free disk space to stage this model release safely")
    print(f"Downloading model release {tag} ({size} bytes), resuming if needed")
    download_resumable(url, archive, size)

    releases = MODEL_ROOT / "releases"
    releases.mkdir(parents=True, exist_ok=True)
    final_dir = releases / tag
    try:
        if final_dir.exists():
            data = verify_manifest_signature(final_dir)
        else:
            with tempfile.TemporaryDirectory(prefix=f".{tag}-", dir=releases) as temporary:
                staged = Path(temporary) / tag
                safe_extract(archive, staged)
                data = verify_manifest_signature(staged)
                if data.get("release_id") != tag:
                    raise ValueError("GitHub release tag and signed manifest release_id do not match")
                os.replace(staged, final_dir)
    except (tarfile.TarError, ValueError, subprocess.CalledProcessError, FileNotFoundError) as error:
        failed_marker.write_text(tag + "\n")
        archive.unlink(missing_ok=True)
        raise ValueError(f"Release package rejected and will not be retried: {error}") from error
    archive.unlink(missing_ok=True)
    try:
        subprocess.run(["/bin/bash", str(Path(__file__).with_name("model_release.sh")), "activate", tag], check=True)
    except subprocess.CalledProcessError:
        failed_marker.write_text(tag + "\n")
        raise
    failed_marker.unlink(missing_ok=True)
    print(f"Model release {tag} activated")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"Model update not applied: {error}", file=sys.stderr)
        sys.exit(1)
