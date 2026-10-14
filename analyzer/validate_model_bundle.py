"""Validate a staged model using the same runtime libraries as the analyzer."""
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath

import joblib
import numpy as np
import tensorflow as tf
import tensorflow_hub as hub
import torch
import yaml

from realtime_analyzer import NeuralNetwork


ARCHITECTURE = "perch2_torch_classifier_v1"
REQUIRED_FILES = {
    "perch2/saved_model.pb",
    "perch2/variables/variables.index",
    "models_assets/model_swa_perch.pth",
    "models_assets/label_encoder_perch2.pkl",
    "threat_config.yaml",
}


def main(manifest_path, expected_release_id=None):
    release_dir = Path(manifest_path).resolve().parent
    manifest = json.loads(Path(manifest_path).read_text())
    if manifest.get("schema_version") != 1:
        raise ValueError("Unsupported release manifest schema_version")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", str(manifest.get("release_id", ""))):
        raise ValueError("Invalid release_id")
    if expected_release_id and manifest["release_id"] != expected_release_id:
        raise ValueError("release.json release_id does not match the requested release")
    if manifest.get("architecture") != ARCHITECTURE:
        raise ValueError(f"Unsupported architecture: {manifest.get('architecture')}")
    if not manifest.get("release_id") or not manifest.get("model_id") or not manifest.get("model_version"):
        raise ValueError("release_id, model_id, and model_version are required")

    files = manifest.get("files")
    if not isinstance(files, dict) or not REQUIRED_FILES.issubset(files):
        raise ValueError("release.json must provide SHA-256 hashes for every required artifact")
    actual_files = {
        path.relative_to(release_dir).as_posix()
        for path in release_dir.rglob("*")
        if path.is_file() and path.name not in {"release.json", "release.json.sig"}
    }
    if actual_files != set(files):
        raise ValueError("The files listed in release.json must match all files in the release bundle")
    for relative, expected_hash in files.items():
        if not re.fullmatch(r"[a-fA-F0-9]{64}", str(expected_hash)):
            raise ValueError(f"Invalid SHA-256 value for {relative}")
        relative_path = PurePosixPath(relative)
        if relative_path.is_absolute() or any(part in ("", ".", "..") for part in relative_path.parts):
            raise ValueError(f"Unsafe file path in release.json: {relative}")
        artifact = release_dir.joinpath(*relative_path.parts)
        if artifact.is_symlink() or not artifact.resolve().is_relative_to(release_dir) or not artifact.is_file() or artifact.stat().st_size == 0:
            raise ValueError(f"Missing or empty release file: {relative}")
        hasher = hashlib.sha256()
        with artifact.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                hasher.update(chunk)
        digest = hasher.hexdigest()
        if digest.lower() != str(expected_hash).lower():
            raise ValueError(f"SHA-256 mismatch for {relative}")

    encoder = joblib.load(release_dir / "models_assets/label_encoder_perch2.pkl")
    labels = [str(label) for label in encoder.classes_]
    if labels != manifest.get("classes"):
        raise ValueError("Manifest classes do not match the classifier label encoder")

    perch = hub.load(str(release_dir / "perch2"))
    if "serving_default" not in perch.signatures:
        raise ValueError("Perch model is missing the serving_default signature")
    classifier = NeuralNetwork(input_dim=1536, num_classes=len(labels), n=256)
    state = torch.load(release_dir / "models_assets/model_swa_perch.pth", map_location="cpu")
    classifier.load_state_dict(state)
    classifier.eval()
    # Exercise both model components together before replacing the active bundle.
    audio = np.zeros((1, 160000), dtype=np.float32)
    embedding = perch.signatures["serving_default"](
        inputs=tf.constant(audio)
    )["embedding"].numpy()
    if embedding.shape != (1, 1536) or not np.isfinite(embedding).all():
        raise ValueError(f"Unexpected Perch embedding output: {embedding.shape}")
    with torch.no_grad():
        logits = classifier(torch.from_numpy(embedding).float())
        probabilities = torch.softmax(logits, dim=1)
    if tuple(logits.shape) != (1, len(labels)) or not torch.isfinite(probabilities).all():
        raise ValueError("Classifier failed the synthetic inference check")

    config = yaml.safe_load((release_dir / "threat_config.yaml").read_text())
    if not isinstance(config, dict) or not isinstance(config.get("threats"), dict):
        raise ValueError("threat_config.yaml must contain a threats mapping")
    for label, settings in config["threats"].items():
        if label not in labels or not isinstance(settings, dict):
            raise ValueError(f"Invalid threat configuration entry: {label}")
        threshold = settings.get("threshold")
        streak = settings.get("min_streak")
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not 0 <= threshold <= 1:
            raise ValueError(f"Invalid threshold for {label}")
        if isinstance(streak, bool) or not isinstance(streak, int) or streak < 1:
            raise ValueError(f"Invalid min_streak for {label}")

    print(json.dumps({"state": "validated", "release_id": manifest["release_id"], "model_id": manifest["model_id"], "model_version": manifest["model_version"], "classes": labels}))


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        raise SystemExit("Usage: validate_model_bundle.py /path/to/release.json [expected_release_id]")
    main(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else None)
