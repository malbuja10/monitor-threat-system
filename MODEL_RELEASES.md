# Remote model updates for field Raspberry Pis

The analyzer's detection program remains unchanged. Docker mounts the active
release at the file paths that `realtime_analyzer.py` already uses. A small
host-side `systemd` updater checks the configured GitHub Releases endpoint
every two minutes. When Starlink is online, it downloads the newest stable model
package; if connectivity stops, the partial download is kept and resumed at a
later check. A downloaded package is verified, staged, tested and activated.
The monitor container receives no Docker socket or host restart privileges.

## What a published release contains

Publish a GitHub Release whose tag exactly matches `release_id`, for example
`2026.10.1`. Attach one asset named `model-release.tar.gz`. Its top-level
contents must be:

```text
release.json
release.json.sig
threat_config.yaml
perch2/
models_assets/
```

The manifest identifies the release, model, version, architecture and classes,
and contains a SHA-256 hash for every model/configuration file. It does not hash
itself or `release.json.sig`. The signature is a detached OpenSSL Ed25519
signature of the exact bytes of `release.json`. The signed manifest authenticates
the hashes, so changing any packaged model file invalidates verification.

Example manifest (replace the hashes with real values):

```json
{
  "schema_version": 1,
  "release_id": "2026.10.1",
  "model_id": "jocotoco-threat-classifier",
  "model_version": "2.1.0",
  "architecture": "perch2_torch_classifier_v1",
  "classes": ["Pirotecnia", "Motosierra", "Motocicleta"],
  "files": {
    "perch2/saved_model.pb": "<64-character SHA-256>",
    "perch2/variables/variables.index": "<64-character SHA-256>",
    "models_assets/model_swa_perch.pth": "<64-character SHA-256>",
    "models_assets/label_encoder_perch2.pkl": "<64-character SHA-256>",
    "threat_config.yaml": "<64-character SHA-256>"
  }
}
```

Include every file under `perch2/` and all other artifacts in `files`. The
class list must exactly match the order in `label_encoder_perch2.pkl`. Do not
publish Git LFS pointer text in place of model files.

## Signing key setup (once per device)

Generate the Ed25519 key pair on a trusted release workstation, not on the
Raspberry Pi and not in a public repository:

```sh
openssl genpkey -algorithm ED25519 -out model-release-private.pem
openssl pkey -in model-release-private.pem -pubout -out model-release-public.pem
```

Keep `model-release-private.pem` secret and backed up securely. Copy only
`model-release-public.pem` to each Pi at:
`/etc/threat_system/model-release-public.pem`, with root ownership and
read-only permissions. For example:

```sh
sudo install -D -m 0644 model-release-public.pem \
  /etc/threat_system/model-release-public.pem
```

This public key is the device's trust anchor.

Before enabling automatic updates on a Pi, initialize the model directory and
start the existing Compose application once so Docker has the analyzer image:

```sh
sudo bash model_release.sh init
docker compose up -d
```

Then install the host updater and boot-recovery services:

```sh
sudo bash model_release.sh install-services
```

The updater uses the public GitHub Releases endpoint for this repository by
default. To use a different repository, set `MODEL_RELEASE_API_URL` when
running `install-services`; the endpoint must return a GitHub-compatible latest
stable release response containing the `model-release.tar.gz` asset.
Keep this project checkout at the same path after installing the services; if
you move it, run `install-services` again so systemd's paths are regenerated.

## Publishing each update

1. Prepare `perch2/`, `models_assets/`, and `threat_config.yaml` together.
2. Create `release.json` with the new tag/version, architecture, exact ordered
   classes, and SHA-256 hashes for every shipped file except the manifest and
   signature.
3. Sign the manifest. The signature file is binary:

   ```sh
   openssl pkeyutl -sign -inkey model-release-private.pem -rawin \
     -in release.json -out release.json.sig
   ```

4. Create `model-release.tar.gz` containing the five top-level entries listed
   above, then attach it to a stable GitHub Release whose tag equals
   `release_id`.

When a Pi next checks during a Starlink connectivity window, it resumes the
download if necessary. It stages the release without overwriting the active
model, verifies the signature, and invokes the analyzer's existing runtime to
check hashes, class order, configuration, model loading and a synthetic
Perch-to-classifier inference. Only then does it switch `current` and recreate
the analyzer. The old release is retained as `previous`. After a release passes
activation, the updater removes older release directories that are not
referenced by `current` or `previous`. It skips cleanup whenever an
activation-recovery marker exists, ignores non-release entries and symlinked
directories, and treats cleanup failures as warnings so an activated model
remains active. Thus the device normally retains the active model, one rollback
model, and any bundled baseline model used by the `current`/`previous` links;
older downloaded releases do not accumulate indefinitely.

## Rollback and recovery

Activation is accepted only if the analyzer emits its existing `Monitor
activo` message, stays running and emits no detected inference/startup error
during a short post-start health window. A host watchdog continues checking the
active model: it rolls back if the analyzer stops, logs a traceback, or records
three or more inference errors in the recent log window. After an automatic rollback,
the watchdog pauses to avoid repeatedly switching models; a later successful
model activation enables it again. A small on-disk marker records an
in-progress activation; the boot recovery service checks that marker after a
power interruption and keeps the new model only if it becomes healthy,
otherwise it restores the recorded old model.

Manual inspection and rollback remain available:

```sh
sudo bash model_release.sh status
sudo bash model_release.sh rollback
```

Updater and recovery logs can be checked with:

```sh
sudo journalctl -u threat-model-update.service
sudo journalctl -u threat-model-recovery.service
```

Do not manually delete the active or previous release directories. Keep enough
free storage for the active model, one previous model, and a staged download.
The updater refuses to start a download when its free-space safety check fails.

## Supported scope and field testing

- Automatic updates support the current `perch2_torch_classifier_v1` runtime.
  New classes can be added/removed by publishing the matching label encoder,
  weights and `threat_config.yaml` together. Different architectures require a
  reviewed change to the analyzer runtime; changing weights alone is not enough.
- `systemd` checks periodically, but actual downloads can happen only while the
  device has internet. Partial downloads persist across connectivity windows.
  The device does not update its operating system or analyzer source code.
- A signed release proves it came from whoever controls the private signing
  key. Protect that key and distribute the public key to devices through a
  trusted setup process. GitHub transport and file hashes alone are not a
  substitute for this signature.
- Synthetic inference and a short startup health window cannot prove long-term
  field performance. Test each release on the Raspberry Pi 5 for peak memory,
  disk capacity, thermal behavior, power consumption, audio input, and sustained
  inference. Keep the Starlink window long enough for reports and allow model
  downloads to resume over multiple windows.
