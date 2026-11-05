# Monitor and analyzer software OTA

This software updater is separate from the signed model OTA. Model files are
still managed by `model_update_agent.py` and `model_release.sh`; this updater
only changes the monitor and analyzer Docker images.

## Image publishing

GitHub Actions first runs the unit tests and basic Python/Bash/Compose checks,
then builds both services for `linux/arm64` on pushes to `main` and
`codex-GPT`, and on version tags beginning with `v`. Branch builds receive an
immutable commit tag (`sha-<full-commit>`); the default branch also publishes
`latest`. Version tags publish the matching version and commit tags. A model
release does not trigger the software workflow.

For a successful build on `main`, Actions collects the monitor and analyzer
digests. The fleet manifest job runs only when the repository variable
`SOFTWARE_FLEET_DEPLOYMENT_ENABLED` is set to `true`, and it uses the GitHub
Environment `software-production`. Configure that environment with required
reviewers. The job waits for approval before it generates and commits
`software-update.json` to `main`. You do not copy or type the digests yourself.
The Raspberry Pis poll that JSON and install the exact image versions named by
those digests. Builds from `codex-GPT` and version tags do not change the fleet
manifest. A stale `main` build is skipped if another commit reaches `main`
before the build finishes.

Before enabling fleet updates, create the `software-production` environment and
configure its required reviewers in GitHub repository settings. Then set the
repository Actions variable `SOFTWARE_FLEET_DEPLOYMENT_ENABLED=true`. Without
that variable the image builds can still run, but the manifest job is skipped.
After a build reaches the environment approval, test those exact digest-pinned
images on the pilot device; approve the environment job only after the pilot
passes.

The generated manifest has this shape (the values are filled by Actions):

```json
{
  "schema_version": 1,
  "release_id": "software-<commit-id>",
  "source_commit": "<full-git-commit>",
  "images": {
    "monitor": "ghcr.io/malbuja10/monitor-threat-system/monitor@sha256:<exact-image-digest>",
    "analyzer": "ghcr.io/malbuja10/monitor-threat-system/analyzer@sha256:<exact-image-digest>"
  }
}
```

The approved manifest is the deployment signal. The workflow's bot commit
requires GitHub Actions to have write access to repository contents and
permission under any `main` branch protection rules. Restrict who can approve
the GitHub Environment and who can push changes to `main`.

The Pi agent downloads this public JSON over HTTPS, validates that both image
references are the expected GHCR repositories pinned by digest, pulls both
images before replacing the running containers, and waits for the monitor and
analyzer to stay running and for the analyzer startup marker. If the check
fails, it restores the previous Compose image references and recreates both
services. A failed release ID is not retried until the manifest target changes.
Before its first software update, the agent resolves the digests of the images
already running and saves those immutable references in `.env`; if it cannot
identify both existing GHCR images, it refuses to update rather than attempt an
ambiguous rollback.

## Install the device updater

Ansible should copy `software_update_agent.py` to
`/usr/local/lib/threat_system/`, install the supplied systemd service and timer,
run `systemctl daemon-reload`, and enable/start `threat-software-update.timer`.
The timer checks every two minutes and requires no always-on connection. When
the manifest host is unreachable, the agent exits normally and tries again on
the next timer event. An interrupted image pull is retried on a later check;
already downloaded layers remain cached by Docker.

## Operational limits

- This process updates container images, not Raspberry Pi OS, firmware, or
  model artifacts.
- Health validation is a startup/liveness check, not a semantic accuracy test.
- Updating images needs enough disk space to retain the old images for rollback.
- GHCR images must be readable anonymously by the devices, or a separately
  provisioned read-only registry credential is required.
- HTTPS and digest pinning protect transport/integrity but do not replace
  control over who can push code to `main`, because a successful `main` build
  automatically authorizes a fleet update.
