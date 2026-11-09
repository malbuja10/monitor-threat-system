# Provision a Raspberry Pi with Ansible

`ansible/playbooks/install_monitor.yml` now provisions a 64-bit Raspberry Pi
OS host, installs Docker, copies the runtime support files and the initial
Perch model bundle, writes a root-only `.env`, starts the two GHCR services,
and installs the software/model update timers and recovery services.

The initial model bundle is about 400 MB. The Ansible controller must have
downloaded the real Git LFS objects (`git lfs pull`) before provisioning; the
playbook checks file sizes so Git LFS pointer text is rejected.
The controller sends that initial bundle to each Raspberry Pi over Ansible/SSH.

## Values to provide

### Jocotoco API and Step CA trust

Before provisioning a device, place the **Jocotoco Root CA certificate**
issued for the API deployment at `monitor/certs/root_ca.crt` in this project
checkout. The Ansible playbook copies that file to each Raspberry Pi, and
Compose mounts it read-only into the monitor container. Do not use the older
`Forestry-PKI Root CA` file: it has a different fingerprint and will prevent
TLS verification against the Jocotoco API/Step CA.

Verify the certificate fingerprint against the value supplied by the server
administrator before deployment:

```sh
openssl x509 -in monitor/certs/root_ca.crt -noout -subject -fingerprint -sha256
```

The repository currently contains the older certificate, so replace it with
the verified Jocotoco Root CA before deploying. Do not disable TLS verification
to work around a mismatch.

The API repository's current deployment document lists this expected SHA-256
fingerprint (colon separators omitted):
`c77163bde598a9bdea25fb91c8544dad8c3269c05e7532c57ec91dae5c63fe91`.
Confirm with the server administrator that the deployed CA has not changed.

Set these variables in inventory/group variables or pass them securely from
Ansible Vault:

- `vault_factory_claim_secret`: factory enrollment secret. Keep it encrypted
  with Ansible Vault. The playbook accepts 16-128 alphanumeric, period,
  underscore, or hyphen characters.
- `jocotoco_threat_api_url`, `jocotoco_voltage_api_url`,
  `jocotoco_device_telemetry_api_url`, and
  `jocotoco_device_enrollment_url`: reachable HTTPS server endpoints. For the
  documented server, these use `https://dev.minkafab.com:8444/...`.
- `step_ca_url`: optional Step CA HTTPS URL; defaults to
  `https://dev.minkafab.com:8443`.
- `site_voltage_turn_off`: cutoff voltage calibrated for the installed battery
  and sensor. The playbook deliberately requires this value.
- Optional per-site settings: `site_timezone`, `site_reporting_times`,
  `site_time_antenna_power_on_minutes`, `site_antenna_rest_time_minutes`,
  `site_reporting_time_on_minutes`,
  `site_starlink_connection_timeout_seconds`, and
  `site_starlink_connection_check_interval_seconds`.
- Optional `jocotoco_device_config_api_url`: HTTPS endpoint for the separate
  remote-configuration API. Leave unset until that server is implemented and
  reachable; the agent will then remain installed but report that configuration
  updates are disabled.

The model public key must be on the Ansible controller. Set
`JOCOTOCO_MODEL_RELEASE_PUBLIC_KEY` to its path before running the playbook.
Copy only the public key; the private signing key must never be sent to a Pi.

On first provisioning, the playbook creates `/home/rpi/client/.env` with root
ownership and mode `0600`; it is not committed to this repository. On later
runs it preserves that file, including the image digests saved by software OTA.
Never put the real secret in a plain-text inventory file.

By default the playbook confirms `software-update.json` already exists on
GitHub before enabling the software OTA timer. To stage a device before the
first approved manifest exists, pass `--extra-vars enable_software_ota=false`;
software-image updates will remain disabled until the playbook is run again
after the manifest is published.

The playbook pulls GHCR images without logging in, so both image packages must
allow anonymous pulls. If you keep them private, a read-only GHCR credential
must be provisioned securely before this playbook can pull them.

## Run on one pilot first

From the `ansible` directory, after configuring the inventory and variables:

```sh
export JOCOTOCO_MODEL_RELEASE_PUBLIC_KEY=/path/to/model-release-public.pem
pipx run --spec ansible ansible-playbook -i ../rp.ini \
  playbooks/install_monitor.yml --limit sitio_01 \
  --ask-become-pass --ask-vault-pass
```

The voltage cutoff is safety-critical. Confirm it against the battery
chemistry, divider calibration and power-controller behavior before using this
playbook on field equipment. Verify the service logs and an actual threat/report
upload before removing `--limit sitio_01` for a larger group.

## Software fleet approval

GitHub Actions builds images on `main`, but it publishes
`software-update.json` only when the repository variable
`SOFTWARE_FLEET_DEPLOYMENT_ENABLED` is `true` and the
`software-production` environment is approved. Configure that environment with
required reviewers. Test the exact digest-pinned image pair on a pilot Pi
before approving the environment job; then the manifest makes the pair
available to the rest of the fleet.
