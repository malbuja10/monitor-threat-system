# Remote monitor configuration through the management API

This channel distributes only monitor operating settings: report times,
Starlink power windows, connection wait limits and the low-battery shutdown
threshold. It does not update model weights, monitor source code or Raspberry Pi
operating-system packages.

The Raspberry Pi client is implemented in `device_config_update_agent.py`.
The management API/server is not part of this repository and must implement
the contract below before the client can be enabled.

## Endpoints the server must provide

Both endpoints require HTTPS with mutual TLS. The server must validate device
certificates against the trusted Step CA root, identify each device from its
certificate, and never trust a device ID supplied in a request body.

### `GET /v1/devices/me/configuration`

The device polls this endpoint periodically. It sends
`X-Active-Config-Revision` and `X-Active-Config-Version` headers so the server
can record the configuration currently reported by that device.

- Return `204 No Content` when there is no newer assignment.
- Return `200 OK` with the configuration JSON itself when an assignment exists:

  ```json
  {
    "schema_version": 1,
    "config_revision": 12,
    "config_version": "field-settings-r12",
    "settings": {
      "timezone": "America/Guayaquil",
      "reporting_times": ["12:48", "14:00", "18:00"],
      "time_antenna_power_on_minutes": 10,
      "antenna_rest_time_minutes": 5,
      "reporting_time_on_minutes": 10,
      "voltage_turn_off": 11.8,
      "starlink_connection_timeout_seconds": 420,
      "starlink_connection_check_interval_seconds": 60
    }
  }
  ```

The device validates the JSON schema and parameter limits before applying it.
The server assigns configurations to devices or groups based on its assignment
records; the device does not choose its target.

### `POST /v1/devices/me/configuration/status`

The device reports state transitions here. The server should treat `status_id`
as an idempotency key and associate each record with the mTLS client identity.
Example request:

```json
{
  "status_id": "c2c6c3ba-0b98-47cf-85e1-f8058ad5ebf4",
  "config_revision": 12,
  "config_version": "field-settings-r12",
  "status": "applied",
  "active_config_revision": 12,
  "active_config_version": "field-settings-r12",
  "occurred_at": "2026-10-20T13:20:00+00:00",
  "detail": ""
}
```

Supported statuses are `deferred`, `applied`, `failed`, `rolled_back`, and
`rejected`. `rolled_back` means the prior configuration was restored and the
monitor passed its restart check; otherwise the device reports `failed`.
Return `200`, `201`, `202`, or `204` after recording the status. The Raspberry
Pi queues status reports locally while offline and retries them later; it
avoids repeatedly reporting the same deferred state.

The management application should show, per device, its certificate identity,
last-seen time, desired revision, active revision/version last reported by the
device, latest status, and failure detail. A rollout view should aggregate
applied, pending/deferred, failed, and rolled-back devices.

## Configuration document

```json
{
  "schema_version": 1,
  "config_revision": 1,
  "config_version": "field-settings-r1",
  "settings": {
    "timezone": "America/Guayaquil",
    "reporting_times": ["12:48", "14:00", "18:00"],
    "time_antenna_power_on_minutes": 10,
    "antenna_rest_time_minutes": 5,
    "reporting_time_on_minutes": 10,
    "voltage_turn_off": 11.8,
    "starlink_connection_timeout_seconds": 420,
    "starlink_connection_check_interval_seconds": 60
  }
}
```

Every setting is required. Report times are unique 24-hour `HH:MM` values.
Accepted ranges are: power windows/rest up to 1440 minutes, connection timeout
10–7200 seconds, check interval 1–600 seconds and no longer than the timeout,
and voltage 1–60 V. Validate the voltage threshold against the battery
chemistry and sensor calibration before deployment.

`config_revision` must increase for every new assignment to a device. To revert
to earlier values, publish them under a newer revision. This prevents an old
response from silently replacing newer settings.

## Client behavior and authentication

The host agent uses each Pi's existing certificate and private key from
`/var/lib/threat_system/certs/<device-id>.crt` and `.key`, and verifies the API
server using `monitor/certs/root_ca.crt`. mTLS authenticates both peers and
protects the configuration and status messages in transit. No detached
Ed25519 signature is used for this configuration channel. The API must
authorize device identities and restrict/audit who can change assignments.

The agent checks periodically but does not turn on Starlink. Offline, it keeps
the active configuration and retries later. It applies updates only after the
monitor records Starlink's commanded state as off; that is not independent
hardware confirmation. The agent atomically writes the file, recreates only
the monitor container, and checks that it remains running for 35 seconds. On
failure it restores the prior configuration and attempts to restart the
monitor. The analyzer is not restarted.

Status events are saved at
`/var/lib/threat_system/device_config_status_queue.json` until the API accepts
them. The last reported state is remembered to suppress duplicate deferred
events.

## Install on a device

After deploying the updated project and rebuilding the monitor image once,
install or refresh the systemd services with the configuration API URL:

```sh
sudo env DEVICE_CONFIG_API_URL='https://<API_HOST>:8444/v1/devices/me/configuration' \
  bash model_release.sh install-services
```

The installer enables `threat-device-config-update.timer`. Future setting
changes do not require SSH: assign the new configuration in the backend and
devices fetch it during their next connected check. The API URL is provisioned
once per device and can be included in fleet provisioning.

For diagnostics:

```sh
sudo journalctl -u threat-device-config-update.service
sudo systemctl status threat-device-config-update.timer
sudo cat /var/lib/threat_system/device_config.json
sudo cat /var/lib/threat_system/device_config_status_queue.json
```

## Pilot sequence

1. Have the backend developer implement the two endpoints, per-device
   assignments, status storage and fleet view above.
2. Deploy the Raspberry Pi client and configure the API URL on one pilot.
3. Assign a configuration and confirm the API shows `applied` and the active
   revision.
4. Test invalid settings, offline status queuing, deferral and rollback.
5. Expand to a few devices, then the whole fleet once reporting is reliable.

This repository contains only the Raspberry Pi client. It does not implement
the server database, API, dashboard, or rollout controls. mTLS protects traffic
and authenticates the peers, but does not protect against a compromised
management server or an authorized operator publishing unsafe settings; keep
API access restricted and audited, and retain device-side validation.
