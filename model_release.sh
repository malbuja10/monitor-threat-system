#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_ROOT="${MODEL_ROOT:-/var/lib/threat_system/models}"
MODEL_RELEASE_API_URL="${MODEL_RELEASE_API_URL:-https://api.github.com/repos/malbuja10/monitor-threat-system/releases/latest}"
MODEL_RELEASE_PUBLIC_KEY="${MODEL_RELEASE_PUBLIC_KEY:-/etc/threat_system/model-release-public.pem}"
export MODEL_ROOT
CURRENT_LINK="$MODEL_ROOT/current"
PREVIOUS_LINK="$MODEL_ROOT/previous"
PENDING_MARKER="$MODEL_ROOT/activation.pending"
WATCHDOG_DISABLED="$MODEL_ROOT/watchdog.disabled"
READY_TEXT="Monitor activo"
READY_TIMEOUT_SECONDS="${MODEL_READY_TIMEOUT_SECONDS:-240}"
HEALTH_SETTLE_SECONDS="${MODEL_HEALTH_SETTLE_SECONDS:-30}"

compose() {
    docker compose --project-directory "$PROJECT_DIR" -f "$PROJECT_DIR/docker-compose.yml" "$@"
}

atomic_link() {
    local link_path="$1" target="$2"
    local temp_path="${link_path}.tmp.$$"
    rm -f -- "$temp_path"
    ln -s -- "$target" "$temp_path"
    mv -Tf -- "$temp_path" "$link_path"
}

record_pending_activation() {
    local target="$1" temporary="$PENDING_MARKER.tmp.$$"
    printf '%s\n' "$target" > "$temporary"
    mv -f -- "$temporary" "$PENDING_MARKER"
}

wait_until_ready() {
    local started_at="$1"
    local elapsed=0
    while (( elapsed < READY_TIMEOUT_SECONDS )); do
        if compose logs --since "$started_at" --no-color analyzer 2>/dev/null | grep -Fq "$READY_TEXT"; then
            return 0
        fi
        sleep 3
        elapsed=$((elapsed + 3))
    done
    compose logs --tail 100 --no-color analyzer >&2 || true
    return 1
}

wait_until_healthy() {
    local started_at="$1"
    local elapsed=0 container_id
    while (( elapsed < HEALTH_SETTLE_SECONDS )); do
        container_id="$(compose ps -q analyzer | head -n 1)"
        if [[ -z "$container_id" ]] || [[ "$(docker inspect --format '{{.State.Running}}' "$container_id" 2>/dev/null || true)" != "true" ]]; then
            echo "Analyzer container stopped during the post-start health window." >&2
            return 1
        fi
        if compose logs --since "$started_at" --no-color analyzer 2>/dev/null | grep -Eq '(^|[[:space:]])(Error:|ERROR:|Traceback)'; then
            echo "Analyzer emitted an error during the post-start health window." >&2
            return 1
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
}

restart_analyzer() {
    local started_at
    started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    compose up -d --force-recreate analyzer
    wait_until_ready "$started_at" || return 1
    wait_until_healthy "$started_at"
}

swap_current_previous() {
    [[ -L "$CURRENT_LINK" && -L "$PREVIOUS_LINK" ]] || {
        echo "Both current and previous model links must exist to roll back." >&2
        return 1
    }
    local current_target previous_target
    current_target="$(readlink "$CURRENT_LINK")"
    previous_target="$(readlink "$PREVIOUS_LINK")"
    atomic_link "$CURRENT_LINK" "$previous_target"
    atomic_link "$PREVIOUS_LINK" "$current_target"
}

usage() {
    cat <<EOF
Usage:
  $0 init
  $0 activate RELEASE_ID
  $0 rollback
  $0 recover
  $0 watchdog
  $0 install-services
  $0 status

MODEL_ROOT defaults to $MODEL_ROOT. Releases must already be unpacked under
\$MODEL_ROOT/releases/RELEASE_ID and contain release.json plus the model files.
EOF
}

command="${1:-}"
case "$command" in
    init)
        mkdir -p "$MODEL_ROOT/releases"
        if [[ -L "$CURRENT_LINK" ]]; then
            echo "Current model link already exists: $(readlink -f "$CURRENT_LINK")"
        elif [[ -e "$CURRENT_LINK" ]]; then
            echo "Current path exists but is not a symlink: $CURRENT_LINK" >&2
            exit 1
        else
            atomic_link "$CURRENT_LINK" "$PROJECT_DIR/analyzer"
            echo "Initialized current model to the analyzer's bundled files."
        fi
        ;;

    install-services)
        [[ "$EUID" -eq 0 ]] || { echo "Run install-services with sudo." >&2; exit 1; }
        command -v systemctl >/dev/null || { echo "systemd is required." >&2; exit 1; }
        [[ -r "$MODEL_RELEASE_PUBLIC_KEY" ]] || { echo "Install the trusted signing key at $MODEL_RELEASE_PUBLIC_KEY first." >&2; exit 1; }
        openssl pkey -pubin -in "$MODEL_RELEASE_PUBLIC_KEY" -noout >/dev/null || { echo "Invalid model-release public key." >&2; exit 1; }
        install -d -m 0755 /etc/systemd/system
        cat > /etc/systemd/system/threat-model-update.service <<EOF
[Unit]
Description=Check for and install a signed analyzer model release
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
Environment=MODEL_ROOT=$MODEL_ROOT
Environment=MODEL_RELEASE_API_URL=$MODEL_RELEASE_API_URL
Environment=MODEL_RELEASE_PUBLIC_KEY=$MODEL_RELEASE_PUBLIC_KEY
ExecStart=/usr/bin/python3 "$PROJECT_DIR/model_update_agent.py"
TimeoutStartSec=20min
EOF
        cat > /etc/systemd/system/threat-model-update.timer <<'EOF'
[Unit]
Description=Check for model updates during available network windows

[Timer]
OnBootSec=90s
OnUnitInactiveSec=2min
AccuracySec=15s
Unit=threat-model-update.service

[Install]
WantedBy=timers.target
EOF
        cat > /etc/systemd/system/threat-model-recovery.service <<EOF
[Unit]
Description=Recover an interrupted analyzer model activation
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
Environment=MODEL_ROOT=$MODEL_ROOT
ExecStart=/bin/bash "$PROJECT_DIR/model_release.sh" recover
TimeoutStartSec=6min

[Install]
WantedBy=multi-user.target
EOF
        cat > /etc/systemd/system/threat-model-watchdog.service <<EOF
[Unit]
Description=Watch analyzer health and roll back a failing model
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
Environment=MODEL_ROOT=$MODEL_ROOT
ExecStart=/bin/bash "$PROJECT_DIR/model_release.sh" watchdog
TimeoutStartSec=6min
EOF
        cat > /etc/systemd/system/threat-model-watchdog.timer <<'EOF'
[Unit]
Description=Periodically check active analyzer model health

[Timer]
OnBootSec=2min
OnUnitInactiveSec=1min
AccuracySec=15s
Unit=threat-model-watchdog.service

[Install]
WantedBy=timers.target
EOF
        systemctl daemon-reload
        systemctl enable --now threat-model-update.timer
        systemctl enable --now threat-model-watchdog.timer
        systemctl enable threat-model-recovery.service
        echo "Installed the updater, health watchdog, and boot recovery services."
        ;;

    activate)
        release_id="${2:-}"
        [[ "$release_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$ ]] || { usage >&2; exit 2; }
        [[ -L "$CURRENT_LINK" ]] || { echo "Run '$0 init' first." >&2; exit 1; }
        candidate="$MODEL_ROOT/releases/$release_id"
        [[ -d "$candidate" && -f "$candidate/release.json" ]] || { echo "Release not found: $candidate" >&2; exit 1; }
        [[ -f "$candidate/release.json.sig" && -r "$MODEL_RELEASE_PUBLIC_KEY" ]] || {
            echo "A detached signature and trusted public key are required for activation." >&2
            exit 1
        }
        openssl pkeyutl -verify -pubin -inkey "$MODEL_RELEASE_PUBLIC_KEY" -rawin \
            -in "$candidate/release.json" -sigfile "$candidate/release.json.sig" >/dev/null || {
            echo "Release manifest signature verification failed." >&2
            exit 1
        }

        old_target="$(readlink "$CURRENT_LINK")"
        container_id="$(compose ps -a -q analyzer | head -n 1)"
        [[ -n "$container_id" ]] || { echo "Start the analyzer service once before activating a release." >&2; exit 1; }
        image_id="$(docker inspect --format '{{.Image}}' "$container_id")"

        # Stop the old model first so validation does not require both models in RAM.
        compose stop analyzer
        if ! docker run --rm --network none \
            -v "$candidate:/candidate:ro" \
            -v "$PROJECT_DIR/analyzer/validate_model_bundle.py:/app/validate_model_bundle.py:ro" \
            --entrypoint python3 "$image_id" \
            /app/validate_model_bundle.py /candidate/release.json "$release_id"; then
            echo "Bundle validation failed; keeping the current release." >&2
            if ! restart_analyzer; then
                echo "Previous analyzer did not reach ready state. Inspect container logs." >&2
            fi
            exit 1
        fi

        record_pending_activation "$old_target"
        atomic_link "$PREVIOUS_LINK" "$old_target"
        atomic_link "$CURRENT_LINK" "$candidate"
        if restart_analyzer; then
            rm -f -- "$WATCHDOG_DISABLED"
            rm -f -- "$PENDING_MARKER"
            echo "Activated model release $release_id. Previous release retained for rollback."
        else
            echo "New release did not reach the analyzer-ready state; restoring previous model." >&2
            swap_current_previous
            if ! restart_analyzer; then
                echo "Rollback selected, but the previous analyzer did not reach ready state. Inspect container logs." >&2
            fi
            rm -f -- "$PENDING_MARKER"
            exit 1
        fi
        ;;

    rollback)
        [[ -L "$CURRENT_LINK" && -L "$PREVIOUS_LINK" ]] || { echo "Both current and previous model links must exist to roll back." >&2; exit 1; }
        rollback_target="$(readlink "$CURRENT_LINK")"
        record_pending_activation "$rollback_target"
        swap_current_previous
        if restart_analyzer; then
            rm -f -- "$PENDING_MARKER"
            echo "Rolled back to $(readlink -f "$CURRENT_LINK")."
        else
            echo "Selected previous release did not become ready; restoring the original active release." >&2
            atomic_link "$CURRENT_LINK" "$rollback_target"
            if ! restart_analyzer; then
                echo "Original active release also failed; inspect analyzer logs." >&2
            fi
            rm -f -- "$PENDING_MARKER"
            exit 1
        fi
        ;;

    recover)
        [[ -f "$PENDING_MARKER" ]] || { echo "No interrupted activation to recover."; exit 0; }
        old_target="$(<"$PENDING_MARKER")"
        [[ -d "$old_target" ]] || { echo "Recorded previous model is missing: $old_target" >&2; exit 1; }
        if restart_analyzer; then
            rm -f -- "$PENDING_MARKER"
            echo "Interrupted activation recovered; current model is ready."
        else
            echo "Current model did not become ready after interruption; restoring previous model." >&2
            atomic_link "$CURRENT_LINK" "$old_target"
            if [[ -L "$PREVIOUS_LINK" ]]; then atomic_link "$PREVIOUS_LINK" "$(readlink "$PREVIOUS_LINK")"; fi
            if ! restart_analyzer; then
                echo "Previous model also failed to start; inspect analyzer logs." >&2
                exit 1
            fi
            rm -f -- "$PENDING_MARKER"
        fi
        ;;

    watchdog)
        [[ -e "$PENDING_MARKER" || -e "$WATCHDOG_DISABLED" ]] && exit 0
        [[ -L "$CURRENT_LINK" ]] || exit 0
        active="$(readlink -f "$CURRENT_LINK")"
        [[ -f "$active/release.json" ]] || exit 0
        container_id="$(compose ps -q analyzer | head -n 1)"
        running="false"
        if [[ -n "$container_id" ]]; then
            running="$(docker inspect --format '{{.State.Running}}' "$container_id" 2>/dev/null || true)"
        fi
        logs="$(compose logs --since 3m --no-color analyzer 2>/dev/null || true)"
        error_count="$(printf '%s\n' "$logs" | grep -Ec '(^|[[:space:]])Error:' || true)"
        if [[ "$running" != "true" ]] || [[ "$logs" == *Traceback* ]] || (( ${error_count:-0} >= 3 )); then
            touch "$WATCHDOG_DISABLED"
            echo "Active model failed its runtime health check; rolling back." >&2
            "$PROJECT_DIR/model_release.sh" rollback
        fi
        ;;

    status)
        if [[ -L "$CURRENT_LINK" ]]; then
            active="$(readlink -f "$CURRENT_LINK")"
            if [[ -f "$active/release.json" ]]; then
                python3 - "$active/release.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    data = json.load(source)
print(json.dumps({key: data.get(key) for key in ("model_id", "model_version", "release_id", "architecture", "classes")}, indent=2))
PY
            else
                echo "Active model: bundled files in $active"
            fi
        else
            echo "No active model link. Run '$0 init' before starting the analyzer." >&2
            exit 1
        fi
        ;;

    *)
        usage >&2
        exit 2
        ;;
esac
