import os
import json
import socket
import sqlite3
import logging
import requests
from contextlib import closing
import config
import certificate
from logging_config import get_logger
import queue
from datetime import datetime
import time
import subprocess

logger = get_logger(__name__)
pending_sync_queue = queue.Queue()
TELEMETRY_BATCH_MAX_RECORDS = 500
TELEMETRY_BATCH_MAX_BYTES = 800 * 1024

def is_connected():
    try:
        with socket.create_connection(('8.8.8.8', 53), timeout=5):
            return True
    except (socket.timeout, socket.error):
        return False

def sync_threats_mtls():
    with sqlite3.connect(config.LOCAL_DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        with closing(conn.cursor()) as cur:
            last_id = 0
            max_id = cur.execute('SELECT COALESCE(MAX(id), 0) FROM threat_detections').fetchone()[0]
            while last_id < max_id:
                cur.execute(
                    'SELECT * FROM threat_detections WHERE id > ? AND id <= ? ORDER BY id ASC LIMIT 30',
                    (last_id, max_id)
                )
                records = cur.fetchall()
                if not records:
                    break
                last_id = records[-1]['id']

                for reg in records:
                    reg_data = dict(reg)
                    reg_data.pop('id', None)
                    payload = {'data': json.dumps(reg_data)}
                    audio_handle = None

                    try:
                        if not reg['audio_path']:
                            raise FileNotFoundError("Event has no audio path; retained for recovery")
                        audio_handle = open(reg['audio_path'], 'rb')
                        files = {'audio': (os.path.basename(reg['audio_path']), audio_handle, 'audio/wav')}
                        res = requests.post(config.API_URL, data=payload, files=files, cert=config.CERT_FILES, verify=config.CA_CERT, timeout=15)
                        if res.status_code in (200, 201):
                            cur.execute('DELETE FROM threat_detections WHERE id = ?', (reg['id'],))
                            conn.commit()
                            audio_handle.close()
                            audio_handle = None
                            try:
                                os.remove(reg['audio_path'])
                                logger.info(f"[NETWORK] Local audio file deleted: {reg['audio_path']}")
                            except OSError as ex:
                                logger.error(f"[NETWORK] Failed to delete audio file {reg['audio_path']}: {ex}")
                        else:
                            logger.warning(f"[NETWORK] Upload rejected for event {reg['event_id']}: HTTP {res.status_code}; retained for retry")
                    except Exception as e:
                        logger.error(f"[NETWORK] Sync failed for record {reg['id']}: {e}")
                    finally:
                        if audio_handle:
                            audio_handle.close()


def _sync_batched_mtls(table_name: str, api_url: str, label: str, build_record):
    """Send bounded JSON batches and delete only records accepted by the API."""
    while True:
        with sqlite3.connect(config.LOCAL_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            with closing(conn.cursor()) as cur:
                rows = cur.execute(
                    f'SELECT * FROM {table_name} ORDER BY id ASC LIMIT ?',
                    (TELEMETRY_BATCH_MAX_RECORDS,),
                ).fetchall()
                if not rows:
                    return

                records = []
                record_ids = []
                body = None
                for row in rows:
                    candidate_records = records + [build_record(row)]
                    candidate_body = json.dumps(
                        {label: candidate_records}, separators=(',', ':'),
                    ).encode('utf-8')
                    if len(candidate_body) > TELEMETRY_BATCH_MAX_BYTES:
                        if not records:
                            logger.error(
                                '[NETWORK] A single %s record exceeds the %d-byte request limit; '
                                'record %s retained.',
                                label, TELEMETRY_BATCH_MAX_BYTES, row['id'],
                            )
                            return
                        break
                    records = candidate_records
                    record_ids.append(row['id'])
                    body = candidate_body

                try:
                    response = requests.post(
                        api_url,
                        data=body,
                        headers={'Content-Type': 'application/json'},
                        cert=config.CERT_FILES,
                        verify=config.CA_CERT,
                        timeout=10,
                    )
                except requests.RequestException as exc:
                    logger.error(
                        '[NETWORK] %s sync failed; retained %d records for retry: %s',
                        label, len(records), exc,
                    )
                    return

                if response.status_code not in (200, 201):
                    logger.warning(
                        '[NETWORK] %s upload rejected: HTTP %s; retained %d records for retry',
                        label, response.status_code, len(records),
                    )
                    return

                placeholders = ','.join(['?'] * len(record_ids))
                cur.execute(
                    f'DELETE FROM {table_name} WHERE id IN ({placeholders})',
                    record_ids,
                )
                conn.commit()
                logger.info('[NETWORK] Successfully synced %d %s records.', len(records), label)


def _sync_telemetry_mtls(table_name: str, api_url: str, label: str):
    def build_record(row):
        return {
            'timestamp': row['timestamp'],
            'cpu_temp': row['cpu_temp'],
            'cpu_usage_pct': row['cpu_usage_pct'],
            'ram_usage_pct': row['ram_usage_pct'],
            'disk_free_gb': row['disk_free_gb'],
            'disk_usage_pct': row['disk_usage_pct'],
            'uptime_hours': row['uptime_hours'],
            'device_id': config.DEVICE_ID,
        }

    _sync_batched_mtls(table_name, api_url, label, build_record)


def _sync_voltage_mtls(table_name: str, api_url: str, label: str):
    def build_record(row):
        return {
            'timestamp': row['timestamp'],
            'value': row['value'],
            'device_id': config.DEVICE_ID,
        }

    _sync_batched_mtls(table_name, api_url, label, build_record)


def sync_voltage_mtls():
    _sync_voltage_mtls('voltage', config.VOLTAGE_API_URL, 'voltage')

def sync_telemetry_mtls():
    _sync_telemetry_mtls('device_telemetry', config.TEMP_API_URL, 'device_telemetry')

def ensure_device_certificate():
    """Retry first-time enrollment only after the network is actually online."""
    if all(os.path.isfile(path) for path in config.CERT_FILES):
        return True
    logger.info('[STEP-CA] Device identity is missing; retrying enrollment over the active connection.')
    return certificate.auto_register_device()

def sync_worker_loop():
    last_report = None
    while True:
        now = datetime.now()
        current_time = now.strftime('%H:%M')

        if current_time in config.REPORTING_TIMES and last_report != current_time:
            logger.info(f'[SYNC_WORKER] Time for reporting ({current_time}).')
            connected, elapsed =  waiting_antenna_connection()
            if connected:
                if ensure_device_certificate():
                    check_and_renew_certificate()
                    sync_threats_mtls()
                    sync_voltage_mtls()
                    sync_telemetry_mtls()
                    last_report = current_time
                else:
                    logger.error('[STEP-CA] Enrollment failed; queued data is retained for retry.')

        try:
            item = pending_sync_queue.get(timeout=30)
            trigger_type = item.get('trigger', 'threat') if isinstance(item, dict) else 'threat'

            logger.info(f'[SYNC_WORKER] Sync triggered ({trigger_type}). Polling Starlink WAN connection...')

            connected, elapsed = waiting_antenna_connection()
            if connected:
                logger.info(f'[SYNC_WORKER] Starlink online ({elapsed}s). Syncing database via mTLS...')
                if ensure_device_certificate():
                    if trigger_type == 'scheduled_report':
                        logger.info('[SYNC_WORKER] Running scheduled certificate check/renewal....')
                        check_and_renew_certificate()
                    sync_threats_mtls()
                    sync_voltage_mtls()
                    sync_telemetry_mtls()
                else:
                    logger.error('[STEP-CA] Enrollment failed; queued data is retained for retry.')
            else:
                logger.error("[SYNC_WORKER] Starlink link connection timed out.")

        # Drain extra queue items queued while waiting so we don't repeat the loop redundantly
            while not pending_sync_queue.empty():
                pending_sync_queue.get_nowait()
                pending_sync_queue.task_done()

            pending_sync_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f'[SYNC_WORKER] Error syncing: {e}')
            time.sleep(5)

def check_and_renew_certificate():
    cmd = [
        'step', 'ca', 'renew', '--force',
        '--ca-url', config.STEP_CA_URL,
        '--root', config.CA_CERT,
        config.CERT_FILES[0], config.CERT_FILES[1],
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        logger.info('[STEP CA] Certificate verified and updated successfully.')
        return True
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or e.stdout or '').strip()
        logger.warning(
            '[STEP CA] Certificate renewal failed (exit %s): %s',
            e.returncode,
            detail or 'step returned no diagnostic output.',
        )
        return False

def waiting_antenna_connection():
    max_wait_sec = config.STARLINK_CONNECTION_TIMEOUT_SECONDS
    check_interval = config.STARLINK_CONNECTION_CHECK_INTERVAL_SECONDS
    elapsed = 0
    #connected = False

    while elapsed < max_wait_sec:
        if is_connected():
            return True, elapsed
        time.sleep(check_interval)  # 0% CPU consumption while sleeping
        elapsed += check_interval
    return False, elapsed
