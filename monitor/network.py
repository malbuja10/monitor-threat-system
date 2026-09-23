import os
import json
import socket
import sqlite3
import logging
import requests
from contextlib import closing
import config
from logging_config import get_logger
import queue
from datetime import datetime
import time
import subprocess

logger = get_logger(__name__)
pending_sync_queue = queue.Queue()

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
            cur.execute('SELECT id, device_id, threat_type, confidence_score, audio_path, timestamp FROM threat_detections ORDER BY id ASC LIMIT 30')
            records = cur.fetchall()

            for reg in records:
                reg_data = dict(reg)
                reg_id = reg_data.pop('id', None)
                payload = {'data': json.dumps(reg_data)}
                files = {}
                audio_handle = None

                if reg['audio_path'] and os.path.exists(reg['audio_path']):
                    audio_handle = open(reg['audio_path'], 'rb')
                    files = {'audio': (os.path.basename(reg['audio_path']), audio_handle, 'audio/wav')}
                try:
                    res = requests.post(config.API_URL, data=payload, files=files if files else None, cert=config.CERT_FILES, verify=config.CA_CERT, timeout=15)
                    if res.status_code in (200, 201):
                        cur.execute('DELETE FROM threat_detections WHERE id = ?', (reg['id'],))
                        conn.commit()
                        if reg['audio_path'] and os.path.exists(reg['audio_path']):
                            try:
                                os.remove(reg['audio_path'])
                                logger.info(f"[NETWORK] Local audio file deleted: {reg['audio_path']}")
                            except Exception as ex:
                                logger.error(f"[NETWORK] Failed to delete audio file {reg['audio_path']}: {ex}")
                except Exception as e:
                    logger.error(f"[NETWORK] Sync failed for record {reg['id']}: {e}")
                finally:
                    if audio_handle:
                        audio_handle.close()

def _sync_telemetry_mtls(table_name: str, api_url: str, label: str):
    with sqlite3.connect(config.LOCAL_DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        with closing(conn.cursor()) as cur:
            cur.execute(f'SELECT id, timestamp, value FROM {table_name}')
            rows = cur.fetchall()

            if not rows:
                return

            records = []
            records_id = []

            for row in rows:
                records_id.append(row['id'])
                record_data = {
                    'timestamp': row['timestamp'],
                    'value': row['value'],
                    'device_id': config.DEVICE_ID
                }
                records.append(record_data)
            payload = {label: records}
            try:
                res = requests.post(api_url, json=payload, cert=config.CERT_FILES, verify=config.CA_CERT, timeout=10)
                if res.status_code in (200, 201):
                    placeholders = ','.join(['?'] * len(records_id))
                    cur.execute(f'DELETE FROM {table_name} WHERE id IN ({placeholders})', records_id)
                    conn.commit()
                    logger.info(f'[NETWORK] Successfully synced {len(records)} {label} records.')
            except Exception as e:
                logger.error(f'[NETWORK] {label.capitalize()} sync failed: {e}')

def sync_voltage_mtls():
    _sync_telemetry_mtls('voltage', config.VOLTAGE_API_URL, 'voltage')

def sync_temperature_mtls():
    _sync_telemetry_mtls('temperature', config.TEMP_API_URL, 'temperature')

def sync_worker_loop():
    last_report = None
    while True:
        now = datetime.now()
        current_time = now.hour

        if current_time in config.REPORTING_TIMES and last_report != current_time:
            logger.info(f'[SYNC_WORKER] Time for reporting ({current_time}:00).')
            connected, elapsed =  waiting_antenna_connection()
            if connected:
                check_and_renew_certificate()
                sync_threats_mtls()
                sync_voltage_mtls()
                sync_temperature_mtls()
                last_report = current_time

        try:
            item = pending_sync_queue.get(timeout=30)
            trigger_type = item.get('trigger', 'threat') if isinstance(item, dict) else 'threat'

            logger.info(f'[SYNC_WORKER] Sync triggered ({trigger_type}). Polling Starlink WAN connection...')

            connected, elapsed = waiting_antenna_connection()
            if connected:
                logger.info(f'[SYNC_WORKER] Starlink online ({elapsed}s). Syncing database via mTLS...')
                if trigger_type == 'scheduled_report':
                    logger.info('[SYNC_WORKER] Running scheduled certificate check/renewal....')
                    check_and_renew_certificate()
                sync_threats_mtls()
                sync_voltage_mtls()
                sync_temperature_mtls()
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
    cmd = ['step', 'ca', 'renew', '--force', config.CERT_FILES[0], config.CERT_FILES[1]]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        logger.info('[STEP CA] Certificate verified and updated successfully.')
        return True
    except subprocess.CalledProcessError as e:
        logger.warning('[STEP CA] Error in the certificate renewing: {e.stderr.strip()}')
        return False

def waiting_antenna_connection():
    max_wait_sec = 420
    check_interval = 60
    elapsed = 0
    #connected = False

    while elapsed < max_wait_sec:
        if is_connected():
            return True, elapsed
        time.sleep(check_interval)  # 0% CPU consumption while sleeping
        elapsed += check_interval
    return False, elapsed
