import json
import os
import time
import threading
import logging
from datetime import datetime
from logging_config import get_logger
import config
#import database
#import hardware
#import network
logger = get_logger('main')
import database
import hardware
import network
import certificate

#pending_sync_queue = queue.Queue()

#def sync_worker_loop():
#    """Background thread that handles Starlink waiting and mTLS syncing."""
#    while True:
        # Wait until a threat triggers an upload attempt
#        threat_item = pending_sync_queue.get()
        
#        logger.info("[SYNC_WORKER] Threat queued for upload. Polling Starlink WAN connection...")
        
#        max_wait_sec = 420
#        check_interval = 60
#        elapsed = 0
#        connected = False

#        while elapsed < max_wait_sec:
#            if network.is_connected():
#                connected = True
#                break
#            time.sleep(check_interval)  # 0% CPU consumption while sleeping
#            elapsed += check_interval

#        if connected:
#            logger.info(f"[SYNC_WORKER] Starlink online ({elapsed}s). Syncing database via mTLS...")
#            network.sync_threats_mtls()
#        else:
#            logger.error("[SYNC_WORKER] Starlink link connection timed out.")

        # Drain extra queue items queued while waiting so we don't repeat the loop redundantly
#        while not pending_sync_queue.empty():
#            pending_sync_queue.get_nowait()
#            pending_sync_queue.task_done()

#        pending_sync_queue.task_done()

def main():
#    setup_logging()
    logger.info('[SYSTEM] Starting modular service....')
    database.run_db_migrations()
    certificate.auto_register_device()

    threading.Thread(target=hardware.uart_monitor_loop, daemon=True).start()
    threading.Thread(target=hardware.read_cpu_temp_loop, daemon=True).start()
    threading.Thread(target=hardware.antenna_timer_monitor_loop, daemon=True).start()
    threading.Thread(target=network.sync_worker_loop, daemon=True).start()
    time.sleep(2)
    hardware.get_date()
    time.sleep(0.5)
    hardware.get_date()
    time.sleep(0.5)
    hardware.power_starlink(0)
    time.sleep(0.5)
    if not os.path.exists(config.PIPE_PATH):
        os.mkfifo(config.PIPE_PATH)
        os.chmod(config.PIPE_PATH, 0o666)

    while True:
        try:
            with open(config.PIPE_PATH, 'r', buffering=1) as fifo:
                while True:
                    line = fifo.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    if line.strip():
                        data = json.loads(line.strip())
                        audio_path = data.get("file", "")
                        #host_path = raw_path.replace("/app/", "/home/rpi/client/")
                        database.save_threat_record(
                            data.get('label', 'Unknown'),
                            float(data.get('prob', 0.0)),
                            audio_path,
                            data.get('time', datetime.now().isoformat())
                        )
#revisar tiempo de transmision (agregar)
                        if hardware.trigger_antenna_on(reason='THREAT'):
                            network.pending_sync_queue.put(data)
        except Exception as e:
            logger.error(f'[MAIN] Pipe read error: {e}')
            time.sleep(1)

if __name__ == '__main__':
    main()
