import os
import json
import time
import serial
import logging
import subprocess
from datetime import datetime
import config
from database import save_telemetry
import threading
import time
from logging_config import get_logger

logger = get_logger(__name__)

_antenna_lock = threading.Lock()
_threat_detected = False
_reporting = False
_antenna_power_on_time = 0.0
_antenna_rest_start_time = time.monotonic() - 100000

serial_conn = serial.Serial(config.SERIAL_PORT, config.BAUD_RATE, timeout=1)
#serial_conn.dtr = False
time.sleep(2)
serial_conn.reset_input_buffer()
serial_conn.reset_output_buffer()
#time.sleep(2)

def is_antenna_resting():
    global _antenna_rest_start_time
    rest_duration = time.monotonic() - _antenna_rest_start_time
    #print(f'{_antenna_rest_start_time} - {rest_duration} - {config.ANTENNA_REST_TIME_MINUTES * 60}')
    return rest_duration < (config.ANTENNA_REST_TIME_MINUTES * 60)

def trigger_antenna_on(reason: str = 'THREAT'):
    global _threat_detected, _reporting, _antenna_power_on_time
    if reason == 'REPORT':
        if not _reporting:
            _reporting = True
            _antenna_power_on_time = time.monotonic()
            logger.info('[ANTENNA] Turning on Starlink immediately for REPORT.')
            power_starlink(1)
        return True

    if reason == 'THREAT':
        if is_antenna_resting():
            _threat_detected = True
            logger.warning('[THREAT] Recorded, but antenna is resting. Will run later.')
            return False

        if not _threat_detected and _antenna_power_on_time == 0:
            _threat_detected = True
            _antenna_power_on_time = time.monotonic()
            logger.info('[ANTENNA] Turning on Starlin for THREAT.')
            power_starlink(1)
            return True
    return True

def antenna_timer_monitor_loop():
    global _threat_detected, _reporting, _antenna_rest_start_time, _antenna_power_on_time
    last_report_hour = None

    while True:
#        with _antenna_lock:
            #print(_antenna_lock)
            #print('dentro de while de monitor antenna')
        now = time.monotonic()
        now_time = datetime.now()
        current_hour = now_time.strftime('%H:%M')

        if current_hour in config.REPORTING_TIMES and last_report_hour != current_hour:
            if not _reporting and _antenna_power_on_time == 0:
                logger.info(f'[ANTENNA] Scheduled reporting time reached ({current_hour}:00). Turning on antenna.')
                trigger_antenna_on(reason='REPORT')
                last_report_hour = current_hour
                try:
                    import network
                    network.pending_sync_queue.put({"trigger": "scheduled_report"})
                except Exception as e:
                    logger.error(f'[ANTENNA] Could not trigger network sync queue for report: {e}')

        if _threat_detected and _antenna_power_on_time > 0 and not _reporting:
            elapsed_min = (now - _antenna_power_on_time) / 60
            if elapsed_min >= config.TIME_ANTENNA_POWER_ON_MINUTES:
                logger.info(f'[STARLINK] Threat transmission window finished ({config.TIME_ANTENNA_POWER_ON_MINUTES}m) Powering down.')
                power_starlink(0)
                _threat_detected = False
                _antenna_power_on_time = 0.0
                _antenna_rest_start_time = time.monotonic()

        if _reporting and _antenna_power_on_time > 0:
            elapsed_min = (now - _antenna_power_on_time) / 60
            if elapsed_min >= config.REPORTING_TIME_ON_MINUTES:
                logger.info(f'[REPORT] Daily report window finished. Powering down.')
                power_starlink(0)
                _reporting = False
                _antenna_power_on_time = 0.0
                _antenna_rest_start_time = time.monotonic()

        if not is_antenna_resting() and _threat_detected and _antenna_power_on_time == 0 and not _reporting:
            logger.info("[ANTENNA] Rest period finished. Powering on antenna for delayed threat sync.")
            _antenna_power_on_time = time.monotonic()
            power_starlink(1)
            try:
                import network
                network.pending_sync_queue.put({"trigger": "rest_ended_sync_backlog"})
                logger.info("[ANTENNA] Sync worker triggered for accumulated threats.")
            except Exception as e:
                logger.error(f"[ANTENNA] Could not trigger network sync queue: {e}")

        time.sleep(5)


def power_starlink(state: int):
#    print('ingresando power_starlink')
    serial_conn.reset_input_buffer()
    serial_conn.reset_output_buffer()
    if state == 0:
        sync_pi_to_esp32()
        time.sleep(0.5)
    payload = json.dumps({'starlink': state}) + '\n'
    serial_conn.write(payload.encode('utf-8'))
    serial_conn.flush()
   # time.sleep(0.1)
    logger.info(f'[STARLINK] Command sent: state={state}')
#    print('saliendo de power_starlink')

def uart_monitor_loop():
    logger.info('[UART] Monitoring loop started')
    while True:
        if serial_conn.in_waiting > 0:
            try:
                line = serial_conn.readline().decode('utf-8').rstrip()
                if 'DATE:' in line:
                    _process_timestamp(line)
                elif 'VOLT:' in line:
                    _process_voltage(line.split(':')[1])
            except Exception as e:
                logger.error(f'[UART] Parsing exception: {e}')
        time.sleep(0.1)

def _process_timestamp(line):
    parts = line.strip().split(' ')
    date_str, time_str = parts[0].replace('DATE:', ''), parts[1].replace('TIME:', '')
    subprocess.run(f'date -s "{date_str} {time_str}"', shell=True, check=True, capture_output=True, text=True)

def _process_voltage(voltage_str):
    voltage = float(voltage_str)
    save_telemetry('voltage', voltage)
    if voltage <= config.VOLTAGE_TURN_OFF:
        logger.warning('[BATTERY] Low battery. Shutting down...')
        os.system('sudo shutdown -h now')

def read_cpu_temp_loop():
    while True:
        try:
            with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                temp = float(f.read()) / 1000.0
                save_telemetry('temperature', temp)
        except Exception as e:
            logger.error(f'[CPU] Read error: {e}')
        time.sleep(60)

def get_date():
    try:
        serial_conn.reset_input_buffer()
        serial_conn.reset_output_buffer()
        payload = json.dumps({'date': 1}) + '\n'
        serial_conn.write(payload.encode('utf-8'))
        serial_conn.flush()
        logger.info(f'[SYSTEM] Date request sent to ATmegaRTC.')
    except Exception as e:
        logger.error('[SYSTEM] Failed to write data request to serial: {e}')

def sync_pi_to_esp32():
    try:
        #status = subprocess.check_output(["timedatectl", "show", "--property=NTPSynchronized"], text=True)
        #if "NTPSynchronized=yes" in status:
        if True:
            now = datetime.now()
            sync_data = {
                "year": now.year,
                "month": now.month,
                "day": now.day,
                "hour": now.hour,
                "minutes": now.minute,
                "seconds": now.second
            }
            serial_conn.write(f"{json.dumps(sync_data)}\n".encode())
            logging.info("[SYSTEM] Pi is online. ESP32 RTC has been refreshed with NTP time.")
    except Exception as e:
        logging.error(f"[SYSTEM] Could not verify NTP status: {e}")
    time.sleep(0.1)
