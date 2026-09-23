import os
import sqlite3
import logging
from contextlib import closing
from alembic.config import Config
from alembic import command
import config
import time
from logging_config import get_logger

logger = get_logger(__name__)

def run_db_migrations():
    ini_path = os.path.join(config.MAIN_DIR, 'alembic.ini')
    script_dir = os.path.join(config.MAIN_DIR, 'alembic')
    db_url = os.getenv('DATABASE_URL', 'sqlite:////var/lib/threat_system/threats.db')
    if os.path.exists(ini_path):
        try:
            alembic_cfg = Config(ini_path)
            alembic_cfg.set_main_option('script_location', script_dir)
            alembic_cfg.set_main_option('sqlalchemy.url', db_url)
            command.upgrade(alembic_cfg, 'head')
            logger.info('[DATABASE] Alembic migrations executed successfully')
            return
        except Exception as e:
            logger.error(f'[DATABASE] Alembic migration error: {e}')
            raise e
    else:
        logger.error(f'[DATABASE] alembic.ini not found at {ini_path}')
        #init_fallback_db()

def init_fallback_db():
    with sqlite3.connect(config.LOCAL_DB_PATH) as conn:
        with closing(conn.cursor()) as cur:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS threat_detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    audio_path TEXT,
                    timestamp INTEGER NOT NULL,
                    sync_status INTEGER DEFAULT 0
                )
            ''')
            cur.execute('''
                CREATE TABLE IF NOT EXISTS voltage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    value REAL NOT NULL,
                    sync_status INTEGER DEFAULT 0
                )
            ''')
            cur.execute('''
                CREATE TABLE IF NOT EXISTS temperature (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    value REAL NOT NULL,
                    sync_status INTEGER DEFAULT 0
                )
            ''')
            conn.commit()

def save_telemetry(table_name, value):
    with sqlite3.connect(config.LOCAL_DB_PATH) as conn:
        with closing(conn.cursor()) as cur:
            cur.execute(f"INSERT INTO {table_name} (timestamp, value) VALUES (?, ?)", (int(time.time()), value))

def save_threat_record(threat_type, confidence, audio_path, timestamp):
    with sqlite3.connect(config.LOCAL_DB_PATH) as conn:
        with closing(conn.cursor()) as cur:
            cur.execute(
                'INSERT INTO threat_detections (device_id, threat_type, confidence_score, audio_path, timestamp) VALUES (?, ?, ?, ?, ?)',
                (config.DEVICE_ID, threat_type, confidence, audio_path, timestamp)
            )
            conn.commit()
