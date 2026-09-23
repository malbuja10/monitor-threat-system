import os
import requests
import subprocess
import config
from logging_config import get_logger

logger = get_logger(__name__)

FACTORY_CLAIM_SECRET = 'sk_factory_9f83a02b11c'

def auto_register_device():
    crt_path, key_path = config.CERT_FILES[0], config.CERT_FILES[1]
    if os.path.exists(crt_path) and os.path.exists(key_path):
        return True

    logger.info('[STEP-CA] Initializing first time cloud check-in...')
    try:
        response = requests.post(
            config.GET_TOKEN,
            json = {
                'device_id': config.DEVICE_ID,
                'factory_secret': FACTORY_CLAIM_SECRET
            },
            verify=config.CA_CERT,
            timeout=15
        )

        if response.status_code == 200:
            ott_token = response.json().get('token')
            cmd = [
                'step', 'ca', 'certificate',
                config.DEVICE_ID,
                crt_path,
                key_path,
                '--token', ott_token,
                '--force'
            ]

            subprocess.run(cmd, check=True)
            logger.info('[STEP-CA] Successfully provisional mTLS identity.')
            return True
        else:
            logger.error(f'[STEP-CA] Registration rejected: {response.text}')
            return False
    except Exception as e:
        logger.error(f'[STEP-CA] Bootstraping failed: {e}')
        return False

