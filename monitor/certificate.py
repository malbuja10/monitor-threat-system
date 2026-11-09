import os
import requests
import subprocess
import config
from logging_config import get_logger

logger = get_logger(__name__)

def auto_register_device():
    crt_path, key_path = config.CERT_FILES[0], config.CERT_FILES[1]
    if os.path.exists(crt_path) and os.path.exists(key_path):
        return True

    logger.info('[STEP-CA] Initializing first time cloud check-in...')
    if not config.FACTORY_CLAIM_SECRET:
        logger.error('[STEP-CA] FACTORY_CLAIM_SECRET is not configured')
        return False
    if not os.path.isfile(config.CA_CERT):
        logger.error('[STEP-CA] Trusted CA certificate is missing: %s', config.CA_CERT)
        return False
    os.makedirs(os.path.dirname(crt_path), exist_ok=True)
    try:
        response = requests.post(
            config.GET_TOKEN,
            json={
                'device_id': config.DEVICE_ID,
                'factory_secret': config.FACTORY_CLAIM_SECRET
            },
            verify=config.CA_CERT,
            timeout=15
        )

        if response.status_code != 200:
            logger.error(
                f'[STEP-CA] Enrollment rejected with HTTP {response.status_code}; '
                'check the server enrollment settings and device authorization.'
            )
            return False

        try:
            enrollment = response.json()
        except requests.exceptions.JSONDecodeError:
            logger.error('[STEP-CA] Enrollment response was not valid JSON.')
            return False
        if not isinstance(enrollment, dict):
            logger.error('[STEP-CA] Enrollment response must be a JSON object.')
            return False

        ott_token = enrollment.get('token')
        ca_url = enrollment.get('ca_url') or config.STEP_CA_URL
        if not isinstance(ott_token, str) or not ott_token.strip():
            logger.error('[STEP-CA] Enrollment response did not contain a token.')
            return False
        if not isinstance(ca_url, str) or not ca_url.startswith('https://'):
            logger.error('[STEP-CA] No valid HTTPS Step CA URL is configured.')
            return False
        cmd = [
            'step', 'ca', 'certificate',
            config.DEVICE_ID,
            crt_path,
            key_path,
            '--token', ott_token,
            '--force',
            '--ca-url', ca_url,
            '--root', config.CA_CERT,
        ]

        try:
            subprocess.run(
                cmd, check=True, capture_output=True, text=True, timeout=60
            )
        except subprocess.CalledProcessError as exc:
            # Do not log the command or token; only sanitized diagnostic output.
            detail = (exc.stderr or exc.stdout or '').strip()
            if ott_token:
                detail = detail.replace(ott_token, '[REDACTED]')
            if config.FACTORY_CLAIM_SECRET:
                detail = detail.replace(config.FACTORY_CLAIM_SECRET, '[REDACTED]')
            logger.error(
                '[STEP-CA] Certificate issuance failed (exit %s): %s',
                exc.returncode,
                detail or 'step returned no diagnostic output.',
            )
            return False
        except subprocess.TimeoutExpired:
            logger.error('[STEP-CA] Certificate issuance timed out after 60 seconds.')
            return False

        os.chmod(key_path, 0o600)
        logger.info('[STEP-CA] Device mTLS certificate issued successfully.')
        return True
    except requests.exceptions.RequestException as exc:
        logger.error('[STEP-CA] Enrollment request failed: %s', exc)
        return False
    except (OSError, ValueError, TypeError) as exc:
        logger.error('[STEP-CA] Enrollment setup failed: %s', exc)
        return False
