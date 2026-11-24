import os
import requests
import subprocess
import tempfile
import config
from logging_config import get_logger

logger = get_logger(__name__)

def auto_register_device(force=False):
    crt_path, key_path = config.CERT_FILES[0], config.CERT_FILES[1]
    if not force and os.path.exists(crt_path) and os.path.exists(key_path):
        return True

    logger.info('[STEP-CA] Initializing first time cloud check-in...')
    if not config.FACTORY_CLAIM_SECRET:
        logger.error('[STEP-CA] FACTORY_CLAIM_SECRET is not configured')
        return False
    if not os.path.isfile(config.CA_CERT):
        logger.error('[STEP-CA] Trusted CA certificate is missing: %s', config.CA_CERT)
        return False
    cert_dir = os.path.dirname(crt_path)
    os.makedirs(cert_dir, exist_ok=True)
    if force:
        # The caller uses force only after verifying that the certificate has
        # expired. Delete the old identity so enrollment creates a fresh pair.
        try:
            for path in (crt_path, key_path):
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
        except OSError as exc:
            logger.error('[STEP-CA] Could not remove the expired device identity: %s', exc)
            return False
        logger.warning('[STEP-CA] Removed expired mTLS certificate and key; requesting a new enrollment token.')
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
        # Stage a fresh certificate/key pair before activating the identity.
        with tempfile.TemporaryDirectory(prefix='.enrollment-', dir=cert_dir) as stage_dir:
            staged_cert = os.path.join(stage_dir, 'device.crt')
            staged_key = os.path.join(stage_dir, 'device.key')
            try:
                subprocess.run(
                    ['step', 'ca', 'certificate', config.DEVICE_ID,
                     staged_cert, staged_key, '--token', ott_token, '--force',
                     '--ca-url', ca_url, '--root', config.CA_CERT],
                    check=True, capture_output=True, text=True, timeout=60,
                )
            except subprocess.CalledProcessError as exc:
                # Do not log the command or token; only sanitized diagnostics.
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

            if not os.path.isfile(staged_cert) or not os.path.isfile(staged_key):
                logger.error('[STEP-CA] Issuance reported success but did not create a certificate/key pair.')
                return False

            os.chmod(staged_cert, 0o644)
            os.chmod(staged_key, 0o600)
            try:
                os.replace(staged_key, key_path)
                os.replace(staged_cert, crt_path)
            except OSError as exc:
                logger.error('[STEP-CA] Could not activate the newly issued identity: %s', exc)
                return False

        logger.info('[STEP-CA] Device mTLS certificate issued successfully.')
        return True
    except requests.exceptions.RequestException as exc:
        logger.error('[STEP-CA] Enrollment request failed: %s', exc)
        return False
    except (OSError, ValueError, TypeError) as exc:
        logger.error('[STEP-CA] Enrollment setup failed: %s', exc)
        return False
