import logging
import sys
import unittest
from pathlib import Path
from subprocess import CalledProcessError
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "monitor"))
logging.basicConfig(level=logging.CRITICAL)
import network


class CertificateRenewalTests(unittest.TestCase):
    def setUp(self):
        self.settings = patch.multiple(
            network.config,
            STEP_CA_URL="https://ca.example.test:8443",
            CA_CERT="/app/certs/root_ca.crt",
            CERT_FILES=("/var/lib/certs/device.crt", "/var/lib/certs/device.key"),
            CERTIFICATE_RENEWAL_TIME="14:00",
            CERTIFICATE_RENEWAL_WINDOW_DAYS=7,
        )
        self.settings.start()
        self.addCleanup(self.settings.stop)

    @patch.object(network.subprocess, "run")
    def test_renewal_uses_explicit_ca_url_and_root(self, run):
        run.return_value = type("Result", (), {"stdout": "", "stderr": ""})()

        self.assertTrue(network.check_and_renew_certificate())
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--ca-url") + 1], "https://ca.example.test:8443")
        self.assertEqual(command[command.index("--root") + 1], "/app/certs/root_ca.crt")
        self.assertEqual(command[-2:], ["/var/lib/certs/device.crt", "/var/lib/certs/device.key"])

    @patch.object(network.subprocess, "run")
    def test_renewal_failure_logs_step_diagnostic(self, run):
        run.side_effect = CalledProcessError(
            1, ["step", "ca", "renew"], stderr="CA rejected renewal"
        )

        with self.assertLogs(network.logger, level="WARNING") as captured:
            self.assertFalse(network.check_and_renew_certificate())

        self.assertIn("CA rejected renewal", captured.output[0])

    @patch.object(network.subprocess, "run")
    def test_expired_certificate_triggers_reenrollment_before_sync(self, run):
        run.return_value = type("Result", (), {"returncode": 1, "stdout": "", "stderr": "Certificate has expired"})()
        with patch.object(network.os.path, "isfile", return_value=True), \
             patch.object(network.certificate, "auto_register_device", return_value=True) as enroll:
            self.assertTrue(network.ensure_device_certificate())
        enroll.assert_called_once_with(force=True)

    @patch.object(network.subprocess, "run")
    def test_valid_certificate_does_not_trigger_reenrollment(self, run):
        run.return_value = type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        with patch.object(network.os.path, "isfile", return_value=True), \
             patch.object(network.certificate, "auto_register_device") as enroll:
            self.assertTrue(network.ensure_device_certificate())
        enroll.assert_not_called()

    @patch.object(network.subprocess, "run")
    def test_certificate_renewal_is_only_due_at_two_pm_and_near_expiry(self, run):
        run.return_value = type("Result", (), {"returncode": 1, "stdout": "", "stderr": ""})()
        self.assertFalse(network._renewal_is_due("10:00"))
        run.assert_not_called()
        self.assertTrue(network._renewal_is_due("14:00"))
        self.assertEqual(run.call_args.args[0][run.call_args.args[0].index("-checkend") + 1], str(7 * 24 * 60 * 60))

    @patch.object(network.subprocess, "run")
    def test_certificate_not_near_expiry_is_not_renewed_at_two_pm(self, run):
        run.return_value = type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        self.assertFalse(network._renewal_is_due("14:00"))


if __name__ == "__main__":
    unittest.main()
