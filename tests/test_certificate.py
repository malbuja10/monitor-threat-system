import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "monitor"))
import certificate


class DeviceEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.ca_cert = self.root / "jocotoco-root-ca.crt"
        self.ca_cert.write_text("test root certificate")
        self.cert_path = self.root / "certs" / "device.crt"
        self.key_path = self.root / "certs" / "device.key"
        self.settings = patch.multiple(
            certificate.config,
            CERT_FILES=(str(self.cert_path), str(self.key_path)),
            CA_CERT=str(self.ca_cert),
            DEVICE_ID="site-01",
            FACTORY_CLAIM_SECRET="test-factory-secret-not-for-logs",
            GET_TOKEN="https://api.example.test/v1/inscripcion",
            STEP_CA_URL="https://ca.example.test:8443",
        )
        self.settings.start()
        self.addCleanup(self.settings.stop)
        self.addCleanup(self.temp_dir.cleanup)

    @patch.object(certificate.subprocess, "run")
    @patch.object(certificate.requests, "post")
    def test_uses_ca_url_from_enrollment_and_explicit_root(self, post, run):
        post.return_value = SimpleNamespace(
            status_code=200,
            json=lambda: {"token": "one-time-token", "ca_url": "https://returned-ca.test:8443"},
        )

        def issue_certificate(command, **kwargs):
            self.key_path.write_text("private key")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        run.side_effect = issue_certificate

        self.assertTrue(certificate.auto_register_device())
        command = run.call_args.args[0]
        self.assertIn("--ca-url", command)
        self.assertEqual(command[command.index("--ca-url") + 1], "https://returned-ca.test:8443")
        self.assertIn("--root", command)
        self.assertEqual(command[command.index("--root") + 1], str(self.ca_cert))
        self.assertEqual(self.key_path.stat().st_mode & 0o777, 0o600)
        self.assertTrue(run.call_args.kwargs["capture_output"])

    @patch.object(certificate.subprocess, "run")
    @patch.object(certificate.requests, "post")
    def test_does_not_request_certificate_after_enrollment_rejection(self, post, run):
        post.return_value = SimpleNamespace(status_code=403)

        self.assertFalse(certificate.auto_register_device())
        run.assert_not_called()

    @patch.object(certificate.requests, "post")
    def test_refuses_missing_trusted_ca_before_enrollment(self, post):
        with patch.object(certificate.config, "CA_CERT", str(self.root / "missing.crt")):
            self.assertFalse(certificate.auto_register_device())
        post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
