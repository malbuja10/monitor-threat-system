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


if __name__ == "__main__":
    unittest.main()
