import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import software_update_agent as agent


class SoftwareManifestTests(unittest.TestCase):
    def manifest(self):
        digest = "a" * 64
        return {
            "schema_version": 1,
            "release_id": "software-test-1",
            "images": {
                "monitor": f"ghcr.io/malbuja10/monitor-threat-system/monitor@sha256:{digest}",
                "analyzer": f"ghcr.io/malbuja10/monitor-threat-system/analyzer@sha256:{digest}",
            },
        }

    def test_accepts_digest_pinned_pair(self):
        release, images = agent.validate_manifest(self.manifest())
        self.assertEqual(release, "software-test-1")
        self.assertEqual(set(images), {"monitor", "analyzer"})

    def test_rejects_mutable_tag(self):
        data = self.manifest()
        data["images"]["monitor"] = "ghcr.io/malbuja10/monitor-threat-system/monitor:latest"
        with self.assertRaisesRegex(ValueError, "pinned by sha256 digest"):
            agent.validate_manifest(data)

    def test_rejects_cross_service_image(self):
        data = self.manifest()
        data["images"]["monitor"] = data["images"]["analyzer"]
        with self.assertRaisesRegex(ValueError, "monitor must use"):
            agent.validate_manifest(data)

    def test_offline_check_is_a_normal_retryable_condition(self):
        with patch.object(agent.socket, "create_connection", side_effect=OSError("offline")):
            self.assertFalse(agent.internet_available())


class SoftwareEnvTests(unittest.TestCase):
    def test_resolves_running_image_to_exact_ghcr_digest(self):
        repo = "ghcr.io/malbuja10/monitor-threat-system/monitor@sha256:" + "a" * 64
        with patch.object(agent, "compose", return_value=SimpleNamespace(stdout="container-id\n")), \
             patch.object(agent, "run", side_effect=[
                 SimpleNamespace(stdout="sha256:image-config-id\n"),
                 SimpleNamespace(stdout=json.dumps([repo])),
             ]):
            self.assertEqual(agent.running_image_digest("monitor"), repo)

    def test_refuses_rollback_target_without_expected_ghcr_digest(self):
        with patch.object(agent, "compose", return_value=SimpleNamespace(stdout="container-id\n")), \
             patch.object(agent, "run", side_effect=[
                 SimpleNamespace(stdout="sha256:image-config-id\n"),
                 SimpleNamespace(stdout="[]"),
             ]):
            with self.assertRaisesRegex(RuntimeError, "no matching GHCR digest"):
                agent.running_image_digest("monitor")

    def test_first_update_pins_current_tags_before_creating_env(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            env_file = project / ".env"
            digests = {
                "monitor": "ghcr.io/malbuja10/monitor-threat-system/monitor@sha256:" + "a" * 64,
                "analyzer": "ghcr.io/malbuja10/monitor-threat-system/analyzer@sha256:" + "b" * 64,
            }
            with patch.object(agent, "ENV_FILE", env_file), \
                 patch.object(agent, "PROJECT_DIR", project), \
                 patch.object(agent, "running_image_digest", side_effect=lambda service: digests[service]):
                original, previous, mode = agent.pin_previous_images(None, {}, 0o600)

            self.assertEqual(previous, digests)
            self.assertIn(f"MONITOR_IMAGE_REF={digests['monitor']}", original)
            self.assertIn(f"ANALYZER_IMAGE_REF={digests['analyzer']}", original)
            self.assertEqual(env_file.stat().st_mode & 0o777, 0o600)

    def test_updates_refs_without_touching_other_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            env_file = project / ".env"
            with patch.object(agent, "ENV_FILE", env_file), patch.object(agent, "PROJECT_DIR", project):
                original = "FACTORY_CLAIM_SECRET=secret\nMONITOR_IMAGE_REF=old\nMONITOR_IMAGE_REF=duplicate\n"
                agent.write_env(original, {
                    "MONITOR_IMAGE_REF": "monitor@sha256:a",
                    "ANALYZER_IMAGE_REF": "analyzer@sha256:b",
                }, 0o600)
                result = env_file.read_text()
            self.assertIn("FACTORY_CLAIM_SECRET=secret", result)
            self.assertEqual(result.count("MONITOR_IMAGE_REF="), 1)
            self.assertIn("MONITOR_IMAGE_REF=monitor@sha256:a", result)
            self.assertIn("ANALYZER_IMAGE_REF=analyzer@sha256:b", result)
            self.assertEqual(env_file.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
