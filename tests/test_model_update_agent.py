import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import model_update_agent as agent


class ModelReleaseCleanupTests(unittest.TestCase):
    def make_release(self, root: Path, release_id: str) -> Path:
        release = root / "releases" / release_id
        release.mkdir(parents=True)
        (release / "release.json").write_text(json.dumps({"release_id": release_id}))
        (release / "weights.bin").write_bytes(b"model")
        return release

    def test_keeps_current_and_previous_and_removes_older_releases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "models"
            current = self.make_release(root, "release-current")
            previous = self.make_release(root, "release-previous")
            obsolete = self.make_release(root, "release-obsolete")
            (root / "current").symlink_to(current)
            (root / "previous").symlink_to(previous)

            with patch.object(agent, "MODEL_ROOT", root):
                agent.cleanup_old_model_releases()

            self.assertTrue(current.exists())
            self.assertTrue(previous.exists())
            self.assertFalse(obsolete.exists())

    def test_skips_cleanup_while_activation_is_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "models"
            obsolete = self.make_release(root, "release-obsolete")
            (root / "activation.pending").touch()

            with patch.object(agent, "MODEL_ROOT", root):
                agent.cleanup_old_model_releases()

            self.assertTrue(obsolete.exists())

    def test_does_not_follow_symlinked_release_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "models"
            releases = root / "releases"
            releases.mkdir(parents=True)
            outside = Path(directory) / "outside-release"
            outside.mkdir()
            (outside / "release.json").write_text("{}")
            (releases / "release-link").symlink_to(outside, target_is_directory=True)

            with patch.object(agent, "MODEL_ROOT", root):
                agent.cleanup_old_model_releases()

            self.assertTrue(outside.exists())
            self.assertTrue((releases / "release-link").is_symlink())

    def test_preserves_directories_that_do_not_look_like_releases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "models"
            releases = root / "releases"
            releases.mkdir(parents=True)
            no_manifest = releases / "temporary-staging"
            no_manifest.mkdir()
            invalid_name = releases / "not a release"
            invalid_name.mkdir()
            (invalid_name / "release.json").write_text("{}")

            with patch.object(agent, "MODEL_ROOT", root):
                agent.cleanup_old_model_releases()

            self.assertTrue(no_manifest.exists())
            self.assertTrue(invalid_name.exists())


if __name__ == "__main__":
    unittest.main()
