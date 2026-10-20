"""Test the real Harbor CLI through controls.py.

From the repository root, use the project tool environment:
    python3 -m unittest discover -s harbor -p test_controls.py -v

Prerequisites: Docker must answer, and the project tools must be on PATH.
The tools include Docker Compose, Docker Buildx, uv, and Python 3.12.
First, use patchgate-harbor run --help to install the pinned Harbor environment.
The tests use DEVENV_STATE, or .devenv/state, for that environment.
The Docker build requires the project image inputs and their network sources.
Each test uses a private state directory under the existing state directory.
The tests execute the real image build and require the home directory mount
when Docker uses Colima. They do not replace tools or agents.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
STATE = Path(os.environ.get("DEVENV_STATE", ROOT / ".devenv" / "state")).resolve()
TASK = "apply-race-human"


class ControlsConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        harbor = STATE / "harbor"
        self.assertTrue(
            (harbor / "bin" / "harbor").is_file(),
            "Install the pinned Harbor environment with patchgate-harbor run --help first.",
        )
        self.directory = tempfile.TemporaryDirectory(prefix="controls-test-", dir=STATE)
        self.addCleanup(self.directory.cleanup)
        self.state = Path(self.directory.name)
        (self.state / "harbor").symlink_to(harbor, target_is_directory=True)
        self.env = {**os.environ, "DEVENV_STATE": str(self.state), "NO_COLOR": "1"}

    def invoke(self, *options: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ROOT / "harbor" / "controls.py"), "run", *options],
            cwd=ROOT,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=1800,
        )

    def test_invalid_harbor_option_preserves_parser_failure(self) -> None:
        option = "--patchgate-invalid-regression-option"
        result = self.invoke(option)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(list((self.state / "harbor-jobs").glob("*/result.json")), [])

    def test_selected_nop_trial_succeeds_with_zero_reward(self) -> None:
        result = self.invoke(
            "--agent", "nop", "--include-task-name", TASK, "--quiet",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        trials = list((self.state / "harbor-jobs").glob("*/*/result.json"))
        self.assertEqual(len(trials), 1, result.stdout)
        trial = json.loads(trials[0].read_text())
        self.assertEqual(trial["task_name"], TASK)
        self.assertIsNotNone(trial.get("finished_at"), trial)
        self.assertIsNone(trial.get("exception_info"), trial)
        self.assertEqual(trial["verifier_result"]["rewards"]["reward"], 0.0)


if __name__ == "__main__":
    unittest.main()
