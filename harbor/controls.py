#!/usr/bin/env python3
"""Run the patchgate Harbor tasks in Docker, and compare the control agents.

    patchgate-harbor check           build the image, run the oracle and nop agents, and compare the rewards
    patchgate-harbor run [OPTIONS]   build the image, then run `harbor run` on harbor/tasks with OPTIONS
                                     (default: --agent oracle)

Docker runs in the Colima profile PATCHGATE_COLIMA_PROFILE (default: patchgate),
unless DOCKER_HOST names another engine. If Docker does not answer, the command
starts the profile. Colima shares only the home directory with its VM, and
Harbor reads each reward through a bind mount, so the jobs stay in
.devenv/state/harbor-jobs.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / "harbor" / "tasks"
IMAGE = "patchgate-harbor:dev"
REQUIREMENTS = ROOT / "harbor" / "requirements.txt"
STATE = Path(os.environ.get("DEVENV_STATE", ROOT / ".devenv" / "state"))
CONTROLS = {"oracle": 1.0, "nop": 0.0}


def say(message: str) -> None:
    print(f"patchgate-harbor: {message}", flush=True)


def run(*args, env: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
    say("$ " + " ".join(map(str, args)))
    result = subprocess.run([str(arg) for arg in args], cwd=ROOT, env=env)
    if check and result.returncode != 0:
        sys.exit(f"patchgate-harbor: {Path(str(args[0])).name} failed with exit code {result.returncode}")
    return result


def docker_env() -> dict:
    """Return the environment for Docker: a private configuration with the Compose and Buildx plugins."""
    config = STATE / "docker"
    plugins = config / "cli-plugins"
    plugins.mkdir(parents=True, exist_ok=True)
    for directory in filter(None, os.environ.get("PATCHGATE_DOCKER_PLUGINS", "").split(":")):
        for plugin in Path(directory).iterdir():
            link = plugins / plugin.name
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(plugin)
    profile = os.environ.get("PATCHGATE_COLIMA_PROFILE", "patchgate")
    env = {**os.environ, "DOCKER_CONFIG": str(config)}
    colima_host = f"unix://{Path.home()}/.colima/{profile}/docker.sock"
    env.setdefault("DOCKER_HOST", colima_host)
    if subprocess.run(["docker", "info"], env=env, capture_output=True).returncode == 0:
        return env
    # A DOCKER_HOST that names another engine is the choice of the user, so this does not start Colima.
    if env["DOCKER_HOST"] != colima_host or sys.platform != "darwin":
        sys.exit(f"patchgate-harbor: Docker does not answer at {env['DOCKER_HOST']}.")
    say(f"Docker does not answer. This starts the Colima profile {profile}. To stop it later, run: colima stop {profile}")
    run(
        "colima", "start", profile, "--vm-type", "vz", "--mount-type", "virtiofs",
        "--mount", f"{Path.home()}:w", "--cpu", "4", "--memory", "6", "--disk", "60",
    )
    return env


def harbor() -> Path:
    """Return the Harbor command of a virtual environment that has the hash-locked requirements."""
    venv = STATE / "harbor"
    marker = venv / ".requirements-sha256"
    digest = hashlib.sha256(REQUIREMENTS.read_bytes()).hexdigest()
    if not (venv / "bin" / "harbor").exists() or not marker.exists() or marker.read_text() != digest:
        run("uv", "venv", "--allow-existing", "--python", os.environ.get("PATCHGATE_HARBOR_PYTHON", "python3.12"), venv)
        run("uv", "pip", "sync", "--require-hashes", "--python", venv / "bin" / "python", REQUIREMENTS)
        marker.write_text(digest)
    return venv / "bin" / "harbor"


def harbor_run(env: dict, label: str, *options: str) -> Path:
    jobs = STATE / "harbor-jobs"
    name = f"{time.strftime('%Y%m%d-%H%M%S')}-{label}"
    run(harbor(), "run", "--path", TASKS, "--env", "docker", "--jobs-dir", jobs, "--job-name", name, "--yes", *options, env=env, check=False)
    return jobs / name


def rewards(job: Path) -> dict[str, object]:
    """Return the reward of each task in a job, or the name of the exception of the trial."""
    found: dict[str, object] = {}
    for path in sorted(job.glob("*/result.json")):
        trial = json.loads(path.read_text())
        if trial.get("exception_info"):
            found[trial["task_name"]] = trial["exception_info"].get("exception_type") or "exception"
        else:
            found[trial["task_name"]] = ((trial.get("verifier_result") or {}).get("rewards") or {}).get("reward")
    return found


def check(env: dict) -> int:
    tasks = sorted(path.name for path in TASKS.iterdir() if (path / "task.toml").exists())
    rows, wrong = [], 0
    for agent, expected in CONTROLS.items():
        found = rewards(harbor_run(env, agent, "--agent", agent, "--quiet"))
        for task in tasks:
            reward = found.get(task, "no trial")
            wrong += reward != expected
            rows.append((task, agent, reward, expected))
    width = max(len(task) for task in tasks)
    for task, agent, reward, expected in rows:
        verdict = "ok" if reward == expected else f"WRONG, expected {expected}"
        print(f"{task:<{width}}  {agent:<6}  {reward!s:<8}  {verdict}")
    say(f"{len(rows) - wrong} of {len(rows)} control results are correct.")
    return 1 if wrong else 0


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in ("check", "run"):
        print(__doc__)
        return 2
    if Path.home() not in STATE.resolve().parents:
        say(f"warning: {STATE} is outside the home directory, so the Colima VM cannot see the Harbor jobs.")
    env = docker_env()
    run("docker", "build", "--tag", IMAGE, "--file", ROOT / "harbor" / "Dockerfile", ROOT, env=env)
    if argv[0] == "check":
        return check(env)
    job = harbor_run(env, "run", *(argv[1:] or ["--agent", "oracle"]))
    for task, reward in rewards(job).items():
        print(f"{task}  {reward}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
