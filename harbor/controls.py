#!/usr/bin/env python3
"""Run the patchgate Harbor tasks in Docker, and compare the control agents.

    patchgate-harbor check           build the image, run the oracle and nop agents, and compare the rewards
    patchgate-harbor run [OPTIONS]   build the image, then run `harbor run` on harbor/tasks with OPTIONS
    patchgate-harbor model OPTIONS  run the Rust live-model evaluation inside Harbor
                                     (default: --agent oracle)
    patchgate-harbor lifecycle      check runner status and both backend lifecycles

Docker runs in the Colima profile PATCHGATE_COLIMA_PROFILE (default: patchgate),
unless DOCKER_HOST names another engine. If Docker does not answer, the command
starts the profile. Colima shares only the home directory with its VM, and
Harbor reads each reward through a bind mount, so the jobs stay in
.devenv/state/harbor-jobs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / "harbor" / "tasks"
IMAGE = "patchgate-harbor:dev"
LIFECYCLE_IMAGE = "patchgate-harbor-lifecycle:dev"
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


def harbor_run(env: dict, label: str, *options: str) -> tuple[Path, int]:
    jobs = STATE / "harbor-jobs"
    name = f"{time.strftime('%Y%m%d-%H%M%S')}-{label}"
    result = run(harbor(), "run", "--path", TASKS, "--env", "docker", "--jobs-dir", jobs, "--job-name", name, "--yes", *options, env=env, check=False)
    return jobs / name, result.returncode


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
    failure = 0
    for agent, expected in CONTROLS.items():
        job, return_code = harbor_run(env, agent, "--agent", agent, "--quiet")
        if return_code:
            failure = failure or return_code
            say(f"{agent} Harbor invocation failed with exit code {return_code}.")
        found = rewards(job)
        for task in tasks:
            reward = found.get(task, "no trial")
            wrong += reward != expected
            rows.append((task, agent, reward, expected))
    width = max(len(task) for task in tasks)
    for task, agent, reward, expected in rows:
        verdict = "ok" if reward == expected else f"WRONG, expected {expected}"
        print(f"{task:<{width}}  {agent:<6}  {reward!s:<8}  {verdict}")
    say(f"{len(rows) - wrong} of {len(rows)} control results are correct.")
    if failure:
        return failure
    if wrong:
        return 1
    return run(
        "patchgate-eval", "verify-harbor", "--harbor", harbor(),
        "--tasks", TASKS, "--jobs", STATE / "harbor-jobs", env=env, check=False,
    ).returncode


def lifecycle(env: dict, options: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="patchgate-harbor lifecycle")
    parser.add_argument("--backend", choices=("all", "docker", "bubblewrap"), default="all")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(options)
    output = args.output or STATE / "lifecycle-jobs" / f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid4().hex[:8]}" / "summary.json"
    output = output.resolve()
    directory = output.parent
    directory.mkdir(parents=True, exist_ok=True)
    python = harbor().parent / "python"
    summary = {"schema_version": 1, "passed": False, "checks": {}}
    checks = summary["checks"]
    failure = 0
    if args.backend in ("all", "docker"):
        result = run(
            python, "-m", "unittest", "discover", "-s", ROOT / "harbor",
            "-p", "test_controls.py", "-v", env=env, check=False,
        )
        checks["runner_status"] = {"exit_code": result.returncode}
        failure = result.returncode
        report = directory / "docker.json"
        result = run(
            python, ROOT / "harbor" / "lifecycle.py", "--backend", "docker",
            "--tasks", TASKS, "--output", report, env=env, check=False,
        )
        checks["docker"] = {
            "exit_code": result.returncode,
            "report": json.loads(report.read_text()) if report.exists() else None,
        }
        failure = failure or result.returncode or (0 if checks["docker"]["report"] and checks["docker"]["report"]["passed"] else 1)
    if args.backend in ("all", "bubblewrap"):
        backend = os.environ.get("PATCHGATE_HARBOR_BACKEND")
        if not backend:
            parser.error("Use the devenv patchgate-harbor command for the pinned backend.")
        lock = json.loads((ROOT / "devenv.lock").read_text())
        summary["backend_source"] = lock["nodes"]["harbor-bubblewrap"]["locked"]
        result = run(
            "docker", "build", "--tag", LIFECYCLE_IMAGE,
            "--build-context", f"backend={backend}",
            "--file", ROOT / "harbor" / "lifecycle.Dockerfile", ROOT,
            env=env, check=False,
        )
        checks["bubblewrap_image"] = {"exit_code": result.returncode}
        failure = failure or result.returncode
        if result.returncode == 0:
            result = run(
                "docker", "run", "--rm", "--privileged", "--security-opt", "seccomp=unconfined",
                "--volume", f"{ROOT}:/project:ro", "--volume", f"{directory}:/evidence:rw",
                LIFECYCLE_IMAGE, "--backend", "bubblewrap", "--tasks", "/project/harbor/tasks",
                "--output", "/evidence/bubblewrap.json", env=env, check=False,
            )
            report = directory / "bubblewrap.json"
            checks["bubblewrap"] = {
                "exit_code": result.returncode,
                "report": json.loads(report.read_text()) if report.exists() else None,
            }
            failure = failure or result.returncode or (0 if checks["bubblewrap"]["report"] and checks["bubblewrap"]["report"]["passed"] else 1)
    summary["passed"] = failure == 0
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    say(f"Lifecycle report: {output}")
    return failure


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in ("check", "run", "model", "lifecycle"):
        print(__doc__)
        return 2
    if Path.home() not in STATE.resolve().parents:
        say(f"warning: {STATE} is outside the home directory, so the Colima VM cannot see the Harbor jobs.")
    env = docker_env()
    run("docker", "build", "--tag", IMAGE, "--file", ROOT / "harbor" / "Dockerfile", ROOT, env=env)
    if argv[0] == "lifecycle":
        return lifecycle(env, argv[1:])
    if argv[0] == "model":
        return run(
            "patchgate-eval", "model-harbor", "--harbor", harbor(),
            "--tasks", TASKS, "--jobs", STATE / "harbor-jobs", *argv[1:],
            env=env, check=False,
        ).returncode
    if argv[0] == "check":
        return check(env)
    job, return_code = harbor_run(env, "run", *(argv[1:] or ["--agent", "oracle"]))
    for task, reward in rewards(job).items():
        print(f"{task}  {reward}")
    return return_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
