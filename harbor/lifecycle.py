#!/usr/bin/env python3
"""Check fixture lifecycle guarantees with real Harbor environments and agents."""

from __future__ import annotations

import argparse
import asyncio
import json
import shlex
import sys
from pathlib import Path
from uuid import uuid4

from harbor.environments.base import HealthcheckError
from harbor.models.trial.config import AgentConfig, EnvironmentConfig, TaskConfig, TrialConfig
from harbor.trial.single_step import SingleStepTrial

CASES = ("merge-order-conflict", "rust-model-decisions")
BACKENDS = {
    "docker": "harbor.environments.docker.docker:DockerEnvironment",
    "bubblewrap": "hell_env.harbor.backends.bubblewrap:BubblewrapEnvironment",
}

# This program runs inside the real environment, not on the host.
SNAPSHOT = r'''
import hashlib
import json
from pathlib import Path

root = Path.cwd()
repo = root / "repo"
facts = root / "facts.json"
entries = {}
for base in (repo, facts):
    paths = [base, *sorted(base.rglob("*"))] if base.is_dir() else [base]
    for path in paths:
        name = str(path.relative_to(root))
        if path.is_symlink():
            entries[name] = {"symlink": str(path.readlink())}
        elif path.is_file():
            entries[name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        elif path.is_dir():
            entries[name] = {"directory": True}
parsed = None
if facts.is_file():
    try:
        parsed = json.loads(facts.read_text())
    except (ValueError, UnicodeError):
        pass
print(json.dumps({
    "repo": repo.is_dir(),
    "facts": facts.is_file(),
    "valid_structure": (repo / ".pijul").is_dir() and isinstance(parsed, dict) and bool(parsed),
    "facts_sha256": hashlib.sha256(facts.read_bytes()).hexdigest() if facts.is_file() else None,
    "marker": (repo / "lifecycle-marker.txt").is_file(),
    "entries": sorted(path.name for path in root.iterdir()),
    "fixture": entries,
}, sort_keys=True))
'''
MUTATE = r'''
import json
from pathlib import Path

Path("repo/lifecycle-marker.txt").write_text("lifecycle mutation\n")
facts = Path("facts.json")
value = json.loads(facts.read_text())
value["lifecycle_marker"] = "mutation"
facts.write_text(json.dumps(value, sort_keys=True) + "\n")
'''
VALIDATE = r'''
import json
import subprocess

results = {}
for channel in ("main", "inbox"):
    result = subprocess.run(
        ["pijul", "log", "--channel", channel, "--hash-only"],
        cwd="repo", capture_output=True, text=True, check=True,
    )
    results[channel] = result.stdout.splitlines()
    if not results[channel]:
        raise RuntimeError("The fixture channel has no changes: " + channel)
print(json.dumps(results, sort_keys=True))
'''


def error(exc: BaseException) -> dict:
    return {"type": type(exc).__name__, "message": str(exc)}


def require(row: dict, name: str, condition: bool) -> None:
    row.setdefault("criteria", {})[name] = bool(condition)


def passed(row: dict) -> bool:
    return bool(row.get("criteria")) and all(row["criteria"].values()) and not row.get("error")


async def command(environment, source: str) -> str:
    result = await environment.exec("python3 -c " + shlex.quote(source), timeout_sec=120)
    if result.return_code != 0:
        raise RuntimeError(f"Fixture inspection failed: {result.stderr or result.stdout}")
    return result.stdout or ""


async def snapshot(environment) -> dict:
    return json.loads(await command(environment, SNAPSHOT))


async def validate(environment) -> dict:
    return json.loads(await command(environment, VALIDATE))


def empty(state: dict) -> bool:
    return not state["repo"] and not state["facts"] and not state["fixture"]


class ObservedTrial(SingleStepTrial):
    """Observe lifecycle boundaries and retain the actual Harbor implementation."""

    def __init__(self, *args, **kwargs):
        self.observations = {}
        self.agent_setup_calls = 0
        self.agent_run_calls = 0
        self.fail_startup = False
        self.failure_capture_attempted = False
        super().__init__(*args, **kwargs)

    async def _setup_agent_environment(self) -> None:
        await super()._setup_agent_environment()
        self.observations["before_healthcheck"] = await snapshot(self.agent_environment)
        if self.fail_startup:
            # Create real fixture state. Harbor then executes its normal healthcheck.
            await self.agent_environment.run_healthcheck()
            self.observations["initialized_channels"] = await validate(self.agent_environment)
            await command(self.agent_environment, MUTATE)
            self.observations["before_failure"] = await snapshot(self.agent_environment)

    async def _setup_agent(self) -> None:
        self.agent_setup_calls += 1
        self.observations["before_agent_setup"] = await snapshot(self.agent_environment)
        self.observations["fixture_channels"] = await validate(self.agent_environment)
        await super()._setup_agent()

    async def _run_agent(self) -> None:
        self.agent_run_calls += 1
        await super()._run_agent()

    async def _stop_agent_environment(self) -> None:
        try:
            if self.fail_startup and not self.failure_capture_attempted:
                self.failure_capture_attempted = True
                self.observations["after_failure"] = await snapshot(self.agent_environment)
                target = self.paths.trial_dir / "failed-fixture"
                await self.agent_environment.download_dir(
                    source_dir=self.task.config.environment.workdir,
                    target_dir=target,
                )
                self.observations["preserved_fixture"] = str(target)
        finally:
            await super()._stop_agent_environment()


async def create_trial(tasks: Path, directory: Path, backend: str, case: str, agent: str) -> ObservedTrial:
    config = TrialConfig(
        task=TaskConfig(path=tasks / case),
        trial_name=f"{case}-{agent}-{uuid4().hex[:12]}",
        trials_dir=directory,
        agent=AgentConfig(name=agent),
        environment=EnvironmentConfig(import_path=BACKENDS[backend], delete=True),
    )
    # Harbor 0.24.0 create() selects its concrete trial class. Load the same
    # task, then use a small observer subclass of that concrete class.
    task, downloaded = await ObservedTrial._load_task(config)
    if task.has_steps:
        raise ValueError("The lifecycle cases must use single-step trials.")
    return ObservedTrial(config, _task=task, _task_download_result=downloaded)


async def control(tasks: Path, directory: Path, backend: str, case: str, agent: str, failure: bool = False) -> dict:
    expected = 1.0 if agent == "oracle" else 0.0
    row = {"case": case, "agent": agent, "expected": expected}
    trial = None
    try:
        trial = await create_trial(tasks, directory, backend, case, agent)
        trial.fail_startup = failure
        result = await trial.run()
        require(row, "empty_before_initial_healthcheck", empty(trial.observations.get("before_healthcheck", {"repo": True})))
        row["trial_dir"] = str(trial.paths.trial_dir)
        row["exception"] = result.exception_info.model_dump(mode="json") if result.exception_info else None
        row["reward"] = result.verifier_result.rewards if result.verifier_result else None
        if failure:
            require(row, "healthcheck_failure", result.exception_info is not None and result.exception_info.exception_type == "HealthcheckError")
            require(row, "no_agent_setup", trial.agent_setup_calls == 0 and result.agent_setup is None)
            require(row, "no_agent_run", trial.agent_run_calls == 0 and result.agent_execution is None)
            before = trial.observations.get("before_failure")
            require(row, "existing_fixture", bool(before and before["valid_structure"] and before["marker"]))
            require(row, "fixture_unchanged", before is not None and before == trial.observations.get("after_failure"))
            require(row, "fixture_preserved", "preserved_fixture" in trial.observations)
        else:
            require(row, "no_exception", result.exception_info is None)
            require(row, "expected_reward", row["reward"] == {"reward": expected})
            state = trial.observations.get("before_agent_setup", {})
            require(row, "valid_before_agent_setup", bool(state.get("valid_structure") and trial.observations.get("fixture_channels")))
            require(row, "actual_agent_setup", trial.agent_setup_calls == 1)
            require(row, "actual_agent_run", trial.agent_run_calls == 1)
    except Exception as exc:
        row["error"] = error(exc)
    finally:
        if trial is not None:
            try:
                await trial._stop_agent_environment()
            except Exception as exc:
                row["cleanup_error"] = error(exc)
                require(row, "environment_stopped", False)
            row["observations"] = trial.observations
            row["agent_setup_calls"] = trial.agent_setup_calls
            row["agent_run_calls"] = trial.agent_run_calls
            trial._close_logger_handler()
    row["passed"] = passed(row)
    return row


async def isolation(tasks: Path, directory: Path, backend: str, case: str) -> dict:
    row = {"case": case}
    trials = []
    try:
        for _ in range(2):
            trials.append(await create_trial(tasks, directory, backend, case, "nop"))
        environments = [trial.agent_environment for trial in trials]
        # Await every start before cleanup, even if one backend start fails.
        starts = await asyncio.gather(*(env.start(force_build=False) for env in environments), return_exceptions=True)
        row["start_errors"] = [error(value) if isinstance(value, BaseException) else None for value in starts]
        for value in starts:
            if isinstance(value, BaseException):
                raise value
        row["before"] = await asyncio.gather(*(snapshot(env) for env in environments))
        require(row, "both_empty", all(empty(state) for state in row["before"]))
        checks = await asyncio.gather(*(env.run_healthcheck() for env in environments), return_exceptions=True)
        row["healthcheck_errors"] = [error(value) if isinstance(value, BaseException) else None for value in checks]
        for value in checks:
            if isinstance(value, BaseException):
                raise value
        row["channels"] = await asyncio.gather(*(validate(env) for env in environments))
        row["initialized"] = await asyncio.gather(*(snapshot(env) for env in environments))
        require(row, "both_valid", all(state["valid_structure"] for state in row["initialized"]))
        await command(environments[0], MUTATE)
        row["mutated"] = await asyncio.gather(*(snapshot(env) for env in environments))
        require(row, "fixture_mutated", row["mutated"][0]["marker"] and row["mutated"][0]["fixture"] != row["initialized"][0]["fixture"])
        require(row, "facts_mutated", row["mutated"][0]["facts_sha256"] != row["initialized"][0]["facts_sha256"])
        require(row, "other_unchanged", row["mutated"][1] == row["initialized"][1])
        row["repeat_errors"] = []
        for env in environments:
            try:
                await env.run_healthcheck()
            except HealthcheckError as exc:
                row["repeat_errors"].append(error(exc))
            else:
                row["repeat_errors"].append(None)
        row["after_refusal"] = await asyncio.gather(*(snapshot(env) for env in environments))
        require(row, "both_repeat_checks_fail", all(row["repeat_errors"]))
        require(row, "both_fixtures_unchanged", row["after_refusal"] == row["mutated"])
    except Exception as exc:
        row["error"] = error(exc)
    finally:
        stops = await asyncio.gather(*(trial.agent_environment.stop(delete=True) for trial in trials), return_exceptions=True)
        row["stop_errors"] = [error(value) if isinstance(value, BaseException) else None for value in stops]
        require(row, "environments_stopped", all(value is None for value in row["stop_errors"]))
        for trial in trials:
            trial._close_logger_handler()
    row["passed"] = passed(row)
    return row


async def run(args) -> dict:
    report = {"schema_version": 1, "backend": args.backend, "passed": False, "trials": [], "isolation": [], "startup_failure": []}
    directory = args.output.parent / (args.output.stem + "-trials-" + uuid4().hex[:12])
    directory.mkdir(parents=True)
    for case in CASES:
        for agent in ("oracle", "nop"):
            report["trials"].append(await control(args.tasks, directory, args.backend, case, agent))
        report["isolation"].append(await isolation(args.tasks, directory, args.backend, case))
        report["startup_failure"].append(await control(args.tasks, directory, args.backend, case, "oracle", failure=True))
    report["passed"] = all(row["passed"] for section in ("trials", "isolation", "startup_failure") for row in report[section])
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=tuple(BACKENDS), required=True)
    parser.add_argument("--tasks", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    args.tasks = args.tasks.resolve()
    args.output = args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        report = asyncio.run(run(args))
    except Exception as exc:
        report = {"schema_version": 1, "backend": args.backend, "passed": False, "trials": [], "isolation": [], "startup_failure": [], "error": error(exc)}
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"Lifecycle report: {args.output}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
