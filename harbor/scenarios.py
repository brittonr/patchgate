#!/usr/bin/env python3
"""The scenarios of the patchgate Harbor tasks: the setup, the oracle, and the verifier.

    scenarios.py setup-all DIR    make the repository of each scenario in DIR/<name>
    scenarios.py solve NAME DIR   the oracle: run patchgate with a scripted model
    scenarios.py check NAME DIR   the verifier: write 1 or 0 to /logs/verifier/reward.txt

Each scenario directory holds repo/, a Pijul repository with its working copy on
the inbox channel, and facts.json, the change hashes that the oracle and the
verifier use. The Nix build of harbor/environment.nix runs setup-all. Harbor
runs solve as the oracle agent, and check as the verifier.

The verifier examines only the channels and the patchgate ledger of the
repository. The nop agent changes neither, so it gets reward 0 on each task.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PATCHGATE = os.environ.get("PATCHGATE_BIN", "patchgate")
REWARD = Path("/logs/verifier/reward.txt")

POLICY = "# Review policy\n\nReject a change that adds a secret. Accept other changes.\n"
TODO_POLICY = "# Review policy\n\nReject a change that adds a TODO.\n"
OPEN_POLICY = "# Review policy\n\nAccept every change.\n"
GREETING = "#!/bin/sh\necho hello\necho bye\n"
FRENCH = "#!/bin/sh\necho hello\necho bonjour\necho bye\n"
GERMAN = "#!/bin/sh\necho hello\necho hallo\necho bye\n"
CLEAN = "clean() {\n  rm -rf build\n  rm -f *.log\n}\n\n"
LIBRARY = "setup() {\n  mkdir -p build\n}\n\n" + CLEAN + "main() {\n  setup\n}\n"


def run(*args, cwd=None, env=None, check=True) -> subprocess.CompletedProcess:
    env = {**(os.environ if env is None else env), "NO_COLOR": "1"}
    result = subprocess.run(
        [str(arg) for arg in args], cwd=cwd, env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(map(str, args))} failed: {(result.stderr or result.stdout).strip()}")
    return result


class Signer:
    """A throwaway ssh-agent with a new key. pijul signs each recorded change with a key from an agent."""

    def __enter__(self) -> Signer:
        self.directory = Path(tempfile.mkdtemp(prefix="scenario-"))
        key, socket = self.directory / "key", self.directory / "agent"
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
        self.agent = subprocess.Popen(
            ["ssh-agent", "-D", "-a", str(socket)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        deadline = time.monotonic() + 10
        while not socket.exists():
            if time.monotonic() > deadline:
                raise RuntimeError("ssh-agent did not start")
            time.sleep(0.02)
        (self.directory / "home").mkdir()
        self.env = {**os.environ, "HOME": str(self.directory / "home"), "SSH_AUTH_SOCK": str(socket)}
        self.env.pop("XDG_CONFIG_HOME", None)
        run("ssh-add", "-q", key, env=self.env)
        return self

    def __exit__(self, *exc_info) -> None:
        self.agent.terminate()
        self.agent.wait()
        shutil.rmtree(self.directory, ignore_errors=True)


class Repo:
    """A Pijul repository and the environment that signs its records."""

    def __init__(self, path: Path, env: dict):
        self.path = path
        self.env = env

    def pijul(self, *args) -> str:
        return run("pijul", *args, cwd=self.path, env=self.env).stdout

    def write(self, name: str, text: str) -> None:
        path = self.path / name
        new = not path.exists()
        path.write_text(text)
        if new:
            self.pijul("add", name)

    def record(self, message: str) -> str:
        return self.pijul("record", "-a", "-m", message).split()[-1]

    def change(self, files: dict[str, str], message: str) -> str:
        for name, text in files.items():
            self.write(name, text)
        return self.record(message)


def start(directory: Path, signer: Signer, files: dict[str, str]) -> Repo:
    """Record the files in main, then make the inbox channel with `patchgate init`."""
    repo = Repo(directory / "repo", signer.env)
    repo.path.mkdir(parents=True)
    repo.pijul("init")
    if files:
        repo.change(files, "Start the project")
    run(PATCHGATE, "init", cwd=repo.path, env=signer.env)
    return repo


def concurrent(repo: Repo, ours: tuple[str, str, str], theirs: tuple[str, str, str]) -> tuple[str, str]:
    """Record one change in the inbox. A second author makes another change in a clone of main and pushes it."""
    with tempfile.TemporaryDirectory() as directory:
        author = Repo(Path(directory) / "author", repo.env)
        run("pijul", "clone", "--channel", "main", repo.path, author.path, env=repo.env)
        first = repo.change({ours[0]: ours[1]}, ours[2])
        second = author.change({theirs[0]: theirs[1]}, theirs[2])
        author.pijul("push", repo.path, "--to-channel", "inbox", "--no-notify", "-a")
    return first, second


def accept(reason: str) -> dict:
    return {"decision": "accept", "summary": "A change.", "reason": reason}


def escalate(reason: str) -> dict:
    return {"choice": "escalate", "reason": reason}


class Model:
    """A scripted model server with an OpenAI-compatible API. patchgate is its client."""

    def __init__(self, verdict=None, merge=None, status=200):
        self.verdict = verdict or (lambda system, change: accept("No rule applies."))
        self.merge = merge or (lambda prompt: escalate("This script has no merge."))
        self.status = status
        model = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                system, user = body["messages"][0]["content"], body["messages"][-1]["content"]
                if body["response_format"]["json_schema"]["name"] == "merge":
                    content = model.merge(user)
                else:
                    content = model.verdict(system, user)
                if not isinstance(content, str):
                    content = json.dumps(content)
                payload = json.dumps({"choices": [{"message": {"role": "assistant", "content": content}}]}).encode()
                if model.status != 200:
                    payload = b'{"error": "scripted failure"}'
                self.send_response(model.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/v1"

    def __enter__(self) -> Model:
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.server.shutdown()
        self.server.server_close()


def patchgate(repo: Path, model: Model, *args, **settings) -> subprocess.CompletedProcess:
    """Run patchgate against the scripted model. Show its output in the agent log."""
    env = {**os.environ, "PATCHGATE_MODEL_URL": model.url, "PATCHGATE_TIMEOUT": "30", **settings}
    result = run(PATCHGATE, *args, cwd=repo, env=env, check=False)
    print(f"$ patchgate {' '.join(args)}  (exit {result.returncode})")
    print(result.stdout, result.stderr, sep="", end="", flush=True)
    return result


class Check:
    """The facts of one scenario repository, and the failures that the verifier finds."""

    def __init__(self, directory: Path):
        self.repo = directory / "repo"
        self.facts = json.loads((directory / "facts.json").read_text())
        self.failures: list[str] = []

    def expect(self, ok: bool, message: str) -> None:
        if not ok:
            self.failures.append(message)

    def hashes(self, channel: str) -> set[str]:
        return set(run("pijul", "log", "--channel", channel, "--hash-only", cwd=self.repo).stdout.split())

    def within(self, channel: str, *names: str) -> None:
        hashes = self.hashes(channel)
        for name in names:
            self.expect(self.facts[name] in hashes, f"{channel} must have the change {name!r}")

    def outside(self, channel: str, *names: str) -> None:
        hashes = self.hashes(channel)
        for name in names:
            self.expect(self.facts[name] not in hashes, f"{channel} must not have the change {name!r}")

    def archive(self, channel: str) -> tuple[dict[str, str], str]:
        """Return the files of a channel and the messages of pijul, which report each conflict."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "channel.tar.gz"
            messages = run("pijul", "archive", "--channel", channel, "-o", path, cwd=self.repo).stderr
            with tarfile.open(path) as tar:
                files = {m.name: tar.extractfile(m).read().decode() for m in tar.getmembers() if m.isfile()}
        return files, messages

    def no_conflict(self, channel: str) -> None:
        _, messages = self.archive(channel)
        self.expect("conflict" not in messages, f"{channel} must have no conflict: {messages.strip()}")

    def file(self, channel: str, path: str) -> str | None:
        return self.archive(channel)[0].get(path)

    def records(self, name: str) -> list[dict]:
        """Return the ledger records of a change, oldest first."""
        ledger = self.repo / ".pijul" / "patchgate" / "ledger.jsonl"
        lines = ledger.read_text().splitlines() if ledger.exists() else []
        return [r for r in map(json.loads, filter(None, lines)) if r["hash"] == self.facts[name]]

    def last(self, name: str, decision: str, by: str, text: str = "") -> None:
        records = self.records(name)
        record = records[-1] if records else {}
        self.expect(
            record.get("decision") == decision and record.get("by") == by and text in record.get("reason", ""),
            f"the last decision for {name!r} must be {decision} by {by} with {text!r}, not {record or 'nothing'}",
        )


class MergeOrderConflict:
    """Two authors change the same line of greet.sh. The model keeps both greetings."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        repo = start(directory, signer, {"POLICY.md": POLICY, "greet.sh": GREETING})
        french, german = concurrent(
            repo, ("greet.sh", FRENCH, "Greet in French"), ("greet.sh", GERMAN, "Greet in German")
        )
        return {"french": french, "german": german}

    def solve(self, directory: Path) -> None:
        def merge(prompt: str) -> dict:
            if "order conflict" in prompt and '"both, side 1 first"' in prompt and "echo hallo" in prompt:
                return {"choice": "both, side 1 first", "reason": "Both greetings stay."}
            return escalate("The prompt does not offer both greetings.")

        with Model(merge=merge) as model:
            patchgate(directory / "repo", model, "review")

    def check(self, c: Check) -> None:
        c.within("main", "french", "german")
        c.no_conflict("main")
        c.no_conflict("inbox")
        lines = (c.file("main", "greet.sh") or "").splitlines()
        c.expect(
            lines[:2] == ["#!/bin/sh", "echo hello"]
            and lines[-1:] == ["echo bye"]
            and sorted(lines[2:-1]) == ["echo bonjour", "echo hallo"],
            f"greet.sh in main must keep both greetings: {lines}",
        )


def deletion_conflict(directory: Path, signer: Signer) -> dict:
    """One author removes the clean function of lib.sh. Another author edits a line of that function."""
    repo = start(directory, signer, {"POLICY.md": POLICY, "lib.sh": LIBRARY})
    removal, fix = concurrent(
        repo,
        ("lib.sh", LIBRARY.replace(CLEAN, ""), "Remove the unused clean function"),
        ("lib.sh", LIBRARY.replace("rm -rf build\n", "rm -rf build dist\n"), "Also clean the dist directory"),
    )
    return {"removal": removal, "fix": fix}


class MergeDeletionConflict:
    """The model keeps the edit. The gate writes the deleted function again, with the edited line in it."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        return deletion_conflict(directory, signer)

    def solve(self, directory: Path) -> None:
        def merge(prompt: str) -> dict:
            # The removal is not a side of the conflict. The prompt must show the lines that it removed.
            restore = "restore the deleted lines with the edit"
            if "deletion conflict" in prompt and "- clean() {" in prompt and json.dumps(restore) in prompt:
                return {"choice": restore, "reason": "The dist cleanup is in use, so the function stays."}
            return escalate("The prompt does not offer to restore the function.")

        with Model(merge=merge) as model:
            patchgate(directory / "repo", model, "review")

    def check(self, c: Check) -> None:
        c.within("main", "removal", "fix")
        c.no_conflict("main")
        c.no_conflict("inbox")
        expected = LIBRARY.replace("rm -rf build\n", "rm -rf build dist\n")
        c.expect(c.file("main", "lib.sh") == expected, f"lib.sh in main must keep the edited function: {c.file('main', 'lib.sh')!r}")


class UnsafeMergeEscalates:
    """The model keeps the edited line without the function around it, as a real 27B model did.

    The edit replaced a line that the removal deleted, so that line alone is not a merge that the gate offers.
    """

    def setup(self, directory: Path, signer: Signer) -> dict:
        return deletion_conflict(directory, signer)

    def solve(self, directory: Path) -> None:
        with Model(merge=lambda prompt: {"choice": "keep the inserted lines", "reason": "Keep the cleanup."}) as model:
            patchgate(directory / "repo", model, "review")

    def check(self, c: Check) -> None:
        c.within("main", "removal")
        c.outside("main", "fix")
        c.no_conflict("main")
        c.expect(c.file("main", "lib.sh") == LIBRARY.replace(CLEAN, ""), f"lib.sh in main must be the removal: {c.file('main', 'lib.sh')!r}")
        c.last("fix", "escalate", "gate", "is not one of the choices")


class ValueConflictEscalates:
    """Two authors set the port to two different values. The gate gives the model no choice.

    A real 27B model kept one value because it was the change under review, so only a human can choose a value.
    """

    def setup(self, directory: Path, signer: Signer) -> dict:
        repo = start(directory, signer, {"POLICY.md": POLICY, "server.conf": "port = 80\nhost = localhost\n"})
        first, second = concurrent(
            repo,
            ("server.conf", "port = 8080\nhost = localhost\n", "Serve on port 8080"),
            ("server.conf", "port = 9090\nhost = localhost\n", "Serve on port 9090"),
        )
        return {"first": first, "second": second}

    def solve(self, directory: Path) -> None:
        with Model(merge=lambda prompt: {"choice": "only side 2", "reason": "The change under review wins."}) as model:
            patchgate(directory / "repo", model, "review")

    def check(self, c: Check) -> None:
        c.within("main", "first")
        c.outside("main", "second")
        c.no_conflict("main")
        c.expect(c.file("main", "server.conf") == "port = 8080\nhost = localhost\n", "server.conf in main must keep port 8080")
        c.last("second", "escalate", "gate", "replace the same lines")


class HumanResolvesConflict:
    """The model escalates a conflict. A human records a resolution and accepts it."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        return MergeOrderConflict().setup(directory, signer)

    def solve(self, directory: Path) -> None:
        repo = directory / "repo"
        with Model(merge=lambda prompt: escalate("Both changes set the greeting.")) as model:
            patchgate(repo, model, "review")
            with Signer() as human:
                (repo / "greet.sh").write_text(GERMAN)
                resolution = Repo(repo, human.env).record("Keep the German greeting")
            patchgate(repo, model, "accept", resolution[:12], "--reason", "The owner keeps the German greeting.")

    def check(self, c: Check) -> None:
        c.within("main", "french", "german")
        c.no_conflict("main")
        c.expect(c.file("main", "greet.sh") == GERMAN, f"greet.sh in main must be German: {c.file('main', 'greet.sh')!r}")
        records = c.records("german")
        c.expect(
            [r["decision"] for r in records] == ["escalate", "accept"]
            and bool(records[0].get("conflict"))
            and records[-1]["by"] == "human",
            f"the German change must be escalated for its conflict, then accepted by a human: {records}",
        )


class NameConflictEscalates:
    """Two authors add a file with the same name. The model does not merge names."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        repo = start(directory, signer, {"POLICY.md": POLICY})
        ours, theirs = concurrent(
            repo, ("notes.md", "from the inbox\n", "Add notes"), ("notes.md", "from the author\n", "Add other notes")
        )
        return {"ours": ours, "theirs": theirs}

    def solve(self, directory: Path) -> None:
        merge = lambda prompt: {"choice": "both, side 1 first", "reason": "This script merges anything."}
        with Model(merge=merge) as model:
            patchgate(directory / "repo", model, "review")

    def check(self, c: Check) -> None:
        c.within("main", "ours")
        c.outside("main", "theirs")
        c.last("theirs", "escalate", "gate", "Name conflict")
        ledger = c.repo / ".pijul" / "patchgate" / "ledger.jsonl"
        records = [json.loads(line) for line in ledger.read_text().splitlines() if line]
        c.expect(all(record.get("decision") != "merge" for record in records), "the model must not merge a name conflict")


class RejectedDependencyBlocks:
    """The model rejects a secret. The change that needs the secret never reaches the model."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        repo = start(directory, signer, {"POLICY.md": POLICY})
        return {
            "greeting": repo.change({"hello.txt": "hello\n"}, "Add a greeting"),
            "secret": repo.change({"secret.env": "SECRET=1\n"}, "Add a secret"),
            "extend": repo.change({"secret.env": "SECRET=1\nOTHER=2\n"}, "Extend the secret file"),
            "world": repo.change({"hello.txt": "hello\nworld\n"}, "Greet the world"),
        }

    def solve(self, directory: Path) -> None:
        def verdict(system: str, change: str) -> dict:
            if "SECRET" in change:
                return {"decision": "reject", "summary": "A secret.", "reason": "Rule 1: the change adds a secret."}
            return accept("No rule applies.")

        with Model(verdict=verdict) as model:
            patchgate(directory / "repo", model, "review")
            patchgate(directory / "repo", model, "review")

    def check(self, c: Check) -> None:
        c.within("main", "greeting", "world")
        c.outside("main", "secret", "extend")
        c.last("secret", "reject", "model")
        c.expect(c.records("extend") == [], "patchgate must not decide on a change that needs a rejected change")


class PolicyChangeNeedsHuman:
    """A change to the policy waits for a human. Reviews use the policy of main, not the new one."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        repo = start(directory, signer, {"POLICY.md": TODO_POLICY})
        return {
            "policy": repo.change({"POLICY.md": OPEN_POLICY}, "Accept every change"),
            "notes": repo.change({"notes.txt": "TODO: write the notes\n"}, "Add notes"),
        }

    def solve(self, directory: Path) -> None:
        def verdict(system: str, change: str) -> dict:
            if "Reject a change that adds a TODO" in system and "TODO" in change:
                return {"decision": "reject", "summary": "A TODO.", "reason": "The policy rejects a TODO."}
            return accept("No rule applies.")

        facts = json.loads((directory / "facts.json").read_text())
        with Model(verdict=verdict) as model:
            patchgate(directory / "repo", model, "review")
            patchgate(directory / "repo", model, "accept", facts["policy"][:12], "--reason", "The owner wrote it.")

    def check(self, c: Check) -> None:
        c.outside("main", "notes")
        c.last("notes", "reject", "model")
        c.within("main", "policy")
        c.expect(c.file("main", "POLICY.md") == OPEN_POLICY, "POLICY.md in main must be the new policy")
        records = c.records("policy")
        c.expect(
            [(r["decision"], r["by"]) for r in records] == [("escalate", "gate"), ("accept", "human")],
            f"the policy change must go to a human: {records}",
        )


class RenameOntoProtectedPath:
    """A rename puts a file on a protected path. `pijul log --files` shows only the old name."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        repo = start(directory, signer, {"POLICY.md": POLICY})
        draft = repo.change({"draft.nix": "{ }\n"}, "Add a draft")
        repo.pijul("move", "draft.nix", "devenv.nix")
        return {"draft": draft, "rename": repo.record("Use the draft")}

    def solve(self, directory: Path) -> None:
        with Model() as model:
            patchgate(directory / "repo", model, "review", PATCHGATE_PROTECTED="devenv.nix")

    def check(self, c: Check) -> None:
        c.within("main", "draft")
        c.outside("main", "rename")
        c.last("rename", "escalate", "gate", "devenv.nix")


class ModelOutageDecidesNothing:
    """The model server fails. patchgate decides nothing until the server works again."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        repo = start(directory, signer, {"POLICY.md": POLICY})
        return {"notes": repo.change({"notes.txt": "notes\n"}, "Add notes")}

    def solve(self, directory: Path) -> None:
        with Model(status=500) as model:
            patchgate(directory / "repo", model, "review")
            model.status = 200
            patchgate(directory / "repo", model, "review")

    def check(self, c: Check) -> None:
        c.within("main", "notes")
        decisions = [r["decision"] for r in c.records("notes")]
        c.expect(decisions == ["accept"], f"the outage must not decide on the change: {decisions}")


class InvalidReplyEscalates:
    """The model replies without a verdict. patchgate escalates the change and does not accept it."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        repo = start(directory, signer, {"POLICY.md": POLICY})
        return {"notes": repo.change({"notes.txt": "notes\n"}, "Add notes")}

    def solve(self, directory: Path) -> None:
        with Model(verdict=lambda system, change: "It looks fine to me.") as model:
            patchgate(directory / "repo", model, "review")

    def check(self, c: Check) -> None:
        c.outside("main", "notes")
        c.last("notes", "escalate", "gate", "not a valid verdict")


class LongChangeEscalates:
    """A change is longer than the model limit. patchgate escalates it without the model."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        repo = start(directory, signer, {"POLICY.md": POLICY})
        return {"data": repo.change({"data.txt": "x" * 3000 + "\n"}, "Add data")}

    def solve(self, directory: Path) -> None:
        with Model() as model:
            patchgate(directory / "repo", model, "review", PATCHGATE_MAX_CHANGE_CHARS="1000")

    def check(self, c: Check) -> None:
        c.outside("main", "data")
        c.last("data", "escalate", "gate", "model limit")


class NewInboxRootChange:
    """The inbox starts before main has a change. The root change lands, and the model waits for a policy."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        repo = start(directory, signer, {})
        notes = repo.change({"notes.txt": "notes\n"}, "Add notes")
        policy = repo.change({"POLICY.md": POLICY}, "Add the review policy")
        root = json.loads(repo.pijul("log", "--channel", "inbox", "--output-format", "json"))[-1]["hash"]
        return {"root": root, "notes": notes, "policy": policy}

    def solve(self, directory: Path) -> None:
        facts = json.loads((directory / "facts.json").read_text())
        with Model() as model:
            patchgate(directory / "repo", model, "review")
            patchgate(directory / "repo", model, "accept", facts["policy"][:12])
            patchgate(directory / "repo", model, "review")

    def check(self, c: Check) -> None:
        c.within("main", "root", "notes", "policy")
        c.last("root", "accept", "gate")
        c.last("policy", "accept", "human")
        c.last("notes", "accept", "model")


SCENARIOS = {
    "merge-order-conflict": MergeOrderConflict(),
    "merge-deletion-conflict": MergeDeletionConflict(),
    "unsafe-merge-escalates": UnsafeMergeEscalates(),
    "value-conflict-escalates": ValueConflictEscalates(),
    "human-resolves-conflict": HumanResolvesConflict(),
    "name-conflict-escalates": NameConflictEscalates(),
    "rejected-dependency-blocks": RejectedDependencyBlocks(),
    "policy-change-needs-human": PolicyChangeNeedsHuman(),
    "rename-onto-protected-path": RenameOntoProtectedPath(),
    "model-outage-decides-nothing": ModelOutageDecidesNothing(),
    "invalid-reply-escalates": InvalidReplyEscalates(),
    "long-change-escalates": LongChangeEscalates(),
    "new-inbox-root-change": NewInboxRootChange(),
}


def setup_all(root: Path) -> None:
    with Signer() as signer:
        for name, scenario in SCENARIOS.items():
            directory = root / name
            directory.mkdir(parents=True)
            facts = scenario.setup(directory, signer)
            (directory / "facts.json").write_text(json.dumps(facts, indent=2, sort_keys=True) + "\n")


def check(name: str, directory: Path) -> None:
    try:
        c = Check(directory)
        SCENARIOS[name].check(c)
        failures = c.failures
    except Exception:
        failures = [traceback.format_exc()]
    for failure in failures:
        print(f"FAIL: {failure}")
    REWARD.parent.mkdir(parents=True, exist_ok=True)
    REWARD.write_text("0\n" if failures else "1\n")
    print("reward:", 0 if failures else 1)


def main(argv: list[str]) -> int:
    usage = "usage: scenarios.py setup-all DIR | solve NAME DIR | check NAME DIR"
    if len(argv) == 2 and argv[0] == "setup-all":
        setup_all(Path(argv[1]))
    elif len(argv) == 3 and argv[0] == "solve" and argv[1] in SCENARIOS:
        SCENARIOS[argv[1]].solve(Path(argv[2]))
    elif len(argv) == 3 and argv[0] == "check" and argv[1] in SCENARIOS:
        check(argv[1], Path(argv[2]))
    else:
        print(usage, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
