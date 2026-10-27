#!/usr/bin/env python3
"""The scenarios of the patchgate Harbor tasks: the setup, the oracle, and the verifier.

    scenarios.py setup NAME DIR   make one repository and its facts in DIR
    scenarios.py solve NAME DIR   the oracle: run patchgate with a scripted model
    scenarios.py check NAME DIR   the verifier: write 1 or 0 to /logs/verifier/reward.txt

Each scenario directory holds repo/, a Pijul repository with its working copy on
the inbox channel, and facts.json, the change hashes that the oracle and the
verifier use. Harbor creates the selected fixture before agent setup.
It runs solve as the oracle agent, and check as the verifier.

The verifier examines the channels, repository files, and patchgate ledger.
The nop agent changes none of these, so it gets reward 0 on each task.
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
    """Record the files in main, then create the inbox channel with `patchgate init --channels-only`."""
    repo = Repo(directory / "repo", signer.env)
    repo.path.mkdir(parents=True)
    repo.pijul("init")
    if files:
        repo.change(files, "Start the project")
    run(PATCHGATE, "init", "--channels-only", cwd=repo.path, env=signer.env)
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


def review_input(body: dict) -> dict:
    """Return structured review data from either model API."""
    state = body["state"] if "state" in body else json.loads(body["messages"][-1]["content"])
    assert isinstance(state, dict), "The review data must be an object."
    assert type(state["schema_version"]) is int and state["schema_version"] == 1, "The review must use schema version 1."
    candidate = state["candidate"]
    assert isinstance(candidate, dict), "The candidate must be an object."
    assert isinstance(candidate["paths"], list), "Candidate paths must be a list."
    assert isinstance(candidate["context"]["files"], list), "Native files must be a list."
    assert isinstance(candidate["metadata_context"], list), "Metadata context must be a list."
    assert state["binding"]["candidates"] == [candidate["hash"]], "The review must bind its candidate."
    assert "policy" not in state, "Policy content must remain in trusted instructions."
    return state


def review_contains(state: dict, path: str, text: str) -> bool:
    """Inspect native vertices and metadata text for a candidate path."""
    candidate = state["candidate"]
    if path not in candidate["paths"]:
        return False
    return any(
        text in vertex["text"]
        for file in candidate["context"]["files"]
        if file["path"] == path
        for vertex in file["vertices"]
        if vertex["kind"] in ("add", "keep")
    ) or any(
        entry["path"] == path and entry["after"] is not None and text in entry["after"]
        for entry in candidate["metadata_context"]
    )



class Model:
    """A scripted model server for the OpenAI and SystemOne APIs."""

    def __init__(self, verdict=None, merge=None, status=200, api="openai", response=None):
        self.verdict = verdict or (lambda system, state: accept("No rule applies."))
        self.merge = merge or (lambda prompt: escalate("This script has no merge."))
        self.status = status
        self.api = api
        self.response = response
        model = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                endpoint = "systemone" if model.api == "systemone" else "chat/completions"
                if self.path != f"/v1/{endpoint}":
                    self.send_error(404)
                    return
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if model.api == "systemone":
                    if "review" in body["questions"]:
                        review_input(body)
                elif body["response_format"]["json_schema"]["name"] != "merge":
                    review_input(body)
                if model.response is not None:
                    reply = model.response(body)
                else:
                    system, user = body["messages"][0]["content"], body["messages"][-1]["content"]
                    if body["response_format"]["json_schema"]["name"] == "merge":
                        content = model.merge(user)
                    else:
                        content = model.verdict(system, review_input(body))
                    if not isinstance(content, str):
                        content = json.dumps(content)
                    reply = {"choices": [{"message": {"role": "assistant", "content": content}}]}
                payload = json.dumps(reply).encode()
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
    env = {**os.environ, "PATCHGATE_MODEL_URL": model.url, "PATCHGATE_MODEL_API": model.api, "PATCHGATE_TIMEOUT": "30", **settings}
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

    def last(self, name: str, decision: str, by: str) -> None:
        records = self.records(name)
        record = records[-1] if records else {}
        self.expect(
            record.get("decision") == decision and record.get("by") == by,
            f"the last decision for {name!r} must be {decision} by {by}, not {record or 'nothing'}",
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
        c.last("fix", "escalate", "gate")


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
        c.last("second", "escalate", "gate")


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
        c.last("theirs", "escalate", "gate")
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
        def verdict(system: str, state: dict) -> dict:
            if review_contains(state, "secret.env", "SECRET"):
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
        def verdict(system: str, state: dict) -> dict:
            if "Reject a change that adds a TODO" in system and review_contains(state, "notes.txt", "TODO"):
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
        c.last("rename", "escalate", "gate")


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
        with Model(verdict=lambda system, state: "It looks fine to me.") as model:
            patchgate(directory / "repo", model, "review")

    def check(self, c: Check) -> None:
        c.outside("main", "notes")
        c.last("notes", "escalate", "gate")


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
        c.last("data", "escalate", "gate")


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


class MultiFileMergeAtomic:
    """A refusal in one file prevents the complete candidate from main."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        repo = start(directory, signer, {"POLICY.md": POLICY, "a.sh": GREETING, "z.sh": GREETING})
        base = repo.pijul("log", "--channel", "main", "--hash-only").split()
        with tempfile.TemporaryDirectory() as temporary:
            author = Repo(Path(temporary) / "author", repo.env)
            run("pijul", "clone", "--channel", "main", repo.path, author.path, env=repo.env)
            first = repo.change({"a.sh": FRENCH, "z.sh": FRENCH}, "Greet in French in both scripts")
            second = author.change({"a.sh": GERMAN, "z.sh": GERMAN}, "Greet in German in both scripts")
            author.pijul("push", repo.path, "--to-channel", "inbox", "--no-notify", "-a")
        return {"first": first, "second": second, "base": base}

    def solve(self, directory: Path) -> None:
        def merge(prompt: str) -> dict:
            if "a.sh" in prompt:
                return {"choice": "both, side 1 first", "reason": "Keep both greetings in this script."}
            return escalate("The owner must decide the other script.")

        with Model(merge=merge) as model:
            result = patchgate(directory / "repo", model, "review")
            assert result.returncode == 0, "The conflict must produce an escalation, not a command error."

    def check(self, c: Check) -> None:
        c.expect(
            c.hashes("main") == set(c.facts["base"]) | {c.facts["first"]},
            "main must contain only the base and the first change, with no partial resolution",
        )
        c.within("inbox", "first", "second")
        c.last("first", "accept", "model")
        c.last("second", "escalate", "gate")
        second = c.records("second")
        c.expect(
            len(second) == 1 and bool(second[0].get("conflict")) and not second[0].get("merge"),
            "the second change must have one conflict escalation and no merge link",
        )
        for path in ("a.sh", "z.sh"):
            c.expect(c.file("main", path) == FRENCH, f"{path} must retain only the first change")
        ledger = c.repo / ".pijul" / "patchgate" / "ledger.jsonl"
        records = [json.loads(line) for line in ledger.read_text().splitlines() if line] if ledger.exists() else []
        c.expect(all(record.get("decision") != "merge" for record in records), "a partial merge must not enter the ledger")
        c.no_conflict("main")


class MergeOutageRetries:
    """A model outage during a merge leaves the candidate available for a later review."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        return MergeOrderConflict().setup(directory, signer)

    def solve(self, directory: Path) -> None:
        repo = directory / "repo"
        ledger = repo / ".pijul" / "patchgate" / "ledger.jsonl"
        snapshot = None

        def response(body: dict) -> dict:
            nonlocal snapshot
            if body["response_format"]["json_schema"]["name"] == "merge":
                snapshot = (Check(directory).hashes("main"), ledger.read_bytes())
                model.status = 503
            return {"choices": [{"message": {"content": json.dumps(accept("No rule applies."))}}]}

        with Model(response=response) as model:
            result = patchgate(repo, model, "review")
            assert result.returncode != 0, "The merge outage must stop the review."
            assert snapshot is not None, "The failed review must reach the merge."
            assert (Check(directory).hashes("main"), ledger.read_bytes()) == snapshot, "The failed merge must preserve main and its ledger."
            model.status = 200
            model.response = None
            model.merge = lambda prompt: {"choice": "both, side 1 first", "reason": "Keep both greetings after recovery."}
            result = patchgate(repo, model, "review")
            assert result.returncode == 0, "The review must succeed after model recovery."

    def check(self, c: Check) -> None:
        MergeOrderConflict().check(c)
        records = c.records("german")
        c.expect(
            [(record.get("decision"), record.get("by")) for record in records] == [("accept", "model")],
            "the failed merge must leave no decision before the successful acceptance",
        )
        link = records[0].get("merge") if len(records) == 1 else None
        ledger = c.repo / ".pijul" / "patchgate" / "ledger.jsonl"
        history = [json.loads(line) for line in ledger.read_text().splitlines() if line] if ledger.exists() else []
        merges = [record for record in history if record.get("decision") == "merge"]
        c.expect(
            len(merges) == 1 and merges[0].get("hash") == link
            and merges[0].get("for") == [c.facts["german"]] and merges[0].get("files") == ["greet.sh"],
            "the accepted candidate must link to one recorded greeting resolution",
        )
        c.expect(
            link is not None and link in c.hashes("main") and link in c.hashes("inbox"),
            "the recorded merge must reach both channels after recovery",
        )


class DirtyInboxMerge:
    """A merge can reach main without loss of unrecorded inbox edits."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        facts = MergeOrderConflict().setup(directory, signer)
        path = directory / "repo" / "greet.sh"
        facts["dirty_text"] = path.read_text() + "echo local-only\n"
        path.write_text(facts["dirty_text"])
        return facts

    def solve(self, directory: Path) -> None:
        with Model(merge=lambda prompt: {"choice": "both, side 1 first", "reason": "Keep both recorded greetings."}) as model:
            result = patchgate(directory / "repo", model, "review")
            assert result.returncode == 0, "The dirty inbox must not prevent a safe merge into main."

    def check(self, c: Check) -> None:
        c.within("main", "french", "german")
        c.no_conflict("main")
        lines = (c.file("main", "greet.sh") or "").splitlines()
        c.expect(
            lines[:2] == ["#!/bin/sh", "echo hello"] and lines[-1:] == ["echo bye"]
            and sorted(lines[2:-1]) == ["echo bonjour", "echo hallo"],
            "main must contain each recorded greeting once, without the local edit",
        )
        c.expect((c.repo / "greet.sh").read_text() == c.facts["dirty_text"], "the complete dirty inbox file must remain unchanged")
        c.last("german", "accept", "model")
        records = c.records("german")
        link = records[-1].get("merge") if records else None
        c.expect(
            link is not None and link in c.hashes("main") and link not in c.hashes("inbox"),
            "the merge must reach main but remain outside the dirty inbox",
        )
        ledger = c.repo / ".pijul" / "patchgate" / "ledger.jsonl"
        history = [json.loads(line) for line in ledger.read_text().splitlines() if line] if ledger.exists() else []
        c.expect(
            any(record.get("hash") == link and record.get("decision") == "merge" for record in history),
            "the successful main resolution must have a merge ledger record",
        )


def workflow_snapshot(repo: Path, channels: tuple[str, ...]) -> tuple:
    ledger = repo / ".pijul" / "patchgate" / "ledger.jsonl"
    hashes = tuple(frozenset(run("pijul", "log", "--channel", name, "--hash-only", cwd=repo).stdout.split()) for name in channels)
    return hashes, ledger.read_bytes() if ledger.exists() else b""


def workflow_require(c: Check) -> None:
    if c.failures:
        raise AssertionError("\n".join(c.failures))


class HumanDependencyOverride:
    """A human must accept the prerequisite before its dependent can enter main."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        repo = start(directory, signer, {"POLICY.md": POLICY})
        prerequisite = repo.change({"secret.env": "SECRET=1\n"}, "Add a secret")
        dependent = repo.change({"secret.env": "SECRET=1\nOTHER=2\n"}, "Extend the secret file")
        return {"prerequisite": prerequisite, "dependent": dependent}

    def solve(self, directory: Path) -> None:
        repo = directory / "repo"
        facts = json.loads((directory / "facts.json").read_text())
        reject = lambda system, state: {"decision": "reject", "summary": "A secret.", "reason": "The policy rejects a secret."}
        with Model(verdict=reject) as model:
            assert patchgate(repo, model, "review").returncode == 0
            c = Check(directory)
            c.outside("main", "prerequisite", "dependent")
            c.last("prerequisite", "reject", "model")
            c.expect(c.records("dependent") == [], "The dependent must have no decision before human acceptance.")
            workflow_require(c)
            before = workflow_snapshot(repo, ("main", "inbox"))
            result = patchgate(repo, model, "accept", facts["dependent"], "--reason", "Accept the dependent.")
            assert result.returncode != 0, "Human acceptance must fail while the prerequisite is absent."
            assert workflow_snapshot(repo, ("main", "inbox")) == before, "Refusal must preserve both channels and the ledger."
            assert patchgate(repo, model, "accept", facts["prerequisite"], "--reason", "The owner permits this secret.").returncode == 0
            model.verdict = lambda system, state: accept("The owner permits this extension.")
            assert patchgate(repo, model, "review").returncode == 0
            assert patchgate(repo, model, "review").returncode == 0

    def check(self, c: Check) -> None:
        c.within("main", "prerequisite", "dependent")
        c.within("inbox", "prerequisite", "dependent")
        c.expect(c.file("main", "secret.env") == "SECRET=1\nOTHER=2\n", "Main must contain the complete extension.")
        c.expect([(r["decision"], r["by"]) for r in c.records("prerequisite")] == [("reject", "model"), ("accept", "human")], "The prerequisite must have a model rejection, then human acceptance.")
        c.expect([(r["decision"], r["by"]) for r in c.records("dependent")] == [("accept", "model")], "The dependent must have exactly one model acceptance.")
        c.no_conflict("main")
        c.no_conflict("inbox")


class RemovedAcceptanceBlocks:
    """A removed acceptance must not restore a prerequisite or permit its dependent."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        repo = start(directory, signer, {"POLICY.md": POLICY})
        prerequisite = repo.change({"base.txt": "base\n"}, "Add the prerequisite")
        dependent = repo.change({"base.txt": "base\ndependent\n"}, "Extend the prerequisite")
        independent = repo.change({"independent.txt": "independent\n"}, "Add an independent file")
        return {"prerequisite": prerequisite, "dependent": dependent, "independent": independent}

    def solve(self, directory: Path) -> None:
        repo = directory / "repo"
        facts = json.loads((directory / "facts.json").read_text())
        with Model() as model:
            assert patchgate(repo, model, "accept", facts["prerequisite"], "--reason", "The owner accepts the prerequisite.").returncode == 0
            before = Check(directory).records("prerequisite")
            run("pijul", "unrecord", "--channel", "main", facts["prerequisite"], cwd=repo)
            c = Check(directory)
            c.outside("main", "prerequisite", "dependent", "independent")
            c.within("inbox", "prerequisite", "dependent", "independent")
            workflow_require(c)
            assert patchgate(repo, model, "review").returncode == 0
            assert patchgate(repo, model, "review").returncode == 0
            assert Check(directory).records("prerequisite") == before, "Review must preserve the original human acceptance."

    def check(self, c: Check) -> None:
        c.outside("main", "prerequisite", "dependent")
        c.within("main", "independent")
        c.within("inbox", "prerequisite", "dependent", "independent")
        c.expect(c.file("main", "base.txt") is None, "Main must not restore the removed file.")
        c.expect(c.file("main", "independent.txt") == "independent\n", "Main must contain the independent file.")
        c.expect(c.file("inbox", "base.txt") == "base\ndependent\n", "Inbox must retain the blocked extension.")
        c.expect([(r["decision"], r["by"]) for r in c.records("prerequisite")] == [("accept", "human")], "The prerequisite must retain only its original human acceptance.")
        c.expect(c.records("dependent") == [], "The blocked dependent must have no decision.")
        c.expect([(r["decision"], r["by"]) for r in c.records("independent")] == [("accept", "model")], "The independent change must have one model acceptance.")
        c.no_conflict("main")
        c.no_conflict("inbox")


class CustomChannelsPolicy:
    """Custom channels and a custom policy path control all gate decisions."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        repo = Repo(directory / "repo", signer.env)
        repo.path.mkdir(parents=True)
        repo.pijul("init")
        repo.change({"review-rules.txt": TODO_POLICY, "POLICY.md": OPEN_POLICY}, "Start the project")
        repo.pijul("channel", "rename", "main", "stable")
        settings = {**signer.env, "PATCHGATE_MAIN": "stable", "PATCHGATE_INBOX": "proposals", "PATCHGATE_POLICY": "review-rules.txt", "PATCHGATE_PROTECTED": ""}
        run(PATCHGATE, "init", "--channels-only", cwd=repo.path, env=settings)
        benign = repo.change({"hello.txt": "hello\n"}, "Add a greeting")
        violation = repo.change({"notes.txt": "TODO: write notes\n"}, "Add notes")
        policy = repo.change({"review-rules.txt": OPEN_POLICY}, "Permit all changes")
        return {"benign": benign, "violation": violation, "policy": policy}

    def solve(self, directory: Path) -> None:
        repo = directory / "repo"
        facts = json.loads((directory / "facts.json").read_text())
        settings = {"PATCHGATE_MAIN": "stable", "PATCHGATE_INBOX": "proposals", "PATCHGATE_POLICY": "review-rules.txt", "PATCHGATE_PROTECTED": ""}

        def verdict(system: str, state: dict) -> dict:
            if "Reject a change that adds a TODO" in system and review_contains(state, "notes.txt", "TODO"):
                return {"decision": "reject", "summary": "A TODO.", "reason": "The custom policy rejects a TODO."}
            return accept("No rule applies.")

        with Model(verdict=verdict) as model:
            assert patchgate(repo, model, "review", **settings).returncode == 0
            c = Check(directory)
            c.within("stable", "benign")
            c.outside("stable", "violation", "policy")
            c.last("violation", "reject", "model")
            c.last("policy", "escalate", "gate")
            c.expect(c.file("stable", "review-rules.txt") == TODO_POLICY, "The target must retain its policy before human acceptance.")
            workflow_require(c)
            assert patchgate(repo, model, "accept", facts["policy"], "--reason", "The owner approves the custom policy.", **settings).returncode == 0
            assert patchgate(repo, model, "review", **settings).returncode == 0

    def check(self, c: Check) -> None:
        channels = {line.strip().lstrip("* ") for line in run("pijul", "channel", cwd=c.repo).stdout.splitlines()}
        c.expect(channels == {"stable", "proposals"}, "Only the custom source and target channels must exist.")
        c.within("stable", "benign", "policy")
        c.outside("stable", "violation")
        c.within("proposals", "benign", "violation", "policy")
        c.expect(c.file("stable", "hello.txt") == "hello\n", "The target must contain the benign file.")
        c.expect(c.file("stable", "notes.txt") is None, "The target must exclude the policy violation.")
        c.expect(c.file("proposals", "notes.txt") == "TODO: write notes\n", "The source must retain the policy violation.")
        for channel in ("stable", "proposals"):
            c.expect(c.file(channel, "review-rules.txt") == OPEN_POLICY, "Both channels must contain the human-approved custom policy.")
            c.expect(c.file(channel, "POLICY.md") == OPEN_POLICY, "The default policy file must remain unchanged.")
            c.no_conflict(channel)
        c.expect([(r["decision"], r["by"]) for r in c.records("benign")] == [("accept", "model")], "The benign change must have one model acceptance.")
        c.expect([(r["decision"], r["by"]) for r in c.records("violation")] == [("reject", "model")], "The custom policy must reject the violation exactly once.")
        c.expect([(r["decision"], r["by"]) for r in c.records("policy")] == [("escalate", "gate"), ("accept", "human")], "The custom policy update must require a human decision.")


def _systemone_answer(question: str, choice: str, confidence: float = 0.91) -> dict:
    return {"answers": {question: {"type": "choice", "choice": choice, "confidence": confidence}}}


def _systemone_ledger(repo: Path) -> list[dict]:
    path = repo / ".pijul" / "patchgate" / "ledger.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line] if path.exists() else []


def _systemone_snapshot(repo: Path) -> tuple:
    hashes = tuple(
        frozenset(run("pijul", "log", "--channel", channel, "--hash-only", cwd=repo).stdout.split())
        for channel in ("main", "inbox")
    )
    ledger = repo / ".pijul" / "patchgate" / "ledger.jsonl"
    return hashes, ledger.read_bytes() if ledger.exists() else None


class SystemOneReviewDecisions:
    """Identified policy rules receive typed answers, and a wrong citation escalates."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        policy = (
            "# Review policy\n\n"
            "1. [R1] Reject a change that adds a TODO.\n"
            "2. [R2] Escalate a change that adds a request for human review.\n"
            "3. [R3] Accept other changes.\n"
        )
        repo = start(directory, signer, {"POLICY.md": policy})
        base = repo.pijul("log", "--channel", "main", "--hash-only").split()
        approved, rejected = concurrent(
            repo,
            ("notes.txt", "public-note-content\n", "Add public notes"),
            ("todo.txt", "TODO: write the report\n", "Add a TODO"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            author = Repo(Path(temporary) / "author", signer.env)
            run("pijul", "clone", "--channel", "main", repo.path, author.path, env=signer.env)
            escalated = author.change({"request.txt": "Request human review: manual-review-content\n"}, "Request a decision")
            author.pijul("push", repo.path, "--to-channel", "inbox", "--no-notify", "-a")
            misquote = author.change({"misquote.txt": "ordinary-content\n"}, "Add ordinary text")
            author.pijul("push", repo.path, "--to-channel", "inbox", "--no-notify", "-a")
        return {
            "approved": approved,
            "rejected": rejected,
            "escalated": escalated,
            "misquote": misquote,
            "base": base,
            "policy": policy,
        }

    def solve(self, directory: Path) -> None:
        def response(body: dict) -> dict:
            state = review_input(body)
            questions = set(body["questions"])
            if review_contains(state, "notes.txt", "public-note-content"):
                labels = {"review": "accept", "rule-R1": "not-covered", "rule-R2": "not-covered", "rule-R3": "allows"}
                path = "notes.txt"
                attacker = False
            elif review_contains(state, "todo.txt", "TODO: write the report"):
                labels = {"review": "reject", "rule-R1": "rejects", "rule-R2": "not-covered", "rule-R3": "not-covered"}
                path = "todo.txt"
                attacker = False
            elif review_contains(state, "request.txt", "manual-review-content"):
                labels = {"review": "escalate", "rule-R1": "not-covered", "rule-R2": "needs-human", "rule-R3": "not-covered"}
                path = "request.txt"
                attacker = False
            elif review_contains(state, "misquote.txt", "ordinary-content"):
                labels = {"review": "accept", "rule-R1": "not-covered", "rule-R2": "not-covered", "rule-R3": "allows"}
                path = "misquote.txt"
                attacker = True
            else:
                raise AssertionError("The review must contain a known change.")
            answers = {}
            for name in questions:
                if name in labels:
                    choice = labels[name]
                elif name == "path":
                    criteria = body["questions"][name]["criteria"]
                    if path not in criteria:
                        raise AssertionError(f"The path question must offer {path}. It offers {sorted(criteria)}.")
                    choice = path
                elif name == "span":
                    criteria = body["questions"][name]["criteria"]
                    if not criteria:
                        raise AssertionError("The span question must offer one native span.")
                    choice = "ATTACKER 0-999" if attacker else next(iter(criteria))
                else:
                    raise AssertionError(f"The scripted model has no answer for {name}.")
                answers[name] = {"type": "choice", "choice": choice, "confidence": 0.93}
            return {"answers": answers}

        with Model(api="systemone", response=response) as model:
            result = patchgate(directory / "repo", model, "review")
            assert result.returncode == 0, "The four reviews must succeed."

    def check(self, c: Check) -> None:
        c.within("main", "approved")
        c.outside("main", "rejected", "escalated", "misquote")
        c.within("inbox", "approved", "rejected", "escalated", "misquote")
        c.expect(c.hashes("main") == set(c.facts["base"]) | {c.facts["approved"]}, "Main must contain only the approved change and its base.")
        c.expect(
            c.hashes("inbox") == set(c.facts["base"]) | {c.facts[name] for name in ("approved", "rejected", "escalated", "misquote")},
            "Inbox must retain all four independent changes.",
        )
        c.expect(c.archive("main")[0] == {"POLICY.md": c.facts["policy"], "notes.txt": "public-note-content\n"}, "Main must contain the policy and exact approved notes only.")
        c.expect(
            c.archive("inbox")[0] == {
                "POLICY.md": c.facts["policy"],
                "notes.txt": "public-note-content\n",
                "todo.txt": "TODO: write the report\n",
                "request.txt": "Request human review: manual-review-content\n",
                "misquote.txt": "ordinary-content\n",
            },
            "Inbox must retain the exact contents of all four changes.",
        )
        for name, decision in (
            ("approved", "accept"),
            ("rejected", "reject"),
            ("escalated", "escalate"),
            ("misquote", "escalate"),
        ):
            c.last(name, decision, "model")
            records = c.records(name)
            c.expect([(record.get("decision"), record.get("by")) for record in records] == [(decision, "model")], f"{name} must have exactly one model decision.")
        c.expect(len(_systemone_ledger(c.repo)) == 4, "The ledger must contain exactly the four model decisions.")
        self._check_answers(c, "approved", ("accept", "not-covered", "not-covered", "allows"), 2)
        self._check_answers(c, "rejected", ("reject", "rejects", "not-covered", "not-covered"), 0)
        self._check_answers(c, "escalated", ("escalate", "not-covered", "needs-human", "not-covered"), 0)
        self._check_answers(c, "misquote", ("accept", "not-covered", "not-covered", "allows"), 1)
        records = c.records("misquote")
        if records:
            misquote = records[-1]
            operations = [answer.get("operation") for answer in misquote.get("answers", [])]
            c.expect("evidence" in operations, "The misquoted change must keep its chosen path.")
            c.expect("ATTACKER 0-999" not in json.dumps(misquote), "A foreign span must not enter the ledger.")
            c.expect("span" in misquote.get("reason", ""), "A foreign span must escalate with its own reason.")
        c.no_conflict("main")
        c.no_conflict("inbox")

    def _check_answers(self, c: Check, name: str, labels: tuple, citations: int) -> None:
        records = c.records(name)
        c.expect(bool(records), f"{name} must have a ledger record.")
        if not records:
            return
        record = records[-1]
        answers = record.get("answers", [])
        c.expect(record.get("decision") is not None, f"{name} must keep its decision.")
        by_question = {answer.get("question"): answer for answer in answers}
        for question, choice in zip(("review", "rule-R1", "rule-R2", "rule-R3"), labels):
            answer = by_question.get(question)
            c.expect(answer is not None, f"{name} must record the answer {question}.")
            if answer is None:
                continue
            c.expect(answer.get("operation") == "review", f"{name} must record {question} in the review operation.")
            c.expect(answer.get("choice") == choice, f"{name} must answer {question} with {choice}.")
            c.expect(answer.get("confidence") == 0.93, f"{name} must keep the probability of {question}.")
        evidence = [answer.get("operation") for answer in answers].count("evidence")
        c.expect(evidence == citations, f"{name} must record {citations} typed citations, not {evidence}.")


class SystemOneMergeConflict:
    """SystemOne reviews both changes and selects both greetings in the merge."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        repo = start(directory, signer, {"POLICY.md": POLICY, "greet.sh": GREETING})
        base = repo.pijul("log", "--channel", "main", "--hash-only").split()
        french, german = concurrent(
            repo, ("greet.sh", FRENCH, "Greet in French"), ("greet.sh", GERMAN, "Greet in German")
        )
        return {"french": french, "german": german, "base": base}

    def solve(self, directory: Path) -> None:
        def response(body: dict) -> dict:
            if "review" in body["questions"]:
                return _systemone_answer("review", "accept")
            return _systemone_answer("merge", "both, side 1 first")

        with Model(api="systemone", response=response) as model:
            result = patchgate(directory / "repo", model, "review")
            assert result.returncode == 0, "The reviews and merge must succeed."

    def check(self, c: Check) -> None:
        c.within("main", "french", "german")
        c.within("inbox", "french", "german")
        c.no_conflict("main")
        c.no_conflict("inbox")
        for channel in ("main", "inbox"):
            files = c.archive(channel)[0]
            lines = files.get("greet.sh", "").splitlines()
            c.expect(
                set(files) == {"POLICY.md", "greet.sh"}
                and files.get("POLICY.md") == POLICY
                and len(lines) == 5
                and lines[:2] == ["#!/bin/sh", "echo hello"]
                and lines[-1:] == ["echo bye"]
                and sorted(lines[2:-1]) == ["echo bonjour", "echo hallo"],
                f"{channel} must contain each greeting exactly once and no other files.",
            )
        records = _systemone_ledger(c.repo)
        accepted = []
        for name in ("french", "german"):
            c.last(name, "accept", "model")
            history = c.records(name)
            c.expect([(record.get("decision"), record.get("by")) for record in history] == [("accept", "model")], f"{name} must have exactly one accepted model review.")
            accepted.extend(history)
        merges = [record for record in records if record.get("decision") == "merge"]
        c.expect(len(records) == 3 and len(merges) == 1, "The ledger must contain two reviews and one real merge.")
        if len(merges) != 1:
            return
        merge = merges[0]
        merge_hash = merge.get("hash")
        linked = [record for record in accepted if record.get("merge") == merge_hash]
        c.expect(merge.get("by") == "model", "The merge must belong to the model decision.")
        c.expect(len(linked) == 1, "One accepted candidate must link to the merge record.")
        if len(linked) == 1:
            c.expect(merge.get("for") == [linked[0]["hash"]], "The merge must identify the accepted candidate.")
            c.expect(records.index(linked[0]) < records.index(merge), "The accepted review record must precede its merge record.")
        c.expect(merge.get("files") == ["greet.sh"], "The merge must identify greet.sh.")
        original = set(c.facts["base"]) | {c.facts["french"], c.facts["german"]}
        c.expect(isinstance(merge_hash, str) and merge_hash not in original, "The merge must have a separate recorded hash.")
        for channel in ("main", "inbox"):
            c.expect(c.hashes(channel) == original | {merge_hash}, f"{channel} must contain the real merge change and both candidates.")


class SystemOneResponseRecovery:
    """Invalid envelopes stop review without decisions. A later valid answer permits recovery."""

    def setup(self, directory: Path, signer: Signer) -> dict:
        repo = start(directory, signer, {"POLICY.md": POLICY})
        base = repo.pijul("log", "--channel", "main", "--hash-only").split()
        benign, unknown = concurrent(
            repo,
            ("notes.txt", "recovery-benign-content\n", "Add recovery notes"),
            ("later.txt", "unknown-choice-content\n", "Add separate notes"),
        )
        return {"benign": benign, "unknown": unknown, "base": base}

    def solve(self, directory: Path) -> None:
        repo = directory / "repo"
        malformed = [
            {"answers": {}},
            {"answers": {"review": {"type": "score", "choice": "accept", "confidence": 0.91}}},
            _systemone_answer("review", "accept", -0.1),
            _systemone_answer("review", "accept", 1.1),
        ]
        for invalid in malformed:
            def response(body: dict) -> dict:
                state = review_input(body)
                if review_contains(state, "notes.txt", "recovery-benign-content"):
                    return invalid
                assert review_contains(state, "later.txt", "unknown-choice-content"), "The request must contain a known change."
                return _systemone_answer("review", "accept")

            before = _systemone_snapshot(repo)
            with Model(api="systemone", response=response) as model:
                result = patchgate(repo, model, "review")
            assert result.returncode != 0, "An invalid answer must abort review."
            assert _systemone_snapshot(repo) == before, "A failed review must preserve both channels and all ledger bytes."

        def recovered(body: dict) -> dict:
            state = review_input(body)
            if review_contains(state, "notes.txt", "recovery-benign-content"):
                return _systemone_answer("review", "accept")
            assert review_contains(state, "later.txt", "unknown-choice-content"), "The request must contain a known change."
            return _systemone_answer("review", "unlisted-choice")

        with Model(api="systemone", response=recovered) as model:
            result = patchgate(repo, model, "review")
            assert result.returncode == 0, "A valid answer must permit review to recover."

    def check(self, c: Check) -> None:
        c.within("main", "benign")
        c.outside("main", "unknown")
        c.within("inbox", "benign", "unknown")
        c.expect(c.hashes("main") == set(c.facts["base"]) | {c.facts["benign"]}, "Main must contain only the recovered benign change and its base.")
        c.expect(c.hashes("inbox") == set(c.facts["base"]) | {c.facts["benign"], c.facts["unknown"]}, "Inbox must retain both pending candidates.")
        c.expect(c.archive("main")[0] == {"POLICY.md": POLICY, "notes.txt": "recovery-benign-content\n"}, "Main must contain only the exact benign content and policy.")
        c.expect(
            c.archive("inbox")[0] == {"POLICY.md": POLICY, "notes.txt": "recovery-benign-content\n", "later.txt": "unknown-choice-content\n"},
            "Inbox must retain both exact candidate contents.",
        )
        c.last("benign", "accept", "model")
        c.last("unknown", "escalate", "gate")
        benign = c.records("benign")
        unknown = c.records("unknown")
        c.expect([(record.get("decision"), record.get("by")) for record in benign] == [("accept", "model")], "Failures must not create benign change decisions.")
        c.expect([(record.get("decision"), record.get("by")) for record in unknown] == [("escalate", "gate")], "The unknown choice must cause exactly one gate escalation.")
        c.expect(len(_systemone_ledger(c.repo)) == 2, "The ledger must contain only the final acceptance and escalation.")
        c.no_conflict("main")
        c.no_conflict("inbox")


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
    "multi-file-merge-atomic": MultiFileMergeAtomic(),
    "merge-outage-retries": MergeOutageRetries(),
    "dirty-inbox-merge": DirtyInboxMerge(),
    "human-dependency-override": HumanDependencyOverride(),
    "removed-acceptance-blocks": RemovedAcceptanceBlocks(),
    "custom-channels-policy": CustomChannelsPolicy(),
    "systemone-review-decisions": SystemOneReviewDecisions(),
    "systemone-merge-conflict": SystemOneMergeConflict(),
    "systemone-response-recovery": SystemOneResponseRecovery(),
}


def setup(name: str, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    if (directory / "repo").exists() or (directory / "facts.json").exists():
        raise RuntimeError(f"The scenario already contains fixture state: {directory}")
    with Signer() as signer:
        facts = SCENARIOS[name].setup(directory, signer)
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
    usage = "usage: scenarios.py setup NAME DIR | solve NAME DIR | check NAME DIR"
    if len(argv) == 3 and argv[0] == "setup" and argv[1] in SCENARIOS:
        setup(argv[1], Path(argv[2]))
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
