use super::support::*;
use parking_lot::Mutex;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Read};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;

pub const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "nix-acceptance",
        setup: setup_acceptance,
        solve,
        check,
    },
    Scenario {
        name: "nix-failed-build",
        setup: setup_failed,
        solve,
        check,
    },
    Scenario {
        name: "nix-combined-failure",
        setup: setup_combined,
        solve,
        check,
    },
    Scenario {
        name: "nix-hostile-definition",
        setup: setup_definition,
        solve,
        check,
    },
    Scenario {
        name: "nix-hostile-input",
        setup: setup_input,
        solve,
        check,
    },
    Scenario {
        name: "nix-main-changed",
        setup: setup_main,
        solve,
        check,
    },
    Scenario {
        name: "nix-timeout",
        setup: setup_timeout,
        solve,
        check,
    },
    Scenario {
        name: "nix-interrupt",
        setup: setup_interrupt,
        solve,
        check,
    },
    Scenario {
        name: "nix-sandbox-exception",
        setup: setup_exception,
        solve,
        check,
    },
];

const BASE: &str = "#!/bin/bash\necho hello\necho bye\n";
const FRENCH: &str = "#!/bin/bash\necho hello\necho bonjour\necho bye\n";
const GERMAN: &str = "#!/bin/bash\necho hello\necho hallo\necho bye\n";
const BAD: &str = "#!/bin/bash\necho hello\necho bonjour\necho hallo\necho bye\n";
const LEDGER: &str = ".pijul/patchgate/ledger.jsonl";
const POLICY: &str =
    "# Review policy\n\nAccept greeting changes. Preserve both contributions in a conflict.\n";
const OBSERVATION: &str = "nix-observations.json";
const EXCLUDED: &[&str] = &[".pijul", ".git", ".devenv", ".direnv", "target", "result"];

fn setup_acceptance(dir: &Path, signer: &Signer) -> Result<Value> {
    setup(dir, signer, "acceptance")
}
fn setup_failed(dir: &Path, signer: &Signer) -> Result<Value> {
    setup(dir, signer, "failed-build")
}
fn setup_combined(dir: &Path, signer: &Signer) -> Result<Value> {
    setup(dir, signer, "combined-failure")
}
fn setup_definition(dir: &Path, signer: &Signer) -> Result<Value> {
    setup(dir, signer, "hostile-definition")
}
fn setup_input(dir: &Path, signer: &Signer) -> Result<Value> {
    setup(dir, signer, "hostile-input")
}
fn setup_main(dir: &Path, signer: &Signer) -> Result<Value> {
    setup(dir, signer, "main-changed")
}
fn setup_timeout(dir: &Path, signer: &Signer) -> Result<Value> {
    setup(dir, signer, "timeout")
}
fn setup_interrupt(dir: &Path, signer: &Signer) -> Result<Value> {
    setup(dir, signer, "interrupt")
}
fn setup_exception(dir: &Path, signer: &Signer) -> Result<Value> {
    setup(dir, signer, "sandbox-exception")
}

fn nix(repo: &Repo, args: &[&str]) -> Result<String> {
    checked_output(
        Command::new("nix")
            .args(["--extra-experimental-features", "nix-command flakes"])
            .args(args)
            .env_clear()
            .envs(repo.env.iter())
            .stdin(Stdio::null())
            .output()?,
        "Execute the real Nix client.",
    )
}

fn store_tree(repo: &Repo, path: &str) -> Result<Value> {
    let info: Value = serde_json::from_str(&nix(repo, &["path-info", "--json", path])?)?;
    let item = info
        .get(path)
        .or_else(|| info.as_array().and_then(|items| items.first()))
        .context("The immutable input has no Nix store record.")?;
    Ok(json!({"path": path, "nar_hash": item["narHash"]}))
}

fn root_path(repo: &Repo, path: &str) -> Result<()> {
    let roots = repo
        .path
        .parent()
        .context("The trial directory is absent.")?
        .join("nix-roots");
    fs::create_dir_all(&roots)?;
    let root = roots.join(
        Path::new(path)
            .file_name()
            .context("The store path has no name.")?,
    );
    checked_output(
        Command::new("nix-store")
            .args(["--realise", "--add-root"])
            .arg(root)
            .args(["--indirect", path])
            .env_clear()
            .envs(repo.env.iter())
            .stdin(Stdio::null())
            .output()?,
        "Retain the trial store path.",
    )?;
    Ok(())
}

fn root_verification(repo: &Repo, record: &Value) -> Result<()> {
    if let Some(results) = record["verification"]["results"].as_array() {
        for result in results {
            root_path(
                repo,
                result["drv_path"]
                    .as_str()
                    .context("The check derivation is absent.")?,
            )?;
            for path in result["outputs"]
                .as_object()
                .context("The check outputs are absent.")?
                .values()
            {
                root_path(repo, path.as_str().context("The output path is absent.")?)?;
            }
        }
    }
    Ok(())
}

fn add_tree(repo: &Repo, path: &Path) -> Result<Value> {
    let path = nix(
        repo,
        &[
            "store",
            "add-path",
            "--name",
            "source",
            path.to_str().context("The source path is not UTF-8.")?,
        ],
    )?;
    root_path(repo, path.trim())?;
    store_tree(repo, path.trim())
}

fn tool_tree(repo: &Repo, name: &str) -> Result<Value> {
    let paths = repo
        .env
        .get(OsStr::new("PATH"))
        .context("The fixture has no tool path.")?;
    let executable = std::env::split_paths(paths)
        .map(|path| path.join(name))
        .find(|path| path.is_file())
        .with_context(|| format!("The fixture needs {name}."))?;
    let executable = executable.canonicalize()?;
    let root = executable
        .parent()
        .and_then(Path::parent)
        .context("The tool has no package directory.")?;
    ensure!(
        root.parent() == Some(Path::new("/nix/store")),
        "The fixture needs a Nix-packaged {name}."
    );
    store_tree(repo, root.to_str().context("The tool path is not UTF-8.")?)
}

fn input(tree: &Value) -> Value {
    json!({"url": format!("path:{}", tree["path"].as_str().unwrap()), "nar_hash": tree["nar_hash"]})
}

fn rules(repo: &Repo, maximum: usize) -> Result<Value> {
    let temporary = tempfile::tempdir()?;
    fs::write(
        temporary.path().join("maximum-lines"),
        format!("{maximum}\n"),
    )?;
    add_tree(repo, temporary.path())
}

fn definition(token: &str, private: &Path, delay: u32, exception: bool) -> String {
    let private = format!("'{}'", private.display().to_string().replace('\'', "'\\''"));
    format!(
        r#"{{ src, system, inputs }}:
assert builtins.getEnv "PATCHGATE_NIX_PRIVATE_TOKEN" == "";
builtins.derivation {{
  name = "patchgate-harbor-{token}";
  inherit system;
  {exception}
  builder = "${{inputs.shell}}/bin/bash";
  args = [ "-e" "-c" ''
    printf '%s\n' PATCHGATE_NIX_BUILD_{token} >&2
    {delay}
    test -z "$SSH_AUTH_SOCK"
    test -z "$PATCHGATE_MODEL_URL"
    test -z "$PATCHGATE_NIX_PRIVATE_TOKEN"
    test ! -e {private}
    test -f ${{src}}/nix/checks.json
    test ! -e ${{src}}/unrecorded.txt
    for item in .pijul .git .devenv .direnv target result; do
      test ! -e "${{src}}/$item"
    done
    for item in ${{src}}/result-*; do
      test ! -e "$item"
    done
    actual="$(${{inputs.shell}}/bin/bash ${{src}}/program.sh)"
    mapfile -t lines <<< "$actual"
    read -r maximum < ${{inputs.rules}}/maximum-lines
    test "''${{#lines[@]}}" -le "$maximum"
    test "''${{lines[0]}}" = hello
    test "''${{lines[-1]}}" = bye
    printf '%s\n' "$actual" > "$out"
  '' ];
}}
"#,
        exception = if exception { "__noChroot = true;" } else { "" },
        delay = if delay == 0 {
            String::new()
        } else {
            format!("${{inputs.coreutils}}/bin/sleep {delay}")
        },
    )
}

fn ledger(repo: &Repo) -> Result<Vec<u8>> {
    match fs::read(repo.path.join(LEDGER)) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

fn snapshot(repo: &Repo) -> Result<Value> {
    let entries: Value = serde_json::from_str(&repo.pijul(&[
        "log",
        "--channel",
        "main",
        "--state",
        "--output-format",
        "json",
    ])?)?;
    let state = entries
        .as_array()
        .context("The native state is not an array.")?
        .first()
        .map(|entry| entry["state"].clone())
        .unwrap_or(Value::Null);
    Ok(json!({
        "hashes": repo.hashes("main")?, "state": state,
        "files": repo.archive("main")?.files, "audit": ledger(repo)?,
    }))
}

fn setup(dir: &Path, signer: &Signer, kind: &str) -> Result<Value> {
    let repo = start(dir, signer, &[("POLICY.md", POLICY), ("program.sh", BASE)])?;
    let seed = repo.change(
        &[("seed.txt", "Preserve this earlier accepted contribution.\n")],
        "Preserve the earlier audit record",
    )?;
    checked_output(
        repo.gate(
            None,
            &[
                "accept",
                &seed,
                "--reason",
                "Preserve the earlier contribution.",
            ],
            &[],
        )?,
        "Accept the audit seed.",
    )?;
    let token_file = tempfile::Builder::new().prefix("nix-").tempfile()?;
    let token = token_file
        .path()
        .file_name()
        .context("The fixture has no unique name.")?
        .to_string_lossy()
        .into_owned();
    let private = dir.canonicalize()?.join("gate-private-marker");
    fs::write(
        &private,
        "This marker must remain outside the Nix sandbox.\n",
    )?;
    let maximum = if kind == "acceptance" { 4 } else { 3 };
    let trees = json!({"shell": tool_tree(&repo, "bash")?, "coreutils": tool_tree(&repo, "sleep")?, "rules": rules(&repo, maximum)?});
    let inputs: serde_json::Map<String, Value> = trees
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, tree)| (name.clone(), input(tree)))
        .collect();
    let manifest = json!({"schema_version": 1, "checks": ["build.nix"], "inputs": inputs});
    let delay = match kind {
        "main-changed" => 3,
        "timeout" | "interrupt" => 30,
        _ => 0,
    };
    let build = definition(&token, &private, delay, kind == "sandbox-exception");
    let manifest_text = serde_json::to_string_pretty(&manifest)?;
    let trusted = repo.change(
        &[
            ("nix/checks.json", &manifest_text),
            ("nix/build.nix", &build),
        ],
        "Define trusted Nix acceptance checks",
    )?;
    repo.pijul(&["apply", "--channel", "main", &trusted])?;
    // Recorded build state must not enter the candidate source tree.
    let state = repo.change(
        &[
            ("target/recorded.txt", "build state\n"),
            ("result-old", "old result\n"),
        ],
        "Record excluded build state",
    )?;
    repo.pijul(&["apply", "--channel", "main", &state])?;
    let (first, candidate, advance) = if matches!(kind, "acceptance" | "combined-failure") {
        let (first, second) = concurrent(
            &repo,
            &[("program.sh", FRENCH)],
            "Add the French greeting",
            &[("program.sh", GERMAN)],
            "Add the German greeting",
        )?;
        (Some(first), second, None)
    } else if kind == "main-changed" {
        let (candidate, advance) = concurrent(
            &repo,
            &[("program.sh", FRENCH)],
            "Add the candidate greeting",
            &[("epoch.txt", "An independent command advances main.\n")],
            "Advance main during the Nix build",
        )?;
        (None, candidate, Some(advance))
    } else {
        let candidate = match kind {
            "hostile-definition" => repo.change(
                &[
                    ("program.sh", BAD),
                    (
                        "nix/build.nix",
                        &build.replace("-le \"$maximum\"", "-le 999"),
                    ),
                ],
                "Replace a trusted check with unconditional permission",
            )?,
            "hostile-input" => {
                let mut replacement = manifest.clone();
                replacement["inputs"]["rules"] = input(&rules(&repo, 999)?);
                repo.change(
                    &[
                        ("program.sh", BAD),
                        (
                            "nix/checks.json",
                            &serde_json::to_string_pretty(&replacement)?,
                        ),
                    ],
                    "Replace the trusted limit input",
                )?
            }
            "failed-build" => {
                repo.change(&[("program.sh", BAD)], "Exceed the trusted greeting limit")?
            }
            _ => repo.change(&[("program.sh", FRENCH)], "Add a valid candidate greeting")?,
        };
        (None, candidate, None)
    };
    fs::write(
        repo.path.join("unrecorded.txt"),
        "This file must not enter a recorded source export.\n",
    )?;
    Ok(
        json!({"kind": kind, "seed": seed, "trusted": trusted, "candidate": candidate, "first": first, "advance": advance,
        "token": token, "inputs": trees, "initial": snapshot(&repo)?, "initial_inbox": repo.hashes("inbox")?}),
    )
}

fn source_tree(repo: &Repo, channel: &str, definitions: bool) -> Result<Value> {
    let temporary = tempfile::tempdir()?;
    for (path, bytes) in repo.archive(channel)?.files {
        let path = if definitions {
            let Some(path) = path.strip_prefix("nix/") else {
                continue;
            };
            path.to_owned()
        } else {
            let top = path
                .split('/')
                .next()
                .context("The archive path is empty.")?;
            if EXCLUDED.contains(&top) || top.starts_with("result-") {
                continue;
            }
            path
        };
        let destination = temporary.path().join(path);
        fs::create_dir_all(
            destination
                .parent()
                .context("The exported path has no parent.")?,
        )?;
        fs::write(destination, bytes)?;
    }
    add_tree(repo, temporary.path())
}

fn expression(source: &Value, definitions: &Value, inputs: &Value) -> Result<String> {
    let context = |tree: &Value| -> Result<String> {
        let path =
            serde_json::to_string(tree["path"].as_str().context("The store path is absent.")?)?;
        Ok(format!(
            "(builtins.appendContext (builtins.fetchTree {{ type = \"path\"; path = {path}; narHash = {}; }}).outPath {{ {path} = {{ path = true; }}; }})",
            serde_json::to_string(
                tree["nar_hash"]
                    .as_str()
                    .context("The input hash is absent.")?
            )?
        ))
    };
    let system = format!(
        "{}-{}",
        std::env::consts::ARCH,
        if cfg!(target_os = "macos") {
            "darwin"
        } else {
            "linux"
        }
    );
    let mut arguments = format!(
        "{{ system = {}; src = {}; inputs = {{ ",
        serde_json::to_string(&system)?,
        context(source)?
    );
    for (name, tree) in inputs
        .as_object()
        .context("The immutable inputs are absent.")?
    {
        arguments.push_str(&format!("{name} = {}; ", context(tree)?));
    }
    arguments.push_str("}; }");
    Ok(format!(
        "import ({} + \"/build.nix\") {arguments}",
        context(definitions)?
    ))
}

fn derivation_path(report: &Value) -> Result<String> {
    let items = report
        .get("derivations")
        .unwrap_or(report)
        .as_object()
        .context("Nix returned no derivation map.")?;
    ensure!(
        items.len() == 1,
        "The fixture check must have one derivation."
    );
    let name = items.keys().next().unwrap();
    Ok(if name.starts_with("/nix/store/") {
        name.clone()
    } else {
        format!("/nix/store/{name}")
    })
}

fn build_independent(repo: &Repo, facts: &Value, hash: &str, kind: &str) -> Result<Value> {
    repo.pijul(&["fork", "--channel", "main", "individual-proof"])?;
    repo.pijul(&["apply", "--channel", "individual-proof", hash])?;
    let source = source_tree(repo, "individual-proof", false)?;
    let definition_channel = if kind == "hostile-definition" {
        "individual-proof"
    } else {
        "main"
    };
    let definitions = source_tree(repo, definition_channel, true)?;
    let mut inputs = facts["inputs"].clone();
    if kind == "hostile-input" {
        let archive = repo.archive("individual-proof")?;
        let manifest: Value = serde_json::from_slice(
            archive
                .files
                .get("nix/checks.json")
                .context("The candidate manifest is absent.")?,
        )?;
        for (name, pin) in manifest["inputs"]
            .as_object()
            .context("The candidate inputs are absent.")?
        {
            let path = pin["url"]
                .as_str()
                .and_then(|url| url.strip_prefix("path:"))
                .context("The candidate input is not an immutable path.")?;
            inputs[name] = store_tree(repo, path)?;
        }
    }
    let expression = expression(&source, &definitions, &inputs)?;
    let output: Value = serde_json::from_str(&nix(
        repo,
        &[
            "build",
            "--no-link",
            "--json",
            "--print-build-logs",
            "--expr",
            &expression,
        ],
    )?)?;
    let path = output[0]["outputs"]["out"]
        .as_str()
        .context("The individual build has no output.")?;
    root_path(repo, path)?;
    let expected = if kind == "combined-failure" {
        "hello\nhallo\nbye\n"
    } else {
        "hello\nbonjour\nhallo\nbye\n"
    };
    let actual = fs::read_to_string(path)?;
    ensure!(
        actual == expected,
        "The independent positive control must pass its real check."
    );
    Ok(json!({"hash": hash, "source": source, "result": output, "output": actual}))
}

fn model(requests: Arc<Mutex<Vec<Value>>>) -> Result<ModelServer> {
    ModelServer::new(move |request| {
        let merge = request.body["response_format"]["json_schema"]["name"] == "merge";
        requests.lock().push(request.body);
        if merge {
            chat_reply(
                json!({"choice": "both, side 1 first", "reason": "Preserve both greeting contributions."}),
            )
        } else {
            chat_reply(verdict("accept"))
        }
    })
}

fn output_evidence(output: &Output) -> Value {
    json!({"exit_code": output.status.code(), "stdout": String::from_utf8_lossy(&output.stdout), "stderr": String::from_utf8_lossy(&output.stderr)})
}

struct Running {
    child: Option<Child>,
    stdout: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
    stderr: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
}

impl Running {
    fn start(mut child: Child, marker: String) -> Result<(Self, mpsc::Receiver<()>)> {
        let mut stdout = child
            .stdout
            .take()
            .context("The command has no stdout pipe.")?;
        let stderr = child
            .stderr
            .take()
            .context("The command has no stderr pipe.")?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let stdout = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes)?;
            Ok(bytes)
        });
        let stderr = thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut bytes = Vec::new();
            let mut line = Vec::new();
            while reader.read_until(b'\n', &mut line)? != 0 {
                if line
                    .windows(marker.len())
                    .any(|part| part == marker.as_bytes())
                {
                    let _ = sender.try_send(());
                }
                bytes.extend_from_slice(&line);
                line.clear();
            }
            Ok(bytes)
        });
        Ok((
            Self {
                child: Some(child),
                stdout: Some(stdout),
                stderr: Some(stderr),
            },
            receiver,
        ))
    }

    fn finish(&mut self) -> Result<Output> {
        let deadline = Instant::now() + Duration::from_secs(120);
        let child = self
            .child
            .as_mut()
            .context("The command process is absent.")?;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            ensure!(
                Instant::now() < deadline,
                "The Nix scenario command did not stop."
            );
            thread::sleep(Duration::from_millis(20));
        };
        self.child.take();
        let stdout = self
            .stdout
            .take()
            .unwrap()
            .join()
            .map_err(|_| anyhow!("The stdout reader failed."))??;
        let stderr = self
            .stderr
            .take()
            .unwrap()
            .join()
            .map_err(|_| anyhow!("The stderr reader failed."))??;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            unsafe {
                libc::kill(child.id() as libc::pid_t, libc::SIGINT);
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            while child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn solve(dir: &Path, _: &RunOptions) -> Result<()> {
    let repo = Repo::open(dir.join("repo"));
    let facts = load_facts(dir)?;
    let kind = facts["kind"]
        .as_str()
        .context("The Nix scenario kind is absent.")?;
    let candidate = facts["candidate"]
        .as_str()
        .context("The candidate hash is absent.")?;
    let requests = Arc::new(Mutex::new(Vec::new()));
    let model = model(Arc::clone(&requests))?;
    let mut observation = json!({"kind": kind});
    if matches!(
        kind,
        "combined-failure" | "hostile-definition" | "hostile-input"
    ) {
        observation["individual"] = build_independent(&repo, &facts, candidate, kind)?;
    }
    if let Some(first) = facts["first"].as_str() {
        let before = snapshot(&repo)?;
        let accepted = repo.gate(
            None,
            &[
                "accept",
                first,
                "--reason",
                "Accept the valid French contribution.",
            ],
            &[],
        )?;
        observation["first_command"] = output_evidence(&accepted);
        checked_output(accepted, "Accept the valid first contribution.")?;
        observation["first_before"] = before;
        observation["first_record"] = repo
            .ledger()?
            .last()
            .cloned()
            .context("The first acceptance record is absent.")?;
        root_verification(&repo, &observation["first_record"])?;
        repo.pijul(&["fork", "--channel", "main", "first-proof"])?;
    }
    if matches!(kind, "hostile-definition" | "hostile-input") {
        let review = repo.gate(Some(&model), &["review"], &[])?;
        observation["protected_review"] = output_evidence(&review);
        checked_output(review, "Escalate the protected Nix replacement.")?;
    }
    observation["before"] = snapshot(&repo)?;
    let extra = [
        (
            "PATCHGATE_CHECK_TIMEOUT",
            if kind == "timeout" { "6" } else { "90" },
        ),
        ("PATCHGATE_NIX_PRIVATE_TOKEN", "fixture-private-value"),
    ];
    let started = Instant::now();
    let output = if matches!(kind, "main-changed" | "interrupt") {
        let args = if kind == "interrupt" {
            vec!["watch", "--interval", "60"]
        } else {
            vec![
                "accept",
                candidate,
                "--reason",
                "Accept the valid candidate.",
            ]
        };
        let marker = format!("PATCHGATE_NIX_BUILD_{}", facts["token"].as_str().unwrap());
        let (mut running, ready) =
            Running::start(repo.spawn_gate(Some(&model), &args, &extra)?, marker)?;
        ready
            .recv_timeout(Duration::from_secs(60))
            .context("The real Nix builder did not reach its barrier.")?;
        observation["builder_reached"] = json!(true);
        if kind == "main-changed" {
            repo.pijul(&[
                "apply",
                "--channel",
                "main",
                facts["advance"]
                    .as_str()
                    .context("The independent change is absent.")?,
            ])?;
            observation["advanced"] = snapshot(&repo)?;
        } else {
            let pid = running.child.as_ref().unwrap().id();
            ensure!(
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGINT) } == 0,
                "Cannot interrupt the watch process."
            );
        }
        let started = Instant::now();
        let output = running.finish()?;
        observation["after_barrier_seconds"] = json!(started.elapsed().as_secs_f64());
        output
    } else if matches!(
        kind,
        "hostile-definition" | "hostile-input" | "timeout" | "sandbox-exception"
    ) {
        repo.gate(
            None,
            &[
                "accept",
                candidate,
                "--reason",
                "Check this candidate through the trusted Nix boundary.",
            ],
            &extra,
        )?
    } else {
        repo.gate(Some(&model), &["review"], &extra)?
    };
    observation["elapsed_seconds"] = json!(started.elapsed().as_secs_f64());
    for record in repo.ledger()? {
        root_verification(&repo, &record)?;
    }
    observation["command"] = output_evidence(&output);
    observation["after"] = snapshot(&repo)?;
    observation["requests"] = json!(*requests.lock());
    fs::write(
        dir.join(OBSERVATION),
        serde_json::to_vec_pretty(&observation)?,
    )?;
    ensure!(
        output.status.success() == (kind == "acceptance"),
        "The Nix scenario returned an unexpected command status."
    );
    Ok(())
}

fn verify_evidence(
    repo: &Repo,
    facts: &Value,
    record: &Value,
    before: &Value,
    channel: &str,
) -> Result<()> {
    let evidence = &record["verification"];
    let hash = record["hash"]
        .as_str()
        .context("The accepted record has no candidate hash.")?;
    ensure!(
        evidence["schema_version"] == 1 && evidence["candidates"] == json!([hash]),
        "The build evidence must bind the exact accepted candidate."
    );
    ensure!(
        evidence["merge"] == record["merge"],
        "The build evidence must bind the actual recorded merge."
    );
    ensure!(
        evidence["main"] == json!({"channel": "main", "state": before["state"]}),
        "The build evidence must bind the reviewed native main state."
    );
    ensure!(
        evidence["inputs"] == facts["inputs"],
        "The build evidence must retain the exact pinned input hashes."
    );
    let source = source_tree(repo, channel, false)?;
    let definitions = source_tree(repo, "main", true)?;
    ensure!(
        evidence["source"] == source,
        "The build evidence must match the independently exported final source."
    );
    ensure!(
        evidence["definitions"] == definitions,
        "The build evidence must match the trusted main definition bytes."
    );
    let expression = expression(&source, &definitions, &facts["inputs"])?;
    let derivation: Value =
        serde_json::from_str(&nix(repo, &["derivation", "show", "--expr", &expression])?)?;
    let results = evidence["results"]
        .as_array()
        .context("The successful evidence has no check results.")?;
    ensure!(
        results.len() == 1
            && results[0]["check"] == "build.nix"
            && results[0]["drv_path"] == derivation_path(&derivation)?,
        "The evidence must identify the exact trusted derivation."
    );
    let path = results[0]["outputs"]["out"]
        .as_str()
        .context("The check has no output path.")?;
    let built: Value = serde_json::from_str(&nix(repo, &["path-info", "--json", path])?)?;
    ensure!(
        built.get(path).is_some()
            || built
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item["path"] == path)),
        "The accepted output must be registered in the real Nix store."
    );
    let source_path = source["path"].as_str().unwrap();
    let output = checked_output(
        Command::new("bash")
            .arg(Path::new(source_path).join("program.sh"))
            .output()?,
        "Execute the accepted recorded source.",
    )?;
    ensure!(
        fs::read_to_string(path)? == output,
        "The realized check output must equal the accepted program behavior."
    );
    Ok(())
}

fn check(check: &mut Check) -> Result<()> {
    let Some(dir) = check.repo.path.parent() else {
        bail!("The scenario directory is absent.")
    };
    let observation = match fs::read(dir.join(OBSERVATION)) {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            check.require(false, "The scenario must record real Nix command evidence.");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let kind = check.facts["kind"]
        .as_str()
        .context("The scenario kind is absent.")?
        .to_owned();
    let current = snapshot(&check.repo)?;
    let candidate = check.facts["candidate"].as_str().unwrap().to_owned();
    let initial_audit: Vec<u8> = serde_json::from_value(check.facts["initial"]["audit"].clone())?;
    check.require(
        ledger(&check.repo)?.starts_with(&initial_audit),
        "The check must preserve every byte of the earlier seed audit.",
    );
    if !matches!(
        kind.as_str(),
        "acceptance" | "combined-failure" | "hostile-definition" | "hostile-input"
    ) {
        check.require(
            observation["before"] == check.facts["initial"],
            "The failed-check boundary must start at the exact initial main and audit state.",
        );
    }
    check.require(
        observation["after"] == current,
        "The saved final evidence must match the actual native state and audit bytes.",
    );
    let mut expected_inbox: BTreeSet<String> =
        serde_json::from_value(check.facts["initial_inbox"].clone())?;
    let mut expected_hashes: BTreeSet<String> =
        serde_json::from_value(check.facts["initial"]["hashes"].clone())?;
    if let Some(first) = check.facts["first"].as_str() {
        expected_hashes.insert(first.to_owned());
    }
    if kind == "main-changed" {
        expected_hashes.insert(check.facts["advance"].as_str().unwrap().to_owned());
    }
    if kind == "acceptance" {
        expected_hashes.insert(candidate.clone());
        for record in check.records("candidate")? {
            if let Some(merge) = record["merge"].as_str() {
                expected_hashes.insert(merge.to_owned());
                expected_inbox.insert(merge.to_owned());
            }
        }
    }
    check.require(
        check.repo.hashes("inbox")? == expected_inbox,
        "Inbox must preserve all original changes and only the verified merge.",
    );
    check.require(
        check.repo.hashes("main")? == expected_hashes,
        "Main must contain exactly the authorized changes and the verified merge.",
    );
    let audit_count = match kind.as_str() {
        "acceptance" => 4,
        "combined-failure" | "hostile-definition" | "hostile-input" => 2,
        _ => 1,
    };
    check.require(
        check.repo.ledger()?.len() == audit_count,
        "The scenario must have exactly the expected complete audit records.",
    );
    check.require(
        !check
            .repo
            .path
            .join(".pijul/patchgate/acceptance.json")
            .exists(),
        "No failed or completed check may leave an acceptance journal.",
    );
    if kind == "acceptance" {
        check.within("main", &["first", "candidate", "seed"])?;
        check.no_conflicts("main")?;
        let records = check.records("candidate")?;
        check.require(
            records.len() == 1,
            "The candidate must have exactly one acceptance record.",
        );
        if let Some(record) = records.first() {
            check.require(
                record["decision"] == "accept" && record["by"] == "model",
                "The successful candidate must retain its model acceptance.",
            );
            let result = verify_evidence(
                &check.repo,
                &check.facts,
                record,
                &observation["before"],
                "main",
            );
            check.require(
                result.is_ok(),
                format!("The merged acceptance evidence is invalid: {result:?}"),
            );
            let merge = record["merge"].as_str().unwrap_or_default();
            let linked = check
                .repo
                .ledger()?
                .into_iter()
                .filter(|entry| {
                    entry["decision"] == "merge"
                        && entry["hash"] == merge
                        && entry["for"] == json!([candidate])
                })
                .count();
            check.require(
                !merge.is_empty() && linked == 1,
                "The successful build must have one actual linked merge record.",
            );
        }
        let program = check.file("main", "program.sh")?.unwrap_or_default();
        let output = checked_output(
            Command::new("bash").arg("-c").arg(&program).output()?,
            "Execute the merged greeting program.",
        )?;
        let lines: Vec<_> = output.lines().collect();
        check.require(
            lines.first() == Some(&"hello")
                && lines.last() == Some(&"bye")
                && lines.iter().filter(|line| **line == "bonjour").count() == 1
                && lines.iter().filter(|line| **line == "hallo").count() == 1
                && lines.len() == 4,
            "The accepted merged source must preserve both greetings exactly once.",
        );
        check.require(
            observation["command"]["exit_code"] == 0,
            "The successful Nix acceptance must return success.",
        );
    } else {
        check.outside("main", &["candidate"])?;
        let expected = if kind == "main-changed" {
            &observation["advanced"]
        } else {
            &observation["before"]
        };
        check.require(&current == expected, "The failed Nix acceptance must preserve exact main state, files, and prior audit bytes.");
        check.require(
            observation["command"]["exit_code"]
                .as_i64()
                .is_some_and(|code| code != 0),
            "A failed Nix acceptance must return a nonzero exit code.",
        );
        check.require(
            check
                .records("candidate")?
                .iter()
                .all(|record| record["decision"] != "accept"),
            "The failed candidate must have no acceptance record.",
        );
        if kind == "combined-failure" {
            check.within("main", &["first", "seed"])?;
            check.require(
                observation["individual"]["hash"] == candidate
                    && observation["individual"]["output"] == "hello\nhallo\nbye\n",
                "The German contribution must pass a real independent build.",
            );
            check.require(
                observation["requests"].as_array().is_some_and(|requests| {
                    requests
                        .iter()
                        .any(|request| request["response_format"]["json_schema"]["name"] == "merge")
                }),
                "The combined failure must follow a real model merge request.",
            );
        }
        if matches!(kind.as_str(), "hostile-definition" | "hostile-input") {
            check.decision("candidate", "escalate", "gate")?;
            check.require(
                observation["requests"] == json!([]),
                "A protected Nix replacement must not reach the model.",
            );
            check.require(
                observation["individual"]["hash"] == candidate
                    && observation["individual"]["output"] == "hello\nbonjour\nhallo\nbye\n",
                "The hostile replacement must pass its independent permissive build.",
            );
        }
        if kind != "sandbox-exception" {
            let marker = format!(
                "PATCHGATE_NIX_BUILD_{}",
                check.facts["token"].as_str().unwrap()
            );
            check.require(
                observation["command"]["stderr"]
                    .as_str()
                    .is_some_and(|text| text.contains(&marker)),
                "The scenario must reach the real sandbox builder before it stops.",
            );
        }
        if kind == "main-changed" {
            check.within("main", &["advance"])?;
            check.require(
                observation["advanced"]["state"] != observation["before"]["state"],
                "The independent Pijul command must change the native main state during the build.",
            );
        }
        if kind == "interrupt" {
            check.require(
                observation["command"]["exit_code"] == 130
                    && observation["after_barrier_seconds"]
                        .as_f64()
                        .is_some_and(|seconds| seconds < 3.0),
                "SIGINT must stop watch with exit 130 within three seconds without acceptance.",
            );
        }
        if kind == "timeout" {
            check.require(
                observation["elapsed_seconds"]
                    .as_f64()
                    .is_some_and(|seconds| (6.0..15.0).contains(&seconds)),
                "The check deadline must stop the real slow build.",
            );
        }
        if kind == "sandbox-exception" {
            check.require(
                observation["command"]["stderr"]
                    .as_str()
                    .is_some_and(|text| {
                        !text.contains(&format!(
                            "PATCHGATE_NIX_BUILD_{}",
                            check.facts["token"].as_str().unwrap()
                        ))
                    }),
                "The forbidden sandbox exception must fail before the real builder starts.",
            );
        }
    }
    if matches!(kind.as_str(), "acceptance" | "combined-failure") {
        let first = check.facts["first"].as_str().unwrap().to_owned();
        check.require(
            check.repo.hashes("first-proof")?.contains(&first),
            "The first proof channel must retain the accepted contribution.",
        );
        let first_record = &observation["first_record"];
        check.require(
            first_record["hash"] == first
                && first_record["decision"] == "accept"
                && first_record["by"] == "human",
            "The first valid contribution must have its real human acceptance record.",
        );
        let result = verify_evidence(
            &check.repo,
            &check.facts,
            first_record,
            &observation["first_before"],
            "first-proof",
        );
        check.require(
            result.is_ok(),
            format!("The first contribution evidence is invalid: {result:?}"),
        );
    }
    Ok(())
}
