use super::support::*;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;

pub const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "structured-review-context",
        setup: setup_context,
        solve: solve_context,
        check: check_context,
    },
    Scenario {
        name: "structured-review-binding",
        setup: setup_binding,
        solve: solve_binding,
        check: check_binding,
    },
    Scenario {
        name: "structured-context-limit",
        setup: setup_limit,
        solve: solve_limit,
        check: check_limit,
    },
];

const CONTEXT_POLICY: &str =
    "# Review policy\n\nReject a change that adds SECRET_TOKEN. Accept other changes.\n";
const BINDING_POLICY: &str =
    "# Review policy\n\nAccept the release notes.\n\nPreserve this exact policy text.  \n";
const NESTED: &str = "src/nested/release.txt";
const ORIGINAL: &str = "Release: draft\nOwner: café\nKeep this exact context.\n";
const APPROVED: &str = "Release: approved\nOwner: café\nKeep this exact context.\n";
const SECRET: &str =
    "Release: approved\nOwner: café\nSECRET_TOKEN=not-for-main\nKeep this exact context.\n";
const OLD_PATH: &str = "docs/archive/source.txt";
const NEW_PATH: &str = "docs/releases/renamed.txt";
const RENAMED: &str = "The release guide retains its exact text.\nUnicode: naïve café.\n";
const FIRST: &str = "Release one is ready.\n";
const SECOND: &str = "Release two is ready.\n";
const LARGE_PATH: &str = "docs/reference/large.txt";
const LIMIT: usize = 4000;
const BINARY_PATH: &str = "assets/raw/payload.bin";
const BINARY: &[u8] = &[0xff, 0xfe, 0x00, 0x80, 0x41, 0x0a];

fn native_state(repo: &Repo, channel: &str) -> Result<Value> {
    let entries: Value = serde_json::from_str(&repo.pijul(&[
        "log",
        "--channel",
        channel,
        "--state",
        "--output-format",
        "json",
    ])?)?;
    let entries = entries
        .as_array()
        .context("The native log is not an array.")?;
    match entries.first() {
        None => Ok(Value::Null),
        Some(entry) => Ok(json!(
            entry["state"]
                .as_str()
                .context("The native state is absent.")?
        )),
    }
}

fn isolated(repo: &Repo, hash: &str, target: &Path) -> Result<Repo> {
    checked_output(
        Command::new("pijul")
            .args(["init", "--channel", "inbox"])
            .arg(target)
            .env_clear()
            .envs(repo.env.iter())
            .stdin(Stdio::null())
            .output()?,
        "Create the isolated native candidate repository.",
    )?;
    let candidate = Repo {
        path: target.to_owned(),
        env: Arc::clone(&repo.env),
    };
    for stored in repo.hashes("inbox")? {
        let relative = Path::new(".pijul/changes")
            .join(&stored[..2])
            .join(format!("{}.change", &stored[2..]));
        let source = repo.path.join(&relative);
        let destination = candidate.path.join(relative);
        fs::create_dir_all(
            destination
                .parent()
                .context("The change directory is absent.")?,
        )?;
        if let Err(error) = fs::hard_link(&source, &destination) {
            if error.kind() != std::io::ErrorKind::CrossesDevices {
                return Err(error.into());
            }
            fs::copy(source, destination)?;
        }
    }
    let file = candidate
        .path
        .join(".pijul/changes")
        .join(&hash[..2])
        .join(format!("{}.change", &hash[2..]));
    candidate.pijul(&[
        "apply",
        file.to_str().context("The change path is not UTF-8.")?,
    ])?;
    Ok(candidate)
}

fn native_context(repo: &Repo, hash: &str) -> Result<Value> {
    let temporary = tempfile::tempdir()?;
    let candidate = isolated(repo, hash, &temporary.path().join("candidate"))?;
    let mut context: Value =
        serde_json::from_str(&candidate.pijul(&["change", "--context", hash])?)?;
    for file in context["files"]
        .as_array_mut()
        .context("Native context files are absent.")?
    {
        file.as_object_mut()
            .context("A native context file is not an object.")?
            .remove("folds");
    }
    Ok(context)
}

fn setup_context(dir: &Path, signer: &Signer) -> Result<Value> {
    let repo = start(
        dir,
        signer,
        &[
            ("POLICY.md", CONTEXT_POLICY),
            (NESTED, ORIGINAL),
            (OLD_PATH, RENAMED),
        ],
    )?;
    let base = repo.hashes("main")?;
    let candidate = repo.change(&[(NESTED, APPROVED)], "Approve the nested release")?;
    let later = repo.change(
        &[(NESTED, SECRET)],
        "Add a secret after the release candidate",
    )?;
    fs::create_dir_all(repo.path.join("docs/releases"))?;
    repo.pijul(&["move", "--", OLD_PATH, NEW_PATH])?;
    let rename = repo.record("Move the release guide without text changes")?;
    let context = native_context(&repo, &candidate)?;
    ensure!(
        !context.to_string().contains("SECRET_TOKEN"),
        "The isolated candidate must exclude the later secret."
    );
    let full: Value = serde_json::from_str(&repo.pijul(&["change", "--context", &candidate])?)?;
    ensure!(
        full.to_string().contains("SECRET_TOKEN"),
        "The full inbox must expose the later edit for this isolation case."
    );
    ensure!(
        native_context(&repo, &rename)?["files"] == json!([]),
        "The rename must need native archive context."
    );
    fs::create_dir_all(repo.path.join("assets/raw"))?;
    fs::write(repo.path.join(BINARY_PATH), BINARY)?;
    repo.pijul(&["add", "--", BINARY_PATH])?;
    let binary = repo.record("Add invalid UTF-8 data for a human review")?;
    Ok(
        json!({"base": base, "candidate": candidate, "later": later, "rename": rename, "binary": binary}),
    )
}

fn setup_binding(dir: &Path, signer: &Signer) -> Result<Value> {
    let repo = start(
        dir,
        signer,
        &[
            ("POLICY.md", BINDING_POLICY),
            ("notes/release.txt", "No release is ready.\n"),
        ],
    )?;
    let base = repo.hashes("main")?;
    let initial_state = native_state(&repo, "main")?;
    let first = repo.change(&[("notes/release.txt", FIRST)], "Prepare release one")?;
    let second = repo.change(&[("notes/release.txt", SECOND)], "Prepare release two")?;
    let temporary = tempfile::tempdir()?;
    let first_repo = isolated(&repo, &first, &temporary.path().join("first"))?;
    let first_state = native_state(&first_repo, "inbox")?;
    ensure!(
        initial_state != first_state,
        "The first candidate must change the native state."
    );
    Ok(
        json!({"base": base, "first": first, "second": second, "initial_state": initial_state, "first_state": first_state}),
    )
}

fn large_text() -> String {
    let mut text = String::new();
    for index in 0..900 {
        text.push_str(&format!(
            "Reference row {index:04}: retain the complete native context.\n"
        ));
    }
    text
}

fn setup_limit(dir: &Path, signer: &Signer) -> Result<Value> {
    let original = large_text();
    let repo = start(
        dir,
        signer,
        &[("POLICY.md", POLICY), (LARGE_PATH, &original)],
    )?;
    let base = repo.hashes("main")?;
    let edited = original.replacen("Reference row 0450:", "Reference row 0450 revised:", 1);
    let candidate = repo.change(&[(LARGE_PATH, &edited)], "Revise one reference row")?;
    let patch_chars = repo.pijul(&["change", &candidate])?.chars().count();
    let context_chars = native_context(&repo, &candidate)?
        .to_string()
        .chars()
        .count();
    ensure!(
        patch_chars < LIMIT,
        "The small patch must fit the review limit."
    );
    ensure!(
        context_chars > LIMIT,
        "The complete native context must exceed the review limit."
    );
    Ok(
        json!({"base": base, "candidate": candidate, "patch_chars": patch_chars, "context_chars": context_chars, "limit": LIMIT}),
    )
}

fn policy_binding(policy: &str) -> Value {
    json!({"path": "POLICY.md", "sha256": format!("{:x}", Sha256::digest(policy.as_bytes()))})
}

fn check_request(repo: &Repo, facts: &Value, input: &Value, kind: &str) -> Result<Value> {
    let candidate = &input["candidate"];
    let hash = candidate["hash"]
        .as_str()
        .context("The candidate hash is absent.")?;
    let keys: &[&str] = if kind == "context" {
        &["candidate", "later", "rename"]
    } else {
        &["first", "second"]
    };
    ensure!(
        keys.iter().any(|key| facts[*key] == hash),
        "The request names an unknown native candidate."
    );
    let state = native_state(repo, "main")?;
    let policy = if kind == "context" {
        CONTEXT_POLICY
    } else {
        BINDING_POLICY
    };
    let expected_binding = json!({"candidates": [hash], "policy": policy_binding(policy), "main": {"channel": "main", "state": state}});
    ensure!(
        input["binding"] == expected_binding,
        "The review binding differs from the exact native request state."
    );
    let archive = repo.archive("main")?;
    ensure!(
        archive.files.get("POLICY.md").map(Vec::as_slice) == Some(policy.as_bytes()),
        "The trusted policy must match the native main archive."
    );
    ensure!(
        candidate["context"] == native_context(repo, hash)?,
        "The review must retain exact isolated native text and provenance."
    );
    if kind == "context" {
        if facts["rename"] == hash {
            let paths = candidate["paths"]
                .as_array()
                .context("The rename paths are absent.")?;
            ensure!(
                paths.contains(&json!(OLD_PATH)) && paths.contains(&json!(NEW_PATH)),
                "The rename must retain both full native paths."
            );
            let metadata = candidate["metadata_context"]
                .as_array()
                .context("The rename archive context is absent.")?;
            ensure!(
                metadata.contains(&json!({"path": OLD_PATH, "before": RENAMED, "after": null})),
                "The rename must retain exact source archive text."
            );
            ensure!(
                metadata.contains(&json!({"path": NEW_PATH, "before": null, "after": RENAMED})),
                "The rename must retain exact destination archive text."
            );
        } else {
            ensure!(
                candidate["paths"] == json!([NESTED]),
                "The text review must retain the complete nested path."
            );
            if facts["candidate"] == hash {
                ensure!(
                    !candidate.to_string().contains("SECRET_TOKEN"),
                    "The candidate context must exclude the later edit."
                );
                let vertices = candidate["context"]["files"]
                    .as_array()
                    .context("Native context files are absent.")?
                    .iter()
                    .flat_map(|file| file["vertices"].as_array().into_iter().flatten());
                let mut kept = false;
                let mut added = false;
                for vertex in vertices {
                    kept |= vertex["kind"] == "keep" && vertex["change"] != hash;
                    added |= vertex["kind"] == "add" && vertex["change"] == hash;
                }
                ensure!(
                    kept && added,
                    "The review must expose prerequisite and candidate provenance."
                );
            }
        }
    } else {
        let expected_state = if facts["first"] == hash {
            &facts["initial_state"]
        } else {
            &facts["first_state"]
        };
        ensure!(
            &state == expected_state,
            "The HTTP request must observe the native prerequisite state."
        );
        ensure!(
            candidate["paths"] == json!(["notes/release.txt"]),
            "The binding case must retain its full native path."
        );
    }
    Ok(
        json!({"hash": hash, "binding": expected_binding, "native_main_hashes": repo.hashes("main")?}),
    )
}

fn solve_context(dir: &Path, options: &RunOptions) -> Result<()> {
    solve_reviews(dir, options, "context")
}

fn solve_binding(dir: &Path, options: &RunOptions) -> Result<()> {
    solve_reviews(dir, options, "binding")
}

fn solve_reviews(dir: &Path, options: &RunOptions, kind: &'static str) -> Result<()> {
    let repo = Repo::open(dir.join("repo"));
    let request_repo = repo.clone();
    let facts = load_facts(dir)?;
    let observations = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&observations);
    let live_url = options.model_url.clone();
    let model = ModelServer::new(move |request| {
        let result = review_input(&request.body).and_then(|input| {
            let observation = check_request(&request_repo, &facts, &input, kind)?;
            let reject = kind == "context"
                && input["candidate"]["context"]["files"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .flat_map(|file| file["vertices"].as_array().into_iter().flatten())
                    .any(|vertex| {
                        vertex["kind"] == "add"
                            && vertex["text"]
                                .as_str()
                                .is_some_and(|text| text.contains("SECRET_TOKEN"))
                    });
            Ok((observation, reject))
        });
        match result {
            Ok((observation, reject)) => {
                captured.lock().push(observation);
                if let Some(url) = live_url.as_deref() {
                    let endpoint = if request.body["questions"]["review"].is_object() {
                        format!("{}/systemone", url.trim_end_matches('/'))
                    } else {
                        format!("{}/chat/completions", url.trim_end_matches('/'))
                    };
                    let result = (|| -> Result<Value> {
                        let mut response = ureq::post(&endpoint).send_json(&request.body)?;
                        Ok(serde_json::from_reader(response.body_mut().as_reader())?)
                    })();
                    return match result {
                        Ok(body) => Reply { status: 200, body },
                        Err(error) => Reply {
                            status: 502,
                            body: json!({"error": error.to_string()}),
                        },
                    };
                }
                if request.body["questions"]["review"].is_object() {
                    Reply {
                        status: 200,
                        body: json!({"answers": {"review": {"type": "choice", "choice": if reject { "reject" } else { "accept" }, "confidence": 1.0}}}),
                    }
                } else {
                    chat_reply(verdict(if reject { "reject" } else { "accept" }))
                }
            }
            Err(error) => {
                captured.lock().push(json!({"error": error.to_string()}));
                chat_reply(verdict("escalate"))
            }
        }
    })?;
    let extra = if options.model_url.is_some() {
        vec![
            ("PATCHGATE_MODEL", options.model.as_str()),
            ("PATCHGATE_MODEL_API", options.api.as_str()),
        ]
    } else {
        Vec::new()
    };
    let output = repo.gate(Some(&model), &["review"], &extra)?;
    fs::write(
        dir.join("structured-observations.json"),
        serde_json::to_vec_pretty(&*observations.lock())?,
    )?;
    checked_output(output, "Review the native structured candidates.")?;
    Ok(())
}

fn solve_limit(dir: &Path, _: &RunOptions) -> Result<()> {
    let repo = Repo::open(dir.join("repo"));
    let requests = Arc::new(Mutex::new(0_u64));
    let captured = Arc::clone(&requests);
    let model = ModelServer::new(move |_| {
        *captured.lock() += 1;
        chat_reply(verdict("accept"))
    })?;
    let output = repo.gate(
        Some(&model),
        &["review"],
        &[("PATCHGATE_MAX_CHANGE_CHARS", "4000")],
    )?;
    fs::write(
        dir.join("structured-observations.json"),
        serde_json::to_vec_pretty(&json!({"requests": *requests.lock()}))?,
    )?;
    checked_output(
        output,
        "Escalate the complete context that exceeds the limit.",
    )?;
    Ok(())
}

fn observations(check: &mut Check) -> Result<Option<Value>> {
    let path = check
        .repo
        .path
        .parent()
        .context("The scenario directory is absent.")?
        .join("structured-observations.json");
    match fs::read(path) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(value) => Ok(Some(value)),
            Err(_) => {
                check.require(false, "The HTTP observations must contain valid JSON.");
                Ok(None)
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            check.require(false, "The scenario must observe the real HTTP boundary.");
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

fn exact_channels(check: &mut Check, accepted: &[&str], pending: &[&str]) -> Result<()> {
    let base: BTreeSet<String> = serde_json::from_value(check.facts["base"].clone())?;
    let mut main = base.clone();
    let mut inbox = base;
    for key in accepted {
        let hash = check.facts[*key]
            .as_str()
            .context("An accepted hash is absent.")?
            .to_owned();
        main.insert(hash.clone());
        inbox.insert(hash);
    }
    for key in pending {
        inbox.insert(
            check.facts[*key]
                .as_str()
                .context("A pending hash is absent.")?
                .to_owned(),
        );
    }
    check.require(
        check.repo.hashes("main")? == main,
        "Main must contain exactly the approved native history.",
    );
    check.require(
        check.repo.hashes("inbox")? == inbox,
        "Inbox must retain exactly the original native history.",
    );
    check.no_conflicts("main")?;
    Ok(())
}

fn check_reviews(check: &mut Check, keys: &[&str], policy: &str) -> Result<()> {
    let observed = observations(check)?;
    let entries = observed.as_ref().and_then(Value::as_array);
    check.require(
        entries.is_some_and(|entries| entries.len() == keys.len()),
        "Each candidate must reach exactly one native HTTP review.",
    );
    let ledger = check.repo.ledger()?;
    for key in keys {
        let hash = check.facts[*key]
            .as_str()
            .context("A review hash is absent.")?
            .to_owned();
        let matches: Vec<_> = entries
            .into_iter()
            .flatten()
            .filter(|entry| entry["hash"] == hash)
            .collect();
        check.require(
            matches.len() == 1,
            format!("{key} must have one successful native HTTP observation."),
        );
        let records: Vec<_> = ledger
            .iter()
            .filter(|record| record["hash"] == hash)
            .collect();
        check.require(
            records.len() == 1,
            format!("{key} must have exactly one model audit record."),
        );
        for record in records {
            check.require(
                record["by"] == "model",
                format!("{key} must use the model actor."),
            );
            check.require(
                record["review"]["candidates"] == json!([hash]),
                format!("{key} must bind the actual candidate hash."),
            );
            check.require(
                record["review"]["policy"] == policy_binding(policy),
                format!("{key} must bind the exact policy bytes."),
            );
            check.require(
                record["review"]["main"]["channel"] == "main",
                format!("{key} must bind the native main channel."),
            );
            if let Some(observation) = matches.first() {
                check.require(
                    record["review"] == observation["binding"],
                    format!("{key} must bind the main state at HTTP request time."),
                );
            }
            if policy == BINDING_POLICY {
                let state_key = if *key == "first" {
                    "initial_state"
                } else {
                    "first_state"
                };
                check.require(
                    record["review"]["main"]["state"] == check.facts[state_key],
                    format!("{key} must bind the independently measured native state."),
                );
            }
        }
    }
    let gate_count = usize::from(check.facts.get("binary").is_some());
    check.require(
        ledger.len() == keys.len() + gate_count,
        "The ledger must contain only the requested model and gate decisions.",
    );
    Ok(())
}

fn check_context(check: &mut Check) -> Result<()> {
    exact_channels(check, &["candidate", "rename"], &["later", "binary"])?;
    check.decision("candidate", "accept", "model")?;
    check.decision("rename", "accept", "model")?;
    check.decision("later", "reject", "model")?;
    check.decision("binary", "escalate", "gate")?;
    let binary_records = check.records("binary")?;
    check.require(
        binary_records.len() == 1,
        "The binary candidate must produce exactly one gate escalation.",
    );
    check.require(
        binary_records
            .iter()
            .all(|record| record.get("review").is_none()),
        "A binary gate escalation must not claim a model review.",
    );
    let main_archive = check.repo.archive("main")?;
    let inbox_archive = check.repo.archive("inbox")?;
    check.require(
        !main_archive.files.contains_key(BINARY_PATH),
        "Main must exclude the invalid UTF-8 candidate.",
    );
    check.require(
        inbox_archive.files.get(BINARY_PATH).map(Vec::as_slice) == Some(BINARY),
        "Inbox must retain the exact invalid UTF-8 bytes.",
    );
    check.require(
        check.file("main", NESTED)?.as_deref() == Some(APPROVED),
        "Main must retain the approved nested release without the later secret.",
    );
    check.require(
        check.file("inbox", NESTED)?.as_deref() == Some(SECRET),
        "Inbox must retain the later secret for native isolation checks.",
    );
    check.require(
        check.file("main", OLD_PATH)?.is_none(),
        "Main must remove the old guide path.",
    );
    check.require(
        check.file("main", NEW_PATH)?.as_deref() == Some(RENAMED),
        "Main must expose the exact renamed guide text.",
    );
    check_reviews(check, &["candidate", "later", "rename"], CONTEXT_POLICY)
}

fn check_binding(check: &mut Check) -> Result<()> {
    exact_channels(check, &["first", "second"], &[])?;
    check.decision("first", "accept", "model")?;
    check.decision("second", "accept", "model")?;
    check.require(
        check.file("main", "notes/release.txt")?.as_deref() == Some(SECOND),
        "The native main archive must expose the second release.",
    );
    check.require(
        check.file("main", "POLICY.md")?.as_deref() == Some(BINDING_POLICY),
        "The native policy must retain exact whitespace and text.",
    );
    check_reviews(check, &["first", "second"], BINDING_POLICY)
}

fn check_limit(check: &mut Check) -> Result<()> {
    exact_channels(check, &[], &["candidate"])?;
    check.decision("candidate", "escalate", "gate")?;
    check.require(
        check.file("main", LARGE_PATH)?.as_deref() == Some(large_text().as_str()),
        "Main must retain the original large reference file.",
    );
    let expected = large_text().replacen("Reference row 0450:", "Reference row 0450 revised:", 1);
    check.require(
        check.file("inbox", LARGE_PATH)?.as_deref() == Some(expected.as_str()),
        "Inbox must retain the small edit for a human decision.",
    );
    if let Some(observed) = observations(check)? {
        check.require(
            observed["requests"] == 0,
            "The gate must not send incomplete or excessive context to the model.",
        );
    }
    let records = check.records("candidate")?;
    check.require(
        records.len() == 1,
        "The context limit must produce one gate decision.",
    );
    check.require(
        records.iter().all(|record| record.get("review").is_none()),
        "A gate escalation must not claim a model review.",
    );
    Ok(())
}
