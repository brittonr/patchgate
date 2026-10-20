use super::support::*;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Control {
    Oracle,
    AcceptAll,
    RejectAll,
    OmitMerge,
    WrongHistory,
    MissingPrerequisite,
    FalseAuditActor,
    FalseAuditLinkage,
    ExtraUnrelatedChange,
    FalsePolicyBinding,
    FalseMainBinding,
}

const CONTROLS: &[(&str, &str)] = &[
    ("accept-all", "rust-model-decisions"),
    ("reject-all", "rust-model-decisions"),
    ("omit-merge", "rust-model-merge"),
    ("wrong-history", "rust-model-decisions"),
    ("missing-prerequisite", "dependency-graph-approved"),
    ("false-audit-actor", "rust-model-merge"),
    ("false-audit-linkage", "rust-model-merge"),
    ("extra-unrelated-change", "rust-model-merge"),
    ("false-policy-binding", "structured-review-binding"),
    ("false-main-binding", "structured-review-binding"),
];

fn oracle_check(scenario: &Scenario, dir: &Path) -> Result<Check> {
    (scenario.solve)(dir, &RunOptions::default())?;
    let mut check = Check::new(dir)?;
    (scenario.check)(&mut check).context("The oracle verifier returned an exception")?;
    ensure!(
        check.failures.is_empty(),
        "The oracle must pass before mutation: {}",
        check.failures.join("\n")
    );
    Ok(check)
}

fn write_ledger(repo: &Repo, records: &[Value]) -> Result<()> {
    let mut text = Vec::new();
    for record in records {
        serde_json::to_writer(&mut text, record)?;
        text.push(b'\n');
    }
    fs::write(repo.path.join(".pijul/patchgate/ledger.jsonl"), text)?;
    Ok(())
}

pub fn solve_control(name: &str, dir: &Path, control: Control) -> Result<()> {
    let scenario = super::find_scenario(name)?;
    if control == Control::Oracle {
        return (scenario.solve)(dir, &RunOptions::default());
    }
    let expected_task = match control {
        Control::AcceptAll | Control::RejectAll | Control::WrongHistory => "rust-model-decisions",
        Control::MissingPrerequisite => "dependency-graph-approved",
        Control::FalsePolicyBinding | Control::FalseMainBinding => "structured-review-binding",
        _ => "rust-model-merge",
    };
    ensure!(name == expected_task, "This control needs {expected_task}.");
    let mut evidence = json!({});
    let mut valid = if matches!(control, Control::AcceptAll | Control::RejectAll) {
        // These controls need the initial candidate state, not an accepted oracle state.
        let temporary = tempfile::tempdir()?;
        let baseline = temporary.path().join("oracle");
        copy_tree(dir, &baseline)?;
        oracle_check(scenario, &baseline)?;
        Check::new(dir)?
    } else {
        oracle_check(scenario, dir)?
    };
    let before_main = valid.repo.hashes("main")?;
    let before_inbox = valid.repo.hashes("inbox")?;
    let before_files = valid.repo.archive("main")?.files;
    let before_records = valid.repo.ledger()?;
    match control {
        Control::AcceptAll | Control::RejectAll => {
            let action = if control == Control::AcceptAll {
                "accept"
            } else {
                "reject"
            };
            for key in ["benign", "escalation", "secret"] {
                let hash = valid.facts[key]
                    .as_str()
                    .context("A candidate hash is absent")?;
                checked_output(
                    valid.repo.gate(
                        None,
                        &[
                            action,
                            hash,
                            "--reason",
                            "This negative control ignores the review policy.",
                        ],
                        &[],
                    )?,
                    "negative control decision",
                )?;
            }
        }
        Control::OmitMerge => {
            let mut records = before_records.clone();
            ensure!(
                records.iter().any(|record| record["decision"] == "merge"),
                "The oracle must create a merge audit."
            );
            records.retain(|record| record["decision"] != "merge");
            write_ledger(&valid.repo, &records)?;
        }
        Control::WrongHistory => {
            let signer = Signer::new()?;
            valid.repo.env = Arc::clone(&signer.env);
            let hash = valid.facts["benign"]
                .as_str()
                .context("The benign hash is absent")?;
            valid.repo.pijul(&["channel", "switch", "main"])?;
            valid.repo.pijul(&["unrecord", "--channel", "main", hash])?;
            let replacement = valid
                .repo
                .record("Replace the accepted history with identical files")?;
            ensure!(
                replacement != hash,
                "The replacement must use a different hash."
            );
            ensure!(
                valid.repo.archive("main")?.files == before_files,
                "The wrong-history control must retain the exact accepted files."
            );
            evidence = json!({"removed_hash": hash, "replacement_hash": replacement, "files_unchanged": true});
        }
        Control::MissingPrerequisite => {
            let nodes = valid.facts["nodes"]
                .as_array()
                .context("Graph nodes are absent")?;
            let root = nodes
                .iter()
                .find_map(|node| node["parents"].as_array()?.first()?.as_str())
                .context("The approved graph needs a prerequisite")?;
            let mut removed = std::collections::BTreeSet::from([root.to_owned()]);
            loop {
                let previous = removed.len();
                for node in nodes {
                    let parents = node["parents"]
                        .as_array()
                        .context("Graph parents are absent")?;
                    if parents
                        .iter()
                        .any(|parent| parent.as_str().is_some_and(|hash| removed.contains(hash)))
                    {
                        removed.insert(
                            node["hash"]
                                .as_str()
                                .context("A graph hash is absent")?
                                .to_owned(),
                        );
                    }
                }
                if previous == removed.len() {
                    break;
                }
            }
            ensure!(removed.len() > 1, "The prerequisite must have a dependent.");
            ensure!(
                removed.iter().all(|hash| before_main.contains(hash)),
                "The oracle must admit the complete dependency closure."
            );
            valid.repo.pijul(&["channel", "switch", "main"])?;
            let mut args = vec!["unrecord", "--channel", "main"];
            args.extend(removed.iter().map(String::as_str));
            valid.repo.pijul(&args)?;
            evidence = json!({"prerequisite": root, "removed_closure": removed});
        }
        Control::FalseAuditActor => {
            let mut records = before_records.clone();
            let record = records
                .iter_mut()
                .find(|record| record["decision"] == "merge")
                .context("The merge audit is absent")?;
            let hash = record["hash"].clone();
            record["by"] = json!("human");
            record["user"] = json!("control-forged-actor");
            write_ledger(&valid.repo, &records)?;
            evidence = json!({"hash": hash, "expected_actor": "model", "false_actor": "human"});
        }
        Control::FalseAuditLinkage => {
            let mut records = before_records.clone();
            let wrong_hash = valid.facts["french"]
                .as_str()
                .context("The French hash is absent")?;
            let record = records
                .iter_mut()
                .find(|record| record["decision"] == "accept" && record["merge"].is_string())
                .context("The merge acceptance is absent")?;
            let correct_hash = record["merge"].clone();
            ensure!(
                correct_hash != wrong_hash,
                "The false link must differ from the merge."
            );
            record["merge"] = json!(wrong_hash);
            write_ledger(&valid.repo, &records)?;
            evidence = json!({"expected_merge": correct_hash, "false_merge": wrong_hash});
        }
        Control::ExtraUnrelatedChange => {
            let signer = Signer::new()?;
            valid.repo.env = Arc::clone(&signer.env);
            valid.repo.pijul(&["channel", "switch", "main"])?;
            let hash = valid.repo.change(
                &[(
                    "control-unrelated.txt",
                    "This file is not part of the approved work.\n",
                )],
                "Add an unrelated change after the accepted merge",
            )?;
            valid.repo.pijul(&["apply", "--channel", "inbox", &hash])?;
            evidence = json!({"extra_hash": hash, "extra_path": "control-unrelated.txt"});
        }
        Control::FalsePolicyBinding | Control::FalseMainBinding => {
            let mut records = before_records.clone();
            let record = records
                .iter_mut()
                .find(|record| record["by"] == "model" && record["decision"] == "accept")
                .context("The model acceptance is absent.")?;
            let original = record["review"].clone();
            ensure!(
                original.is_object(),
                "The oracle must retain a structured review binding."
            );
            if control == Control::FalsePolicyBinding {
                record["review"]["policy"]["sha256"] = json!("0".repeat(64));
            } else {
                record["review"]["main"]["state"] = json!("CONTROL-FALSE-NATIVE-STATE");
            }
            ensure!(
                record["review"] != original,
                "The control must change the review binding."
            );
            evidence = json!({"hash": record["hash"], "expected_review": original, "false_review": record["review"]});
            write_ledger(&valid.repo, &records)?;
        }
        Control::Oracle => unreachable!(),
    }
    (scenario.check)(&mut valid)
        .context("A verifier exception is not a successful control result")?;
    ensure!(
        !valid.failures.is_empty(),
        "The negative control did not fail the verifier."
    );
    let main = valid.repo.hashes("main")?;
    let inbox = valid.repo.hashes("inbox")?;
    let records = valid.repo.ledger()?;
    let outcome_is_wrong = match control {
        Control::AcceptAll => valid.facts["secret"]
            .as_str()
            .is_some_and(|hash| main.contains(hash)),
        Control::RejectAll => valid.facts["benign"]
            .as_str()
            .is_some_and(|hash| !main.contains(hash)),
        Control::OmitMerge => !records.iter().any(|record| record["decision"] == "merge"),
        Control::WrongHistory => {
            valid.facts["benign"]
                .as_str()
                .is_some_and(|hash| !main.contains(hash))
                && valid.repo.archive("main")?.files == before_files
        }
        Control::MissingPrerequisite => {
            evidence["prerequisite"]
                .as_str()
                .is_some_and(|hash| !main.contains(hash))
                && inbox == before_inbox
                && records == before_records
        }
        Control::FalseAuditActor
        | Control::FalseAuditLinkage
        | Control::FalsePolicyBinding
        | Control::FalseMainBinding => {
            main == before_main
                && inbox == before_inbox
                && records != before_records
                && valid.repo.archive("main")?.files == before_files
        }
        Control::ExtraUnrelatedChange => {
            evidence["extra_hash"].as_str().is_some_and(|hash| {
                main.contains(hash) && inbox.contains(hash) && !before_main.contains(hash)
            }) && valid
                .repo
                .archive("main")?
                .files
                .contains_key("control-unrelated.txt")
        }
        Control::Oracle => false,
    };
    ensure!(
        outcome_is_wrong,
        "The negative control must cause an incorrect repository or audit outcome."
    );
    fs::write(
        dir.join("model-metrics.json"),
        serde_json::to_vec_pretty(&json!({
            "scenario": name, "control": format!("{control:?}"), "live": false,
            "oracle_passed": true, "verifier_error": null, "outcome_is_wrong": outcome_is_wrong,
            "mutation": evidence, "verifier_failures": valid.failures, "records": records,
            "main_hashes": main, "inbox_hashes": inbox,
        }))?,
    )?;
    println!("Negative control failures: {}", valid.failures.join("\n"));
    Ok(())
}

#[derive(clap::Args)]
pub struct ControlArgs {
    #[arg(long, default_value = "harbor")]
    pub harbor: PathBuf,
    #[arg(long, default_value = "harbor/tasks")]
    pub tasks: PathBuf,
    #[arg(long, default_value = ".devenv/state/harbor-control-jobs")]
    pub jobs: PathBuf,
}

pub fn verify_harbor(args: ControlArgs) -> Result<()> {
    let mut oracle_reports = Vec::new();
    let mut reports = Vec::new();
    let mut failures = Vec::new();
    let mut passed_oracles = std::collections::BTreeSet::new();
    let tasks: std::collections::BTreeSet<_> = CONTROLS.iter().map(|(_, task)| *task).collect();
    for task in tasks {
        let (report, errors) = run_control_job(&args, "oracle", task, 1.0)?;
        if errors.is_empty() {
            passed_oracles.insert(task);
        }
        failures.extend(
            errors
                .into_iter()
                .map(|error| format!("oracle {task}: {error}")),
        );
        oracle_reports.push(report);
    }
    for &(control, task) in CONTROLS {
        if !passed_oracles.contains(task) {
            let error = format!("{control}: The task oracle did not pass before mutation.");
            reports.push(json!({"control": control, "task": task, "failures": [&error]}));
            failures.push(error);
            continue;
        }
        let (report, errors) = run_control_job(&args, control, task, 0.0)?;
        for trial in report["trials"].as_array().into_iter().flatten() {
            println!(
                "{control}: reward={}, trial_exception={}, verifier_error={}",
                trial["result"]["verifier_result"]["rewards"]["reward"],
                trial["result"]["exception_info"],
                trial["verification"]["verifier_error"],
            );
        }
        failures.extend(
            errors
                .into_iter()
                .map(|error| format!("{control}: {error}")),
        );
        reports.push(report);
    }
    fs::create_dir_all(&args.jobs)?;
    let report = args
        .jobs
        .join(format!("{}.json", job_name("negative-controls")));
    fs::write(
        &report,
        serde_json::to_vec_pretty(&json!({
            "oracles": oracle_reports, "controls": reports, "failures": failures,
            "control_count": CONTROLS.len(),
        }))?,
    )?;
    ensure!(
        failures.is_empty(),
        "Negative controls failed: {}",
        failures.join("\n")
    );
    println!(
        "All {} negative controls received reward 0 with zero trial or verifier exceptions. Report: {}",
        CONTROLS.len(),
        report.display()
    );
    Ok(())
}

fn run_control_job(
    args: &ControlArgs,
    control: &str,
    task: &str,
    reward: f64,
) -> Result<(Value, Vec<String>)> {
    let name = job_name(&format!("{control}-{task}"));
    let job = args.jobs.join(&name);
    let inputs = job.join("task-configs");
    clone_tasks(
        &args.tasks,
        &inputs,
        &[task],
        &[("PATCHGATE_EVAL_CONTROL", control)],
    )?;
    let status = run_harbor(&args.harbor, &inputs, &args.jobs, &name)?;
    let (mut trials, mut errors) = collect_trials(&job, &[task], reward)?;
    if !status.success() {
        errors.push(format!("Harbor returned {status}."));
    }
    if reward == 0.0 {
        for trial in &mut trials {
            let path = trial["result_path"]
                .as_str()
                .context("The trial path is absent")?;
            let path = Path::new(path)
                .parent()
                .context("The trial directory is absent")?
                .join("artifacts/model-metrics.json");
            match fs::read(&path)
                .map_err(anyhow::Error::from)
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).map_err(Into::into))
            {
                Ok(evidence) => {
                    if evidence["oracle_passed"] != true
                        || evidence["outcome_is_wrong"] != true
                        || evidence.get("verifier_error") != Some(&Value::Null)
                        || !evidence["verifier_failures"]
                            .as_array()
                            .is_some_and(|items| !items.is_empty())
                    {
                        errors.push(format!("Control {control} lacks valid mutation evidence."));
                    }
                    trial["mutation_evidence"] = evidence;
                }
                Err(error) => {
                    errors.push(format!("Read control evidence {}: {error}", path.display()))
                }
            }
        }
    }
    Ok((
        json!({
            "control": control, "task": task, "expected_reward": reward,
            "job": job, "trials": trials, "failures": errors,
        }),
        errors,
    ))
}

pub(super) fn job_name(label: &str) -> String {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("rust-{label}-{stamp}-{}", std::process::id())
}

pub(super) fn clone_tasks(
    source: &Path,
    destination: &Path,
    names: &[&str],
    env: &[(&str, &str)],
) -> Result<()> {
    fs::create_dir_all(destination)?;
    for name in names {
        let target = destination.join(name);
        copy_tree(&source.join(name), &target)?;
        let config = target.join("task.toml");
        let mut text = fs::read_to_string(&config)?;
        ensure!(
            !text
                .lines()
                .any(|line| matches!(line.trim(), "[solution.env]" | "[solution]")),
            "The source task already defines solution settings: {}",
            config.display()
        );
        text.push_str("\n[solution.env]\n");
        for (key, value) in env {
            ensure!(
                !value.contains('\0'),
                "A solution environment value contains NUL."
            );
            text.push_str(key);
            text.push_str(" = ");
            text.push_str(&toml_string(value));
            text.push('\n');
        }
        fs::write(config, text)?;
    }
    Ok(())
}

fn toml_string(value: &str) -> String {
    let mut result = String::from("\"");
    for character in value.chars() {
        match character {
            '\"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            value if value.is_control() => result.push_str(&format!("\\u{:04X}", u32::from(value))),
            value => result.push(value),
        }
    }
    result.push('\"');
    result
}

fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    ensure!(
        source.is_dir(),
        "Task directory is absent: {}",
        source.display()
    );
    fs::create_dir(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let destination = target.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &destination)?;
        } else {
            ensure!(
                kind.is_file(),
                "Task inputs must be regular files: {}",
                entry.path().display()
            );
            fs::copy(entry.path(), destination)?;
        }
    }
    Ok(())
}

pub(super) fn run_harbor(
    harbor: &Path,
    tasks: &Path,
    jobs: &Path,
    name: &str,
) -> Result<std::process::ExitStatus> {
    // The caller owns Docker settings. Do not replace its environment or start a Docker engine.
    Command::new(harbor)
        .arg("run")
        .arg("--path")
        .arg(tasks)
        .args(["--agent", "oracle", "--env", "docker", "--jobs-dir"])
        .arg(jobs)
        .args(["--job-name", name, "--yes", "--quiet", "--n-attempts", "1"])
        .status()
        .with_context(|| format!("Run Harbor at {}", harbor.display()))
}

pub(super) fn collect_trials(
    job: &Path,
    names: &[&str],
    reward: f64,
) -> Result<(Vec<Value>, Vec<String>)> {
    let mut trials = Vec::new();
    let mut failures = Vec::new();
    let mut found = std::collections::BTreeSet::new();
    for entry in fs::read_dir(job).with_context(|| format!("Read Harbor job {}", job.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path().join("result.json");
        if !path.exists() {
            continue;
        }
        let result: Value = match fs::read(&path)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
        {
            Ok(value) => value,
            Err(error) => {
                failures.push(format!("Invalid trial at {}: {error}", path.display()));
                continue;
            }
        };
        let name = result["task_name"].as_str().unwrap_or_default();
        if !names.contains(&name) {
            failures.push(format!("Unexpected trial {name}."));
        }
        if !found.insert(name.to_owned()) {
            failures.push(format!("Duplicate trial {name}."));
        }
        if result
            .get("exception_info")
            .is_some_and(|value| !value.is_null())
        {
            failures.push(format!(
                "Trial {name} has an exception: {}",
                result["exception_info"]
            ));
        }
        if result["step_results"].as_array().is_some_and(|steps| {
            steps.iter().any(|step| {
                step.get("exception_info")
                    .is_some_and(|value| !value.is_null())
            })
        }) {
            failures.push(format!("Trial {name} has a step exception."));
        }
        if result["verifier_result"]
            .get("exception_info")
            .is_some_and(|value| !value.is_null())
        {
            failures.push(format!("Trial {name} has a verifier exception."));
        }
        if result["verifier_result"]["rewards"]["reward"].as_f64() != Some(reward) {
            failures.push(format!(
                "Trial {name} must receive reward {reward}, not {}.",
                result["verifier_result"]["rewards"]["reward"]
            ));
        }
        let exit = entry.path().join("agent/exit-code.txt");
        if exit.exists() && fs::read_to_string(&exit)?.trim() != "0" {
            failures.push(format!("The oracle process failed for {name}."));
        }
        let verification_path = entry.path().join("verifier/patchgate-check.json");
        let verification = match fs::read(&verification_path)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).map_err(Into::into))
        {
            Ok(value) => {
                if value.get("verifier_error") != Some(&Value::Null) {
                    failures.push(format!(
                        "Trial {name} has a verifier error: {}",
                        value["verifier_error"]
                    ));
                }
                if value["scenario"] != name {
                    failures.push(format!(
                        "Trial {name} has verifier evidence for another scenario."
                    ));
                }
                if !value["failures"].is_array() {
                    failures.push(format!("Trial {name} lacks verifier assertion results."));
                } else if reward == 0.0 && value["failures"].as_array().is_some_and(Vec::is_empty) {
                    failures.push(format!("Trial {name} lacks a failed verifier assertion."));
                } else if reward == 1.0
                    && value["failures"]
                        .as_array()
                        .is_some_and(|items| !items.is_empty())
                {
                    failures.push(format!("Trial {name} has oracle verifier failures."));
                }
                value
            }
            Err(error) => {
                failures.push(format!(
                    "Read verifier evidence {}: {error}",
                    verification_path.display()
                ));
                Value::Null
            }
        };
        trials.push(json!({
            "task": name, "result_path": path, "result": result, "verification": verification,
        }));
    }
    for name in names {
        if !found.contains(*name) {
            failures.push(format!("Trial {name} is absent."));
        }
    }
    Ok((trials, failures))
}
