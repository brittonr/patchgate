use super::support::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Control {
    Oracle,
    AcceptAll,
    RejectAll,
    OmitMerge,
}

pub fn solve_control(name: &str, dir: &Path, control: Control) -> Result<()> {
    let scenario = super::find_scenario(name)?;
    if control == Control::Oracle {
        return (scenario.solve)(dir, &RunOptions::default());
    }
    match control {
        Control::AcceptAll | Control::RejectAll => {
            ensure!(
                name == "rust-model-decisions",
                "This control requires rust-model-decisions."
            );
            let repo = Repo::open(dir.join("repo"));
            let facts = load_facts(dir)?;
            let action = if control == Control::AcceptAll {
                "accept"
            } else {
                "reject"
            };
            for key in ["benign", "escalation", "secret"] {
                let hash = facts[key].as_str().context("A candidate hash is absent")?;
                checked_output(
                    repo.gate(
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
            ensure!(
                name == "rust-model-merge",
                "This control requires rust-model-merge."
            );
            (scenario.solve)(dir, &RunOptions::default())?;
            let mut valid = Check::new(dir)?;
            (scenario.check)(&mut valid)?;
            ensure!(
                valid.failures.is_empty(),
                "The oracle must pass before the merge audit is removed: {}",
                valid.failures.join("\n")
            );
            let ledger = valid.repo.ledger()?;
            ensure!(
                ledger.iter().any(|record| record["decision"] == "merge"),
                "The valid oracle must create a merge audit."
            );
            let mut text = String::new();
            for record in ledger.iter().filter(|record| record["decision"] != "merge") {
                text.push_str(&serde_json::to_string(record)?);
                text.push('\n');
            }
            fs::write(valid.repo.path.join(".pijul/patchgate/ledger.jsonl"), text)?;
        }
        Control::Oracle => unreachable!(),
    }
    let mut check = Check::new(dir)?;
    (scenario.check)(&mut check)
        .context("A verifier exception is not a successful control result")?;
    ensure!(
        !check.failures.is_empty(),
        "The negative control did not fail the verifier."
    );
    let main = check.repo.hashes("main")?;
    let outcome_is_wrong = match control {
        Control::AcceptAll => check.facts["secret"]
            .as_str()
            .is_some_and(|hash| main.contains(hash)),
        Control::RejectAll => check.facts["benign"]
            .as_str()
            .is_some_and(|hash| !main.contains(hash)),
        Control::OmitMerge => !check
            .repo
            .ledger()?
            .iter()
            .any(|record| record["decision"] == "merge"),
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
            "verifier_failures": check.failures, "records": check.repo.ledger()?, "main_hashes": main,
        }))?,
    )?;
    println!("Negative control failures: {}", check.failures.join("\n"));
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
    let controls = [
        ("accept-all", "rust-model-decisions"),
        ("reject-all", "rust-model-decisions"),
        ("omit-merge", "rust-model-merge"),
    ];
    let mut reports = Vec::new();
    let mut failures = Vec::new();
    for (control, task) in controls {
        let name = job_name(control);
        let job = args.jobs.join(&name);
        let inputs = job.join("task-configs");
        clone_tasks(
            &args.tasks,
            &inputs,
            &[task],
            &[("PATCHGATE_EVAL_CONTROL", control)],
        )?;
        let status = run_harbor(&args.harbor, &inputs, &args.jobs, &name)?;
        let (trials, mut errors) = collect_trials(&job, &[task], 0.0)?;
        if !status.success() {
            errors.push(format!("Harbor returned {status}."));
        }
        reports.push(json!({"control": control, "job": job, "trials": trials, "failures": errors}));
        failures.extend(
            errors
                .into_iter()
                .map(|error| format!("{control}: {error}")),
        );
    }
    fs::create_dir_all(&args.jobs)?;
    let report = args
        .jobs
        .join(format!("{}.json", job_name("negative-controls")));
    fs::write(
        &report,
        serde_json::to_vec_pretty(&json!({"controls": reports, "failures": failures}))?,
    )?;
    ensure!(
        failures.is_empty(),
        "Negative controls failed: {}",
        failures.join("\n")
    );
    println!(
        "All three negative controls received reward 0 with zero trial exceptions. Report: {}",
        report.display()
    );
    Ok(())
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
        trials.push(json!({"task": name, "result_path": path, "result": result}));
    }
    for name in names {
        if !found.contains(*name) {
            failures.push(format!("Trial {name} is absent."));
        }
    }
    Ok((trials, failures))
}
