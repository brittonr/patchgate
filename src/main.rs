mod change;
mod doctor;
mod gate;
mod isolation;
mod model;
mod pijul;
mod protected;
mod review;
mod secrets;
mod verify;

use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use change::short;
use gate::{Gate, Item, Settings, State};

#[derive(Parser)]
#[command(
    name = "patchgate",
    version,
    about = "A local model merges conflicting Pijul changes and decides which changes go from the inbox channel into main."
)]
struct Cli {
    /// The Pijul repository. Default: the repository of the current directory.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// The channel that receives new changes.
    #[arg(long, env = "PATCHGATE_INBOX", default_value = "inbox")]
    inbox: String,
    /// The channel that the gate controls.
    #[arg(long, env = "PATCHGATE_MAIN", default_value = "main")]
    main: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Make the inbox channel from main and put the working copy on it.
    Init,
    /// Show the inbox changes that are not in main.
    Status {
        /// Print a versioned JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Explain a change, its dependencies, and its decision evidence.
    Explain {
        change: String,
        #[arg(long)]
        json: bool,
    },
    /// Review and merge the pending changes one time.
    Review {
        /// Review in isolation without source acceptance.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    /// Diagnose setup without repository changes.
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Review and merge new changes until stopped. devenv up runs this command.
    Watch {
        /// Seconds between reviews.
        #[arg(long, default_value_t = 10.0)]
        interval: f64,
    },
    /// Accept a change and the conflicting changes that it resolves.
    Accept {
        /// The change hash, or the start of the hash.
        change: String,
        /// The reason for the decision.
        #[arg(short = 'm', long)]
        reason: Option<String>,
    },
    /// Reject a change by hand.
    Reject {
        /// The change hash, or the start of the hash.
        change: String,
        /// The reason for the decision.
        #[arg(short = 'm', long)]
        reason: Option<String>,
    },
    /// Show the decisions and merges, newest first.
    Log {
        /// The number of records to show.
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
}

fn show(item: &Item) {
    let indent = "                        ";
    let message = if item.message.is_empty() {
        "(no message)"
    } else {
        &item.message
    };
    println!(
        "{:<9} {}  {message}",
        item.state.as_str(),
        short(&item.hash)
    );
    if !item.needs.is_empty() && matches!(item.state, State::Blocked | State::Waiting) {
        let needs = item
            .needs
            .iter()
            .map(|(hash, state)| format!("{} ({})", short(hash), state.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        println!("{indent}needs {needs}");
    } else if !item.reason.is_empty() {
        println!("{indent}{}", item.reason);
    }
    if let Some(merge) = &item.merge {
        println!("{:<9} {}  {}", "merged", short(&merge.hash), merge.message);
        println!("{indent}{}", merge.reason);
    }
    if !item.note.is_empty() {
        println!("{indent}{}", item.note);
    }
}

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    use std::io::Write;
    let mut output = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    writeln!(output)?;
    Ok(())
}

fn show_explanation(explanation: &gate::Explanation) -> Result<()> {
    println!("{}  {}", explanation.hash, explanation.message);
    println!("State: {}", explanation.state.as_str());
    for path in &explanation.paths {
        let protected = if explanation.protected_paths.contains(path) {
            " (protected)"
        } else {
            ""
        };
        println!("Path: {path}{protected}");
    }
    for dependency in &explanation.dependencies {
        println!(
            "Dependency: {} ({})",
            dependency.hash,
            dependency.state.as_str()
        );
        for need in &dependency.needs {
            println!("  needs {need}");
        }
    }
    println!("Current policy and main binding:");
    print_json(&explanation.current)?;
    if let Some(checks) = &explanation.checks {
        println!("Trusted check manifest:");
        print_json(checks)?;
    }
    if !explanation.records.is_empty() {
        println!("Decision and verification evidence:");
        print_json(&explanation.records)?;
    }
    for action in &explanation.next_actions {
        println!("Next: {action}");
    }
    Ok(())
}

fn show_review(report: &gate::ReviewReport, json: bool) -> Result<()> {
    if json {
        print_json(report)?;
    } else {
        if report.dry_run {
            println!("Dry-run only. Source channels and acceptance records stay unchanged.");
        }
        for item in &report.items {
            show(item);
        }
        if report
            .records
            .iter()
            .any(|record| record.verification.is_some())
        {
            println!("Trusted Nix checks passed. Use --json for exact verification evidence.");
        }
        if report.dry_run {
            println!(
                "This report does not authorize acceptance. Run patchgate review for a new review."
            );
        }
    }
    if report.dry_run
        && report
            .records
            .iter()
            .any(|record| record.execution_error.is_some())
    {
        bail!("The model returned an invalid reply. The dry-run does not authorize acceptance.");
    }
    Ok(())
}

fn run(settings: Settings, command: Command, interrupted: &AtomicBool) -> Result<()> {
    match command {
        Command::Init => {
            let gate = Gate::new(settings)?;
            for line in gate.init()? {
                println!("{line}");
            }
        }
        Command::Status { json } => {
            let mut gate = Gate::new(settings)?;
            if json {
                return print_json(&gate.status_report()?);
            }
            let items = gate.status()?;
            let s = &gate.settings;
            if items.is_empty() {
                println!("{} has every change in {}.", s.main, s.inbox);
            } else {
                println!(
                    "{} change(s) in {} are not in {}:",
                    items.len(),
                    s.inbox,
                    s.main
                );
                for item in &items {
                    show(item);
                }
            }
            let behind = gate.behind()?;
            if !behind.is_empty() {
                println!("{} does not have these changes of {}:", s.inbox, s.main);
                for entry in &behind {
                    let message = if entry.message.is_empty() {
                        "(no message)"
                    } else {
                        &entry.message
                    };
                    println!("          {}  {message}", short(&entry.hash));
                }
                println!(
                    "When the working copy is clean, run: pijul apply --channel {} {}",
                    s.inbox,
                    behind
                        .iter()
                        .map(|entry| short(&entry.hash))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            }
        }
        Command::Explain { change, json } => {
            let mut gate = Gate::new(settings)?;
            let explanation = gate.explain(&change)?;
            if json {
                print_json(&explanation)?;
            } else {
                show_explanation(&explanation)?;
            }
        }
        Command::Doctor { json } => {
            let report = doctor::inspect(&settings)?;
            if json {
                print_json(&report)?;
            } else {
                doctor::show(&report);
            }
            if !report.ok {
                bail!("Setup diagnostics found errors. Use the repair commands in the report.");
            }
        }
        Command::Review { dry_run, json } => {
            if dry_run {
                return show_review(&Gate::dry_run(settings)?, json);
            }
            let mut gate = Gate::new(settings)?;
            if json {
                return show_review(&gate.review_report(false)?, true);
            }
            let items = gate.review(show)?;
            if !items.iter().any(|item| item.decided) {
                println!("No change is ready for review.");
            }
            let waiting = items.iter().filter(|item| item.state.stuck()).count();
            if waiting > 0 {
                println!("{waiting} change(s) need a human. Run: patchgate status");
            }
        }
        Command::Watch { interval } => {
            let mut gate = Gate::new(settings)?;
            let delay = Duration::try_from_secs_f64(interval)
                .context("--interval must be a finite, nonnegative number")?;
            let s = &gate.settings;
            println!(
                "patchgate watches {} -> {} in {} every {interval} s.",
                s.inbox,
                s.main,
                s.repo.display()
            );
            println!("Model: {} at {}", s.model, s.model_url);
            let mut last_error = None;
            while !interrupted.load(Ordering::Relaxed) {
                match gate.review(show) {
                    Ok(_) => last_error = None,
                    Err(error) => {
                        let error = format!("{error:#}");
                        if last_error.as_ref() != Some(&error) {
                            eprintln!("patchgate: {error}");
                            last_error = Some(error);
                        }
                    }
                }
                let deadline = Instant::now() + delay;
                while !interrupted.load(Ordering::Relaxed) {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    std::thread::park_timeout(remaining);
                }
            }
        }
        Command::Accept { change, reason } => {
            let mut gate = Gate::new(settings)?;
            show(&gate.decide_by_hand(&change, "accept", reason.as_deref())?)
        }
        Command::Reject { change, reason } => {
            let mut gate = Gate::new(settings)?;
            show(&gate.decide_by_hand(&change, "reject", reason.as_deref())?)
        }
        Command::Log { limit, json } => {
            let gate = Gate::new(settings)?;
            let mut history = gate.ledger.history()?;
            if json {
                #[derive(serde::Serialize)]
                struct LogReport<'a> {
                    schema_version: u8,
                    records: &'a [gate::Record],
                }
                let start = history.len().saturating_sub(limit);
                let records = &mut history[start..];
                records.reverse();
                return print_json(&LogReport {
                    schema_version: 1,
                    records,
                });
            }
            for record in history.iter().rev().take(limit) {
                let when = record
                    .at
                    .chars()
                    .take(16)
                    .collect::<String>()
                    .replace('T', " ");
                let actor = record
                    .model
                    .as_deref()
                    .or(record.user.as_deref())
                    .unwrap_or_default();
                let who = if actor.is_empty() {
                    record.by.clone()
                } else {
                    format!("{} {actor}", record.by)
                };
                let message = if record.message.is_empty() {
                    "(no message)"
                } else {
                    &record.message
                };
                println!(
                    "{when}  {:<8}  {}  {message}",
                    record.decision,
                    short(&record.hash)
                );
                println!("                  {who}: {}", record.reason);
            }
        }
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let interrupted = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&interrupted);
    let thread = std::thread::current();
    let result = (|| {
        ctrlc::set_handler(move || {
            stop.store(true, Ordering::Relaxed);
            thread.unpark();
        })?;
        let repo = gate::find_repo(&cli.repo)?;
        let settings = Settings::from_env(repo, cli.inbox, cli.main, Arc::clone(&interrupted))?;
        run(settings, cli.command, &interrupted)
    })();
    if interrupted.load(Ordering::Relaxed) {
        return std::process::ExitCode::from(130);
    }
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("patchgate: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
