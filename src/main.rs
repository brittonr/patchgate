mod change;
mod gate;
mod model;
mod pijul;
mod protected;

use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
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
    Status,
    /// Review and merge the pending changes one time.
    Review,
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

fn run(gate: &mut Gate, command: Command, interrupted: &AtomicBool) -> Result<()> {
    match command {
        Command::Init => {
            for line in gate.init()? {
                println!("{line}");
            }
        }
        Command::Status => {
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
        Command::Review => {
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
            show(&gate.decide_by_hand(&change, "accept", reason.as_deref())?)
        }
        Command::Reject { change, reason } => {
            show(&gate.decide_by_hand(&change, "reject", reason.as_deref())?)
        }
        Command::Log { limit } => {
            for record in gate.ledger.history()?.iter().rev().take(limit) {
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
        let settings = Settings::from_env(repo, cli.inbox, cli.main)?;
        let mut gate = Gate::new(settings)?;
        run(&mut gate, cli.command, &interrupted)
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
