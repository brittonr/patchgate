pub mod artifact;
mod budget;
pub mod bundle;
mod case_view;
mod cases;
mod change;
mod configuration;
mod decision;
mod doctor;
mod gate;
mod isolation;
mod model;
mod models;
mod patch_view;
mod pijul;
mod protected;
pub mod provenance;
pub mod release_policy;
mod resolution;
mod review;
mod review_plan;
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
use gate::{Gate, Item, Selection, Settings, State};
use pijul::Pijul;

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
    /// Fold configured lane channels into the inbox without a review.
    Lanes {
        #[arg(long)]
        json: bool,
    },
    /// Explain a change, its dependencies, and its decision evidence.
    Explain {
        change: String,
        #[arg(long)]
        json: bool,
    },
    /// Show the native palimpsest of one change.
    Show {
        change: String,
        #[arg(long)]
        json: bool,
    },
    /// Attribute channel lines to native changes and their gate decisions.
    Blame {
        path: String,
        /// The channel to read. Default: the main channel.
        #[arg(long)]
        channel: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Report complete review context costs without a model request.
    Budget {
        change: String,
        #[arg(long)]
        json: bool,
    },
    /// Prepare an isolated workspace for a human resolution.
    Resolve {
        #[arg(required_unless_present = "refresh", conflicts_with = "refresh")]
        change: Option<String>,
        /// Preserve recorded human work against current main in a new workspace.
        #[arg(long, required_unless_present = "change", conflicts_with = "change")]
        refresh: Option<PathBuf>,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Inspect a human workspace without records or acceptance.
    WorkspaceStatus {
        workspace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Verify a human workspace in isolation without acceptance.
    Verify {
        #[arg(long)]
        resolution: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Sign or verify replay artifacts with an explicit reviewer identity.
    Artifact {
        #[command(subcommand)]
        command: ArtifactCommand,
    },
    /// Review an earlier gate or model decision without loss of its evidence.
    Reconsider {
        change: String,
        #[arg(short = 'm', long)]
        reason: String,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    /// Capture, label, and export historical replay cases.
    Cases {
        #[command(subcommand)]
        command: CaseCommand,
    },
    /// Review and merge the pending changes one time.
    #[command(group(clap::ArgGroup::new("review_selection").args(["changes", "authors"]).multiple(true)))]
    Review {
        /// Review in isolation without source acceptance.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
        /// Select a change hash or a unique prefix. Repeat for several changes.
        #[arg(long = "change")]
        changes: Vec<String>,
        /// Select unaccepted changes by an exact native author name.
        #[arg(long = "author")]
        authors: Vec<String>,
        /// Include pending native prerequisites for the explicit selection.
        #[arg(long, requires = "review_selection")]
        include_dependencies: bool,
    },
    /// Show the effective model profile, and optionally probe its typed questions.
    Model {
        #[arg(long)]
        json: bool,
        /// Send two harmless typed questions to the endpoint.
        #[arg(long)]
        probe: bool,
    },
    /// Diagnose setup without repository changes.
    Doctor {
        #[arg(long)]
        json: bool,
        /// Exercise native state refusal and Nix isolation in private fixtures.
        #[arg(long)]
        runtime: bool,
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
        #[arg(required_unless_present = "resolution", conflicts_with = "resolution")]
        change: Option<String>,
        /// Accept the edited workspace against its original main state.
        #[arg(long, required_unless_present = "change", conflicts_with = "change")]
        resolution: Option<PathBuf>,
        /// The reason for the decision.
        #[arg(short = 'm', long)]
        reason: Option<String>,
        /// Refuse the decision when this native main state token is stale.
        #[arg(long)]
        expected_state: Option<String>,
    },
    /// Reject a change by hand.
    Reject {
        /// The change hash, or the start of the hash.
        change: String,
        /// The reason for the decision.
        #[arg(short = 'm', long)]
        reason: Option<String>,
    },
    /// Remove one accepted change and its merge from main exactly.
    Revert {
        /// The change hash, or the start of the hash.
        change: String,
        /// The reason for the revert.
        #[arg(short = 'm', long)]
        reason: Option<String>,
        /// Refuse the revert when this native main state token is stale.
        #[arg(long)]
        expected_state: Option<String>,
        #[arg(long)]
        json: bool,
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

#[derive(Subcommand)]
enum CaseCommand {
    /// Capture the current main snapshot for one pending change.
    Capture {
        change: String,
        #[arg(long)]
        json: bool,
    },
    /// Show captured snapshots and human label state.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show captured historical context without model verdicts.
    Show {
        case: String,
        #[arg(long)]
        json: bool,
    },
    /// Append an explicit human label.
    Label {
        case: String,
        #[arg(value_enum)]
        expected: cases::Label,
        #[arg(short = 'm', long)]
        reason: String,
        #[arg(long)]
        json: bool,
    },
    /// Replace human case tags and retain their history.
    Tag {
        case: String,
        #[arg(long = "policy-rule")]
        policy_rules: Vec<String>,
        #[arg(long = "conflict-kind")]
        conflict_kinds: Vec<String>,
        #[arg(short = 'm', long)]
        reason: String,
        #[arg(long)]
        json: bool,
    },
    /// Export labeled cases and explicit model variants for replay.
    Export {
        #[arg(long)]
        variants: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long = "case")]
        cases: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Export explicitly selected cases and native history as a portable bundle.
    Bundle {
        #[arg(long)]
        variants: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long = "case", required = true)]
        cases: Vec<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ArtifactCommand {
    /// Sign an artifact digest with a separate reviewer key.
    Sign {
        artifact: PathBuf,
        #[arg(long, value_enum)]
        kind: artifact::Kind,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Verify an artifact digest against explicit trusted signers.
    Verify {
        artifact: PathBuf,
        #[arg(long, value_enum)]
        kind: artifact::Kind,
        #[arg(long)]
        signature: PathBuf,
        #[arg(long)]
        allowed_signers: PathBuf,
        #[arg(long)]
        revoked_keys: Option<PathBuf>,
        #[arg(long)]
        identity: String,
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

fn label_name(label: cases::Label) -> &'static str {
    match label {
        cases::Label::Accept => "accept",
        cases::Label::Reject => "reject",
        cases::Label::Escalate => "escalate",
    }
}

fn show_case(record: &cases::CaseRecord, json: bool) -> Result<()> {
    if json {
        return print_json(record);
    }
    let label = record
        .labels
        .last()
        .map(|label| label_name(label.expected))
        .unwrap_or("unlabeled");
    println!(
        "{}  {}  {label}",
        record.id,
        short(&record.snapshot.candidate)
    );
    Ok(())
}

fn run_cases(settings: Settings, command: CaseCommand) -> Result<()> {
    match command {
        CaseCommand::Capture { change, json } => {
            show_case(&Gate::capture_case(settings, &change)?, json)?;
        }
        CaseCommand::Show { case, json } => {
            let report = case_view::inspect(&settings.repo, &case)?;
            if json {
                print_json(&report)?;
            } else {
                case_view::show(&report);
            }
        }
        CaseCommand::List { json } => {
            let records = cases::Store::new(&settings.repo).list()?;
            if json {
                #[derive(serde::Serialize)]
                struct CasesReport<'a> {
                    schema_version: u8,
                    cases: &'a [cases::CaseRecord],
                }
                print_json(&CasesReport {
                    schema_version: 1,
                    cases: &records,
                })?;
            } else {
                for record in &records {
                    show_case(record, false)?;
                }
                if records.is_empty() {
                    println!("No replay cases exist.");
                }
            }
        }
        CaseCommand::Label {
            case,
            expected,
            reason,
            json,
        } => {
            let record = cases::Store::new(&settings.repo).label(&case, expected, &reason)?;
            show_case(&record, json)?;
        }
        CaseCommand::Tag {
            case,
            policy_rules,
            conflict_kinds,
            reason,
            json,
        } => {
            let record = cases::Store::new(&settings.repo).tag(
                &case,
                &policy_rules,
                &conflict_kinds,
                &reason,
            )?;
            show_case(&record, json)?;
        }
        CaseCommand::Export {
            variants,
            output,
            cases,
            json,
        } => {
            let report = cases::Store::new(&settings.repo).export(&cases, &variants, &output)?;
            if json {
                print_json(&report)?;
            } else {
                println!(
                    "Exported labeled replay cases to {}.",
                    report.output.display()
                );
            }
        }
        CaseCommand::Bundle {
            variants,
            output,
            cases,
            json,
        } => {
            eprintln!(
                "patchgate: Bundle history can contain credentials. Store this file as sensitive data."
            );
            let report = cases::Store::new(&settings.repo).bundle(&cases, &variants, &output)?;
            if json {
                print_json(&report)?;
            } else {
                println!(
                    "Exported {} selected cases to {}.",
                    report.cases.len(),
                    report.output.display()
                );
                println!("Bundle SHA-256: {}", report.sha256);
            }
        }
    }
    Ok(())
}

fn run_artifact(source: &std::path::Path, command: ArtifactCommand) -> Result<()> {
    match command {
        ArtifactCommand::Sign {
            artifact,
            kind,
            key,
            output,
            json,
        } => {
            let report = artifact::sign(source, &artifact, kind, &key, &output)?;
            if json {
                print_json(&report)?;
            } else {
                println!("Signature: {}", report.signature.display());
                println!("Artifact SHA-256: {}", report.sha256);
                println!("Reviewer key: {}", report.signer_fingerprint);
            }
        }
        ArtifactCommand::Verify {
            artifact,
            kind,
            signature,
            allowed_signers,
            revoked_keys,
            identity,
            json,
        } => {
            let trust = artifact::Trust {
                signature,
                allowed_signers,
                revoked_keys,
                identity,
            };
            let report = artifact::verify(&artifact, kind, &trust)?;
            if json {
                print_json(&report)?;
            } else {
                println!("Verified reviewer: {}", report.identity);
                println!("Verified key: {}", report.signer_fingerprint);
                println!("Artifact SHA-256: {}", report.sha256);
                println!("The signature grants no acceptance authority.");
            }
        }
    }
    Ok(())
}

fn quote_path(path: &std::path::Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn run(settings: Settings, command: Command, interrupted: &AtomicBool) -> Result<()> {
    match command {
        Command::Artifact { command } => run_artifact(&settings.repo, command)?,
        Command::Verify { resolution, json } => {
            let report = Gate::verify_resolution(settings, &resolution)?;
            if json {
                print_json(&report)?;
            } else {
                resolution::show_verification(&report);
            }
        }
        Command::WorkspaceStatus { workspace, json } => {
            let report = Gate::workspace_status(settings, &workspace)?;
            if json {
                print_json(&report)?;
            } else {
                println!("Workspace: {}", report.workspace.display());
                for blocker in &report.blockers {
                    println!("Blocked [{}]: {}", blocker.code, blocker.detail);
                }
                if let Some(pending) = report.pending_tracked_edits {
                    println!("Pending tracked edits: {pending}");
                }
                if let Some(conflicts) = &report.recorded_conflicts {
                    println!("Recorded conflicts: {}", conflicts.len());
                }
                for check in &report.pending_verification {
                    println!("Pending [{}]: {}", check.code, check.detail);
                }
                println!("The report grants no acceptance authority.");
            }
            if !report.blockers.is_empty() {
                bail!("Workspace inspection found acceptance blockers.");
            }
        }
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
        Command::Lanes { json } => {
            let mut gate = Gate::new(settings)?;
            let reports = gate.sync_lanes()?;
            if json {
                #[derive(serde::Serialize)]
                struct LanesReport {
                    schema_version: u8,
                    lanes: Vec<gate::LaneReport>,
                }
                print_json(&LanesReport {
                    schema_version: 1,
                    lanes: reports,
                })?;
            } else if reports.is_empty() {
                println!("No lane channel is configured. Set PATCHGATE_LANES.");
            } else {
                for lane in &reports {
                    println!("{}  folded {} change(s)", lane.lane, lane.applied.len());
                    for hash in &lane.applied {
                        println!("          {}", short(hash));
                    }
                }
            }
        }
        Command::Show { change, json } => {
            let pijul = Pijul::new(settings.repo.clone());
            let report = patch_view::show(&pijul, &change)?;
            if json {
                print_json(&report)?;
            } else {
                patch_view::print_show(&report);
            }
        }
        Command::Blame {
            path,
            channel,
            json,
        } => {
            let channel = channel.unwrap_or_else(|| settings.main.clone());
            let pijul = Pijul::new(settings.repo.clone());
            let ledger = gate::Ledger::new(&settings.repo);
            let report = patch_view::blame(&pijul, &ledger, &channel, &path)?;
            if json {
                print_json(&report)?;
            } else {
                patch_view::print_blame(&report);
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
        Command::Budget { change, json } => {
            let report = Gate::budget(settings, &change)?;
            if json {
                print_json(&report)?;
            } else {
                budget::show(&report);
            }
        }
        Command::Resolve {
            change,
            refresh,
            workspace,
            json,
        } => {
            let repository = settings.repo.clone();
            let (prepared, refreshed) = if let Some(previous) = refresh {
                let result = Gate::refresh_resolution(settings, &previous, &workspace)?;
                (
                    result.prepared,
                    Some((result.previous_id, result.preserved)),
                )
            } else {
                (
                    Gate::prepare_resolution(
                        settings,
                        change
                            .as_deref()
                            .context("Give a change or an old workspace.")?,
                        &workspace,
                    )?,
                    None,
                )
            };
            if json {
                #[derive(serde::Serialize)]
                struct ResolutionReport<'a> {
                    schema_version: u8,
                    authorizes_acceptance: bool,
                    prepared: &'a resolution::Prepared,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    refreshed_from: Option<&'a str>,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    preserved: Option<&'a [String]>,
                }
                print_json(&ResolutionReport {
                    schema_version: 1,
                    authorizes_acceptance: false,
                    prepared: &prepared,
                    refreshed_from: refreshed.as_ref().map(|(previous, _)| previous.as_str()),
                    preserved: refreshed.as_ref().map(|(_, hashes)| hashes.as_slice()),
                })?;
            } else {
                println!("Resolution: {}", prepared.id);
                println!("Workspace: {}", prepared.workspace.display());
                println!("Conflicts: {}", prepared.conflicts.len());
                if let Some((previous, preserved)) = &refreshed {
                    println!("Refreshed from: {previous}");
                    println!("Preserved human records: {}", preserved.len());
                    println!(
                        "The old workspace remains unchanged. Its untracked files stay there."
                    );
                }
                if let Some(policy) = &prepared.policy_file {
                    println!("Trusted policy: {}", policy.display());
                }
                println!("Native review: {}", prepared.review_file.display());
                println!("Edit tracked files. Use pijul add for new files.");
                println!(
                    "Accept explicitly: patchgate --repo {} accept --resolution {}",
                    quote_path(&repository),
                    quote_path(&prepared.workspace),
                );
            }
        }
        Command::Reconsider {
            change,
            reason,
            dry_run,
            json,
        } => {
            let report = if dry_run {
                Gate::reconsider_dry_run(settings, &change, &reason)?
            } else {
                Gate::new(settings)?.reconsider(&change, &reason)?
            };
            show_review(&report, json)?;
        }
        Command::Cases { command } => run_cases(settings, command)?,
        Command::Model { json, probe } => {
            let selection = models::select()?;
            if json {
                #[derive(serde::Serialize)]
                struct ModelReport<'a> {
                    schema_version: u8,
                    profile: Option<&'a str>,
                    url: &'a str,
                    model: &'a str,
                    api: &'a str,
                    typed_decisions: bool,
                    revision: Option<&'a str>,
                    key_file: Option<&'a std::path::Path>,
                    profiles_file: Option<&'a std::path::Path>,
                    profiles: &'a [String],
                }
                print_json(&ModelReport {
                    schema_version: 1,
                    profile: selection.profile.as_deref(),
                    url: &selection.url,
                    model: &selection.model,
                    api: selection.api.as_str(),
                    typed_decisions: matches!(selection.api, model::Api::SystemOne),
                    revision: selection.revision.as_deref(),
                    key_file: selection.key_file.as_deref(),
                    profiles_file: selection.source.as_deref(),
                    profiles: &selection.available,
                })?;
            } else {
                println!("Profile: {}", selection.profile_name());
                println!("Endpoint: {}", selection.url);
                println!("Model: {}", selection.model);
                println!("API: {}", selection.api.as_str());
                println!(
                    "Decision path: {}",
                    if matches!(selection.api, model::Api::SystemOne) {
                        "typed choices with label probabilities"
                    } else {
                        "chat generation (legacy)"
                    }
                );
                if let Some(revision) = &selection.revision {
                    println!("Revision: {revision}");
                }
                if let Some(key_file) = &selection.key_file {
                    println!("Key file: {}", key_file.display());
                }
                match &selection.source {
                    Some(path) => println!("Profiles file: {}", path.display()),
                    None => println!("Profiles file: none"),
                }
                if !selection.available.is_empty() {
                    println!("Profiles: {}", selection.available.join(", "));
                }
                if !probe {
                    println!("This reports configuration only. It makes no model request.");
                }
            }
            if probe {
                run_probe(&selection, json)?;
            }
        }
        Command::Doctor { json, runtime } => {
            let report = if runtime {
                doctor::inspect_runtime(&settings)?
            } else {
                doctor::inspect(&settings)?
            };
            if json {
                print_json(&report)?;
            } else {
                doctor::show(&report);
            }
            if !report.ok {
                bail!("Setup diagnostics found errors. Use the repair commands in the report.");
            }
        }
        Command::Review {
            dry_run,
            json,
            changes,
            authors,
            include_dependencies,
        } => {
            let selection = Selection {
                changes,
                authors,
                include_dependencies,
            };
            if dry_run {
                return show_review(&Gate::dry_run(settings, &selection)?, json);
            }
            let mut gate = Gate::new(settings)?;
            if json {
                return show_review(&gate.review_report(false, &selection)?, true);
            }
            let (items, selected) = gate.review(&selection, show)?;
            if let Some(selected) = selected {
                println!(
                    "Selected {} change(s), with {} added prerequisite(s).",
                    selected.selected.len(),
                    selected.added_dependencies.len()
                );
                for item in items.iter().filter(|item| !item.decided) {
                    show(item);
                }
            }
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
            println!(
                "Model: {} at {} (profile {})",
                s.model,
                s.model_url,
                s.model_profile.as_deref().unwrap_or("environment")
            );
            let mut last_error = None;
            while !interrupted.load(Ordering::Relaxed) {
                match gate.review(&Selection::default(), show) {
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
        Command::Accept {
            change,
            resolution,
            reason,
            expected_state,
        } => {
            let mut gate = Gate::new(settings)?;
            gate.require_state(expected_state.as_deref())?;
            let item = if let Some(workspace) = resolution {
                gate.accept_resolution(&workspace, reason.as_deref())?
            } else {
                gate.decide_by_hand(
                    &change.context("Give a change or a resolution workspace")?,
                    "accept",
                    reason.as_deref(),
                )?
            };
            show(&item);
        }
        Command::Reject { change, reason } => {
            let mut gate = Gate::new(settings)?;
            show(&gate.decide_by_hand(&change, "reject", reason.as_deref())?)
        }
        Command::Revert {
            change,
            reason,
            expected_state,
            json,
        } => {
            let mut gate = Gate::new(settings)?;
            gate.require_state(expected_state.as_deref())?;
            let report = gate.revert(&change, reason.as_deref())?;
            if json {
                print_json(&report)?;
            } else {
                println!("Reverted {} from main.", short(&report.target));
                for hash in &report.reverted {
                    println!("          {}", short(hash));
                }
                println!("The inbox keeps the changes. The ledger records the revert.");
            }
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
        match cli.command {
            Command::Artifact { command } => run_artifact(&cli.repo, command),
            command => {
                let repo = gate::find_repo(&cli.repo)?;
                let settings =
                    Settings::from_env(repo, cli.inbox, cli.main, Arc::clone(&interrupted))?;
                run(settings, command, &interrupted)
            }
        }
    })();
    if interrupted.load(Ordering::Relaxed) {
        return std::process::ExitCode::from(130);
    }
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("patchgate: {error:#}");
            if error.downcast_ref::<gate::StateTokenMismatch>().is_some() {
                return std::process::ExitCode::from(gate::STATE_TOKEN_MISMATCH);
            }
            std::process::ExitCode::FAILURE
        }
    }
}

/// Send two harmless typed questions, so a caller can see the question-set support.
fn run_probe(selection: &models::Selection, json: bool) -> Result<()> {
    if !matches!(selection.api, model::Api::SystemOne) {
        if json {
            print_json(&serde_json::json!({
                "schema_version": 1,
                "typed_questions": false,
                "detail": "chat generation has no typed question set"
            }))?;
        } else {
            println!("Probe: chat generation has no typed question set.");
        }
        return Ok(());
    }
    let key = selection
        .key_file
        .as_deref()
        .map(models::read_key)
        .transpose()?;
    let model = model::Model::new(
        &selection.url,
        &selection.model,
        Duration::from_secs(60),
        selection.api,
        selection.revision.as_deref(),
        key.as_deref(),
    )?;
    let rules = [change::PolicyRule {
        id: "R1".into(),
        text: "The probe has no change to review.".into(),
    }];
    let state = serde_json::value::to_raw_value(&serde_json::json!({
        "schema_version": 1,
        "probe": true
    }))?;
    let batch = model.review_questions(
        "This is a capability probe. It has no policy and no change.",
        &state,
        &rules,
    )?;
    let answered = batch.answers.len();
    let invalid = batch.invalid.len();
    if json {
        print_json(&serde_json::json!({
            "schema_version": 1,
            "typed_questions": true,
            "questions": 2,
            "answered": answered,
            "invalid": invalid
        }))?;
    } else {
        println!("Probe: {answered} of 2 typed questions answered, {invalid} invalid.");
    }
    if invalid > 0 {
        bail!("The typed endpoint did not answer every probe question.");
    }
    Ok(())
}
