use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::doctor;
use crate::gate::Settings;
use crate::pijul::Pijul;

#[derive(Serialize)]
pub(crate) struct Report {
    pub schema_version: u32,
    pub initialized: bool,
    pub ready: bool,
    pub channels_only: bool,
    pub authorizes_acceptance: bool,
    pub actions: Vec<String>,
    pub diagnostics: Option<doctor::Report>,
}

pub(crate) fn run(
    settings: Settings,
    channels_only: bool,
    interrupted: &AtomicBool,
) -> Result<Report> {
    let mut report = Report {
        schema_version: 1,
        initialized: false,
        ready: false,
        channels_only,
        authorizes_acceptance: false,
        actions: Vec::new(),
        diagnostics: None,
    };
    let checked_main = if channels_only {
        ensure!(
            settings.main != settings.inbox,
            "Main and inbox must use different channel names."
        );
        doctor::metadata_safety(&settings.repo)?;
        match fs::symlink_metadata(settings.repo.join(".pijul/patchgate/acceptance.json")) {
            Ok(_) => anyhow::bail!(
                "A pending acceptance journal prevents channel setup. Run patchgate status first."
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("Cannot inspect pending acceptance state."),
        }
        None
    } else {
        let (diagnostics, main) = doctor::inspect_initialization(&settings)?;
        let ok = diagnostics.ok;
        report.diagnostics = Some(diagnostics);
        if !ok {
            return Ok(report);
        }
        Some(main.context("Initialization checks did not bind the main state.")?)
    };
    ensure!(
        !interrupted.load(Ordering::Relaxed),
        "Setup stopped before channel changes."
    );
    let pijul = Pijul::new(settings.repo.clone());
    if let Some(main) = &checked_main {
        ensure!(
            pijul.snapshot(&settings.main)? == *main,
            "The main channel changed during setup checks. Run patchgate init again."
        );
    }
    report.actions = create_channels(&settings, &pijul)?;
    if let Some(main) = &checked_main {
        ensure!(
            pijul.snapshot(&settings.main)? == *main,
            "The main channel changed during setup. Readiness is not established. Run patchgate init again."
        );
    }
    report.initialized = true;
    report.ready = !channels_only;
    Ok(report)
}

fn create_channels(settings: &Settings, pijul: &Pijul) -> Result<Vec<String>> {
    let (current, names) = pijul.channels()?;
    let mut actions = Vec::new();
    if names.contains(&settings.inbox) {
        actions.push(format!("Channel {} exists.", settings.inbox));
    } else {
        pijul.run(["fork", "--channel", &settings.main, &settings.inbox])?;
        actions.push(format!(
            "Made channel {} from {}.",
            settings.inbox, settings.main
        ));
    }
    if current.as_deref() != Some(&settings.inbox) {
        pijul
            .run(["channel", "switch", &settings.inbox])
            .with_context(|| {
                format!(
                    "Record or reset the working copy, then run: pijul channel switch {}",
                    settings.inbox
                )
            })?;
        actions.push(format!("The working copy is now on {}.", settings.inbox));
    }
    actions.push(format!(
        "Record changes in {}. patchgate decides which changes go into {}.",
        settings.inbox, settings.main
    ));
    Ok(actions)
}

pub(crate) fn show(report: &Report) {
    if let Some(diagnostics) = &report.diagnostics {
        doctor::show(diagnostics);
    }
    for action in &report.actions {
        println!("{action}");
    }
    if report.initialized {
        if report.channels_only {
            println!(
                "Channel setup only. Policy, checks, model readiness, and runtime isolation were not verified."
            );
        } else {
            println!("Gate setup passed. This report does not authorize acceptance.");
        }
    }
}
