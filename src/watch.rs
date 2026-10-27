use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::gate::{Gate, Item, Selection, Settings, State};
use crate::review_control::ReviewStop;
use crate::watch_health::{Counts, Failure, Store};

pub(crate) fn run(settings: Settings, interval: f64, interrupted: &AtomicBool) -> Result<()> {
    let delay = Duration::try_from_secs_f64(interval)
        .context("--interval must be a finite, nonnegative number")?;
    Instant::now()
        .checked_add(delay)
        .context("--interval exceeds the clock range")?;
    let startup_timeout = settings.timeout.max(settings.check_timeout);
    let mut health = Store::start(
        &settings.repo,
        &settings.main,
        &settings.inbox,
        startup_timeout,
    )?;
    let mut gate = match Gate::new(settings) {
        Ok(gate) => gate,
        Err(error) => {
            health.complete(None, Some(Failure::StartupError), delay)?;
            return Err(error);
        }
    };
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
        health.reviewing(gate.settings.timeout.max(gate.settings.check_timeout))?;
        let mut publication_failed = false;
        let result = gate.review_observed(&Selection::default(), crate::show, |timeout| {
            let result = health.reviewing(timeout);
            publication_failed = result.is_err();
            result
        });
        if publication_failed {
            return result.map(|_| ()).context("Cannot publish watch progress");
        }
        if interrupted.load(Ordering::Relaxed) {
            break;
        }
        match result {
            Ok((items, _)) => {
                let counts = counts(&items);
                let failure =
                    (counts.execution_errors != 0).then_some(Failure::ReviewExecutionError);
                health.complete(Some(counts), failure, delay)?;
                last_error = None;
            }
            Err(error) => {
                let failure = match error.downcast_ref::<ReviewStop>() {
                    Some(ReviewStop::Timeout) => Failure::ReviewTimeout,
                    Some(ReviewStop::RequestLimit) => Failure::ReviewRequestLimit,
                    Some(ReviewStop::Interrupted) => break,
                    None => Failure::ReviewError,
                };
                health.complete(None, Some(failure), delay)?;
                let error = format!("{error:#}");
                if last_error.as_ref() != Some(&error) {
                    eprintln!("patchgate: {error}");
                    last_error = Some(error);
                }
            }
        }
        let deadline = Instant::now()
            .checked_add(delay)
            .context("--interval exceeds the clock range")?;
        while !interrupted.load(Ordering::Relaxed) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            std::thread::park_timeout(remaining);
        }
    }
    health.stop()
}

fn counts(items: &[Item]) -> Counts {
    let mut counts = Counts::default();
    for item in items {
        match item.state {
            State::Accepted => counts.accepted += 1,
            State::Rejected => counts.rejected += 1,
            State::Escalated => counts.escalated += 1,
            State::Blocked => counts.blocked += 1,
            State::Waiting => counts.waiting += 1,
            State::Pending => counts.pending += 1,
            State::Removed => counts.removed += 1,
            State::Reverted => counts.reverted += 1,
            State::Unknown => counts.unknown += 1,
        }
        counts.execution_errors += usize::from(item.execution_failed);
    }
    counts
}
