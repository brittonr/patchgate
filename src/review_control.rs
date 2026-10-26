use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use parking_lot::Mutex;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewStop {
    Timeout,
    RequestLimit,
    Interrupted,
}

impl ReviewStop {
    pub fn code(self) -> &'static str {
        match self {
            Self::Timeout => "review-timeout",
            Self::RequestLimit => "review-request-limit",
            Self::Interrupted => "interrupted",
        }
    }
}

impl fmt::Display for ReviewStop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Timeout => "The review time limit expired",
            Self::RequestLimit => "The review request limit stopped the next request",
            Self::Interrupted => "The review was interrupted",
        })
    }
}

impl std::error::Error for ReviewStop {}

#[derive(Clone, Debug, Serialize)]
pub struct ReviewUsage {
    pub requests: usize,
    pub max_requests: usize,
    pub elapsed_seconds: f64,
    pub timeout_seconds: f64,
    pub stop: Option<ReviewStop>,
}

struct State {
    requests: usize,
    stop: Option<ReviewStop>,
    context: Option<RequestContext>,
}

struct RequestContext {
    candidate_hash: Option<[u8; 53]>,
    candidate_digest: String,
    window: Option<(usize, usize)>,
    tier: &'static str,
}

pub struct ReviewControl {
    started: Instant,
    deadline: Instant,
    timeout: Duration,
    max_requests: usize,
    interrupted: Arc<AtomicBool>,
    state: Mutex<State>,
}

impl ReviewControl {
    pub fn new(
        max_requests: usize,
        timeout: Duration,
        interrupted: Arc<AtomicBool>,
    ) -> Result<Self> {
        ensure!(max_requests > 0, "The review request limit must be positive");
        ensure!(!timeout.is_zero(), "The review time limit must be positive");
        let started = Instant::now();
        let deadline = started
            .checked_add(timeout)
            .ok_or_else(|| anyhow::anyhow!("The review time limit is too large"))?;
        Ok(Self {
            started,
            deadline,
            timeout,
            max_requests,
            interrupted,
            state: Mutex::new(State {
                requests: 0,
                stop: None,
                context: None,
            }),
        })
    }

    fn refresh(&self, state: &mut State) -> Result<()> {
        if state.stop.is_none() {
            state.stop = if self.interrupted.load(Ordering::Acquire) {
                Some(ReviewStop::Interrupted)
            } else if Instant::now() >= self.deadline {
                Some(ReviewStop::Timeout)
            } else {
                None
            };
        }
        match state.stop {
            Some(stop) => Err(stop.into()),
            None => Ok(()),
        }
    }

    pub fn check(&self) -> Result<()> {
        self.refresh(&mut self.state.lock())
    }

    pub fn remaining(&self) -> Result<Duration> {
        let mut state = self.state.lock();
        self.refresh(&mut state)?;
        match self.deadline.checked_duration_since(Instant::now()) {
            Some(remaining) if !remaining.is_zero() => Ok(remaining),
            _ => {
                state.stop = Some(ReviewStop::Timeout);
                Err(ReviewStop::Timeout.into())
            }
        }
    }

    pub fn usage(&self) -> ReviewUsage {
        let mut state = self.state.lock();
        let _ = self.refresh(&mut state);
        ReviewUsage {
            requests: state.requests,
            max_requests: self.max_requests,
            elapsed_seconds: self.started.elapsed().as_secs_f64(),
            timeout_seconds: self.timeout.as_secs_f64(),
            stop: state.stop,
        }
    }

    pub fn stop(&self) -> Option<ReviewStop> {
        let mut state = self.state.lock();
        let _ = self.refresh(&mut state);
        state.stop
    }

    pub fn set_context(
        &self,
        candidate: &str,
        window: Option<(usize, usize)>,
        tier: &'static str,
    ) {
        let tier = match tier {
            "primary" => "primary",
            "larger" => "larger",
            _ => "model",
        };
        let mut state = self.state.lock();
        if let Some(context) = &mut state.context {
            if context.candidate_hash.as_ref().is_some_and(|hash| hash.as_slice() == candidate.as_bytes()) {
                context.window = window;
                context.tier = tier;
                return;
            }
        }
        let native_hash = candidate.len() == 53
            && candidate.bytes().all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte));
        let mut candidate_digest = String::with_capacity(12);
        let candidate_hash = if native_hash {
            candidate_digest.push_str(&candidate[..12]);
            Some(candidate.as_bytes().try_into().expect("The native hash has 53 bytes"))
        } else {
            let digest = Sha256::digest(candidate.as_bytes());
            for byte in &digest[..6] {
                use std::fmt::Write;
                let _ = write!(candidate_digest, "{byte:02x}");
            }
            None
        };
        state.context = Some(RequestContext {
            candidate_hash,
            candidate_digest,
            window,
            tier,
        });
    }

    pub(crate) fn begin_request(&self) -> Result<()> {
        let mut state = self.state.lock();
        self.refresh(&mut state)?;
        if state.requests == self.max_requests {
            state.stop = Some(ReviewStop::RequestLimit);
            return Err(ReviewStop::RequestLimit.into());
        }
        state.requests += 1;
        self.print_progress(&state, false);
        Ok(())
    }

    pub(crate) fn cache_hit(&self) -> Result<()> {
        let mut state = self.state.lock();
        self.refresh(&mut state)?;
        self.print_progress(&state, true);
        Ok(())
    }

    fn print_progress(&self, state: &State, cached: bool) {
        let suffix = if cached { " cache-hit" } else { "" };
        let elapsed = self.started.elapsed().as_secs_f64();
        if let Some(context) = &state.context {
            if let Some((number, total)) = context.window {
                eprintln!(
                    "patchgate: candidate {} window {number}/{total} tier {} request {}/{} elapsed {elapsed:.1}s{suffix}",
                    context.candidate_digest, context.tier, state.requests, self.max_requests
                );
            } else {
                eprintln!(
                    "patchgate: candidate {} tier {} request {}/{} elapsed {elapsed:.1}s{suffix}",
                    context.candidate_digest, context.tier, state.requests, self.max_requests
                );
            }
        } else {
            eprintln!(
                "patchgate: request {}/{} elapsed {elapsed:.1}s{suffix}",
                state.requests, self.max_requests
            );
        }
    }

    pub(crate) async fn wait_for_stop(&self) -> anyhow::Error {
        loop {
            match self.remaining() {
                Ok(remaining) => {
                    tokio::time::sleep(remaining.min(Duration::from_millis(10))).await;
                }
                Err(error) => return error,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_limit_allows_completion_and_refuses_the_next_request() -> Result<()> {
        let control = ReviewControl::new(
            2,
            Duration::from_secs(5),
            Arc::new(AtomicBool::new(false)),
        )?;
        control.begin_request()?;
        control.begin_request()?;
        control.check()?;
        assert!(control.remaining()? > Duration::ZERO);
        assert_eq!(control.usage().requests, 2);
        assert_eq!(control.stop(), None);
        let error = control.begin_request().unwrap_err();
        assert_eq!(error.downcast_ref::<ReviewStop>(), Some(&ReviewStop::RequestLimit));
        assert_eq!(control.usage().requests, 2);
        assert_eq!(control.stop(), Some(ReviewStop::RequestLimit));
        Ok(())
    }

    #[test]
    fn interruption_is_terminal() -> Result<()> {
        let interrupted = Arc::new(AtomicBool::new(true));
        let control = ReviewControl::new(1, Duration::from_secs(5), interrupted.clone())?;
        assert_eq!(control.stop(), Some(ReviewStop::Interrupted));
        interrupted.store(false, Ordering::Release);
        let error = control.check().unwrap_err();
        assert_eq!(error.downcast_ref::<ReviewStop>(), Some(&ReviewStop::Interrupted));
        assert_eq!(control.usage().requests, 0);
        Ok(())
    }

    #[test]
    fn zero_or_unrepresentable_limits_fail() {
        for (requests, timeout) in [
            (0, Duration::from_secs(1)),
            (1, Duration::ZERO),
            (1, Duration::MAX),
        ] {
            assert!(ReviewControl::new(requests, timeout, Arc::new(AtomicBool::new(false))).is_err());
        }
    }
}
