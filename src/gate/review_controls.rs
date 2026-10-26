use super::*;

impl Gate {
    pub(super) fn with_review<T>(
        &mut self,
        action: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        anyhow::ensure!(self.review_control.is_none(), "A review pass is already active");
        let timeout = Duration::try_from_secs_f64(self.settings.review_timeout_seconds)?;
        let control = Arc::new(ReviewControl::new(
            self.settings.max_review_requests,
            timeout,
            Arc::clone(&self.settings.interrupted),
        )?);
        self.model.set_review_control(Some(Arc::clone(&control)));
        if let Some(model) = &mut self.escalation {
            model.set_review_control(Some(Arc::clone(&control)));
        }
        self.review_control = Some(Arc::clone(&control));
        self.last_review_usage = None;
        let result = action(self);
        let usage = control.usage();
        if let Some(stop) = usage.stop {
            eprintln!(
                "patchgate: review stopped: {stop}. requests={}/{} elapsed={:.1}s",
                usage.requests, usage.max_requests, usage.elapsed_seconds
            );
        }
        self.last_review_usage = Some(usage);
        self.review_control = None;
        self.model.set_review_control(None);
        if let Some(model) = &mut self.escalation {
            model.set_review_control(None);
        }
        result
    }

    pub(super) fn check_review(&self) -> Result<()> {
        if let Some(control) = &self.review_control {
            control.check()?;
        }
        Ok(())
    }

    pub(super) fn review_stop(&self) -> Option<ReviewStop> {
        self.review_control.as_ref().and_then(|control| control.stop())
    }

    pub(super) fn review_context(
        &self,
        candidate: &str,
        window: Option<(usize, usize)>,
        tier: &'static str,
    ) {
        if let Some(control) = &self.review_control {
            control.set_context(candidate, window, tier);
        }
    }

    pub(super) fn stop_review_record(&self, record: &mut Record, stop: ReviewStop) {
        record.decision = "escalate".into();
        record.by = "gate".into();
        record.execution_error = Some(stop.code().into());
        record.reason = format!(
            "The review stopped: {stop}. The unfinished change was not accepted."
        );
    }

    pub(super) fn review_failure(&self, mut record: Record, error: anyhow::Error) -> Result<Record> {
        let Some(stop) = error.downcast_ref::<ReviewStop>().copied() else {
            return Err(error);
        };
        self.stop_review_record(&mut record, stop);
        Ok(record)
    }

    pub(super) fn stop_review_chunk(
        &self,
        chunk: &mut [(Item, Rc<str>)],
        records: &mut [Record],
        stop: ReviewStop,
        report: &mut impl FnMut(&Item),
    ) -> Result<()> {
        for ((item, _), record) in chunk.iter_mut().zip(records) {
            if record.decision == "accept" {
                self.stop_review_record(record, stop);
            }
            self.append_under_lock(record)?;
            self.apply_decision(item, record);
        }
        for (item, _) in chunk {
            report(item);
        }
        Ok(())
    }
}
