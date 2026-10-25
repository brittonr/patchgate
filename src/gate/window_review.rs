use super::*;

impl Gate {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn decide_windows(
        &mut self,
        mut record: Record,
        candidate: &crate::pijul::ReviewChange,
        policy: &str,
        rules: &[change::PolicyRule],
        binding: &ReviewBinding,
        plan: &crate::review_plan::Plan<'_>,
        main: &ChannelSnapshot,
    ) -> Result<Record> {
        record.by = "model".into();
        record.model = Some(self.settings.model.clone());
        record.review = Some(binding.clone());
        record.coverage = Some(ContextCoverage {
            schema_version: 1,
            source_sha256: plan.source_sha256().to_owned(),
            planned_pages: plan.len(),
            complete: false,
            pages: Vec::with_capacity(plan.len()),
        });
        let mut citation_input = None;
        let mut citation_escalation = false;
        let threshold = self
            .settings
            .escalation_confidence
            .unwrap_or(DEFAULT_ESCALATION_CONFIDENCE);
        for index in 0..plan.len() {
            self.require_window_state(main)?;
            let input = plan.input(index)?;
            let answer_start = record.answers.len();
            let requests = &mut record.provenance.as_mut().context("Decision provenance is absent")?.requests;
            let request_start = requests.len();
            let mut batch = self.model.review_window(policy, &input, rules)?;
            self.require_window_state(main)?;
            record.answers.extend(self.window_answers("review-window", &batch, rules)?);
            requests.extend(std::mem::take(&mut batch.evidence));
            let mut operation = "review-window";
            let weak = batch.answers.values().any(|answer| {
                answer.confidence.is_none_or(|probability| probability < threshold)
            });
            if weak && batch.invalid.is_empty() {
                if let Some(model) = &self.escalation {
                    let mut second = model.review_window(policy, &input, rules)?;
                    self.require_window_state(main)?;
                    operation = "review-window-escalation";
                    record.answers.extend(self.window_answers(operation, &second, rules)?);
                    requests.extend(std::mem::take(&mut second.evidence));
                    batch = second;
                    citation_escalation = true;
                }
            }
            let mut page = ContextPage {
                index,
                input_sha256: format!("{:x}", Sha256::digest(input.get().as_bytes())),
                ranges: plan.ranges(index),
                answer_start,
                answer_count: record.answers.len() - answer_start,
                request_start,
                request_count: requests.len() - request_start,
                decision: "escalate".into(),
            };
            let verdict = window_verdict(&batch, rules, self.settings.rule_confidence);
            let Some(mut verdict) = verdict else {
                record.execution_error = Some("invalid-model-reply".into());
                record.reason = format!(
                    "Context window {index} has no valid answer for every review question. A human must decide."
                );
                record.coverage.as_mut().expect("The window coverage exists").pages.push(page);
                return Ok(record);
            };
            let abstained = self.abstain(
                &mut verdict.decision,
                &mut verdict.reason,
                verdict.confidence,
            );
            for answer in record.answers[answer_start..].iter_mut().filter(|answer| answer.operation == operation) {
                if abstained || (answer.question == "context" && answer.confidence.is_some_and(|probability| probability < self.settings.rule_confidence)) {
                    answer.abstained = true;
                }
            }
            page.decision.clone_from(&verdict.decision);
            record.coverage.as_mut().expect("The window coverage exists").pages.push(page);
            if verdict.decision != "accept" {
                record.decision = verdict.decision;
                record.reason = format!("Context window {index}: {}", verdict.reason);
                return Ok(record);
            }
            if index == 0 {
                citation_input = Some(input);
            }
        }
        record.coverage.as_mut().expect("The window coverage exists").complete = true;
        self.require_window_state(main)?;
        let model = if citation_escalation {
            self.escalation.as_ref().context("The escalation model is absent")?
        } else {
            &self.model
        };
        let input = citation_input.as_deref().context("The first context window is absent")?;
        let evidence_start = record.answers.len();
        let requests = &mut record.provenance.as_mut().context("Decision provenance is absent")?.requests;
        let evidence_request_start = requests.len();
        let evidence = self.pick_evidence(candidate, policy, input, model, &mut record.answers, requests)?;
        if !record.answers[evidence_start..].is_empty() {
            let request = requests.get(evidence_request_start).context("The citation request evidence is absent")?;
            for answer in &mut record.answers[evidence_start..] {
                answer.model.clone_from(&request.model);
            }
        }
        self.require_window_state(main)?;
        match evidence {
            Ok(detail) => {
                record.decision = "accept".into();
                record.reason = format!(
                    "All {} bounded context windows accept the complete change. The review covers every unchanged native span.{detail}",
                    plan.len()
                );
            }
            Err(problem) => record.reason = problem,
        }
        Ok(record)
    }

    fn require_window_state(&self, main: &ChannelSnapshot) -> Result<()> {
        if self.settings.interrupted.load(Ordering::Relaxed) {
            bail!("Interrupted before the next context request");
        }
        self.require_current_main(main)
    }

    fn window_answers(
        &self,
        operation: &str,
        batch: &crate::model::TypedBatch,
        rules: &[change::PolicyRule],
    ) -> Result<Vec<TypedAnswer>> {
        let model = &batch.evidence.first().context("The window request evidence is absent")?.model;
        let mut answers = self.batch_answers(operation, batch, rules)?;
        for answer in &mut answers {
            answer.model.clone_from(model);
        }
        Ok(answers)
    }
}

fn window_verdict(
    batch: &crate::model::TypedBatch,
    rules: &[change::PolicyRule],
    rule_confidence: f64,
) -> Option<RuleVerdict> {
    if !batch.invalid.is_empty() {
        return None;
    }
    let mut verdict = aggregate_answers(&batch.answers, rules, rule_confidence)?;
    let context = batch.answers.get("context")?;
    let probability = context.confidence?;
    verdict.confidence = verdict.confidence.map(|value| value.min(probability));
    match context.choice.as_str() {
        "sufficient" if probability >= rule_confidence => {}
        "sufficient" => {
            verdict.decision = "escalate".into();
            verdict.reason = format!(
                "The context answer probability {probability:.4} is below {rule_confidence:.4}. A human must decide."
            );
        }
        "needs-context" => {
            verdict.decision = "escalate".into();
            verdict.reason = "The policy decision needs source outside this context window. A human must decide.".into();
        }
        _ => return None,
    }
    Some(verdict)
}
