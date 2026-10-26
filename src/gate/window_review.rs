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
            self.review_context(&candidate.hash, Some((index + 1, plan.len())), "primary");
            if let Err(error) = self.require_window_state(main) {
                return self.review_failure(record, error);
            }
            let input = plan.input(index)?;
            let input_sha256 = format!("{:x}", Sha256::digest(input.get().as_bytes()));
            let mut cache_hits = Vec::new();
            let answer_start = record.answers.len();
            let requests = &mut record.provenance.as_mut().context("Decision provenance is absent")?.requests;
            let request_start = requests.len();
            let (mut batch, hit) = match self.window_batch(
                &self.model, policy, &input, rules, plan.source_sha256(), &input_sha256, main,
            ) {
                Ok(result) => result,
                Err(error) => return self.review_failure(record, error),
            };
            if let Some(key) = hit {
                cache_hits.push(WindowCacheHit {
                    key,
                    request_start: requests.len(),
                    request_count: batch.evidence.len(),
                });
            }
            record.answers.extend(self.window_answers("review-window", &batch, rules)?);
            requests.extend(std::mem::take(&mut batch.evidence));
            let mut operation = "review-window";
            let weak = batch.answers.values().any(|answer| {
                answer.confidence.is_none_or(|probability| probability < threshold)
            });
            if weak && batch.invalid.is_empty() {
                if let Some(model) = &self.escalation {
                    self.review_context(&candidate.hash, Some((index + 1, plan.len())), "larger");
                    let (mut second, hit) = match self.window_batch(
                        model, policy, &input, rules, plan.source_sha256(), &input_sha256, main,
                    ) {
                        Ok(result) => result,
                        Err(error) => return self.review_failure(record, error),
                    };
                    if let Some(key) = hit {
                        cache_hits.push(WindowCacheHit {
                            key,
                            request_start: requests.len(),
                            request_count: second.evidence.len(),
                        });
                    }
                    operation = "review-window-escalation";
                    record.answers.extend(self.window_answers(operation, &second, rules)?);
                    requests.extend(std::mem::take(&mut second.evidence));
                    batch = second;
                    citation_escalation = true;
                }
            }
            let mut page = ContextPage {
                index,
                input_sha256,
                ranges: plan.ranges(index),
                answer_start,
                answer_count: record.answers.len() - answer_start,
                request_start,
                request_count: requests.len() - request_start,
                decision: "escalate".into(),
                cache_hits,
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
        if let Err(error) = self.require_window_state(main) {
            return self.review_failure(record, error);
        }
        self.review_context(
            &candidate.hash,
            None,
            if citation_escalation { "larger" } else { "primary" },
        );
        let model = if citation_escalation {
            self.escalation.as_ref().context("The escalation model is absent")?
        } else {
            &self.model
        };
        let input = citation_input.as_deref().context("The first context window is absent")?;
        let evidence_start = record.answers.len();
        let requests = &mut record.provenance.as_mut().context("Decision provenance is absent")?.requests;
        let evidence_request_start = requests.len();
        let evidence = match self.pick_evidence(candidate, policy, input, model, &mut record.answers, requests) {
            Ok(evidence) => evidence,
            Err(error) => return self.review_failure(record, error),
        };
        if !record.answers[evidence_start..].is_empty() {
            let request = requests.get(evidence_request_start).context("The citation request evidence is absent")?;
            for answer in &mut record.answers[evidence_start..] {
                answer.model.clone_from(&request.model);
            }
        }
        if let Err(error) = self.require_window_state(main) {
            return self.review_failure(record, error);
        }
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

    #[allow(clippy::too_many_arguments)]
    fn window_batch(
        &self,
        model: &Model,
        policy: &str,
        input: &RawValue,
        rules: &[change::PolicyRule],
        source_sha256: &str,
        input_sha256: &str,
        main: &ChannelSnapshot,
    ) -> Result<(crate::model::TypedBatch, Option<String>)> {
        let prepared = model.prepare_window(policy, input, rules)?;
        let key = crate::window_cache::key(&crate::window_cache::Binding {
            source_sha256,
            input_sha256,
            request: prepared.evidence(),
            model_identity: model.identity_sha256(),
            min_confidence: self.settings.min_confidence,
            rule_confidence: self.settings.rule_confidence,
            escalation_confidence: self.settings.escalation_confidence
                .unwrap_or(DEFAULT_ESCALATION_CONFIDENCE),
            escalation_identity: self.escalation.as_ref().map(Model::identity_sha256),
        })?;
        if let Some(batch) = self.windows.load(&key, prepared.evidence())? {
            if prepared.valid_batch(&batch) {
                self.require_window_state(main)?;
                if let Some(control) = &self.review_control {
                    control.cache_hit()?;
                }
                return Ok((batch, Some(key)));
            }
        }
        let batch = prepared.execute()?;
        self.check_review()?;
        if batch.invalid.is_empty() && batch.answers.len() == rules.len() + 2 {
            if let Err(error) = self.windows.store(&key, &batch) {
                eprintln!("patchgate: the window cache did not record this batch: {error}");
            }
        }
        self.require_window_state(main)?;
        Ok((batch, None))
    }

    fn require_window_state(&self, main: &ChannelSnapshot) -> Result<()> {
        self.check_review()?;
        if self.settings.interrupted.load(Ordering::Relaxed) {
            return Err(ReviewStop::Interrupted.into());
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
