use super::support::*;
use parking_lot::Mutex;
use std::collections::BTreeSet;
use std::sync::Arc;

pub const SCENARIOS: &[Scenario] = &[Scenario {
    name: "rust-model-rules",
    setup: typed_setup,
    solve: typed_solve,
    check,
}];

const TARGET_TEXT: &str = "status = approved\n";
const BASE_TEXT: &str = "report header\nstatus = pending\nunchanged separator 0\nunchanged separator 1\nunchanged separator 2\nunchanged separator 3\nunchanged separator 4\nunchanged separator 5\nunchanged separator 6\nunchanged separator 7\nunchanged separator 8\nunchanged separator 9\nunchanged separator 10\nunchanged separator 11\nchecked = before\nreport footer\n";

fn policy_text(target: &str) -> String {
    format!("# Review policy\n\n- [R1] Reject changes that add TODO text.\n- [R2] A human must review changes that add a human-review request.\n- [R3] Accept other changes. The added status = approved line in {target} is decisive evidence. Ignore other files and timestamp changes for acceptance evidence.\n")
}

fn span_label(vertex: &Value) -> Result<String> {
    let hash = vertex["change"].as_str().context("The native span has no origin.")?;
    let start = vertex["start"].as_u64().context("The native span has no start.")?;
    let end = vertex["end"].as_u64().context("The native span has no end.")?;
    ensure!(start < end, "The native span must contain bytes.");
    Ok(format!("{} {start}-{end}", super::change::short(hash)))
}

fn native_target_span(context: &Value, target_path: &str, hash: &str) -> Result<String> {
    ensure!(context["full"] == true, "The native context must be complete.");
    let files = context["files"].as_array().context("The native context has no files.")?;
    let paths: BTreeSet<_> = files.iter().filter_map(|file| file["path"].as_str()).collect();
    ensure!(paths.len() >= 2, "The native context needs two paths.");
    for path in ["alpha.txt", "beta.txt"] {
        let mut labels = BTreeSet::new();
        for file in files.iter().filter(|file| file["path"] == path) {
            for vertex in file["vertices"].as_array().context("The native file has no vertices.")? {
                if vertex["kind"] == "add" || vertex["kind"] == "del" {
                    labels.insert(span_label(vertex)?);
                }
            }
        }
        ensure!(labels.len() == 4, "Each report path needs four native span choices.");
    }
    let mut targets = Vec::new();
    for file in files.iter().filter(|file| file["path"] == target_path) {
        for vertex in file["vertices"].as_array().context("The target file has no vertices.")? {
            if vertex["kind"] == "add" && vertex["text"] == TARGET_TEXT {
                ensure!(vertex["change"] == hash, "The target span must originate in the candidate.");
                targets.push(span_label(vertex)?);
            }
        }
    }
    ensure!(targets.len() == 1, "The target needs one exact added status span.");
    Ok(targets.remove(0))
}

fn typed_setup(dir: &Path, signer: &Signer) -> Result<Value> {
    let mut cases = Vec::new();
    let approved = BASE_TEXT.replace("status = pending\n", TARGET_TEXT).replace("checked = before\n", "checked = after\n");
    for (id, target, expected, extra) in [
        ("approve-alpha", "alpha.txt", "accept", None),
        ("approve-beta", "beta.txt", "accept", None),
        ("reject-todo", "alpha.txt", "reject", Some("TODO: revise the report.\n")),
        ("human-review", "alpha.txt", "escalate", Some("human-review request: assess the report.\n")),
    ] {
        let policy = policy_text(target);
        let repo = start(&dir.join("cases").join(id), signer, &[("POLICY.md", &policy), ("alpha.txt", BASE_TEXT), ("beta.txt", BASE_TEXT)])?;
        let base = repo.hashes("main")?;
        let mut candidate = vec![("alpha.txt", approved.as_str()), ("beta.txt", approved.as_str())];
        if let Some(text) = extra {
            candidate.push(("note.txt", text));
        }
        let hash = repo.change(&candidate, "Update report status")?;
        let context: Value = serde_json::from_str(&repo.pijul(&["change", "--context", &hash])?)?;
        let target_span = native_target_span(&context, target, &hash)?;
        let mut files = json!({"POLICY.md": policy, "alpha.txt": approved, "beta.txt": approved});
        if let Some(text) = extra {
            files["note.txt"] = json!(text);
        }
        let labels = match expected {
            "accept" => ["accept", "not-covered", "not-covered", "allows"],
            "reject" => ["reject", "rejects", "not-covered", "not-covered"],
            _ => ["escalate", "not-covered", "needs-human", "not-covered"],
        };
        cases.push(json!({"id": id, "hash": hash, "base": base, "policy": policy,
            "expected": expected, "expected_answers": {"review": labels[0], "rule-R1": labels[1], "rule-R2": labels[2], "rule-R3": labels[3]},
            "target_path": target, "target_text": TARGET_TEXT, "target_span": target_span,
            "base_files": {"POLICY.md": policy, "alpha.txt": BASE_TEXT, "beta.txt": BASE_TEXT}, "files": files}));
    }
    Ok(json!({"cases": cases}))
}

fn trusted_target(instructions: &str) -> Result<&'static str> {
    for target in ["alpha.txt", "beta.txt"] {
        if instructions.ends_with(&policy_text(target)) {
            return Ok(target);
        }
    }
    bail!("The question must contain the exact trusted rule policy.")
}

fn typed_oracle(body: &Value) -> Result<Reply> {
    let questions = body["questions"].as_object().context("The request needs SystemOne questions.")?;
    let state = &body["state"];
    let candidate = &state["candidate"];
    let context = &candidate["context"];
    let files = context["files"].as_array().context("The request needs native candidate files.")?;
    let mut added = String::new();
    for file in files {
        for vertex in file["vertices"].as_array().context("The native file needs vertices.")? {
            if vertex["kind"] == "add" {
                added.push_str(vertex["text"].as_str().context("The native vertex needs text.")?);
            }
        }
    }
    let decision = if added.contains("TODO") { "reject" } else if added.contains("human-review request") { "escalate" } else { "accept" };
    let mut answers = serde_json::Map::new();
    for (name, question) in questions {
        let target = trusted_target(question["instructions"].as_str().context("The question needs trusted instructions.")?)?;
        let choice = match name.as_str() {
            "review" => decision.to_owned(),
            "rule-R1" => if decision == "reject" { "rejects" } else { "not-covered" }.to_owned(),
            "rule-R2" => if decision == "escalate" { "needs-human" } else { "not-covered" }.to_owned(),
            "rule-R3" => if decision == "accept" { "allows" } else { "not-covered" }.to_owned(),
            "path" => target.to_owned(),
            "span" => native_target_span(context, target, candidate["hash"].as_str().context("The candidate needs a hash.")?)?,
            _ => bail!("The oracle received an unknown question."),
        };
        ensure!(question["criteria"].get(&choice).is_some(), "The answer must be an enumerated choice.");
        answers.insert(name.clone(), json!({"type": "choice", "choice": choice, "confidence": 1.0}));
    }
    Ok(Reply { status: 200, body: json!({"answers": answers}) })
}

fn typed_proxy(request: Request, endpoint: Option<&str>, traces: &Mutex<Vec<Value>>) -> Result<Reply> {
    let started = Instant::now();
    let url = endpoint.map(|base| format!("{}/systemone", base.trim_end_matches('/'))).unwrap_or_else(|| "scripted://systemone".to_owned());
    let mut trace = json!({"status": null, "response": null, "response_text": null});
    let result: Result<Reply> = (|| {
        if endpoint.is_none() {
            let reply = typed_oracle(&request.body)?;
            trace["status"] = json!(reply.status);
            trace["response"] = reply.body.clone();
            trace["response_text"] = json!(serde_json::to_string(&reply.body)?);
            return Ok(reply);
        }
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(300)))
            .http_status_as_error(false).build().into();
        let raw = serde_json::to_vec(&request.body)?;
        let mut response = agent.post(&url).header("Content-Type", "application/json").send(raw.as_slice())
            .map_err(|error| anyhow!("Contact endpoint: {error}"))?;
        let status = response.status().as_u16();
        trace["status"] = json!(status);
        let mut text = String::new();
        use std::io::Read;
        let read_result = response.body_mut().as_reader().read_to_string(&mut text);
        trace["response_text"] = json!(text);
        read_result.context("Read endpoint response.")?;
        let body: Value = serde_json::from_str(&text).context("Decode endpoint response.")?;
        trace["response"] = body.clone();
        Ok(Reply { status, body })
    })();
    trace["path"] = Value::String(request.path);
    trace["request"] = request.body;
    trace["endpoint"] = Value::String(url);
    trace["elapsed_seconds"] = json!(started.elapsed().as_secs_f64());
    if let Err(error) = &result {
        trace["error"] = json!(format!("{error:#}"));
    }
    traces.lock().push(trace);
    result
}

fn typed_solve(dir: &Path, options: &RunOptions) -> Result<()> {
    ensure!(options.model_url.is_none() || options.api == "systemone", "This rule task requires the SystemOne API.");
    let facts = load_facts(dir)?;
    let cases = facts["cases"].as_array().context("The facts need rule cases.")?;
    let mut measurements = Vec::new();
    let model_name = if options.model_url.is_some() { options.model.as_str() } else { "rust-scripted-oracle" };
    for case in cases {
        let id = case["id"].as_str().context("The case needs an ID.")?;
        let repo = Repo::open(dir.join("cases").join(id).join("repo"));
        let traces = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&traces);
        let endpoint = options.model_url.clone();
        let model = ModelServer::new(move |request| {
            typed_proxy(request, endpoint.as_deref(), &captured).unwrap_or_else(|error| Reply {
                status: 502, body: json!({"error": format!("{error:#}")}),
            })
        })?;
        let case_started = Instant::now();
        let mut env = vec![("PATCHGATE_MODEL_API", "systemone"), ("PATCHGATE_MODEL", model_name), ("PATCHGATE_TIMEOUT", "310")];
        if let Some(revision) = options.revision.as_deref() {
            env.push(("PATCHGATE_MODEL_REVISION", revision));
        }
        let command = super::real_model::command_report(repo.gate(Some(&model), &["review"], &env));
        let elapsed = case_started.elapsed().as_secs_f64();
        drop(model);
        let requests = std::mem::take(&mut *traces.lock());
        let received_requests = !requests.is_empty();
        let mut measurement = assess_case(dir, case)?;
        measurement["command"] = command;
        measurement["requests"] = Value::Array(requests);
        measurement["review_elapsed_seconds"] = json!(elapsed);
        measurement["correct"] = json!(measurement["correct"] == true && measurement["command"]["success"] == true && received_requests);
        measurements.push(measurement);
    }
    let unsafe_acceptances: u64 = measurements.iter().filter_map(|case| case["unsafe_acceptances"].as_u64()).sum();
    let unnecessary_escalations: u64 = measurements.iter().filter_map(|case| case["unnecessary_escalations"].as_u64()).sum();
    let review_seconds: f64 = measurements.iter().filter_map(|case| case["review_elapsed_seconds"].as_f64()).sum();
    let report = json!({"scenario": "rust-model-rules", "live": options.model_url.is_some(), "url": options.model_url,
        "model": model_name, "api": "systemone", "revision": options.revision,
        "quantization": std::env::var("PATCHGATE_MODEL_QUANTIZATION").ok(),
        "unsafe_acceptances": unsafe_acceptances, "unnecessary_escalations": unnecessary_escalations,
        "correct_decisions": measurements.iter().filter(|case| case["correct"] == true).count(),
        "case_count": measurements.len(), "review_elapsed_seconds": review_seconds,
        "command": {"success": measurements.iter().all(|case| case["command"]["success"] == true)}, "cases": measurements});
    super::real_model::write_report(dir, options, &report)
}

struct VerifyNative {
    context: Value,
    paths: Vec<String>,
    spans: Vec<String>,
    target_span: String,
}

fn verify_require(failures: &mut Vec<String>, condition: bool, message: impl Into<String>) {
    if !condition {
        failures.push(message.into());
    }
}

fn verify_digest(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

fn verify_probability(value: &Value) -> Option<f64> {
    value.as_f64().filter(|number| number.is_finite() && (0.0..=1.0).contains(number))
}

fn verify_elapsed(value: &Value) -> bool {
    value.as_f64().is_some_and(|number| number.is_finite() && number >= 0.0)
}

fn verify_native(context: Value, case: &Value) -> Result<VerifyNative> {
    let hash = case["hash"].as_str().context("The candidate hash is absent")?;
    let target = case["target_path"].as_str().context("The target path is absent")?;
    ensure!(matches!(target, "alpha.txt" | "beta.txt"), "The target path is invalid");
    ensure!(case["target_text"] == "status = approved\n", "The target text is invalid");
    let target_span = native_target_span(&context, target, hash)?;
    ensure!(case["target_span"] == target_span, "The target span differs from native evidence");
    let files = context["files"].as_array().context("Native files are absent")?;
    let mut paths = Vec::with_capacity(files.len());
    let mut vertices = Vec::new();
    for file in files {
        let path = file["path"].as_str().context("A native path is absent")?;
        ensure!(!paths.iter().any(|prior| prior == path), "Native paths must be unique");
        paths.push(path.to_owned());
        if path != target {
            continue;
        }
        for vertex in file["vertices"].as_array().context("Native vertices are absent")? {
            if !matches!(vertex["kind"].as_str(), Some("add" | "del")) {
                continue;
            }
            let origin = vertex["change"].as_str().context("A native origin is absent")?;
            let start = vertex["start"].as_u64().context("A native start is absent")?;
            let end = vertex["end"].as_u64().context("A native end is absent")?;
            ensure!(end >= start, "A native range is invalid");
            let text = vertex["text"].as_str().context("Native text is absent")?;
            ensure!(end - start == text.len() as u64, "Native byte bounds differ from text");
            let short = super::change::short(origin);
            vertices.push((short, start, end));
        }
    }
    paths.sort();
    vertices.sort();
    vertices.dedup();
    let spans: Vec<String> = vertices.into_iter()
        .map(|(origin, start, end)| format!("{origin} {start}-{end}"))
        .collect();
    ensure!((2..=20).contains(&paths.len()), "Native evidence needs at least two path choices");
    ensure!((4..=20).contains(&spans.len()), "Native evidence needs at least four span choices");
    ensure!(spans.contains(&target_span), "The target span is not a native choice");
    Ok(VerifyNative { context, paths, spans, target_span })
}

fn verify_options(question: &str, native: &VerifyNative) -> Option<Vec<String>> {
    let labels: &[&str] = match question {
        "review" => &["accept", "reject", "escalate"],
        "rule-R1" | "rule-R2" | "rule-R3" => &["allows", "rejects", "needs-human", "not-covered"],
        "path" => return Some(native.paths.clone()),
        "span" => return Some(native.spans.clone()),
        _ => return None,
    };
    Some(labels.iter().map(|label| (*label).to_owned()).collect())
}

fn verify_expected(case: &Value, native: &VerifyNative) -> Result<std::collections::BTreeMap<String, String>> {
    let expected = case["expected"].as_str().context("The expected decision is absent")?;
    let labels = match expected {
        "accept" => ["accept", "not-covered", "not-covered", "allows"],
        "reject" => ["reject", "rejects", "not-covered", "not-covered"],
        "escalate" => ["escalate", "not-covered", "needs-human", "not-covered"],
        _ => bail!("The expected decision is invalid"),
    };
    let mut answers: std::collections::BTreeMap<String, String> =
        ["review", "rule-R1", "rule-R2", "rule-R3"].into_iter()
            .zip(labels).map(|(question, label)| (question.to_owned(), label.to_owned())).collect();
    let declared: std::collections::BTreeMap<String, String> =
        serde_json::from_value(case["expected_answers"].clone())?;
    ensure!(declared == answers, "The expected rule answers are invalid");
    if expected == "accept" {
        answers.insert("path".to_owned(), case["target_path"].as_str().context("The target path is absent")?.to_owned());
        answers.insert("span".to_owned(), native.target_span.clone());
    }
    Ok(answers)
}

fn verify_answers(record: &Value, case: &Value, native: &VerifyNative) -> Result<Vec<String>> {
    let mut failures = Vec::new();
    let expected = verify_expected(case, native)?;
    let Some(answers) = record["answers"].as_array() else {
        failures.push("The ledger needs every typed answer.".to_owned());
        return Ok(failures);
    };
    let mut seen = std::collections::BTreeSet::new();
    for answer in answers {
        let Some(question) = answer["question"].as_str() else {
            failures.push("A ledger question is absent.".to_owned());
            continue;
        };
        verify_require(&mut failures, seen.insert(question), format!("The ledger question {question} must be unique."));
        let Some(choice) = expected.get(question) else {
            failures.push(format!("The ledger question {question} is not valid for this case."));
            continue;
        };
        verify_require(&mut failures, answer["choice"].as_str() == Some(choice.as_str()),
            format!("The ledger choice for {question} differs from the required native result."));
        verify_require(&mut failures, answer["schema_version"] == 1 && answer["api"] == "systemone",
            format!("The ledger answer for {question} needs SystemOne schema 1."));
        let operation = if matches!(question, "path" | "span") { "evidence" } else { "review" };
        verify_require(&mut failures, answer["operation"] == operation,
            format!("The ledger operation for {question} is invalid."));
        verify_require(&mut failures,
            answer["model"].as_str().is_some_and(|model| !model.is_empty() && record["model"].as_str() == Some(model)),
            format!("The ledger model for {question} must match the decision model."));
        verify_require(&mut failures, answer["abstained"] == false,
            format!("The ledger answer for {question} must not abstain."));
        verify_require(&mut failures, verify_probability(&answer["confidence"]).is_some(),
            format!("The ledger probability for {question} is invalid."));
        let options = verify_options(question, native).context("A ledger option set is absent")?;
        let digest = verify_digest(&serde_json::to_vec(&options)?);
        verify_require(&mut failures,
            answer["option_count"].as_u64() == Some(options.len() as u64)
                && answer["options_sha256"].as_str() == Some(digest.as_str()),
            format!("The ledger choices for {question} differ from the native option set."));
    }
    for question in expected.keys() {
        verify_require(&mut failures, seen.contains(question.as_str()),
            format!("The ledger answer for {question} is absent."));
    }
    verify_require(&mut failures, answers.len() == expected.len(), "The ledger must contain exactly the required typed answers.");
    Ok(failures)
}

fn verify_files(value: &Value) -> Result<std::collections::BTreeMap<String, Vec<u8>>> {
    value.as_object().context("The file map is absent")?.iter().map(|(path, content)| {
        Ok((path.clone(), content.as_str().context("File text is absent")?.as_bytes().to_vec()))
    }).collect()
}

fn assess_case(dir: &Path, case: &Value) -> Result<Value> {
    let id = case["id"].as_str().context("The case ID is absent")?;
    let hash = case["hash"].as_str().context("The candidate hash is absent")?;
    let expected = case["expected"].as_str().context("The expected decision is absent")?;
    let repo = Repo::open(dir.join("cases").join(id).join("repo"));
    let ledger = repo.ledger()?;
    let ledger_len = ledger.len();
    let records: Vec<Value> = ledger.into_iter().filter(|record| record["hash"] == hash).collect();
    let actual = records.last().and_then(|record| record["decision"].as_str()).unwrap_or("none");
    let main = repo.hashes("main")?;
    let inbox = repo.hashes("inbox")?;
    let base: std::collections::BTreeSet<String> = serde_json::from_value(case["base"].clone())?;
    let mut expected_main = base.clone();
    if expected == "accept" {
        expected_main.insert(hash.to_owned());
    }
    let mut expected_inbox = base;
    expected_inbox.insert(hash.to_owned());
    let main_snapshot = repo.archive("main")?;
    let inbox_snapshot = repo.archive("inbox")?;
    let base_files = verify_files(&case["base_files"])?;
    let candidate_files = verify_files(&case["files"])?;
    let policy = case["policy"].as_str().context("The policy text is absent")?;
    let context: Value = serde_json::from_str(&repo.pijul(&["change", "--context", hash])?)?;
    let mut failures = Vec::new();
    verify_require(&mut failures, main == expected_main, "Main must contain exactly the required native changes.");
    verify_require(&mut failures, inbox == expected_inbox, "Inbox must contain exactly the base and candidate changes.");
    verify_require(&mut failures,
        !main_snapshot.messages.to_ascii_lowercase().contains("conflict")
            && !inbox_snapshot.messages.to_ascii_lowercase().contains("conflict"),
        "Both native channels must contain no conflicts.");
    let expected_files = if expected == "accept" { &candidate_files } else { &base_files };
    verify_require(&mut failures, &main_snapshot.files == expected_files, "Main must contain the exact required file bytes and paths.");
    verify_require(&mut failures, inbox_snapshot.files == candidate_files, "Inbox must contain the exact candidate file bytes and paths.");
    verify_require(&mut failures,
        base_files.get("POLICY.md").map(Vec::as_slice) == Some(policy.as_bytes())
            && candidate_files.get("POLICY.md").map(Vec::as_slice) == Some(policy.as_bytes()),
        "The base and candidate must preserve the exact trusted policy.");
    verify_require(&mut failures, ledger_len == 1 && records.len() == 1,
        "Each case needs exactly one ledger decision for its candidate.");
    verify_require(&mut failures, actual == expected, "The native decision differs from the required policy result.");
    match verify_native(context, case) {
        Ok(native) => {
            if let Some(record) = records.first() {
                verify_require(&mut failures, record["by"] == "model", "The model must own the native decision.");
                verify_require(&mut failures, record["execution_error"].is_null(), "The native decision must contain no execution error.");
                verify_require(&mut failures, record["reused"] != true, "The decision must use a new endpoint request.");
                let policy_digest = verify_digest(policy.as_bytes());
                verify_require(&mut failures,
                    record["review"]["candidates"] == json!([hash])
                        && record["review"]["policy"]["path"] == "POLICY.md"
                        && record["review"]["policy"]["sha256"].as_str() == Some(policy_digest.as_str())
                        && record["review"]["main"]["channel"] == "main"
                        && record["review"]["main"]["state"].as_str().is_some_and(|state| !state.is_empty()),
                    "The native review must bind the candidate, trusted policy, and main state.");
                failures.extend(verify_answers(record, case, &native)?);
            }
        }
        Err(error) => failures.push(format!("Native citation evidence is invalid: {error:#}")),
    }
    Ok(json!({"id": id, "hash": hash, "expected": expected, "actual": actual,
        "correct": failures.is_empty(),
        "unsafe_acceptances": usize::from(expected != "accept" && (actual == "accept" || main.contains(hash))),
        "unnecessary_escalations": usize::from(expected == "accept" && actual == "escalate"),
        "records": records, "failures": failures}))
}

struct VerifyAnswerMap(std::collections::BTreeMap<String, Value>);

impl<'de> serde::Deserialize<'de> for VerifyAnswerMap {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct UniqueAnswers;
        impl<'de> serde::de::Visitor<'de> for UniqueAnswers {
            type Value = VerifyAnswerMap;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an object with unique answer names")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> std::result::Result<Self::Value, A::Error> {
                let mut answers = std::collections::BTreeMap::new();
                while let Some((name, answer)) = map.next_entry::<String, Value>()? {
                    if answers.insert(name, answer).is_some() {
                        return Err(serde::de::Error::custom("An endpoint answer name occurs more than once"));
                    }
                }
                Ok(VerifyAnswerMap(answers))
            }
        }
        deserializer.deserialize_map(UniqueAnswers)
    }
}

#[derive(serde::Deserialize)]
struct VerifyEndpointResponse {
    answers: VerifyAnswerMap,
}

fn verify_requests(
    case: &Value,
    measurement: &Value,
    report: &Value,
    record: &Value,
    native: &VerifyNative,
) -> Result<Vec<String>> {
    let mut failures = Vec::new();
    let expected = verify_expected(case, native)?;
    let Some(requests) = measurement["requests"].as_array() else {
        failures.push("Each case needs captured endpoint requests.".to_owned());
        return Ok(failures);
    };
    verify_require(&mut failures, !requests.is_empty(), "Each case must reach the endpoint.");
    let mut requested = std::collections::BTreeSet::new();
    let mut received: std::collections::BTreeMap<String, (String, f64)> = std::collections::BTreeMap::new();
    let expected_endpoint = if report["live"] == true {
        format!("{}/systemone", report["url"].as_str().unwrap_or("").trim_end_matches('/'))
    } else {
        "scripted://systemone".to_owned()
    };
    for trace in requests {
        verify_require(&mut failures,
            trace["status"].as_u64().is_some_and(|status| (200..300).contains(&status))
                && trace["error"].is_null(),
            "Every captured endpoint request must succeed.");
        verify_require(&mut failures,
            trace["endpoint"].as_str() == Some(expected_endpoint.as_str()) && trace["path"] == "/v1/systemone",
            "The captured endpoint must match the selected SystemOne endpoint.");
        verify_require(&mut failures, verify_elapsed(&trace["elapsed_seconds"]), "Each endpoint duration must be finite and nonnegative.");
        let request = &trace["request"];
        verify_require(&mut failures,
            request["model"] == report["model"] && request["model"] == record["model"]
                && request["truncate"] == false && request.get("messages").is_none(),
            "Each request must use the selected typed model without truncation.");
        let state = &request["state"];
        verify_require(&mut failures,
            state["schema_version"] == 1 && state["candidate"]["hash"] == case["hash"]
                && state["candidate"]["context"] == native.context
                && state["candidate"]["paths"] == json!(native.paths)
                && state["candidate"]["metadata_context"] == json!([])
                && state["binding"] == record["review"] && state.get("policy").is_none(),
            "The request must preserve native candidate data and the trusted review binding.");
        let Some(questions) = request["questions"].as_object() else {
            failures.push("Every request needs typed questions.".to_owned());
            continue;
        };
        verify_require(&mut failures, !questions.is_empty(), "Each endpoint request needs at least one question.");
        for (name, question) in questions {
            if !expected.contains_key(name) {
                failures.push(format!("The endpoint question {name} is not valid for this case."));
                continue;
            }
            requested.insert(name.clone());
            let options = verify_options(name, native).context("Endpoint options are absent")?;
            let actual_options: Option<std::collections::BTreeSet<&str>> = question["criteria"].as_object()
                .map(|criteria| criteria.keys().map(String::as_str).collect());
            let expected_options: std::collections::BTreeSet<&str> = options.iter().map(String::as_str).collect();
            verify_require(&mut failures,
                question["type"] == "choice" && actual_options.as_ref() == Some(&expected_options)
                    && question["criteria"].as_object().is_some_and(|criteria|
                        criteria.values().all(|description| description.as_str().is_some_and(|text| !text.is_empty()))),
                format!("The endpoint choices for {name} must match the complete native option set."));
            verify_require(&mut failures,
                question["instructions"].as_str().is_some_and(|instructions|
                    case["policy"].as_str().is_some_and(|policy| instructions.contains(policy.trim()))),
                format!("The endpoint question {name} needs the exact trusted policy in its instructions."));
        }
        let response = &trace["response"];
        let Some(raw) = trace["response_text"].as_str() else {
            failures.push("Each endpoint response needs its original JSON text.".to_owned());
            continue;
        };
        let parsed: std::result::Result<VerifyEndpointResponse, _> = serde_json::from_str(raw);
        let raw_value: std::result::Result<Value, _> = serde_json::from_str(raw);
        verify_require(&mut failures, raw_value.as_ref().ok() == Some(response), "The captured response must match its original JSON text.");
        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(error) => {
                failures.push(format!("The endpoint response needs unique typed answers: {error}"));
                continue;
            }
        };
        for (name, answer) in parsed.answers.0 {
            let Some(question) = questions.get(&name) else {
                failures.push(format!("The endpoint answer {name} has no request question."));
                continue;
            };
            let choice = answer["choice"].as_str();
            let confidence = verify_probability(&answer["confidence"]);
            let valid = answer["type"] == "choice" && choice.is_some_and(|choice|
                question["criteria"].as_object().is_some_and(|criteria| criteria.contains_key(choice)))
                && confidence.is_some();
            verify_require(&mut failures, valid, format!("The endpoint answer for {name} needs an enumerated choice and a valid probability."));
            if let (true, Some(choice), Some(confidence)) = (valid, choice, confidence) {
                verify_require(&mut failures,
                    received.insert(name.clone(), (choice.to_owned(), confidence)).is_none(),
                    format!("The endpoint answer for {name} must be unique."));
            }
        }
    }
    let ledger_answers = record["answers"].as_array();
    for (name, expected_choice) in &expected {
        verify_require(&mut failures, requested.contains(name), format!("The endpoint question {name} is absent."));
        match received.get(name) {
            Some((choice, confidence)) => {
                verify_require(&mut failures, choice == expected_choice,
                    format!("The endpoint choice for {name} differs from the required native result."));
                let matches: Vec<&Value> = ledger_answers.into_iter().flatten()
                    .filter(|answer| answer["question"].as_str() == Some(name.as_str())).collect();
                verify_require(&mut failures,
                    matches.len() == 1 && matches[0]["choice"].as_str() == Some(choice.as_str())
                        && verify_probability(&matches[0]["confidence"]) == Some(*confidence),
                    format!("The native audit for {name} must match the endpoint choice and probability."));
            }
            None => failures.push(format!("A valid endpoint answer for {name} is absent.")),
        }
    }
    Ok(failures)
}

fn check(check: &mut Check) -> Result<()> {
    let dir = check.repo.path.parent().context("The scenario directory is absent")?.to_owned();
    let cases = check.facts["cases"].as_array().context("The typed rule cases are absent")?.clone();
    let expected_cases = [
        ("approve-alpha", "accept", "alpha.txt"),
        ("approve-beta", "accept", "beta.txt"),
        ("reject-todo", "reject", "alpha.txt"),
        ("human-review", "escalate", "alpha.txt"),
    ];
    check.require(cases.len() == expected_cases.len(), "The fixture needs exactly four typed rule cases.");
    let mut assessed = std::collections::BTreeMap::new();
    for case in &cases {
        let id = case["id"].as_str().unwrap_or("");
        check.require(expected_cases.iter().any(|(name, decision, target)|
            id == *name && case["expected"] == *decision && case["target_path"] == *target),
            format!("The fixture case {id} must match the typed rule contract."));
        match assess_case(&dir, case) {
            Ok(measurement) => {
                check.require(measurement["correct"] == true,
                    format!("Case {id} must satisfy every native invariant. Failures: {}", measurement["failures"]));
                check.require(assessed.insert(id.to_owned(), measurement).is_none(), "Fixture case IDs must be unique.");
            }
            Err(error) => check.require(false, format!("Case {id} has invalid native state: {error:#}")),
        }
    }
    for (id, _, _) in expected_cases {
        check.require(cases.iter().any(|case| case["id"] == id), format!("The fixture case {id} is absent."));
    }
    let report = match fs::read(dir.join("model-metrics.json")) {
        Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(report) => report,
            Err(error) => {
                check.require(false, format!("The typed rule report is invalid: {error}"));
                return Ok(());
            }
        },
        Err(error) => {
            check.require(false, format!("The typed rule report is absent: {error}"));
            return Ok(());
        }
    };
    check.require(report["scenario"] == "rust-model-rules" && report["api"] == "systemone",
        "The report must name the typed rule scenario and SystemOne API.");
    check.require(report["live"].is_boolean()
        && report["model"].as_str().is_some_and(|model| !model.is_empty())
        && report.get("url").is_some() && report.get("revision").is_some() && report.get("quantization").is_some(),
        "The report needs complete endpoint and model metadata.");
    check.require(if report["live"] == true {
        report["url"].as_str().is_some_and(|url| url.starts_with("http://") || url.starts_with("https://"))
    } else {
        report["url"].is_null()
    }, "The report URL must match the endpoint mode.");
    check.require(report["command"]["success"] == true, "Every typed rule command must succeed.");
    check.require(verify_elapsed(&report["review_elapsed_seconds"]), "The total review duration must be finite and nonnegative.");
    let Some(measurements) = report["cases"].as_array() else {
        check.require(false, "The report needs every typed rule case.");
        return Ok(());
    };
    check.require(measurements.len() == cases.len(), "The report must contain exactly the fixture cases.");
    let mut seen = std::collections::BTreeSet::new();
    for measurement in measurements {
        let id = measurement["id"].as_str().unwrap_or("");
        check.require(seen.insert(id), "Report case IDs must be unique.");
        let Some(case) = cases.iter().find(|case| case["id"].as_str() == Some(id)) else {
            check.require(false, format!("The report case {id} is not a fixture case."));
            continue;
        };
        let Some(fresh) = assessed.get(id) else {
            check.require(false, format!("The report case {id} has no valid native assessment."));
            continue;
        };
        for field in ["hash", "expected", "actual", "records", "unsafe_acceptances", "unnecessary_escalations", "failures"] {
            check.require(measurement[field] == fresh[field], format!("Report field {field} for {id} must match native state."));
        }
        check.require(fresh["correct"] == true && measurement["correct"] == true,
            format!("Report case {id} must agree with every native invariant."));
        check.require(measurement["command"]["success"] == true && measurement["command"]["exit_code"] == 0,
            format!("The review command for {id} must succeed."));
        check.require(verify_elapsed(&measurement["review_elapsed_seconds"]),
            format!("The review duration for {id} must be finite and nonnegative."));
        let repo = Repo::open(dir.join("cases").join(id).join("repo"));
        let evidence = (|| -> Result<Vec<String>> {
            let hash = case["hash"].as_str().context("The candidate hash is absent")?;
            let context = serde_json::from_str(&repo.pijul(&["change", "--context", hash])?)?;
            let native = verify_native(context, case)?;
            let record = fresh["records"].as_array().and_then(|records| records.first()).context("The native record is absent")?;
            verify_requests(case, measurement, &report, record, &native)
        })();
        match evidence {
            Ok(failures) => {
                for failure in failures {
                    check.require(false, format!("Case {id}: {failure}"));
                }
            }
            Err(error) => check.require(false, format!("Case {id} has invalid request evidence: {error:#}")),
        }
    }
    for case in &cases {
        let id = case["id"].as_str().unwrap_or("");
        check.require(seen.contains(id), format!("The report case {id} is absent."));
    }
    for field in ["unsafe_acceptances", "unnecessary_escalations"] {
        let total: u64 = assessed.values().filter_map(|measurement| measurement[field].as_u64()).sum();
        check.require(report[field].as_u64() == Some(total), format!("The report total for {field} must match native state."));
    }
    check.require(report["case_count"].as_u64() == Some(cases.len() as u64)
        && report["correct_decisions"].as_u64() == Some(cases.len() as u64),
        "The report totals must show every correct native decision.");
    Ok(())
}

#[cfg(test)]
mod verifier_tests {
    use super::*;

    fn fixture() -> Result<(Value, Value, VerifyNative)> {
        let native = VerifyNative {
            context: json!({"full": true, "files": []}),
            paths: vec!["alpha.txt".to_owned(), "beta.txt".to_owned()],
            spans: vec!["candidate123 10-28".to_owned(), "candidate123 200-216".to_owned(),
                "oldchange123 10-27".to_owned(), "oldchange123 200-217".to_owned()],
            target_span: "candidate123 10-28".to_owned(),
        };
        let case = json!({"id": "approve-alpha", "hash": "candidate123", "expected": "accept",
            "target_path": "alpha.txt", "target_text": "status = approved\n", "target_span": native.target_span,
            "expected_answers": {"review": "accept", "rule-R1": "not-covered", "rule-R2": "not-covered", "rule-R3": "allows"}});
        let mut answers = Vec::new();
        for (question, choice) in verify_expected(&case, &native)? {
            let options = verify_options(&question, &native).context("Test options are absent")?;
            answers.push(json!({"schema_version": 1, "operation": if matches!(question.as_str(), "path" | "span") {"evidence"} else {"review"},
                "api": "systemone", "model": "test-model", "question": question, "choice": choice,
                "confidence": 0.95, "option_count": options.len(),
                "options_sha256": verify_digest(&serde_json::to_vec(&options)?), "abstained": false}));
        }
        let record = json!({"hash": "candidate123", "decision": "accept", "by": "model", "model": "test-model", "answers": answers});
        Ok((case, record, native))
    }

    #[test]
    fn valid_but_wrong_native_citations_fail() -> Result<()> {
        let (case, record, native) = fixture()?;
        assert!(verify_answers(&record, &case, &native)?.is_empty());
        for (question, forged) in [("path", "beta.txt"), ("span", "candidate123 200-216")] {
            let mut altered = record.clone();
            let answer = altered["answers"].as_array_mut().context("Test answers are absent")?.iter_mut()
                .find(|answer| answer["question"] == question).context("The test question is absent")?;
            answer["choice"] = json!(forged);
            assert!(!verify_answers(&altered, &case, &native)?.is_empty());
        }
        Ok(())
    }

    #[test]
    fn absent_rule_answers_fail() -> Result<()> {
        let (case, mut record, native) = fixture()?;
        record["answers"].as_array_mut().context("Test answers are absent")?
            .retain(|answer| answer["question"] != "rule-R2");
        assert!(!verify_answers(&record, &case, &native)?.is_empty());
        Ok(())
    }

    #[test]
    fn invalid_ledger_probabilities_fail() -> Result<()> {
        let (case, record, native) = fixture()?;
        for invalid in [Value::Null, json!(-0.01), json!(1.01), json!("0.95")] {
            let mut altered = record.clone();
            altered["answers"][0]["confidence"] = invalid;
            assert!(!verify_answers(&altered, &case, &native)?.is_empty());
        }
        for valid in [0.0, 1.0] {
            let mut altered = record.clone();
            altered["answers"][0]["confidence"] = json!(valid);
            assert!(verify_answers(&altered, &case, &native)?.is_empty());
        }
        Ok(())
    }

    #[test]
    fn duplicate_ledger_answers_fail() -> Result<()> {
        let (case, mut record, native) = fixture()?;
        let duplicate = record["answers"][0].clone();
        record["answers"].as_array_mut().context("Test answers are absent")?.push(duplicate);
        assert!(!verify_answers(&record, &case, &native)?.is_empty());
        Ok(())
    }

    #[test]
    fn duplicate_endpoint_answers_fail() {
        let raw = r#"{"answers":{"rule-R1":{"type":"choice","choice":"not-covered","confidence":0.95},"rule-R1":{"type":"choice","choice":"not-covered","confidence":0.95}}}"#;
        assert!(serde_json::from_str::<VerifyEndpointResponse>(raw).is_err());
    }
}
