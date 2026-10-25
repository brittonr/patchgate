use super::*;
use super::feature_tests::{fixture_edit, pending_fixture};
use serde_json::{Value, json};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread::{self, JoinHandle};

const LIMIT: usize = 8_000;

struct Fixture {
    _directory: tempfile::TempDir,
    settings: Settings,
    candidate: String,
    full: Value,
    source_sha256: String,
    span: String,
}

fn fixture(large_change: bool) -> Result<Fixture> {
    let original: String = (0..1_000)
        .map(|index| format!("let row_{index:04} = \"native café λ {index:04}\";\n"))
        .collect();
    let (directory, mut settings, base) = pending_fixture(&[
        ("value.txt", original.as_bytes()),
        ("POLICY.md", b"- [R1] Accept safe source changes.\n"),
    ])?;
    let pijul = Pijul::new(settings.repo.clone());
    pijul.run(["apply", "--channel", "main", &base])?;
    let edited = if large_change {
        "A completely new source line.\n".repeat(1_000)
    } else {
        original.replace("native café λ 0500", "reviewed café λ 0500")
    };
    let candidate = fixture_edit(&settings, "value.txt", &edited, "patchgate")?;
    settings.model_api = Api::SystemOne;
    settings.max_change_chars = LIMIT;
    let entry = pijul
        .review_metadata("inbox")?
        .into_iter()
        .find(|entry| entry.hash == candidate)
        .context("The candidate metadata is absent")?;
    let text = pijul.change(&candidate)?;
    let paths = pijul.touched_paths("inbox", &entry.paths, &text)?;
    let change = pijul.review_change("inbox", &candidate, &text, &paths)?;
    let policy = pijul.read_file("main", "POLICY.md")?.context("The policy is absent")?;
    let binding = ReviewBinding::new(
        std::slice::from_ref(&candidate),
        "POLICY.md",
        Some(&policy),
        "main",
        &pijul.snapshot("main")?,
    );
    let input = review::input(&change, &binding)?;
    assert!(input.get().chars().count() > LIMIT);
    let span = change
        .context
        .files
        .iter()
        .flat_map(|file| &file.vertices)
        .find(|vertex| matches!(vertex.kind, crate::pijul::NativeVertexKind::Add))
        .map(|vertex| format!("{} {}-{}", short(&vertex.change), vertex.start, vertex.end))
        .context("The candidate has no added span")?;
    Ok(Fixture {
        _directory: directory,
        settings,
        candidate,
        full: serde_json::from_str(input.get())?,
        source_sha256: digest(input.get()),
        span,
    })
}

fn digest(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

struct Request {
    body: Value,
    state: String,
}

#[derive(Clone, Copy)]
enum Script {
    Accept,
    RejectLater,
    NeedsContext,
    WeakContext,
}

struct Server {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<Vec<Request>>>>,
}

impl Server {
    fn start(script: Script, span: String, movement: Option<(PathBuf, String)>) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let worker = thread::spawn(move || -> Result<Vec<Request>> {
            let mut requests = Vec::new();
            let mut movement = movement;
            loop {
                let (stream, _) = listener.accept()?;
                if stopped.load(Ordering::SeqCst) {
                    return Ok(requests);
                }
                stream.set_read_timeout(Some(Duration::from_secs(10)))?;
                stream.set_write_timeout(Some(Duration::from_secs(10)))?;
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                let mut length = None;
                loop {
                    line.clear();
                    anyhow::ensure!(stream.read_line(&mut line)? > 0, "The request is incomplete");
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = Some(value.trim().parse::<usize>()?);
                        }
                    }
                }
                let mut bytes = vec![0; length.context("The request has no length")?];
                stream.read_exact(&mut bytes)?;
                let body: Value = serde_json::from_slice(&bytes)?;
                #[derive(Deserialize)]
                struct State {
                    state: Box<RawValue>,
                }
                let raw: State = serde_json::from_slice(&bytes)?;
                let questions = body["questions"].as_object().context("The questions are absent")?;
                let answer = if questions.contains_key("review") {
                    anyhow::ensure!(questions.len() == 3, "The window must ask three questions");
                    let page = body["state"]["coverage"]["page"]
                        .as_u64()
                        .context("The window index is absent")?;
                    if page == 0 {
                        if let Some((root, hash)) = movement.take() {
                            Pijul::new(root).run(["apply", "--channel", "main", &hash])?;
                        }
                    }
                    let verdict = if matches!(script, Script::RejectLater) && page == 1 {
                        "reject"
                    } else {
                        "accept"
                    };
                    let context = if matches!(script, Script::NeedsContext) && page == 0 {
                        "needs-context"
                    } else {
                        "sufficient"
                    };
                    let context_probability = if matches!(script, Script::WeakContext) { 0.59 } else { 0.99 };
                    json!({"answers": {
                        "review": {"type": "choice", "choice": verdict, "confidence": 0.99},
                        "rule-R1": {"type": "choice", "choice": "allows", "confidence": 0.99},
                        "context": {"type": "choice", "choice": context, "confidence": context_probability}
                    }})
                } else if questions.contains_key("path") && questions.len() == 1 {
                    json!({"answers": {"path": {
                        "type": "choice", "choice": "value.txt", "confidence": 0.99
                    }}})
                } else if questions.contains_key("span") && questions.len() == 1 {
                    json!({"answers": {"span": {
                        "type": "choice", "choice": span, "confidence": 0.99
                    }}})
                } else {
                    bail!("The request has an unexpected question");
                };
                requests.push(Request { body, state: raw.state.get().to_owned() });
                let response = serde_json::to_string(&answer)?;
                write!(
                    stream.get_mut(),
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                    response.len()
                )?;
            }
        });
        Ok(Self { address, stop, worker: Some(worker) })
    }

    fn url(&self) -> String {
        format!("http://{}/v1", self.address)
    }

    fn finish(mut self) -> Result<Vec<Request>> {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        self.worker.take().expect("The server thread is absent")
            .join().expect("The server thread panicked")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn windows(requests: &[Request]) -> Vec<&Request> {
    requests.iter().filter(|request| request.body["questions"].get("review").is_some()).collect()
}

fn assert_windows(fixture: &Fixture, requests: &[Request], complete: bool) {
    let windows = windows(requests);
    assert!(!windows.is_empty());
    let planned = windows[0].body["state"]["coverage"]["pages"].as_u64().unwrap() as usize;
    assert!(planned > 2);
    if complete {
        assert_eq!(windows.len(), planned);
    } else {
        assert!(windows.len() < planned);
    }
    let mut core = fixture.full["candidate"].clone();
    core["context"]["full"] = json!(false);
    let files = core["context"]["files"].as_array_mut().unwrap();
    for file in files {
        file["vertices"].as_array_mut().unwrap().retain(|vertex| vertex["kind"] != "keep");
    }
    let mut keeps = Vec::new();
    for file in fixture.full["candidate"]["context"]["files"].as_array().unwrap() {
        for vertex in file["vertices"].as_array().unwrap() {
            if vertex["kind"] == "keep" {
                keeps.push((file["path"].clone(), vertex));
            }
        }
    }
    let mut ranges: Vec<Vec<(u64, u64)>> = vec![Vec::new(); keeps.len()];
    for (index, request) in windows.iter().enumerate() {
        let state = &request.body["state"];
        assert_eq!(request.body["truncate"], false);
        assert!(request.state.chars().count() <= fixture.settings.max_change_chars);
        assert_eq!(state["schema_version"], 2);
        assert_eq!(state["binding"], fixture.full["binding"]);
        assert_eq!(state["candidate"], core);
        assert_eq!(state["coverage"]["source_sha256"], fixture.source_sha256);
        assert_eq!(state["coverage"]["page"], index);
        assert_eq!(state["coverage"]["pages"], planned);
        assert_eq!(state["coverage"]["changed_context_complete"], true);
        for fragment in state["context_window"].as_array().unwrap() {
            assert_eq!(fragment["kind"], "keep");
            let start = fragment["start"].as_u64().unwrap();
            let end = fragment["end"].as_u64().unwrap();
            let (native_index, (_, native)) = keeps.iter().enumerate().find(|(_, (path, native))| {
                *path == fragment["path"] && native["change"] == fragment["change"]
                    && native["start"].as_u64().unwrap() <= start
                    && end <= native["end"].as_u64().unwrap()
            }).expect("The fragment has no native source span");
            assert!(start <= end);
            let native_start = native["start"].as_u64().unwrap();
            let text = native["text"].as_str().unwrap();
            assert_eq!(fragment["text"], &text[(start - native_start) as usize..(end - native_start) as usize]);
            ranges[native_index].push((start, end));
        }
    }
    for ((_, native), fragments) in keeps.iter().zip(&mut ranges) {
        fragments.sort_unstable();
        for pair in fragments.windows(2) {
            assert!(pair[0].1 <= pair[1].0);
        }
        if complete {
            let mut cursor = native["start"].as_u64().unwrap();
            for &(start, end) in fragments.iter() {
                assert_eq!(start, cursor);
                cursor = end;
            }
            assert_eq!(cursor, native["end"].as_u64().unwrap());
        }
    }
}

fn assert_audit(fixture: &Fixture, record: &Record, requests: &[Request], decisions: &[&str], complete: bool) -> Result<()> {
    let encoded = serde_json::to_value(record)?;
    let coverage = &encoded["coverage"];
    let windows = windows(requests);
    assert_eq!(coverage["schema_version"], 1);
    assert_eq!(coverage["source_sha256"], fixture.source_sha256);
    assert_eq!(coverage["planned_pages"], windows[0].body["state"]["coverage"]["pages"]);
    assert_eq!(coverage["complete"], complete);
    let pages = coverage["pages"].as_array().context("The audit pages are absent")?;
    assert_eq!(pages.len(), windows.len());
    assert_eq!(pages.len(), decisions.len());
    let provenance = record.provenance.as_ref().context("The request evidence is absent")?;
    assert_eq!(provenance.requests.len(), requests.len());
    assert!(!record.reused);
    assert_eq!(record.by, "model");
    let mut answer_offset = 0;
    let mut request_offset = 0;
    for (index, ((page, request), decision)) in pages.iter().zip(windows).zip(decisions).enumerate() {
        assert_eq!(page["index"], index);
        assert_eq!(page["decision"], *decision);
        assert_eq!(page["input_sha256"], digest(&request.state));
        assert_eq!(page["answer_start"], answer_offset);
        assert_eq!(page["answer_count"], 3);
        assert_eq!(page["request_start"], request_offset);
        assert_eq!(page["request_count"], 1);
        let expected_ranges: Vec<Value> = request.body["state"]["context_window"].as_array().unwrap().iter().map(|fragment| {
            json!({"path": fragment["path"], "change": fragment["change"], "start": fragment["start"], "end": fragment["end"]})
        }).collect();
        assert_eq!(page["ranges"], json!(expected_ranges));
        let answers = &record.answers[answer_offset..answer_offset + 3];
        for question in ["review", "rule-R1", "context"] {
            let answer = answers.iter().find(|answer| answer.question == question).context("The window answer is absent")?;
            assert_eq!(answer.operation, "review-window");
            assert_eq!(answer.api, "systemone");
            assert_eq!(answer.confidence, Some(0.99));
            assert!(!answer.abstained);
        }
        assert_eq!(provenance.requests[request_offset].operation, "review-window");
        answer_offset += 3;
        request_offset += 1;
    }
    Ok(())
}

#[test]
fn acceptance_requires_every_native_context_window() -> Result<()> {
    let fixture = fixture(false)?;
    let server = Server::start(Script::Accept, fixture.span.clone(), None)?;
    let mut settings = fixture.settings.clone();
    settings.model_url = server.url();
    let mut gate = Gate::new(settings)?;
    let inbox = gate.pijul.snapshot("inbox")?;
    let result = gate.review(&Selection::default(), |_| {});
    let requests = server.finish()?;
    let (items, _) = result?;
    assert_windows(&fixture, &requests, true);
    let count = windows(&requests).len();
    assert_eq!(requests.len(), count + 2);
    for (request, question) in requests[count..].iter().zip(["path", "span"]) {
        assert!(request.body["questions"].get(question).is_some());
        assert_eq!(request.state, requests[0].state);
        assert_eq!(request.body["truncate"], false);
    }
    assert!(gate.pijul.hashes("main")?.contains(&fixture.candidate));
    assert_eq!(gate.pijul.snapshot("inbox")?, inbox);
    assert!(items.iter().any(|item| item.hash == fixture.candidate && item.state == State::Accepted));
    let records = gate.ledger.latest()?;
    let record = &records[&fixture.candidate];
    assert_eq!(record.decision, "accept");
    assert_audit(&fixture, record, &requests, &vec!["accept"; count], true)?;
    assert_eq!(record.answers.len(), count * 3 + 2);
    assert_eq!(record.answers.iter().filter(|answer| answer.operation == "evidence").count(), 2);
    assert!(gate.ledger.pending()?.is_none());
    Ok(())
}

#[test]
fn a_later_window_rejection_preserves_incomplete_coverage() -> Result<()> {
    let fixture = fixture(false)?;
    let server = Server::start(Script::RejectLater, fixture.span.clone(), None)?;
    let mut settings = fixture.settings.clone();
    settings.model_url = server.url();
    let mut gate = Gate::new(settings)?;
    let main = gate.pijul.snapshot("main")?;
    let inbox = gate.pijul.snapshot("inbox")?;
    let result = gate.review(&Selection::default(), |_| {});
    let requests = server.finish()?;
    let (items, _) = result?;
    assert_eq!(requests.len(), 2);
    assert_windows(&fixture, &requests, false);
    assert_eq!(gate.pijul.snapshot("main")?, main);
    assert_eq!(gate.pijul.snapshot("inbox")?, inbox);
    assert!(items.iter().any(|item| item.hash == fixture.candidate && item.state == State::Rejected));
    let records = gate.ledger.latest()?;
    let record = &records[&fixture.candidate];
    assert_eq!(record.decision, "reject");
    assert_audit(&fixture, record, &requests, &["accept", "reject"], false)?;
    assert_eq!(record.answers.len(), 6);
    assert!(record.answers.iter().any(|answer| answer.question == "review" && answer.choice == "reject"));
    Ok(())
}

#[test]
fn an_accept_verdict_cannot_override_a_context_refusal() -> Result<()> {
    let fixture = fixture(false)?;
    let server = Server::start(Script::NeedsContext, fixture.span.clone(), None)?;
    let mut settings = fixture.settings.clone();
    settings.model_url = server.url();
    let mut gate = Gate::new(settings)?;
    let main = gate.pijul.snapshot("main")?;
    let inbox = gate.pijul.snapshot("inbox")?;
    let result = gate.review(&Selection::default(), |_| {});
    let requests = server.finish()?;
    let (items, _) = result?;
    assert_eq!(requests.len(), 1);
    assert_windows(&fixture, &requests, false);
    assert_eq!(gate.pijul.snapshot("main")?, main);
    assert_eq!(gate.pijul.snapshot("inbox")?, inbox);
    assert!(items.iter().any(|item| item.hash == fixture.candidate && item.state == State::Escalated));
    let records = gate.ledger.latest()?;
    let record = &records[&fixture.candidate];
    assert_eq!(record.decision, "escalate");
    assert_audit(&fixture, record, &requests, &["escalate"], false)?;
    assert_eq!(record.answers.len(), 3);
    assert!(record.answers.iter().any(|answer| answer.question == "review" && answer.choice == "accept"));
    assert!(record.answers.iter().any(|answer| answer.question == "context" && answer.choice == "needs-context"));
    Ok(())
}

#[test]
fn an_oversized_changed_core_makes_no_model_request() -> Result<()> {
    let fixture = fixture(true)?;
    let server = Server::start(Script::Accept, fixture.span.clone(), None)?;
    let mut settings = fixture.settings.clone();
    settings.model_url = server.url();
    let mut gate = Gate::new(settings)?;
    let main = gate.pijul.snapshot("main")?;
    let inbox = gate.pijul.snapshot("inbox")?;
    let result = gate.review(&Selection::default(), |_| {});
    let requests = server.finish()?;
    let (items, _) = result?;
    assert!(requests.is_empty());
    assert_eq!(gate.pijul.snapshot("main")?, main);
    assert_eq!(gate.pijul.snapshot("inbox")?, inbox);
    assert!(items.iter().any(|item| item.hash == fixture.candidate && item.state == State::Escalated));
    let records = gate.ledger.latest()?;
    let record = &records[&fixture.candidate];
    assert_eq!(record.decision, "escalate");
    assert_eq!(record.by, "gate");
    assert!(record.answers.is_empty());
    assert!(record.provenance.as_ref().context("The provenance is absent")?.requests.is_empty());
    let encoded = serde_json::to_value(record)?;
    assert_ne!(encoded["coverage"]["complete"], true);
    Ok(())
}

#[test]
fn main_state_movement_stops_review_before_the_next_window() -> Result<()> {
    let fixture = fixture(false)?;
    let pijul = Pijul::new(fixture.settings.repo.clone());
    pijul.run(["fork", "--channel", "main", "other-author"])?;
    pijul.run(["channel", "switch", "other-author"])?;
    let movement = fixture_edit(&fixture.settings, "other.txt", "An independent change.\n", "other-author")?;
    pijul.run(["channel", "switch", "inbox"])?;
    let server = Server::start(
        Script::Accept,
        fixture.span.clone(),
        Some((fixture.settings.repo.clone(), movement.clone())),
    )?;
    let mut settings = fixture.settings.clone();
    settings.model_url = server.url();
    let mut gate = Gate::new(settings)?;
    let main = gate.pijul.snapshot("main")?;
    let inbox = gate.pijul.snapshot("inbox")?;
    let result = gate.review(&Selection::default(), |_| {});
    let requests = server.finish()?;
    assert!(result.is_err());
    assert_eq!(requests.len(), 1);
    assert_windows(&fixture, &requests, false);
    let moved = gate.pijul.snapshot("main")?;
    assert_ne!(moved, main);
    assert!(moved.hashes.contains(&movement));
    assert!(!moved.hashes.contains(&fixture.candidate));
    assert_eq!(gate.pijul.snapshot("inbox")?, inbox);
    for record in gate.ledger.latest()?.values().filter(|record| record.hash == fixture.candidate) {
        assert_ne!(record.decision, "accept");
        assert_ne!(serde_json::to_value(record)?["coverage"]["complete"], true);
    }
    assert!(gate.ledger.pending()?.is_none());
    Ok(())
}

#[test]
fn a_weak_context_answer_cannot_authorize_acceptance() -> Result<()> {
    let fixture = fixture(false)?;
    let server = Server::start(Script::WeakContext, fixture.span.clone(), None)?;
    let mut settings = fixture.settings.clone();
    settings.model_url = server.url();
    let mut gate = Gate::new(settings)?;
    let main = gate.pijul.snapshot("main")?;
    let result = gate.review(&Selection::default(), |_| {});
    let requests = server.finish()?;
    let (items, _) = result?;
    assert_eq!(requests.len(), 1);
    assert_eq!(gate.pijul.snapshot("main")?, main);
    assert!(items.iter().any(|item| item.hash == fixture.candidate && item.state == State::Escalated));
    let records = gate.ledger.latest()?;
    let record = &records[&fixture.candidate];
    assert_eq!(record.decision, "escalate");
    assert!(!record.coverage.as_ref().context("The coverage is absent")?.complete);
    let context = record.answers.iter().find(|answer| answer.question == "context").context("The context answer is absent")?;
    assert_eq!(context.choice, "sufficient");
    assert_eq!(context.confidence, Some(0.59));
    assert!(context.abstained);
    Ok(())
}
