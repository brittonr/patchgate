use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;

pub use std::fs;
pub use std::path::{Path, PathBuf};
pub use std::process::{Child, Command, Output, Stdio};
pub use std::thread;
pub use std::time::{Duration, Instant};

pub use anyhow::{Context, Result, anyhow, bail, ensure};
use flate2::read::GzDecoder;
pub use serde_json::{Value, json};
use tempfile::TempDir;

pub const POLICY: &str =
    "# Review policy\n\nReject a change that adds a secret. Accept other changes.\n";
pub type Env = BTreeMap<OsString, OsString>;

pub struct Scenario {
    pub name: &'static str,
    pub setup: fn(&Path, &Signer) -> Result<Value>,
    pub solve: fn(&Path, &RunOptions) -> Result<()>,
    pub check: fn(&mut Check) -> Result<()>,
}

#[derive(Default)]
pub struct RunOptions {
    pub model_url: Option<String>,
    pub model: String,
    pub api: String,
    pub revision: Option<String>,
    pub report: Option<PathBuf>,
}

pub struct Signer {
    pub env: Arc<Env>,
    agent: Child,
    _directory: TempDir,
}

impl Signer {
    pub fn new() -> Result<Self> {
        Self::with_path(std::env::var_os("PATH").unwrap_or_default())
    }

    pub fn with_path(path: OsString) -> Result<Self> {
        let directory = tempfile::Builder::new().prefix("pge-").tempdir()?;
        let key = directory.path().join("key");
        let socket = directory.path().join("agent");
        let home = directory.path().join("home");
        fs::create_dir(&home)?;
        checked_output(
            Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&key)
                .env("PATH", &path)
                .output()?,
            "create fixture key",
        )?;
        let agent = Command::new("ssh-agent")
            .args(["-D", "-a"])
            .arg(&socket)
            .env("PATH", &path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut env: Env = std::env::vars_os().collect();
        env.insert("PATH".into(), path);
        env.insert("HOME".into(), home.into_os_string());
        env.insert("SSH_AUTH_SOCK".into(), socket.as_os_str().to_owned());
        env.remove(OsStr::new("XDG_CONFIG_HOME"));
        let mut signer = Self {
            env: Arc::new(env),
            agent,
            _directory: directory,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            ensure!(
                signer.agent.try_wait()?.is_none() && Instant::now() < deadline,
                "fixture SSH agent did not start"
            );
            thread::sleep(Duration::from_millis(10));
        }
        checked_output(
            Command::new("ssh-add")
                .arg("-q")
                .arg(key)
                .env_clear()
                .envs(signer.env.iter())
                .output()?,
            "load fixture key",
        )?;
        Ok(signer)
    }
}

impl Drop for Signer {
    fn drop(&mut self) {
        let _ = self.agent.kill();
        let _ = self.agent.wait();
    }
}

#[derive(Clone)]
pub struct Repo {
    pub path: PathBuf,
    pub env: Arc<Env>,
}

impl Repo {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            env: Arc::new(std::env::vars_os().collect()),
        }
    }

    pub fn pijul(&self, args: &[&str]) -> Result<String> {
        checked_output(
            Command::new("pijul")
                .args(args)
                .current_dir(&self.path)
                .env_clear()
                .envs(self.env.iter())
                .env("NO_COLOR", "1")
                .stdin(Stdio::null())
                .output()?,
            "pijul",
        )
    }

    pub fn write(&self, path: &str, text: &str) -> Result<()> {
        let target = self.path.join(path);
        let new = !target.exists();
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, text)?;
        if new {
            self.pijul(&["add", "--", path])?;
        }
        Ok(())
    }

    pub fn record(&self, message: &str) -> Result<String> {
        let output = self.pijul(&["record", "-a", "-m", message, "--author", "harbor"])?;
        output
            .split_whitespace()
            .next_back()
            .map(str::to_owned)
            .context("Pijul did not return a change hash")
    }

    pub fn change(&self, files: &[(&str, &str)], message: &str) -> Result<String> {
        for &(path, text) in files {
            self.write(path, text)?;
        }
        self.record(message)
    }

    pub fn hashes(&self, channel: &str) -> Result<BTreeSet<String>> {
        Ok(self
            .pijul(&["log", "--channel", channel, "--hash-only"])?
            .split_whitespace()
            .map(str::to_owned)
            .collect())
    }

    pub fn archive(&self, channel: &str) -> Result<Snapshot> {
        let temporary = tempfile::tempdir()?;
        let archive = temporary.path().join("channel.tar.gz");
        let output = Command::new("pijul")
            .args(["archive", "--channel", channel, "-o"])
            .arg(&archive)
            .current_dir(&self.path)
            .env_clear()
            .envs(self.env.iter())
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .output()?;
        ensure!(
            output.status.success(),
            "archive channel: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let messages = String::from_utf8(output.stderr)?;
        let mut tar = tar::Archive::new(GzDecoder::new(fs::File::open(archive)?));
        let mut files = BTreeMap::new();
        for entry in tar.entries()? {
            let mut entry = entry?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let name = entry
                .path()?
                .to_str()
                .context("archive path is not UTF-8")?
                .to_owned();
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            files.insert(name, data);
        }
        Ok(Snapshot { files, messages })
    }

    pub fn ledger(&self) -> Result<Vec<Value>> {
        let path = self.path.join(".pijul/patchgate/ledger.jsonl");
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).map_err(Into::into))
            .collect()
    }

    fn gate_command(
        &self,
        model: Option<&ModelServer>,
        args: &[&str],
        extra: &[(&str, &str)],
    ) -> Result<Command> {
        let binary =
            if let Some((_, path)) = extra.iter().rev().find(|(key, _)| *key == "PATCHGATE_BIN") {
                PathBuf::from(path)
            } else if let Some(path) = self.env.get(OsStr::new("PATCHGATE_BIN")) {
                PathBuf::from(path)
            } else {
                gate_binary()?
            };
        let mut command = Command::new(binary);
        command
            .args(args)
            .current_dir(&self.path)
            .env_clear()
            .envs(self.env.iter())
            .env("PATCHGATE_PROTECTED", "")
            .env("PATCHGATE_INBOX", "inbox")
            .env("PATCHGATE_MAIN", "main")
            .env("PATCHGATE_POLICY", "POLICY.md")
            .env("PATCHGATE_MAX_CHANGE_CHARS", "16000")
            .env("PATCHGATE_TIMEOUT", "30")
            .env("PATCHGATE_MODEL_API", "openai")
            .env("PATCHGATE_MODEL", "harbor-scripted")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(model) = model {
            command.env("PATCHGATE_MODEL_URL", &model.url);
        }
        for &(key, value) in extra {
            command.env(key, value);
        }
        Ok(command)
    }

    pub fn gate(
        &self,
        model: Option<&ModelServer>,
        args: &[&str],
        extra: &[(&str, &str)],
    ) -> Result<Output> {
        self.gate_command(model, args, extra)?
            .output()
            .context("execute gate")
    }

    pub fn spawn_gate(
        &self,
        model: Option<&ModelServer>,
        args: &[&str],
        extra: &[(&str, &str)],
    ) -> Result<Child> {
        self.gate_command(model, args, extra)?
            .process_group(0)
            .spawn()
            .context("start gate")
    }
}

pub struct Snapshot {
    pub files: BTreeMap<String, Vec<u8>>,
    pub messages: String,
}

pub fn start(dir: &Path, signer: &Signer, files: &[(&str, &str)]) -> Result<Repo> {
    let repo = Repo {
        path: dir.join("repo"),
        env: Arc::clone(&signer.env),
    };
    fs::create_dir_all(&repo.path)?;
    repo.pijul(&["init"])?;
    if !files.is_empty() {
        repo.change(files, "Start the Rust fixture")?;
    }
    checked_output(repo.gate(None, &["init"], &[])?, "initialize gate")?;
    Ok(repo)
}

pub fn concurrent(
    repo: &Repo,
    ours: &[(&str, &str)],
    ours_message: &str,
    theirs: &[(&str, &str)],
    theirs_message: &str,
) -> Result<(String, String)> {
    let temporary = tempfile::tempdir()?;
    let author = Repo {
        path: temporary.path().join("author"),
        env: Arc::clone(&repo.env),
    };
    checked_output(
        Command::new("pijul")
            .args(["clone", "--channel", "main"])
            .arg(&repo.path)
            .arg(&author.path)
            .env_clear()
            .envs(repo.env.iter())
            .stdin(Stdio::null())
            .output()?,
        "clone author",
    )?;
    let first = repo.change(ours, ours_message)?;
    let second = author.change(theirs, theirs_message)?;
    author.pijul(&[
        "push",
        repo.path.to_str().context("repository path is not UTF-8")?,
        "--to-channel",
        "inbox",
        "--no-notify",
        "-a",
    ])?;
    Ok((first, second))
}

pub fn load_facts(dir: &Path) -> Result<Value> {
    serde_json::from_slice(&fs::read(dir.join("facts.json"))?).context("read scenario facts")
}

pub fn gate_binary() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("PATCHGATE_BIN") {
        return Ok(PathBuf::from(path));
    }
    Ok(std::env::current_exe()?
        .parent()
        .context("evaluation executable has no directory")?
        .join("patchgate"))
}

pub fn checked_output(output: Output, context: &str) -> Result<String> {
    ensure!(
        output.status.success(),
        "{context}: {}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).with_context(|| context.to_owned())
}

pub struct Request {
    pub path: String,
    pub body: Value,
}

pub struct Reply {
    pub status: u16,
    pub body: Value,
}

pub struct ModelServer {
    pub url: String,
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl ModelServer {
    pub fn new(handler: impl Fn(Request) -> Reply + Send + Sync + 'static) -> Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let handler = Arc::new(handler);
        let worker = thread::spawn(move || {
            let mut connections = Vec::new();
            for stream in listener.incoming() {
                if stopped.load(Ordering::Acquire) {
                    break;
                }
                let Ok(stream) = stream else {
                    break;
                };
                let handler = Arc::clone(&handler);
                connections.push(thread::spawn(move || {
                    if let Err(error) = serve_request(stream, handler.as_ref()) {
                        eprintln!("scripted model: {error:#}");
                    }
                }));
            }
            for connection in connections {
                let _ = connection.join();
            }
        });
        Ok(Self {
            url: format!("http://{address}/v1"),
            address,
            stop,
            worker: Some(worker),
        })
    }
}

impl Drop for ModelServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn serve_request(mut stream: TcpStream, handler: &dyn Fn(Request) -> Reply) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(35)))?;
    stream.set_write_timeout(Some(Duration::from_secs(35)))?;
    let mut bytes = Vec::with_capacity(4096);
    let mut buffer = [0_u8; 4096];
    let end = loop {
        let count = stream.read(&mut buffer)?;
        ensure!(count != 0, "incomplete HTTP request");
        bytes.extend_from_slice(&buffer[..count]);
        ensure!(
            bytes.len() <= 1024 * 1024,
            "HTTP request exceeds fixture limit"
        );
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..end])?;
    let mut request_line = headers
        .lines()
        .next()
        .context("missing HTTP request line")?
        .split_whitespace();
    ensure!(request_line.next() == Some("POST"), "expected HTTP POST");
    let path = request_line
        .next()
        .context("missing request path")?
        .to_owned();
    let length = headers
        .lines()
        .skip(1)
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>())
        })
        .context("missing HTTP content length")??;
    ensure!(length <= 1024 * 1024, "HTTP body exceeds fixture limit");
    while bytes.len() < end + length {
        let count = stream.read(&mut buffer)?;
        ensure!(count != 0, "incomplete HTTP body");
        bytes.extend_from_slice(&buffer[..count]);
    }
    let request = Request {
        path,
        body: serde_json::from_slice(&bytes[end..end + length])?,
    };
    if request.body["questions"]["review"].is_object()
        || request.body["response_format"]["json_schema"]["name"] == "verdict"
    {
        review_input(&request.body)?;
    }
    let reply = handler(request);
    let body = serde_json::to_vec(&reply.body)?;
    write!(
        stream,
        "HTTP/1.1 {} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reply.status,
        body.len()
    )?;
    stream.write_all(&body)?;
    Ok(())
}

pub fn review_input(body: &Value) -> Result<Value> {
    let input = if body["questions"]["review"].is_object() {
        body.get("state").context("Missing review state")?.clone()
    } else {
        let content = body["messages"]
            .as_array()
            .and_then(|messages| messages.iter().find(|message| message["role"] == "user"))
            .and_then(|message| message["content"].as_str())
            .context("Missing review user content")?;
        serde_json::from_str(content).context("Invalid review JSON")?
    };
    ensure!(input.is_object(), "Review data must be an object");
    ensure!(
        input["schema_version"].as_u64() == Some(1),
        "Unknown review schema version"
    );
    ensure!(input["candidate"].is_object(), "Missing candidate object");
    ensure!(input["binding"].is_object(), "Missing binding object");
    ensure!(
        input.get("change").is_none(),
        "Raw change aliases are not valid"
    );
    ensure!(
        input["candidate"]["context"].is_object(),
        "Missing native context object"
    );
    ensure!(
        input["candidate"]["context"]["files"].is_array(),
        "Missing native context files"
    );
    ensure!(
        input["candidate"]["paths"].is_array(),
        "Missing candidate paths"
    );
    ensure!(
        input["candidate"]["metadata_context"].is_array(),
        "Missing metadata context"
    );
    ensure!(
        input["binding"]["candidates"].is_array(),
        "Missing bound candidate hashes"
    );
    ensure!(
        input["binding"]["policy"].is_object(),
        "Missing bound policy object"
    );
    ensure!(
        input["binding"]["main"].is_object(),
        "Missing bound main object"
    );
    for file in input["candidate"]["context"]["files"]
        .as_array()
        .expect("Native context files")
    {
        ensure!(file.is_object(), "Native context file must be an object");
        ensure!(file["path"].is_string(), "Missing native context path");
        let vertices = file["vertices"]
            .as_array()
            .context("Missing native vertices")?;
        for vertex in vertices {
            ensure!(vertex.is_object(), "Native vertex must be an object");
            ensure!(vertex["text"].is_string(), "Missing native vertex text");
            ensure!(
                matches!(vertex["kind"].as_str(), Some("add" | "del" | "keep")),
                "Unknown native vertex kind"
            );
        }
    }
    Ok(input)
}

pub fn review_contains_text(input: &Value, needle: &str) -> bool {
    let candidate = &input["candidate"];
    candidate["context"]["files"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|file| {
            file["vertices"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|vertex| {
                    vertex["text"]
                        .as_str()
                        .is_some_and(|text| text.contains(needle))
                })
        })
        || candidate["metadata_context"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|file| {
                ["before", "after"].iter().any(|side| {
                    file[*side]
                        .as_str()
                        .is_some_and(|text| text.contains(needle))
                })
            })
}

pub fn chat_reply(content: Value) -> Reply {
    Reply {
        status: 200,
        body: json!({"choices": [{"message": {"role": "assistant", "content": content.to_string()}}]}),
    }
}

pub fn verdict(decision: &str) -> Value {
    json!({"decision": decision, "summary": "A fixture change.", "reason": "Apply the fixture policy."})
}

pub fn accepting_model() -> Result<ModelServer> {
    ModelServer::new(|request| {
        if request.path != "/v1/chat/completions" {
            return Reply {
                status: 404,
                body: json!({"error": "unknown endpoint"}),
            };
        }
        if request.body["response_format"]["json_schema"]["name"] == "merge" {
            chat_reply(
                json!({"choice": "both, side 1 first", "reason": "Preserve both contributions."}),
            )
        } else {
            chat_reply(verdict("accept"))
        }
    })
}

pub struct Check {
    pub repo: Repo,
    pub facts: Value,
    pub failures: Vec<String>,
}

impl Check {
    pub fn new(dir: &Path) -> Result<Self> {
        Ok(Self {
            repo: Repo::open(dir.join("repo")),
            facts: load_facts(dir)?,
            failures: Vec::new(),
        })
    }

    pub fn require(&mut self, condition: bool, message: impl Into<String>) {
        if !condition {
            self.failures.push(message.into());
        }
    }

    pub fn within(&mut self, channel: &str, names: &[&str]) -> Result<()> {
        let hashes = self.repo.hashes(channel)?;
        for &name in names {
            let hash = self.facts[name]
                .as_str()
                .with_context(|| format!("missing hash {name}"))?;
            self.require(
                hashes.contains(hash),
                format!("{channel} must contain {name}"),
            );
        }
        Ok(())
    }

    pub fn outside(&mut self, channel: &str, names: &[&str]) -> Result<()> {
        let hashes = self.repo.hashes(channel)?;
        for &name in names {
            let hash = self.facts[name]
                .as_str()
                .with_context(|| format!("missing hash {name}"))?;
            self.require(
                !hashes.contains(hash),
                format!("{channel} must exclude {name}"),
            );
        }
        Ok(())
    }

    pub fn file(&self, channel: &str, path: &str) -> Result<Option<String>> {
        self.repo
            .archive(channel)?
            .files
            .remove(path)
            .map(|bytes| String::from_utf8(bytes).map_err(Into::into))
            .transpose()
    }

    pub fn records(&self, name: &str) -> Result<Vec<Value>> {
        let hash = self.facts[name]
            .as_str()
            .with_context(|| format!("missing hash {name}"))?;
        Ok(self
            .repo
            .ledger()?
            .into_iter()
            .filter(|record| record["hash"] == hash)
            .collect())
    }

    pub fn decision(&mut self, name: &str, decision: &str, by: &str) -> Result<()> {
        let records = self.records(name)?;
        self.require(
            records
                .last()
                .is_some_and(|record| record["decision"] == decision && record["by"] == by),
            format!("{name} must end with {decision} by {by}"),
        );
        Ok(())
    }

    pub fn no_conflicts(&mut self, channel: &str) -> Result<()> {
        self.require(
            !self.repo.archive(channel)?.messages.contains("conflict"),
            format!("{channel} must contain no conflicts"),
        );
        Ok(())
    }
}
