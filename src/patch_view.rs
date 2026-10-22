use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::Value;

use crate::change::{self, short};
use crate::gate::Ledger;
use crate::pijul::{NativeContext, NativeVertexKind, Pijul};

#[derive(Clone, Serialize)]
pub struct BlameChange {
    pub hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Serialize)]
pub struct BlameLine {
    pub line: usize,
    pub text: String,
    pub conflict: bool,
    pub changes: Vec<BlameChange>,
}

#[derive(Serialize)]
pub struct BlameReport {
    pub schema_version: u8,
    pub channel: String,
    pub path: String,
    pub lines: Vec<BlameLine>,
}

#[derive(Serialize)]
pub struct ShowLine {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_line: Option<usize>,
    pub change: String,
    pub text: String,
}

#[derive(Serialize)]
pub struct ShowFile {
    pub path: String,
    pub lines: Vec<ShowLine>,
}

#[derive(Serialize)]
pub struct ShowReport {
    pub schema_version: u8,
    pub hash: String,
    pub message: String,
    pub files: Vec<ShowFile>,
}

fn number(value: Option<&Value>, name: &str) -> Result<usize> {
    value
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .with_context(|| format!("pijul credit shows an invalid {name}"))
}

fn hashes(value: Option<&Value>) -> Result<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value
        .as_array()
        .context("pijul credit shows invalid line changes")?
        .iter()
        .map(|hash| {
            hash.as_str()
                .map(str::to_owned)
                .context("pijul credit shows an invalid change hash")
        })
        .collect()
}

fn split_lines(content: &str) -> Vec<&str> {
    if content.is_empty() {
        return vec![content];
    }
    content.split_inclusive('\n').collect()
}

/// Turn native per-line attribution into lines with the ledger decision of each change.
pub fn blame(
    pijul: &Pijul,
    ledger: &Ledger,
    channel: &str,
    path: &str,
) -> Result<BlameReport> {
    let safe = crate::pijul::safe_path(&pijul.repo, Path::new(path))?;
    if Path::new(path).components().next().is_some_and(|part| part.as_os_str() == ".pijul") {
        bail!("A blame path cannot be repository metadata: {path}");
    }
    if !safe.is_file() {
        bail!("The blame path is not a regular file in the working copy: {path}");
    }
    let records = ledger.latest()?;
    let entries = pijul.credit(channel, path)?;
    let mut lines = Vec::new();
    let mut conflict = false;
    for entry in &entries {
        let kind = entry.get("type").and_then(Value::as_str);
        match kind {
            Some("line") => {
                let line = number(entry.get("startLine"), "startLine")?;
                let count = number(entry.get("lineCount"), "lineCount")?;
                let content = entry
                    .get("content")
                    .and_then(Value::as_str)
                    .context("pijul credit shows invalid line content")?;
                let mut changes = Vec::new();
                for hash in hashes(entry.get("changes"))? {
                    let record = records.get(&hash);
                    changes.push(BlameChange {
                        hash,
                        decision: record.map(|record| record.decision.clone()),
                        by: record.map(|record| record.by.clone()),
                        message: record.map(|record| record.message.clone()),
                    });
                }
                let pieces = split_lines(content);
                if pieces.len() != count {
                    bail!("pijul credit shows a line range that differs from its text");
                }
                for (index, text) in pieces.into_iter().enumerate() {
                    lines.push(BlameLine {
                        line: line + index,
                        text: text.to_owned(),
                        conflict,
                        changes: changes.clone(),
                    });
                }
            }
            Some("conflict") => {
                match entry.get("marker").and_then(Value::as_str) {
                    Some("start") => {
                        let mut changes = Vec::new();
                        for hash in hashes(entry.get("sides"))? {
                            let record = records.get(&hash);
                            changes.push(BlameChange {
                                hash,
                                decision: record.map(|record| record.decision.clone()),
                                by: record.map(|record| record.by.clone()),
                                message: record.map(|record| record.message.clone()),
                            });
                        }
                        lines.push(BlameLine {
                            line: lines.len() + 1,
                            text: "<<<<<<< conflict >>>>>>>".into(),
                            conflict: true,
                            changes,
                        });
                        conflict = true;
                    }
                    Some("end") => conflict = false,
                    Some("separator") => {}
                    other => bail!(
                        "pijul credit shows a conflict marker that patchgate does not know: {}",
                        other.unwrap_or("none")
                    ),
                }
            }
            other => bail!(
                "pijul credit shows an entry that patchgate does not know: {}",
                other.unwrap_or("none")
            ),
        }
    }
    Ok(BlameReport {
        schema_version: 1,
        channel: channel.to_owned(),
        path: path.to_owned(),
        lines,
    })
}

pub fn show(pijul: &Pijul, hash: &str) -> Result<ShowReport> {
    if hash.is_empty()
        || hash.len() > 64
        || !hash
            .chars()
            .all(|character| character.is_ascii_uppercase() || ('2'..='7').contains(&character))
    {
        bail!("Give a native change hash of base32 characters.");
    }
    let text = pijul.change(hash)?;
    let context: NativeContext = pijul.context(hash)?;
    let mut files = Vec::new();
    for file in context.files {
        let mut lines = Vec::new();
        let mut old_line = 1;
        let mut new_line = 1;
        for vertex in file.vertices {
            if vertex.end.checked_sub(vertex.start) != Some(vertex.text.len() as u64)
                || vertex.text.contains('\0')
            {
                bail!("Native context has invalid or binary spans: {}", file.path);
            }
            for text in vertex.text.split_inclusive('\n') {
                let (old, new, kind) = match vertex.kind {
                    NativeVertexKind::Add => {
                        let line = new_line;
                        new_line += 1;
                        (None, Some(line), "add")
                    }
                    NativeVertexKind::Del => {
                        let line = old_line;
                        old_line += 1;
                        (Some(line), None, "del")
                    }
                    NativeVertexKind::Keep => {
                        let line = (old_line, new_line);
                        old_line += 1;
                        new_line += 1;
                        (Some(line.0), Some(line.1), "keep")
                    }
                };
                lines.push(ShowLine {
                    kind: kind.into(),
                    old_line: old,
                    new_line: new,
                    change: vertex.change.clone(),
                    text: text.to_owned(),
                });
            }
        }
        files.push(ShowFile {
            path: file.path,
            lines,
        });
    }
    Ok(ShowReport {
        schema_version: 1,
        hash: hash.to_owned(),
        message: change::message(&text),
        files,
    })
}

pub fn print_blame(report: &BlameReport) {
    println!("{}  {}  {}", report.channel, report.path, report.lines.len());
    let mut legend: BTreeMap<&str, ()> = BTreeMap::new();
    for line in &report.lines {
        let label = if line.conflict {
            "conflict".to_owned()
        } else if let Some(last) = line.changes.last() {
            let extra = line.changes.len().saturating_sub(1);
            if extra == 0 {
                short(&last.hash).to_owned()
            } else {
                format!("+{extra} {}", short(&last.hash))
            }
        } else {
            "-".to_owned()
        };
        println!("{:>6}  {:<9}  {}", line.line, label, line.text.trim_end_matches('\n'));
        for change in &line.changes {
            legend.insert(&change.hash, ());
        }
    }
    println!();
    for hash in legend.keys() {
        let change = report
            .lines
            .iter()
            .flat_map(|line| &line.changes)
            .find(|change| change.hash == *hash);
        if let Some(change) = change {
            println!(
                "{}  {:<9}  {}",
                short(&change.hash),
                change.decision.as_deref().unwrap_or("unrecorded"),
                change.message.as_deref().unwrap_or("")
            );
        }
    }
    println!("Blame reports native attribution only. It grants no acceptance authority.");
}

pub fn print_show(report: &ShowReport) {
    println!("{}  {}", short(&report.hash), report.message);
    for file in &report.files {
        println!();
        println!("{}", file.path);
        for line in &file.lines {
            let marker = match line.kind.as_str() {
                "add" => '+',
                "del" => '-',
                _ => ' ',
            };
            let old = line
                .old_line
                .map(|line| line.to_string())
                .unwrap_or_else(|| "·".into());
            let new = line
                .new_line
                .map(|line| line.to_string())
                .unwrap_or_else(|| "·".into());
            println!(
                "{marker} {:>5} {:>5}  {}",
                old,
                new,
                line.text.trim_end_matches('\n')
            );
        }
    }
    println!();
    println!("Spans come from the native palimpsest. This report grants no acceptance authority.");
}
