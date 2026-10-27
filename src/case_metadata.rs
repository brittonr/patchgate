use std::path::{Component, Path};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum NoteKind {
    Comment,
    Constraint,
    Alternative,
    Evidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpanAnchor {
    pub path: String,
    pub vertex_change: String,
    pub start: u64,
    pub end: u64,
    pub kind: String,
    pub text_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NoteRecord {
    pub user: String,
    pub time: String,
    pub kind: NoteKind,
    pub text: String,
    pub references: Vec<String>,
    pub anchor: Option<SpanAnchor>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeenRecord {
    pub user: String,
    pub time: String,
    pub path: String,
    pub content_sha256: String,
    pub seen: bool,
}

fn safe_text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

fn validate_content(value: &str) -> Result<()> {
    ensure!(
        crate::secrets::scan_text("[case.human]", value.as_bytes()).is_empty(),
        "The human case metadata contains credential data."
    );
    Ok(())
}

pub fn validate_path(path: &str) -> Result<()> {
    ensure!(
        safe_text(path)
            && !path.contains('\\')
            && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
            && Path::new(path)
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
            && !Path::new(path).starts_with(".pijul"),
        "The case file path is not safe."
    );
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_human(user: &str, time: &str) -> Result<()> {
    ensure!(safe_text(user), "The human user name is not valid.");
    chrono::DateTime::parse_from_rfc3339(time).context("The human record time is not valid.")?;
    Ok(())
}

pub fn validate_histories(notes: &[NoteRecord], seen: &[SeenRecord]) -> Result<()> {
    for note in notes {
        validate_human(&note.user, &note.time)?;
        ensure!(
            safe_text(&note.text) && note.references.iter().all(|value| safe_text(value)),
            "Human notes need explicit text and references without control characters."
        );
        for value in [&note.user, &note.text].into_iter().chain(&note.references) {
            validate_content(value)?;
        }
        if let Some(anchor) = &note.anchor {
            validate_path(&anchor.path)?;
            validate_content(&anchor.path)?;
            ensure!(
                anchor.vertex_change.len() == 53
                    && anchor
                        .vertex_change
                        .bytes()
                        .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
                    && anchor.start <= anchor.end
                    && matches!(anchor.kind.as_str(), "add" | "del" | "keep")
                    && valid_digest(&anchor.text_sha256),
                "The human note span is not valid."
            );
        }
    }
    for record in seen {
        validate_human(&record.user, &record.time)?;
        validate_path(&record.path)?;
        validate_content(&record.user)?;
        validate_content(&record.path)?;
        ensure!(
            valid_digest(&record.content_sha256),
            "The seen file digest is not valid."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note() -> NoteRecord {
        NoteRecord {
            user: "reviewer".into(),
            time: "2026-10-26T00:00:00Z".into(),
            kind: NoteKind::Evidence,
            text: "The test report supports this claim.".into(),
            references: vec!["test:parser".into()],
            anchor: None,
        }
    }

    #[test]
    fn human_metadata_refuses_controls_credentials_and_unsafe_paths() {
        let original = note();
        validate_histories(std::slice::from_ref(&original), &[]).unwrap();
        let credential = ["password = \"", "Ab3dEf5hGj7kLm9nPq2sTu4w", "\""].concat();
        for value in ["", "Line\nbreak", credential.as_str()] {
            let mut record = original.clone();
            record.user = value.into();
            assert!(validate_histories(&[record], &[]).is_err());
            let mut record = original.clone();
            record.text = value.into();
            assert!(validate_histories(&[record], &[]).is_err());
            let mut record = original.clone();
            record.references = vec![value.into()];
            assert!(validate_histories(&[record], &[]).is_err());
        }
        for path in [
            "",
            "../value.txt",
            "/value.txt",
            "a//b",
            "a/./b",
            ".pijul/config",
            "a\\b",
        ] {
            assert!(validate_path(path).is_err());
        }
    }
}
