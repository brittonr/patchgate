use std::path::{Component, Path};
use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::pijul::Pijul;

pub const PATH: &str = "patchgate.json";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Values {
    pub policy_path: String,
    pub protected: Vec<String>,
    pub max_change_chars: usize,
    pub timeout_seconds: f64,
    pub check_timeout_seconds: f64,
}

impl Default for Values {
    fn default() -> Self {
        Self {
            policy_path: "POLICY.md".into(),
            protected: Vec::new(),
            max_change_chars: 8000,
            timeout_seconds: 300.0,
            check_timeout_seconds: 900.0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Evidence {
    pub source: String,
    pub path: Option<String>,
    pub sha256: Option<String>,
    pub values: Values,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u32,
    #[serde(default)]
    settings: Values,
}

pub fn load(pijul: &Pijul, main: &str, fallback: &Values) -> Result<Evidence> {
    let text = pijul
        .read_regular_file(main, PATH)
        .map_err(|_| anyhow!("Cannot read trusted configuration from main"))?;
    evidence(text.as_deref(), fallback)
}

fn evidence(text: Option<&str>, fallback: &Values) -> Result<Evidence> {
    let Some(text) = text else {
        return Ok(Evidence {
            source: "environment".into(),
            path: None,
            sha256: None,
            values: fallback.clone(),
        });
    };
    ensure!(
        crate::secrets::scan_text(PATH, text.as_bytes()).is_empty(),
        "Trusted configuration contains supported credential data"
    );
    // Parser details can contain unknown keys or values. Do not expose them.
    let document: Document = serde_json::from_str(text)
        .map_err(|_| anyhow!("Trusted configuration has invalid JSON or fields"))?;
    ensure!(
        document.schema_version == 1,
        "Unsupported trusted configuration schema"
    );
    validate(&document.settings)?;
    Ok(Evidence {
        source: "main".into(),
        path: Some(PATH.into()),
        sha256: Some(format!("{:x}", Sha256::digest(text.as_bytes()))),
        values: document.settings,
    })
}

fn validate(values: &Values) -> Result<()> {
    for value in std::iter::once(&values.policy_path).chain(&values.protected) {
        ensure!(
            crate::secrets::scan_text(PATH, value.as_bytes()).is_empty(),
            "Trusted configuration contains supported credential data"
        );
    }
    ensure!(
        relative_path(&values.policy_path) && !Path::new(&values.policy_path).starts_with(".pijul"),
        "Trusted configuration has an invalid relative policy path"
    );
    for pattern in &values.protected {
        ensure!(
            relative_path(pattern) && !pattern.contains(','),
            "Trusted configuration has an unsafe protected pattern"
        );
        regex::Regex::new(&crate::protected::pattern_regex(pattern))
            .map_err(|_| anyhow!("Trusted configuration has an invalid protected pattern"))?;
    }
    for seconds in [values.timeout_seconds, values.check_timeout_seconds] {
        ensure!(
            seconds.is_finite()
                && seconds > 0.0
                && Duration::try_from_secs_f64(seconds).is_ok_and(|value| !value.is_zero()),
            "Trusted configuration time limits must be finite, positive, and within range"
        );
    }
    Ok(())
}

fn relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.chars().any(char::is_control)
        && !value.contains('\\')
        && !value.contains(':')
        && value
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
        && Path::new(value)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(settings: serde_json::Value) -> Result<Evidence> {
        evidence(
            Some(&json!({"schema_version": 1, "settings": settings}).to_string()),
            &Values::default(),
        )
    }

    #[test]
    fn absent_file_preserves_raw_environment_values() -> Result<()> {
        let fallback = Values {
            policy_path: "../legacy-policy".into(),
            protected: vec!["".into()],
            max_change_chars: 0,
            timeout_seconds: 0.0,
            check_timeout_seconds: 0.0,
        };
        let loaded = evidence(None, &fallback)?;
        assert_eq!(loaded.source, "environment");
        assert_eq!(loaded.values, fallback);
        assert_eq!(loaded.path, None);
        assert_eq!(loaded.sha256, None);
        Ok(())
    }

    #[test]
    fn recorded_settings_use_fixed_defaults_and_exact_text_hash() -> Result<()> {
        let fallback = Values {
            policy_path: "OTHER.md".into(),
            protected: vec!["*".into()],
            max_change_chars: 1,
            timeout_seconds: 1.0,
            check_timeout_seconds: 1.0,
        };
        let text = "{\r\n  \"schema_version\": 1, \"settings\": {}\r\n}\n";
        let loaded = evidence(Some(text), &fallback)?;
        assert_eq!(loaded.source, "main");
        assert_eq!(loaded.path.as_deref(), Some(PATH));
        assert_eq!(loaded.values, Values::default());
        assert_eq!(
            loaded.sha256,
            Some(format!("{:x}", Sha256::digest(text.as_bytes())))
        );
        assert_eq!(
            evidence(Some("{\"schema_version\":1}"), &fallback)?.values,
            Values::default()
        );
        Ok(())
    }

    #[test]
    fn explicit_values_preserve_unicode_patterns_and_fractional_limits() -> Result<()> {
        let loaded = parse(json!({
            "policy_path": "docs/政策.md",
            "protected": ["src/*", "docs/?.md", "[!a-c].txt", "a{b}.txt"],
            "max_change_chars": 0,
            "timeout_seconds": 0.125,
            "check_timeout_seconds": 1.75
        }))?;
        assert_eq!(loaded.values.policy_path, "docs/政策.md");
        assert_eq!(loaded.values.protected.len(), 4);
        assert_eq!(loaded.values.max_change_chars, 0);
        assert_eq!(loaded.values.timeout_seconds, 0.125);
        assert_eq!(loaded.values.check_timeout_seconds, 1.75);
        Ok(())
    }

    #[test]
    fn malformed_documents_never_use_fallback_values() {
        for text in [
            "not JSON",
            "null",
            "{}",
            "{\"schema_version\":2}",
            "{\"schema_version\":1,\"extra\":true}",
            "{\"schema_version\":1,\"settings\":{\"extra\":true}}",
            "{\"schema_version\":1,\"settings\":null}",
            "{\"schema_version\":1,\"settings\":{\"max_change_chars\":-1}}",
            "{\"schema_version\":1,\"schema_version\":1}",
        ] {
            assert!(evidence(Some(text), &Values::default()).is_err());
        }
    }

    #[test]
    fn paths_and_patterns_cannot_escape_or_hide_control_data() {
        for path in [
            "",
            "/absolute",
            "../policy",
            "docs/../policy",
            "./policy",
            "docs/./policy",
            "docs//policy",
            "docs/",
            "C:\\policy",
            "a\\b",
            "a\nb",
            "a\0b",
        ] {
            assert!(parse(json!({"policy_path": path})).is_err(), "{path:?}");
            assert!(parse(json!({"protected": [path]})).is_err(), "{path:?}");
        }
    }

    #[test]
    fn trusted_time_limits_must_fit_a_positive_duration() {
        for seconds in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::MAX, 1e-100] {
            for check in [false, true] {
                let mut values = Values::default();
                if check {
                    values.check_timeout_seconds = seconds;
                } else {
                    values.timeout_seconds = seconds;
                }
                assert!(validate(&values).is_err());
            }
        }
    }

    #[test]
    fn sensitive_data_and_parser_details_stay_out_of_errors() {
        let credential = ["-----BEGIN OPENSSH ", "PRIVATE KEY-----"].concat();
        let text =
            json!({"schema_version": 1, "settings": {"policy_path": &credential}}).to_string();
        let error = evidence(Some(&text), &Values::default()).unwrap_err();
        assert!(!format!("{error:#}").contains(&credential));
        let marker = "PRIVATE_UNKNOWN_FIELD";
        let text = json!({"schema_version": 1, "settings": {(marker): "value"}}).to_string();
        let error = evidence(Some(&text), &Values::default()).unwrap_err();
        assert!(!format!("{error:#}").contains(marker));
        let text = r#"{"schema_version":1,"settings":{"policy_path":"\u002d----BEGIN OPENSSH PRIVATE KEY-----"}}"#;
        let error = evidence(Some(text), &Values::default()).unwrap_err();
        assert!(error.to_string().contains("credential data"));
        assert!(!format!("{error:#}").contains("PRIVATE KEY"));
    }

    #[test]
    fn load_uses_only_the_requested_recorded_channel() -> Result<()> {
        use crate::pijul::Signer;
        use std::fs;

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("repo");
        fs::create_dir(&root)?;
        let pijul = Pijul::new(root.clone());
        pijul.run(["init"])?;
        fs::write(root.join("base.txt"), "base\n")?;
        pijul.run(["add", "base.txt"])?;
        let signer = Signer::new(root.join(".pijul/patchgate"));
        let environment = signer.environment()?;
        let record = |message: &str| -> Result<()> {
            pijul.call_with_env(
                ["record", "-a", "-m", message, "--author", "patchgate"],
                &environment.vars,
            )?;
            Ok(())
        };
        record("Record the base")?;
        let fallback = Values {
            max_change_chars: 42,
            ..Values::default()
        };
        let text = "{\"schema_version\":1,\"settings\":{\"max_change_chars\":123}}\r\n";
        fs::write(root.join(PATH), text)?;
        assert_eq!(load(&pijul, "main", &fallback)?.values, fallback);
        pijul.run(["add", PATH])?;
        record("Record trusted settings")?;
        let expected = load(&pijul, "main", &fallback)?;
        assert_eq!(expected.values.max_change_chars, 123);
        assert_eq!(
            expected.sha256,
            Some(format!("{:x}", Sha256::digest(text.as_bytes())))
        );
        pijul.run(["fork", "--channel", "main", "inbox"])?;
        pijul.run(["channel", "switch", "inbox"])?;
        fs::write(root.join(PATH), "{\"schema_version\":2}")?;
        record("Record invalid inbox settings")?;
        assert!(load(&pijul, "inbox", &fallback).is_err());
        fs::write(root.join(PATH), "unrecorded data")?;
        assert_eq!(load(&pijul, "main", &fallback)?, expected);
        assert_eq!(fs::read_to_string(root.join(PATH))?, "unrecorded data");
        Ok(())
    }

    #[test]
    fn recorded_directory_cannot_enable_environment_fallback() -> Result<()> {
        use crate::pijul::Signer;
        use std::fs;

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("repo");
        fs::create_dir(&root)?;
        let pijul = Pijul::new(root.clone());
        pijul.run(["init"])?;
        fs::create_dir(root.join(PATH))?;
        fs::write(root.join(PATH).join("child"), "invalid configuration")?;
        pijul.run(["add", "patchgate.json/child"])?;
        let signer = Signer::new(root.join(".pijul/patchgate"));
        let environment = signer.environment()?;
        pijul.call_with_env(
            [
                "record",
                "-a",
                "-m",
                "Record a configuration directory",
                "--author",
                "patchgate",
            ],
            &environment.vars,
        )?;
        assert!(load(&pijul, "main", &Values::default()).is_err());
        Ok(())
    }
}
