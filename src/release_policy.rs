use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PATH: &str = "release-policy.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: u32,
    pub limits: Limits,
    pub coverage: Coverage,
    pub signatures: Signatures,
    pub baseline_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_unsafe_acceptances: usize,
    pub max_label_mismatches: usize,
    pub max_regressions: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    #[serde(deserialize_with = "unique_counts")]
    pub policy_rules: BTreeMap<String, usize>,
    #[serde(deserialize_with = "unique_counts")]
    pub conflict_kinds: BTreeMap<String, usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Signatures {
    pub require_bundle: bool,
    pub require_baseline: bool,
    pub signer: Option<String>,
    pub allowed_signers_sha256: Option<String>,
    pub revoked_keys_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub schema_version: u32,
    pub source_repository: PathBuf,
    pub main: String,
    pub main_state: Option<String>,
    pub policy_sha256: String,
}

#[derive(Debug)]
pub struct Loaded {
    pub policy: Option<Policy>,
    pub evidence: Option<Evidence>,
}

fn unique_counts<'de, D>(deserializer: D) -> std::result::Result<BTreeMap<String, usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Counts;
    impl<'de> serde::de::Visitor<'de> for Counts {
        type Value = BTreeMap<String, usize>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("unique coverage counts")
        }
        fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut counts = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, usize>()? {
                if counts.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("Duplicate coverage tag"));
                }
            }
            Ok(counts)
        }
    }
    deserializer.deserialize_map(Counts)
}

fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 64
        && tag.as_bytes()[0].is_ascii_lowercase()
        && tag.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

pub fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "Unsupported trusted release policy schema"
        );
        ensure!(
            self.coverage
                .policy_rules
                .keys()
                .chain(self.coverage.conflict_kinds.keys())
                .all(|tag| valid_tag(tag)),
            "Trusted release policy has an invalid coverage tag"
        );
        for digest in [
            &self.baseline_sha256,
            &self.signatures.allowed_signers_sha256,
            &self.signatures.revoked_keys_sha256,
        ]
        .into_iter()
        .flatten()
        {
            ensure!(
                valid_digest(digest),
                "Trusted release policy has an invalid SHA-256 digest"
            );
        }
        let signatures = &self.signatures;
        if let Some(signer) = &signatures.signer {
            ensure!(
                !signer.trim().is_empty() && !signer.chars().any(char::is_control),
                "Trusted release policy has an invalid signer identity"
            );
            ensure!(
                crate::secrets::scan_text(PATH, signer.as_bytes()).is_empty(),
                "Trusted release policy contains supported credential data"
            );
        }
        let trust_selected = signatures.require_bundle
            || signatures.require_baseline
            || signatures.signer.is_some()
            || signatures.allowed_signers_sha256.is_some()
            || signatures.revoked_keys_sha256.is_some();
        ensure!(
            !trust_selected
                || (signatures.signer.is_some() && signatures.allowed_signers_sha256.is_some()),
            "Trusted release signature requirements need a signer and allowed-signers digest"
        );
        Ok(())
    }
}

fn parse(bytes: &[u8]) -> Result<Policy> {
    ensure!(
        crate::secrets::scan_text(PATH, bytes).is_empty(),
        "Trusted release policy contains supported credential data"
    );
    let policy: Policy = serde_json::from_slice(bytes)
        .map_err(|_| anyhow!("Trusted release policy has invalid JSON or fields"))?;
    policy.validate()?;
    Ok(policy)
}

pub fn load(repository: &Path, main: &str) -> Result<Loaded> {
    ensure!(
        !main.trim().is_empty() && !main.starts_with('-') && !main.chars().any(char::is_control),
        "The trusted release channel name is invalid"
    );
    let repository = std::fs::canonicalize(repository)
        .map_err(|_| anyhow!("Cannot read the trusted release repository"))?;
    let isolated = crate::isolation::copy_repository(&repository)
        .map_err(|_| anyhow!("Cannot copy trusted release metadata"))?;
    let pijul =
        crate::pijul::Pijul::with_timeout(isolated.pijul.repo.clone(), Duration::from_secs(30));
    let snapshot = pijul
        .snapshot(main)
        .map_err(|_| anyhow!("Cannot read the trusted release channel"))?;
    let text = pijul
        .read_regular_file(main, PATH)
        .map_err(|_| anyhow!("Cannot read the trusted release policy"))?;
    let Some(text) = text else {
        return Ok(Loaded {
            policy: None,
            evidence: None,
        });
    };
    let policy = parse(text.as_bytes())?;
    Ok(Loaded {
        policy: Some(policy),
        evidence: Some(Evidence {
            schema_version: 1,
            source_repository: repository,
            main: main.into(),
            main_state: snapshot.state,
            policy_sha256: format!("{:x}", Sha256::digest(text.as_bytes())),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn document() -> serde_json::Value {
        json!({
            "schema_version": 1,
            "limits": {"max_unsafe_acceptances": 1, "max_label_mismatches": 2, "max_regressions": 0},
            "coverage": {"policy_rules": {"policy": 1}, "conflict_kinds": {}},
            "signatures": {"require_bundle": false, "require_baseline": false}
        })
    }

    #[test]
    fn recorded_policy_ignores_working_and_inbox_copies() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("repo");
        std::fs::create_dir(&root)?;
        let pijul = crate::pijul::Pijul::new(root.clone());
        pijul.run(["init"])?;
        std::fs::write(root.join("base.txt"), "base\n")?;
        pijul.run(["add", "base.txt"])?;
        let signer = crate::pijul::Signer::new(root.join(".pijul/patchgate"));
        let environment = signer.environment()?;
        let record = |message: &str| -> Result<()> {
            pijul.call_with_env(
                ["record", "-a", "-m", message, "--author", "patchgate"],
                &environment.vars,
            )?;
            Ok(())
        };
        record("Record the base")?;
        let bytes = serde_json::to_vec(&document())?;
        std::fs::write(root.join(PATH), &bytes)?;
        assert!(load(&root, "main")?.policy.is_none());
        pijul.run(["add", PATH])?;
        record("Record release requirements")?;
        let before = pijul.snapshot("main")?;
        let expected = format!("{:x}", Sha256::digest(&bytes));
        pijul.run(["fork", "--channel", "main", "inbox"])?;
        pijul.run(["channel", "switch", "inbox"])?;
        std::fs::write(root.join(PATH), "{\"schema_version\":2}")?;
        record("Record invalid inbox requirements")?;
        std::fs::write(root.join(PATH), "unrecorded policy")?;
        let loaded = load(&root, "main")?;
        assert_eq!(loaded.policy.unwrap().limits.max_label_mismatches, 2);
        assert_eq!(loaded.evidence.unwrap().policy_sha256, expected);
        assert!(load(&root, "inbox").is_err());
        assert_eq!(pijul.snapshot("main")?, before);
        assert_eq!(
            std::fs::read_to_string(root.join(PATH))?,
            "unrecorded policy"
        );
        Ok(())
    }

    #[test]
    fn invalid_requirements_and_sensitive_parser_data_are_refused() {
        let mut value = document();
        value["signatures"]["require_bundle"] = json!(true);
        assert!(parse(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut value = document();
        value["baseline_sha256"] = json!("A".repeat(64));
        assert!(parse(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut value = document();
        value["private_unknown_field"] = json!("private parser text");
        let error = parse(&serde_json::to_vec(&value).unwrap()).unwrap_err();
        assert!(!format!("{error:#}").contains("private parser text"));
        let bytes = serde_json::to_vec(&document()).unwrap();
        let duplicate = String::from_utf8(bytes)
            .unwrap()
            .replace("\"policy\":1", "\"policy\":1,\"policy\":2");
        assert!(parse(duplicate.as_bytes()).is_err());
    }
}
