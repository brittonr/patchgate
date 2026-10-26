use std::io::{self, Write};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEvidence {
    pub schema_version: u32,
    pub operation: String,
    pub api: String,
    pub model: String,
    pub declared_revision: Option<String>,
    pub revision_verified: bool,
    pub prompt_sha256: String,
    pub schema_sha256: String,
}

impl RequestEvidence {
    pub(crate) fn new(
        operation: &str,
        api: &str,
        model: &str,
        declared_revision: Option<&str>,
        prompt: &impl Serialize,
        schema: &impl Serialize,
    ) -> Result<Self> {
        Ok(Self {
            schema_version: 1,
            operation: operation.to_owned(),
            api: api.to_owned(),
            model: model.to_owned(),
            declared_revision: declared_revision.map(str::to_owned),
            revision_verified: false,
            prompt_sha256: digest(prompt)?,
            schema_sha256: digest(schema)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierVersions {
    pub schema_version: u32,
    pub patchgate: String,
    pub pijul: String,
    pub nix: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub requests: Vec<RequestEvidence>,
    pub verifiers: VerifierVersions,
}

pub fn verifier_versions(pijul: &crate::pijul::Pijul) -> Result<VerifierVersions> {
    Ok(VerifierVersions {
        schema_version: 1,
        patchgate: env!("CARGO_PKG_VERSION").to_owned(),
        pijul: pijul.version()?,
        nix: None,
    })
}

pub(crate) fn digest(value: &impl Serialize) -> Result<String> {
    struct DigestWriter(Sha256);

    impl Write for DigestWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut writer = DigestWriter(Sha256::new());
    serde_json::to_writer(&mut writer, value)?;
    Ok(format!("{:x}", writer.0.finalize()))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn request_evidence_contains_digests_without_request_data() -> Result<()> {
        let prompt = json!({"policy": "PRIVATE_POLICY", "state": "PRIVATE_STATE"});
        let schema = json!({"type": "choice", "criteria": {"accept": "Accept."}});
        let evidence = RequestEvidence::new(
            "review",
            "systemone",
            "fixture-model",
            Some("revision-7"),
            &prompt,
            &schema,
        )?;
        assert_eq!(
            evidence.prompt_sha256,
            format!("{:x}", Sha256::digest(serde_json::to_vec(&prompt)?))
        );
        assert_eq!(
            evidence.schema_sha256,
            format!("{:x}", Sha256::digest(serde_json::to_vec(&schema)?))
        );
        assert_eq!(evidence.declared_revision.as_deref(), Some("revision-7"));
        assert!(!evidence.revision_verified);
        let encoded = serde_json::to_string(&evidence)?;
        assert!(!encoded.contains("PRIVATE_POLICY"));
        assert!(!encoded.contains("PRIVATE_STATE"));
        assert_eq!(serde_json::from_str::<RequestEvidence>(&encoded)?, evidence);
        Ok(())
    }

    #[test]
    fn request_digests_bind_prompt_and_schema_separately() -> Result<()> {
        let first = RequestEvidence::new(
            "review",
            "openai",
            "fixture-model",
            None,
            &json!(["first"]),
            &json!({"type": "object"}),
        )?;
        let prompt = RequestEvidence::new(
            "review",
            "openai",
            "fixture-model",
            None,
            &json!(["second"]),
            &json!({"type": "object"}),
        )?;
        let schema = RequestEvidence::new(
            "review",
            "openai",
            "fixture-model",
            None,
            &json!(["first"]),
            &json!({"type": "string"}),
        )?;
        assert_ne!(first.prompt_sha256, prompt.prompt_sha256);
        assert_eq!(first.schema_sha256, prompt.schema_sha256);
        assert_eq!(first.prompt_sha256, schema.prompt_sha256);
        assert_ne!(first.schema_sha256, schema.schema_sha256);
        assert_eq!(first.declared_revision, None);
        Ok(())
    }
}
