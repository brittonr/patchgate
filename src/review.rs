use serde::{Deserialize, Serialize};
use serde_json::value::{RawValue, to_raw_value};
use sha2::{Digest, Sha256};

use crate::pijul::{ChannelSnapshot, ReviewChange};

#[derive(Clone, Deserialize, Serialize)]
pub struct PolicyBinding {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MainBinding {
    pub channel: String,
    pub state: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ReviewBinding {
    pub candidates: Vec<String>,
    pub policy: Option<PolicyBinding>,
    pub main: MainBinding,
}

impl ReviewBinding {
    pub fn new(
        candidates: &[String],
        policy_path: &str,
        policy: Option<&str>,
        channel: &str,
        main: &ChannelSnapshot,
    ) -> Self {
        Self {
            candidates: candidates.to_vec(),
            policy: policy.map(|text| PolicyBinding {
                path: policy_path.to_owned(),
                sha256: format!("{:x}", Sha256::digest(text.as_bytes())),
            }),
            main: MainBinding {
                channel: channel.to_owned(),
                state: main.state.clone(),
            },
        }
    }
}

#[derive(Serialize)]
struct ReviewInput<'a> {
    schema_version: u8,
    candidate: &'a ReviewChange,
    binding: &'a ReviewBinding,
}

pub fn input(
    candidate: &ReviewChange,
    binding: &ReviewBinding,
) -> serde_json::Result<Box<RawValue>> {
    to_raw_value(&ReviewInput {
        schema_version: 1,
        candidate,
        binding,
    })
}
