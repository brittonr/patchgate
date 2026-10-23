//! Named model profiles, so that a model swap is one selector.
//!
//! Treat the profiles file as untrusted local configuration. It names
//! endpoints, models, and key files. It never supplies policy, and a profile
//! cannot make a check weaker.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

use crate::model::Api;

pub const PATH: &str = "PATCHGATE_MODELS";
pub const PROFILE: &str = "PATCHGATE_MODEL_PROFILE";
pub const KEY_FILE: &str = "PATCHGATE_MODEL_KEY_FILE";

const FALLBACK_URL: &str = "http://127.0.0.1:8124/v1";
const FALLBACK_MODEL: &str = "mlx-community/clef-4bit";
const KEY_LIMIT: usize = 4096;

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub url: String,
    pub model: String,
    #[serde(default = "systemone_api")]
    pub api: String,
    #[serde(default)]
    pub revision: Option<String>,
    #[serde(default)]
    pub key_file: Option<String>,
}

fn systemone_api() -> String {
    "systemone".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    #[serde(default)]
    default: Option<String>,
    profiles: BTreeMap<String, Profile>,
}

/// The effective model endpoint, its source, and the profiles that exist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    pub profile: Option<String>,
    pub url: String,
    pub model: String,
    pub api: Api,
    pub revision: Option<String>,
    pub key_file: Option<PathBuf>,
    pub source: Option<PathBuf>,
    pub available: Vec<String>,
}

impl Selection {
    pub fn profile_name(&self) -> &str {
        self.profile.as_deref().unwrap_or("environment")
    }
}

pub fn default_path() -> Result<PathBuf> {
    let home =
        env::var_os("HOME").context("HOME is unset, so the model profiles path is unknown")?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("patchgate")
        .join("models.toml"))
}

fn setting(name: &str) -> Result<Option<String>> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(_) => bail!("{name} is not valid UTF-8"),
    }
}

fn home_path(value: &str) -> Result<PathBuf> {
    if let Some(rest) = value.strip_prefix("~/") {
        let home = env::var_os("HOME").context("HOME is unset, so a key file path is unknown")?;
        return Ok(PathBuf::from(home).join(rest));
    }
    ensure!(
        !value.trim().is_empty() && !value.chars().any(char::is_control),
        "A model profile path is empty or contains control characters"
    );
    Ok(PathBuf::from(value))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
}

fn valid_url(url: &str) -> bool {
    let address = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"));
    address.is_some_and(|address| {
        !address.is_empty() && !address.starts_with('/') && !url.chars().any(char::is_whitespace)
    })
}

fn parse(text: &str) -> Result<Document> {
    let document: Document =
        toml::from_str(text).context("The model profiles are not valid TOML")?;
    ensure!(
        !document.profiles.is_empty(),
        "The model profiles file has no profiles"
    );
    for (name, profile) in &document.profiles {
        ensure!(valid_name(name), "A model profile name is invalid");
        ensure!(
            valid_url(&profile.url),
            "Model profile {name:?} needs an HTTP or HTTPS URL"
        );
        ensure!(
            !profile.model.trim().is_empty() && !profile.model.chars().any(char::is_control),
            "Model profile {name:?} needs a model name"
        );
        ensure!(
            !profile.api.chars().any(char::is_control),
            "Model profile {name:?} has an invalid API name"
        );
        if let Some(revision) = &profile.revision {
            ensure!(
                !revision.chars().any(char::is_control),
                "Model profile {name:?} has an invalid revision"
            );
        }
        if let Some(key_file) = &profile.key_file {
            home_path(key_file)
                .with_context(|| format!("Model profile {name:?} has an invalid key file"))?;
        }
    }
    if let Some(default) = &document.default {
        ensure!(
            document.profiles.contains_key(default),
            "The default model profile {default:?} does not exist"
        );
    }
    Ok(document)
}

#[derive(Default)]
struct Overrides {
    url: Option<String>,
    model: Option<String>,
    api: Option<String>,
    revision: Option<String>,
    key_file: Option<String>,
}

fn overrides() -> Result<Overrides> {
    Ok(Overrides {
        url: setting("PATCHGATE_MODEL_URL")?,
        model: setting("PATCHGATE_MODEL")?,
        api: setting("PATCHGATE_MODEL_API")?,
        revision: setting("PATCHGATE_MODEL_REVISION")?,
        key_file: setting(KEY_FILE)?,
    })
}

fn resolve(
    document: Option<Document>,
    requested: Option<String>,
    path: &Path,
    overrides: Overrides,
) -> Result<Selection> {
    let chosen = match (requested.as_deref(), document.as_ref()) {
        (Some(name), Some(_)) => Some(name.to_owned()),
        (Some(name), None) => bail!(
            "{PROFILE}={name} needs a model profiles file at {}",
            path.display()
        ),
        (None, Some(document)) => document.default.clone(),
        (None, None) => None,
    };
    let mut available = document
        .as_ref()
        .map(|document| document.profiles.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    available.sort();
    let profile = match (&chosen, document.as_ref()) {
        (Some(name), Some(document)) => Some(document.profiles.get(name).with_context(|| {
            format!(
                "The model profiles file {} has no profile {name:?}",
                path.display()
            )
        })?),
        _ => None,
    };
    let url = overrides
        .url
        .or_else(|| profile.map(|profile| profile.url.clone()))
        .unwrap_or_else(|| FALLBACK_URL.into());
    ensure!(
        valid_url(&url),
        "The model URL must start with http:// or https:// and contain no whitespace"
    );
    let model = overrides
        .model
        .or_else(|| profile.map(|profile| profile.model.clone()))
        .unwrap_or_else(|| FALLBACK_MODEL.into());
    ensure!(
        !model.trim().is_empty() && !model.chars().any(char::is_control),
        "The model name is empty or contains control characters"
    );
    let api = overrides
        .api
        .or_else(|| profile.map(|profile| profile.api.clone()))
        .unwrap_or_else(systemone_api)
        .parse::<Api>()?;
    let revision = match overrides.revision {
        Some(value) if value.trim().is_empty() => None,
        Some(value) => Some(value),
        None => profile.and_then(|profile| profile.revision.clone()),
    };
    let key_file = match overrides.key_file {
        Some(value) => Some(home_path(&value)?),
        None => profile
            .and_then(|profile| profile.key_file.as_deref())
            .map(home_path)
            .transpose()?,
    };
    Ok(Selection {
        profile: chosen,
        url,
        model,
        api,
        revision,
        key_file,
        source: document.as_ref().map(|_| path.to_path_buf()),
        available,
    })
}

/// Read the profiles file, then select one profile and apply environment
/// overrides. An absent file keeps the environment-only behavior.
pub fn select() -> Result<Selection> {
    let path = match setting(PATH)? {
        Some(value) => home_path(&value)?,
        None => default_path()?,
    };
    let text = match fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| {
                format!("Cannot read the model profiles file {}", path.display())
            });
        }
    };
    let document =
        match &text {
            Some(text) => Some(parse(text).with_context(|| {
                format!("The model profiles file {} is invalid", path.display())
            })?),
            None => None,
        };
    resolve(document, setting(PROFILE)?, &path, overrides()?)
}

/// Select one named profile without the primary environment overrides.
///
/// Use it for a second, larger typed tier. The profile must exist.
pub fn select_named(name: &str) -> Result<Selection> {
    let path = match setting(PATH)? {
        Some(value) => home_path(&value)?,
        None => default_path()?,
    };
    let text = fs::read_to_string(&path)
        .with_context(|| format!("Cannot read the model profiles file {}", path.display()))?;
    let document = parse(&text)
        .with_context(|| format!("The model profiles file {} is invalid", path.display()))?;
    resolve(
        Some(document),
        Some(name.to_owned()),
        &path,
        Overrides::default(),
    )
}

/// Read a bearer key from a file that only its owner can read. The returned
/// value never appears in an error message.
pub fn read_key(path: &Path) -> Result<String> {
    ensure!(
        path.is_absolute(),
        "The model key file path must be absolute"
    );
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("Cannot read the model key file {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "The model key file {} is not a regular file",
        path.display()
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "The model key file {} is readable by other users. Run: chmod 600 {}",
        path.display(),
        path.display()
    );
    ensure!(
        metadata.len() <= KEY_LIMIT as u64,
        "The model key file {} is too large",
        path.display()
    );
    let bytes = fs::read(path)
        .with_context(|| format!("Cannot read the model key file {}", path.display()))?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("The model key file {} is not UTF-8", path.display()))?;
    let key = text.trim_end_matches(['\r', '\n']);
    ensure!(
        !key.trim().is_empty(),
        "The model key file {} is empty",
        path.display()
    );
    ensure!(
        !key.chars().any(char::is_control),
        "The model key file {} contains control characters",
        path.display()
    );
    Ok(key.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_reject_unknown_fields_and_weak_urls() -> Result<()> {
        assert!(parse("[profiles.a]\nurl = \"ftp://host\"\nmodel = \"m\"\n").is_err());
        assert!(parse("[profiles.a]\nurl = \"http://host\"\nmodel = \"m\"\nextra = 1\n").is_err());
        assert!(parse("[profiles.a]\nurl = \"http://host\"\n").is_err());
        assert!(
            parse("default = \"missing\"\n[profiles.a]\nurl = \"http://host\"\nmodel = \"m\"\n")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn key_files_require_owner_only_reading() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("key");
        fs::write(&path, "sk-test\n")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        assert_eq!(read_key(&path)?, "sk-test");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        let error = read_key(&path).unwrap_err().to_string();
        assert!(error.contains("chmod 600"), "unexpected error: {error}");
        assert!(!error.contains("sk-test"));
        fs::write(&path, "")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        assert!(read_key(&path).is_err());
        Ok(())
    }

    #[test]
    fn profile_names_are_plain_identifiers() {
        assert!(valid_name("local"));
        assert!(valid_name("gpu_1"));
        assert!(!valid_name(""));
        assert!(!valid_name("a b"));
        assert!(!valid_name("a/b"));
    }

    const DOCUMENT: &str = "default = \"local\"\n\
        [profiles.local]\nurl = \"http://127.0.0.1:1234/v1\"\nmodel = \"gemma\"\napi = \"openai\"\n\
        [profiles.remote]\nurl = \"https://api.example/v1\"\nmodel = \"gpt\"\napi = \"systemone\"\nrevision = \"r1\"\n";

    fn document() -> Document {
        parse(DOCUMENT).unwrap()
    }

    #[test]
    fn selectors_and_environment_overrides_have_explicit_precedence() -> Result<()> {
        let path = Path::new("/config/models.toml");
        let default = resolve(Some(document()), None, path, Overrides::default())?;
        assert_eq!(default.profile.as_deref(), Some("local"));
        assert_eq!(default.model, "gemma");
        assert_eq!(default.api, Api::OpenAi);
        assert_eq!(default.source.as_deref(), Some(path));
        assert_eq!(default.available, ["local", "remote"]);

        let remote = resolve(
            Some(document()),
            Some("remote".into()),
            path,
            Overrides::default(),
        )?;
        assert_eq!(remote.api, Api::SystemOne);
        assert_eq!(remote.revision.as_deref(), Some("r1"));

        let overridden = resolve(
            Some(document()),
            Some("remote".into()),
            path,
            Overrides {
                url: Some("http://host:1234/v1".into()),
                model: Some("other".into()),
                revision: Some("  ".into()),
                ..Overrides::default()
            },
        )?;
        assert_eq!(overridden.url, "http://host:1234/v1");
        assert_eq!(overridden.model, "other");
        assert_eq!(overridden.revision, None);
        assert_eq!(overridden.api, Api::SystemOne);
        Ok(())
    }

    #[test]
    fn a_profile_selector_needs_a_file_and_a_declared_profile() -> Result<()> {
        let path = Path::new("/config/models.toml");
        let missing_file = resolve(None, Some("local".into()), path, Overrides::default())
            .unwrap_err()
            .to_string();
        assert!(
            missing_file.contains("PATCHGATE_MODEL_PROFILE"),
            "{missing_file}"
        );
        let unknown = resolve(
            Some(document()),
            Some("gpu".into()),
            path,
            Overrides::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(unknown.contains("no profile"), "{unknown}");

        let environment = resolve(None, None, path, Overrides::default())?;
        assert_eq!(environment.profile, None);
        assert_eq!(environment.source, None);
        assert_eq!(environment.available, Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn environment_urls_cannot_smuggle_a_weak_endpoint() {
        let path = Path::new("/config/models.toml");
        for url in ["file:///etc/passwd", "http://", "http://host path"] {
            assert!(
                resolve(
                    Some(document()),
                    None,
                    path,
                    Overrides {
                        url: Some(url.into()),
                        ..Overrides::default()
                    }
                )
                .is_err(),
                "accepted {url}"
            );
        }
    }
}
