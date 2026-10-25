use std::fs;
use std::process::Command;

use anyhow::Result;

#[test]
fn check_timeout_requires_a_finite_positive_duration() -> Result<()> {
    let repo = tempfile::tempdir()?;
    fs::create_dir(repo.path().join(".pijul"))?;
    for seconds in ["0", "-0", "0.0000000001", "-1", "NaN", "inf", "-inf"] {
        let output = Command::new(env!("CARGO_BIN_EXE_patchgate"))
            .arg("--repo")
            .arg(repo.path())
            .args(["model", "--json"])
            .env_clear()
            .env("HOME", repo.path())
            .env("PATCHGATE_CHECK_TIMEOUT", seconds)
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(1),
            "The invalid check duration {seconds:?} must stop the command."
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("PATCHGATE_CHECK_TIMEOUT"),
            "The error must identify the invalid setting."
        );
    }
    Ok(())
}
