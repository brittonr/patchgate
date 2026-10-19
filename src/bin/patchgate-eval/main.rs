mod concurrency;
mod controls;
mod executable;
mod hostile;
mod real_model;
mod recovery;
mod support;

use std::ffi::OsString;

use clap::{Args, Parser, Subcommand};
use controls::Control;
use support::*;

#[derive(Parser)]
#[command(
    name = "patchgate-eval",
    about = "Run Rust Harbor scenarios, verifier controls, and live model jobs"
)]
struct Cli {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    List,
    SetupAll {
        directory: PathBuf,
    },
    Setup {
        name: String,
        directory: PathBuf,
    },
    Solve(SolveArgs),
    Check {
        name: String,
        directory: PathBuf,
        #[arg(long, default_value = "/logs/verifier/reward.txt")]
        reward: PathBuf,
    },
    Smoke {
        #[arg(long = "case")]
        cases: Vec<String>,
    },
    VerifyHarbor(controls::ControlArgs),
    ModelHarbor(real_model::LiveArgs),
    #[command(disable_help_flag = true)]
    InterceptPijul {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
}

#[derive(Args)]
struct SolveArgs {
    name: String,
    directory: PathBuf,
    #[arg(
        long,
        value_enum,
        env = "PATCHGATE_EVAL_CONTROL",
        default_value = "oracle"
    )]
    control: Control,
    #[arg(long, env = "PATCHGATE_EVAL_MODEL_URL")]
    model_url: Option<String>,
    #[arg(long, env = "PATCHGATE_MODEL", default_value = "harbor-scripted")]
    model: String,
    #[arg(long, env = "PATCHGATE_MODEL_API", default_value = "openai")]
    api: String,
    #[arg(long, env = "PATCHGATE_MODEL_REVISION")]
    revision: Option<String>,
    #[arg(long, env = "PATCHGATE_EVAL_REPORT")]
    report: Option<PathBuf>,
}

fn scenarios() -> impl Iterator<Item = &'static Scenario> {
    [
        executable::SCENARIOS,
        concurrency::SCENARIOS,
        recovery::SCENARIOS,
        hostile::SCENARIOS,
        real_model::SCENARIOS,
    ]
    .into_iter()
    .flatten()
}

pub fn find_scenario(name: &str) -> Result<&'static Scenario> {
    scenarios()
        .find(|case| case.name == name)
        .with_context(|| format!("unknown Rust scenario {name}"))
}

fn setup(case: &Scenario, directory: &Path, signer: &Signer) -> Result<()> {
    fs::create_dir_all(directory)?;
    let facts = (case.setup)(directory, signer)?;
    let mut file = fs::File::create(directory.join("facts.json"))?;
    serde_json::to_writer_pretty(&mut file, &facts)?;
    std::io::Write::write_all(&mut file, b"\n")?;
    Ok(())
}

fn verify(case: &Scenario, directory: &Path) -> Vec<String> {
    let mut check = match Check::new(directory) {
        Ok(check) => check,
        Err(error) => return vec![format!("{error:#}")],
    };
    if let Err(error) = (case.check)(&mut check) {
        check.failures.push(format!("{error:#}"));
    }
    check.failures
}

fn smoke(cases: &[String]) -> Result<()> {
    for name in cases {
        find_scenario(name)?;
    }
    let root = tempfile::Builder::new().prefix("pge-smoke-").tempdir()?;
    let signer = Signer::new()?;
    let options = RunOptions::default();
    let mut failures = Vec::new();
    let mut trials = 0;
    for case in
        scenarios().filter(|case| cases.is_empty() || cases.iter().any(|name| name == case.name))
    {
        for oracle in [true, false] {
            let agent = if oracle { "oracle" } else { "nop" };
            let directory = root.path().join(agent).join(case.name);
            let result = setup(case, &directory, &signer).and_then(|()| {
                if oracle {
                    (case.solve)(&directory, &options)?;
                }
                Ok(verify(case, &directory))
            });
            trials += 1;
            match result {
                Ok(errors) if errors.is_empty() == oracle => println!(
                    "{} {agent}: expected reward {}",
                    case.name,
                    u8::from(oracle)
                ),
                Ok(errors) => {
                    failures.push(format!("{} {agent}: {}", case.name, errors.join("\n")))
                }
                Err(error) => failures.push(format!("{} {agent}: {error:#}", case.name)),
            }
        }
    }
    for failure in &failures {
        eprintln!("{failure}");
    }
    ensure!(
        failures.is_empty(),
        "{} of {trials} Rust controls failed",
        failures.len()
    );
    println!("All {trials} Rust control results match.");
    Ok(())
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Action::List => {
            for case in scenarios() {
                println!("{}", case.name);
            }
        }
        Action::SetupAll { directory } => {
            let signer = Signer::new()?;
            for case in scenarios() {
                setup(case, &directory.join(case.name), &signer)?;
            }
        }
        Action::Setup { name, directory } => {
            setup(find_scenario(&name)?, &directory, &Signer::new()?)?
        }
        Action::Solve(args) => {
            if matches!(args.control, Control::Oracle) {
                let options = RunOptions {
                    model_url: args.model_url,
                    model: args.model,
                    api: args.api,
                    revision: args.revision,
                    report: args.report,
                };
                (find_scenario(&args.name)?.solve)(&args.directory, &options)?;
            } else {
                controls::solve_control(&args.name, &args.directory, args.control)?;
            }
        }
        Action::Check {
            name,
            directory,
            reward,
        } => {
            let failures = verify(find_scenario(&name)?, &directory);
            for failure in &failures {
                eprintln!("FAIL: {failure}");
            }
            if let Some(parent) = reward.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(reward, if failures.is_empty() { "1\n" } else { "0\n" })?;
            println!("reward: {}", u8::from(failures.is_empty()));
        }
        Action::Smoke { cases } => smoke(&cases)?,
        Action::VerifyHarbor(args) => controls::verify_harbor(args)?,
        Action::ModelHarbor(args) => real_model::model_harbor(args)?,
        Action::InterceptPijul { args } => recovery::intercept_pijul(&args)?,
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("patchgate-eval: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
