//! Explicit CLI flags and a Linux-only execution guard.
use std::{collections::BTreeMap, path::PathBuf};
use super::Result;
pub(super) const HELP: &str = "oneiron-bench cua taskgen --manifest S1.json --seed N --out DIR
oneiron-bench cua run --plan plan.json --server /absolute/oneiron --pinned-config pins.json --out DIR
oneiron-bench cua report --in rows.jsonl --out DIR
oneiron-bench cua drift --plan S5.json --programs submissions.json --out DIR";
pub(super) enum Command {
    Taskgen { manifest: PathBuf, seed: u64, out: PathBuf },
    Run { plan: PathBuf, server: PathBuf, pins: PathBuf, out: PathBuf },
    Report { input: PathBuf, out: PathBuf },
    Drift { plan: PathBuf, programs: PathBuf, out: PathBuf }, Help,
}
pub(super) fn parse(args: &[String]) -> Result<Command> {
    let Some(sub) = args.first() else { return Ok(Command::Help) };
    if sub == "--help" { return Ok(Command::Help) }
    if matches!(sub.as_str(), "run" | "drift") && !cfg!(target_os = "linux") {
        return Err(format!(r#"{{"cause":"linux_execution_required","command":"{sub}"}}"#));
    }
    let allowed: &[&str] = match sub.as_str() {
        "taskgen" => &["--manifest", "--seed", "--out"],
        "run" => &["--plan", "--server", "--pinned-config", "--out"],
        "report" => &["--in", "--out"],
        "drift" => &["--plan", "--programs", "--out"],
        _ => return Err(format!("unknown_cua_command:{sub}")),
    };
    let mut values = BTreeMap::new();
    let mut pairs = args[1..].chunks_exact(2);
    for pair in &mut pairs {
        if !allowed.contains(&pair[0].as_str()) || pair[1].is_empty()
            || values.insert(pair[0].as_str(), pair[1].as_str()).is_some() {
            return Err(format!("invalid_or_duplicate_flag:{}", pair[0]));
        }
    }
    if !pairs.remainder().is_empty() { return Err("flag_value_missing".into()) }
    let value = |key: &str| values.get(key).copied().ok_or_else(|| format!("required_flag:{key}"));
    let out = PathBuf::from(value("--out")?);
    match sub.as_str() {
        "taskgen" => Ok(Command::Taskgen { manifest: value("--manifest")?.into(),
            seed: value("--seed")?.parse().map_err(|_| "invalid_seed")?, out }),
        "run" => {
            let server = PathBuf::from(value("--server")?);
            if !server.is_absolute() { return Err("server_path_not_absolute".into()) }
            Ok(Command::Run { plan: value("--plan")?.into(), server, pins: value("--pinned-config")?.into(), out })
        }
        "report" => Ok(Command::Report { input: value("--in")?.into(), out }),
        "drift" => Ok(Command::Drift { plan: value("--plan")?.into(), programs: value("--programs")?.into(), out }),
        _ => Err("unknown_cua_command".into()),
    }
}
