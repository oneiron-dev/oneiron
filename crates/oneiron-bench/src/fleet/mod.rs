//! Fleet load, real held sockets, paired PPR optimization, and measured JSON receipts.
mod configuration;
mod optimization;
mod report;
mod scaling;
#[cfg(test)]
mod tests;
mod wire;
mod workload;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use configuration::Plan;
use report::{Host, Receipt};

type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, Error>;

pub(crate) fn run(args: &[String]) -> ExitCode {
    match dispatch(args, &mut std::io::stdout()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(std::io::stderr().lock(), "fleet: {error}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(args: &[String], stdout: &mut dyn Write) -> Result<()> {
    if let [cmd, flag, file] = args
        && cmd == "digest"
        && flag == "--file"
    {
        writeln!(stdout, "{}", file_hash(Path::new(file))?)?;
        return Ok(());
    }
    if let [cmd, flag, input, out_flag, output] = args
        && cmd == "ppr-scaling"
        && flag == "--plan"
        && out_flag == "--out"
    {
        let plan: Plan = serde_json::from_slice(&std::fs::read(input)?)?;
        plan.validate()?;
        let receipt = scaling::measure(&plan)?;
        report::write_new(Path::new(output), &receipt)?;
        return Ok(());
    }
    let (plan, out) = match args {
        [help] if help == "--help" => {
            writeln!(
                stdout,
                "fleet run --plan <JSON> --out <NEW_JSON>\n\
                fleet smoke --scratch <ABS_DIR> --out <NEW_JSON>\n\
                fleet digest --file <PATH>  (BLAKE3 hex of the file's bytes)\n\
                Floors: python3 scripts/fleet-regression.py --help\n\
                See docs/ops/fleet-benchmark.md. No default or zero CI floors."
            )?;
            return Ok(());
        }
        [cmd, flag, input, out_flag, output]
            if cmd == "run" && flag == "--plan" && out_flag == "--out" =>
        {
            (
                serde_json::from_slice::<Plan>(&std::fs::read(input)?)?,
                PathBuf::from(output),
            )
        }
        [cmd, flag, scratch, out_flag, output]
            if cmd == "smoke" && flag == "--scratch" && out_flag == "--out" =>
        {
            (Plan::fixture(PathBuf::from(scratch)), PathBuf::from(output))
        }
        _ => return Err("expected fleet run --plan <JSON> --out <JSON>; or fleet --help".into()),
    };
    plan.validate()?;
    if out.exists() {
        return Err("receipt path already exists; receipts are not overwritten".into());
    }
    match execute(plan.clone()) {
        Ok(receipt) => {
            report::write_new(&out, &receipt)?;
            report::table(&receipt)?;
            Ok(())
        }
        Err(error) => {
            report::write_new(
                &out,
                &serde_json::json!({"schema":"oneiron-fleet-v1",
                "status":"failed","plan":plan,"error":error.to_string()}),
            )?;
            Err(error)
        }
    }
}

fn execute(plan: Plan) -> Result<Receipt> {
    let started_unix_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let host = Host::capture()?;
    // Source archives and the remote build mirror intentionally omit .git.
    // Do not invent a commit for them: the actual binary digest is mandatory.
    let revision = report::command("git", &["rev-parse", "HEAD"]).ok();
    let dirty = revision.as_ref().and_then(|_| {
        std::process::Command::new("git")
            .args(["status", "--porcelain"])
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| !out.stdout.is_empty())
    });
    let revision = dirty.and(revision);
    let binary_blake3 = file_hash(&std::env::current_exe()?)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(plan.runtime_threads)
        .enable_all()
        .build()?;
    let observed = runtime.block_on(workload::measure(&plan))?;
    // Shut down server/clients before paired CPU/storage measurements.
    runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    let mut metrics = observed.metrics;
    let optimization = optimization::measure(&plan, &mut metrics)?;
    Ok(Receipt {
        schema: "oneiron-fleet-v1".into(),
        status: "complete".into(),
        plan,
        host,
        revision,
        dirty,
        binary_blake3,
        started_unix_ms,
        metrics,
        held_sockets: observed.held_sockets,
        verified_writes: observed.verified_writes,
        verified_recalls: observed.verified_recalls,
        hold_observed_ms: observed.hold_observed_ms,
        optimization,
    })
}

fn file_hash(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hash = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(hash.finalize().to_hex().to_string())
}
