//! Core half of `git_wire::hub_read`: its store-layer items live in `oneiron_store::git_wire::hub_read` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::git_wire::hub_read::*;

use super::execution_context::GitCommandSpec;
use super::failure::{invalid, uncertain};
use super::{GitWireProcessEnv, process::spawn_git};
use crate::error::Result;
use std::{
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

pub(crate) fn read_hub_git(root: &Path, args: &[&str], limit: usize) -> Result<Vec<u8>> {
    // This internal door only touches the caller-owned scratch repository.
    // It cannot become a general mutation bridge or accept arbitrary -c pairs.
    let valid = args == ["init", "--bare", "--quiet", "repo"]
        || (args.first() == Some(&"--git-dir=repo")
            && match args.get(1).copied() {
                Some("config") => {
                    args.len() == 4
                        && matches!(
                            args[2],
                            "remote.origin.url"
                                | "remote.origin.promisor"
                                | "remote.origin.partialclonefilter"
                        )
                }
                Some("fetch") => {
                    args.len() == 10
                        && args[2..9]
                            == [
                                "--quiet",
                                "--no-tags",
                                "--no-recurse-submodules",
                                "--depth=1",
                                "--filter=blob:none",
                                "--",
                                "origin",
                            ]
                }
                Some("rev-parse") => args[2..] == ["--verify", "FETCH_HEAD^{commit}"],
                Some("ls-tree") => args.len() == 6 && args[2..5] == ["-r", "-z", "--full-tree"],
                Some("cat-file") => args.len() == 4 && matches!(args[2], "-s" | "blob"),
                _ => false,
            });
    if !valid {
        return Err(invalid("unsupported hub Git operation"));
    }
    let mut argv = Vec::with_capacity(args.len());
    for arg in args {
        super::argv::validate_argv_token(arg)?;
        argv.push(std::ffi::OsString::from(arg));
    }
    let mut env =
        GitWireProcessEnv::capture()?.with_limits(Duration::from_secs(30), limit.max(4096))?;
    env.hub_root = Some(root.to_path_buf());
    // Validation above guarantees a subcommand at args[1] outside init.
    let op = if args[0] == "init" { "init" } else { args[1] };
    let started = Instant::now();
    let command = GitCommandSpec::hub(root, &argv, op)?;
    let output = spawn_git(&env, &command)
        .map_err(|error| refused(op, "spawn", started, &format!(" error={error}")))?;
    // `success` is already false when output was truncated, so the order of
    // these checks is what names the cause.
    let (cause, detail) = if output.timed_out {
        (
            "timeout",
            format!(" budget_ms={}", env.timeout().as_millis()),
        )
    } else if output.truncated {
        let (out, err, cap) = (output.stdout.len(), output.stderr.len(), limit.max(4096));
        (
            "truncated",
            format!(" stdout_bytes={out} stderr_bytes={err} cap={cap}"),
        )
    } else if !output.success {
        let code = output
            .exit_code
            .map_or_else(|| "signal".to_owned(), |code| code.to_string());
        (
            "exit",
            format!(" code={code} stderr={}", stderr_head(&output.stderr)),
        )
    } else if output.stdout.len() > limit {
        let out = output.stdout.len();
        ("oversize", format!(" stdout_bytes={out} limit={limit}"))
    } else {
        return Ok(output.stdout);
    };
    Err(refused(op, cause, started, &detail))
}
