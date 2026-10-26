//! The engine build's own identity (FIX 6581), compiled in as
//! `ONEIRON_ENGINE_BUILD`: the 40-hex commit the release pipeline names in
//! `ONEIRON_ENGINE_REVISION`, the same one an image manifest's
//! `engine_revision` carries; else the commit the source tree's `HEAD`
//! names; else `unknown`, which no commit spells. A missing identity never
//! fails the build.

use std::path::PathBuf;
use std::process::Command;

/// The release pipeline's commit for this build.
const RELEASE_REVISION: &str = "ONEIRON_ENGINE_REVISION";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed={RELEASE_REVISION}");
    let build = std::env::var(RELEASE_REVISION)
        .ok()
        .filter(|revision| is_commit(revision))
        .or_else(source_head)
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=ONEIRON_ENGINE_BUILD={build}");
}

/// A full commit id: 40 lowercase hex digits.
fn is_commit(revision: &str) -> bool {
    revision.len() == 40
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The commit the source tree's `HEAD` names, read again when `HEAD` or
/// the branch it names moves. `None` without git or outside a checkout.
fn source_head() -> Option<String> {
    let source = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR")?);
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(args)
            .output()
            .ok()
            .filter(|out| out.status.success())
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|out| out.trim().to_owned())
    };
    let branch = git(&["symbolic-ref", "-q", "HEAD"]);
    let watched = ["HEAD", "packed-refs"]
        .into_iter()
        .map(str::to_owned)
        .chain(branch);
    for name in watched {
        // A path that does not exist is never watched: Cargo would run this
        // script again on every build.
        if let Some(path) = git(&["rev-parse", "--git-path", &name])
            .map(|path| source.join(path))
            .filter(|path| path.exists())
        {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    git(&["rev-parse", "HEAD"]).filter(|revision| is_commit(revision))
}
