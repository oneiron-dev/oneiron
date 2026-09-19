//! Guest PID-1 entry point and explicitly named, unprivileged local test tools.

use oneiron_guest::{Error, Result};
use std::{fs, io::Write, path::Path};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.is_empty() {
        return production();
    }
    // Test adapters must never become a PID-1 production fallback.
    // SAFETY: getpid has no preconditions.
    if unsafe { libc::getpid() } == 1 {
        return Err(Error::Runtime("PID 1 refuses localtest modes"));
    }
    match args.as_slice() {
        [mode, artifact] if mode == "--artifact-digest" => {
            let mut input = fs::File::open(artifact)?;
            let mut digest = blake3::Hasher::new();
            digest.update_reader(&mut input)?;
            writeln!(std::io::stdout().lock(), "{}", digest.finalize().to_hex())?;
            Ok(())
        }
        [mode, output] if mode == "--write-conformance" => {
            let bytes = oneiron_guest::conformance::component()?;
            // Avoid clobbering artifacts or following a pre-existing symlink.
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)?;
            file.write_all(&bytes)?;
            Ok(())
        }
        [mode, socket, workspace] if mode == "--localtest-socket" => {
            // SAFETY: geteuid has no preconditions.
            if unsafe { libc::geteuid() } == 0 {
                return Err(Error::Runtime("LOCALTEST must run unprivileged"));
            }
            let stream = std::os::unix::net::UnixStream::connect(socket)?;
            oneiron_guest::serve_localtest(stream, Path::new(workspace))
        }
        _ => Err(Error::Runtime(
            "usage: no arguments (Linux PID 1); --artifact-digest FILE; --write-conformance NEW.wasm; --localtest-socket SOCKET EMPTY_WORKSPACE",
        )),
    }
}

#[cfg(target_os = "linux")]
fn production() -> Result<()> {
    oneiron_guest::boot::run()
}

#[cfg(not(target_os = "linux"))]
fn production() -> Result<()> {
    Err(Error::Runtime("production guest requires Linux PID 1"))
}
