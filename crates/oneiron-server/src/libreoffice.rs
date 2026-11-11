//! The host's LibreOffice headless runs for the precision recalculator
//! ([`crate::xlsx_recalc`]): where `soffice` is and the version it names,
//! which it looks for once; a fresh private scratch directory with its own
//! user profile; and a child run in its own process group, with no input and
//! no error output, under its own timeout, its work's deadline and a stop
//! flag its caller sets on leaving. The review renderer
//! ([`crate::slide_render`]) keeps its own, with its capped scratch (#5494).
//! Entry: `Soffice::find`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use oneiron::{EntityId, Error, Result};

/// The version probe's own timeout: no caller's deadline or leaving ends it,
/// as its answer stands for every later run.
const PROBE_TIMEOUT: Duration = Duration::from_secs(120);
/// How often a running child is looked at.
const POLL: Duration = Duration::from_millis(50);

/// The host's LibreOffice: its `soffice` and the version it names.
pub(crate) struct Soffice {
    pub(crate) path: PathBuf,
    /// The first line `soffice --version` prints (`LibreOffice 24.8.4.2
    /// 480(Build:2)`).
    pub(crate) version: String,
}

impl Soffice {
    /// The host's LibreOffice, its version probe run in a private directory
    /// under `spool`: `None` when `soffice` is not on PATH or names no
    /// version.
    pub(crate) fn find(spool: &Path) -> Option<Self> {
        let path = on_path("soffice")?;
        let scratch = Scratch::new(spool, "oneiron-soffice").ok()?;
        let out = scratch.path.join("version");
        let mut version = oneiron_spawn::command(&path);
        version
            .arg(profile_arg(&scratch.path))
            .arg("--version")
            .env("TMPDIR", &scratch.path)
            .stdout(std::fs::File::create(&out).ok()?);
        let alone = AtomicBool::new(false);
        let under = Under {
            deadline: Instant::now() + PROBE_TIMEOUT,
            stop: &alone,
        };
        let ran = run(
            version,
            PROBE_TIMEOUT,
            &under,
            "the LibreOffice version probe",
        )
        .ok()?;
        if ran == Ran::Cut {
            return None;
        }
        let version = std::fs::read_to_string(&out).ok()?;
        let version = version.lines().next()?.trim();
        if version.is_empty() {
            return None;
        }
        Some(Self {
            path,
            version: version.to_owned(),
        })
    }
}

/// A private directory removed with everything in it when dropped.
pub(crate) struct Scratch {
    pub(crate) path: PathBuf,
}

impl Scratch {
    /// A fresh private directory under `spool`, named `{prefix}-{id}`.
    pub(crate) fn new(spool: &Path, prefix: &str) -> Result<Self> {
        let path = spool.join(format!("{prefix}-{}", EntityId::now().to_hex()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(&path)?;
        Ok(Self { path })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A run's own LibreOffice user profile, inside its directory.
pub(crate) fn profile_arg(dir: &Path) -> String {
    format!("-env:UserInstallation=file://{}/profile", dir.display())
}

/// `program` in the first PATH directory that holds it.
pub(crate) fn on_path(program: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|path| path.is_file())
}

/// What one child runs under: its work's deadline, and the flag its caller
/// sets on leaving.
pub(crate) struct Under<'a> {
    pub(crate) deadline: Instant,
    pub(crate) stop: &'a AtomicBool,
}

/// How a child's run ended without an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ran {
    /// It exited with success.
    Exited,
    /// Its work's deadline passed, or its caller left, first.
    Cut,
}

/// Runs `command` in its own process group with no input and no error
/// output until it exits. A failed exit, or a run past `timeout`, fails,
/// named as `what`; past its work's deadline, or once its caller left, it
/// answers [`Ran::Cut`] instead. However its run ends, an error or a panic
/// among them, its group is stopped ([`Group`]).
pub(crate) fn run(
    mut command: Command,
    timeout: Duration,
    under: &Under<'_>,
    what: &str,
) -> Result<Ran> {
    command.stdin(Stdio::null()).stderr(Stdio::null());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let own = Instant::now() + timeout;
    let mut child = Group(command.spawn()?);
    loop {
        if let Some(status) = child.0.try_wait()? {
            return if status.success() {
                Ok(Ran::Exited)
            } else {
                Err(failed(&format!("{what} failed")))
            };
        }
        let now = Instant::now();
        if under.stop.load(Ordering::Relaxed) || now >= under.deadline {
            return Ok(Ran::Cut);
        }
        if now >= own {
            return Err(failed(&format!("{what} timed out")));
        }
        std::thread::sleep(POLL);
    }
}

fn failed(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}

/// A running child whose process group is stopped however its run ends.
struct Group(Child);

impl Drop for Group {
    fn drop(&mut self) {
        stop(&mut self.0);
    }
}

/// Kills whatever the run left in its process group, then reaps it.
fn stop(child: &mut Child) {
    #[cfg(unix)]
    if let Some(group) = i32::try_from(child.id())
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}
