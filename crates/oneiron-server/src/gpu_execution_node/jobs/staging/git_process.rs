//! The git a staging runs (row R3c): the git directory the stager writes for
//! one staging, the fenced command on it, and the started git as the leader
//! of its own process group, killed with its group before it is reaped.

use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::Duration;

use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};

use super::{GIT_VIEW_DIR_NAME, StageFailure, StagingRefusal, remove_tree};

/// How often the stager looks at a running git and at `closed`.
const GIT_POLL: Duration = Duration::from_millis(20);

/// The git directory of one staging: a `HEAD` with no ref behind it, an
/// empty `refs/` and `objects/`, attributes that turn `export-subst` and
/// `export-ignore` off, and a configuration that names the object format
/// alone. The mirror's object directory is git's `GIT_OBJECT_DIRECTORY`.
pub(super) struct GitView {
    pub(super) dir: PathBuf,
    pub(super) objects: PathBuf,
}

impl GitView {
    /// Writes the view beneath `payload_dir`, in place of one an earlier
    /// staging of the key left. A 64-character commit id is a SHA-256
    /// repository's; a 40-character one, a SHA-1 repository's.
    pub(super) fn write(
        payload_dir: &Path,
        objects: PathBuf,
        commit: &str,
    ) -> std::io::Result<Self> {
        let dir = payload_dir.join(GIT_VIEW_DIR_NAME);
        remove_tree(&dir)?;
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        // `refs/` and an empty `objects/` make it a git directory to every
        // git; the objects git reads are the mirror's.
        for part in ["refs", "objects", "info"] {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(dir.join(part))?;
        }
        std::fs::write(dir.join("HEAD"), b"ref: refs/heads/staging\n")?;
        // The git directory's attributes come before the commit's own: the
        // export is the commit's tree as committed, with no `$Format:` text
        // filled in (so no signature program runs) and no path left out.
        std::fs::write(
            dir.join("info").join("attributes"),
            b"* -export-subst -export-ignore\n",
        )?;
        let config: &[u8] = if commit.len() == 64 {
            b"[core]\n\trepositoryformatversion = 1\n\tbare = true\n[extensions]\n\tobjectformat = sha256\n"
        } else {
            b"[core]\n\trepositoryformatversion = 0\n\tbare = true\n"
        };
        std::fs::write(dir.join("config"), config)?;
        Ok(Self { dir, objects })
    }

    /// git on the view with the node's fences: an empty environment but
    /// `PATH`, no system or global configuration or attributes, no replace
    /// refs, no lazy fetch, every transport refused, no multi-pack index (a
    /// pack name in it could lead outside `pack/`) and no commit graph (a
    /// commit's tree is read from the commit), and git the leader of its own
    /// process group.
    pub(super) fn command(&self, git: &Path) -> Command {
        let mut command = Command::new(git);
        command.env_clear();
        if let Some(path) = std::env::var_os("PATH") {
            command.env("PATH", path);
        }
        command
            .env("GIT_DIR", &self.dir)
            .env("GIT_OBJECT_DIRECTORY", &self.objects)
            .envs([
                ("GIT_CONFIG_NOSYSTEM", "1"),
                ("GIT_CONFIG_GLOBAL", "/dev/null"),
                ("GIT_ATTR_NOSYSTEM", "1"),
                ("GIT_NO_REPLACE_OBJECTS", "1"),
                ("GIT_NO_LAZY_FETCH", "1"),
                // Set and empty: no transport is allowed, whatever a
                // `protocol.<name>.allow` says.
                ("GIT_ALLOW_PROTOCOL", ""),
                ("GIT_TERMINAL_PROMPT", "0"),
                ("LC_ALL", "C"),
            ])
            .args([
                "-c",
                "core.attributesFile=/dev/null",
                "-c",
                "protocol.allow=never",
                "-c",
                "core.multiPackIndex=false",
                "-c",
                "core.commitGraph=false",
            ])
            .current_dir("/")
            .process_group(0);
        command
    }
}

/// A started git, the leader of its own process group. Its end kills the
/// group before git is reaped, while git's id still names the group, so no
/// process git started outlives it. Dropped unreaped, it does the same.
pub(super) struct GitChild {
    pub(super) child: Child,
    reaped: bool,
}

impl GitChild {
    pub(super) fn spawn(mut command: Command) -> std::io::Result<Self> {
        command.spawn().map(|child| Self {
            child,
            reaped: false,
        })
    }

    /// Waits for git to exit, ending it once `closed` answers true.
    pub(super) fn wait(
        &mut self,
        closed: &dyn Fn() -> bool,
        failed: StagingRefusal,
    ) -> Result<ExitStatus, StageFailure> {
        let pid = Pid::from_child(&self.child);
        let exited = WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG;
        loop {
            match rustix::process::waitid(WaitId::Pid(pid), exited) {
                Ok(Some(_)) => {
                    // git has exited and is not reaped yet.
                    self.kill_group();
                    self.reaped = true;
                    return self.child.wait().map_err(|error| {
                        tracing::warn!(%error, "job staging: git's exit status does not read");
                        failed.into()
                    });
                }
                Ok(None) | Err(rustix::io::Errno::INTR) => {}
                Err(rustix::io::Errno::CHILD) => {
                    // Another reaper took git: its id may name another
                    // process now, so nothing is signalled.
                    tracing::warn!("job staging: git was reaped outside the stager");
                    self.reaped = true;
                    return Err(failed.into());
                }
                Err(error) => {
                    tracing::warn!(%error, "job staging: git's state does not read");
                    self.end();
                    return Err(failed.into());
                }
            }
            if closed() {
                self.end();
                return Err(StageFailure::Closed);
            }
            std::thread::sleep(GIT_POLL);
        }
    }

    fn kill_group(&self) {
        // A group with no process left answers ESRCH.
        let _ = rustix::process::kill_process_group(Pid::from_child(&self.child), Signal::KILL);
    }

    /// Kills git's group and reaps git.
    fn end(&mut self) {
        if self.reaped {
            return;
        }
        self.kill_group();
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.reaped = true;
    }
}

impl Drop for GitChild {
    fn drop(&mut self) {
        self.end();
    }
}
