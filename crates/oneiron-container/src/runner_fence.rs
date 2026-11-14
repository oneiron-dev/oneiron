//! The runner fence (canon `#runner-fence`): every runner the daemon starts
//! on the host (a BYO seat's CLI, a stdio MCP child, a foreign-code helper)
//! loses access to the vault's trees under one fixed rule, Landlock on Linux
//! and Seatbelt on macOS, and keeps the rest of the host as it was.
//!
//! The rule removes trees; it is not an allow-list, as an organ's fence is.
//! Seatbelt says so directly: `(allow default)`, then a denial of every file
//! read, write, executable map and exec beneath each removed tree. Landlock
//! handles every filesystem right of its ABI 3, execution among them, and
//! cannot deny beneath a
//! path it allows, so the Linux rule allows, in each directory on the way
//! from `/` down to a removed tree, every entry except the removed tree and
//! the next directory on that way. The directories on the way get no right
//! of their own: a runner cannot list them, or make, remove or rename an
//! entry directly in them, and an entry made in them after the spawn stays
//! out of its reach. Everything beneath every other entry is the runner's.
//! An entry that resolves into a removed tree or onto the way to one (a
//! link) is left out, so it does not hand the tree back. Both mechanisms
//! match paths, not files: a hard link or a bind mount the host made of a
//! removed file or tree elsewhere is a copy outside the trees, and is not
//! looked for.
//!
//! The rule is built before the fork. Between fork and exec the child only
//! restricts itself ([`crate::landlock_restrict`]); on macOS the command is
//! `sandbox-exec` with the rule as its profile and the runner's program
//! after it.
//!
//! [`RunnerFence::prove`] checks the rule on this host: a probe child under
//! it must fail to list each removed tree that exists, and to read a file at
//! its top where it holds one, and must list a directory outside them. Its [`RunnerFenceOutcome`] goes on each runner
//! session's manifest: the ruleset hash when proven, `fence_unproven`
//! otherwise. A host that cannot prove the fence still runs the runner
//! (canon `#fence-unproven`); the caller withholds payment credentials from
//! it.

use crate::{FenceProof, GuestSeccomp, SessionManifest};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The programs a proof's probe children run: one lists the directory it is
/// given and one reads the file it is given, each failing where it cannot.
const PROBE_LIST: &str = "/bin/ls";
const PROBE_READ: &str = "/bin/cat";

/// macOS's Seatbelt launcher, as the organ fence runs it.
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// The version of the rule's shape, hashed into [`RunnerFence::ruleset_hash`].
const RULE_VERSION: u8 = 1;

/// How this host applies the runner fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum RunnerFenceMechanism {
    /// Linux Landlock, at the kernel's ABI (3 or later).
    Landlock { abi: i32 },
    /// macOS Seatbelt, through `sandbox-exec`.
    Seatbelt,
    /// Neither: the runner runs unfenced, and each session it starts is
    /// unproven.
    Unavailable,
}

/// The runner fence of one vault: the trees it removes, and how this host
/// applies it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnerFence {
    /// Each removed tree as the kernel resolves it, sorted.
    removed: Vec<PathBuf>,
    mechanism: RunnerFenceMechanism,
}

impl RunnerFence {
    /// The fence that removes `removed` (the vault's data and control
    /// trees), applied by this host's mechanism: Landlock where the kernel
    /// has ABI 3 or later, Seatbelt where `sandbox-exec` exists, else none.
    ///
    /// # Errors
    /// A removed tree is not an absolute path, or no tree is named.
    pub fn for_host(removed: impl IntoIterator<Item = PathBuf>) -> io::Result<Self> {
        Self::with_mechanism(removed, host_mechanism())
    }

    /// The same rule with no mechanism: the runner runs unfenced, and each
    /// session it starts is unproven. [`Self::for_host`] gives this on a host
    /// with neither Landlock nor Seatbelt.
    ///
    /// # Errors
    /// As [`Self::for_host`].
    pub fn unavailable(removed: impl IntoIterator<Item = PathBuf>) -> io::Result<Self> {
        Self::with_mechanism(removed, RunnerFenceMechanism::Unavailable)
    }

    fn with_mechanism(
        removed: impl IntoIterator<Item = PathBuf>,
        mechanism: RunnerFenceMechanism,
    ) -> io::Result<Self> {
        let mut trees = BTreeSet::new();
        for tree in removed {
            if !tree.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "runner fence tree {} is not an absolute path",
                        tree.display()
                    ),
                ));
            }
            let tree = resolved(&tree);
            if tree.parent().is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "runner fence tree / would remove the whole host",
                ));
            }
            trees.insert(tree);
        }
        if trees.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runner fence names no tree",
            ));
        }
        Ok(Self {
            removed: trees.into_iter().collect(),
            mechanism,
        })
    }

    #[must_use]
    pub fn mechanism(&self) -> RunnerFenceMechanism {
        self.mechanism
    }

    /// The removed trees, as the kernel resolves them, sorted.
    #[must_use]
    pub fn removed(&self) -> &[PathBuf] {
        &self.removed
    }

    /// blake3 of the rule: its shape's version, the mechanism (with
    /// Landlock's ABI) and the removed trees. One value for one vault on one
    /// host. The entries the Linux rule allows are not in it: they are read
    /// again at each spawn.
    #[must_use]
    pub fn ruleset_hash(&self) -> String {
        let removed: Vec<String> = self
            .removed
            .iter()
            .map(|tree| tree.to_string_lossy().into_owned())
            .collect();
        let bytes = serde_json::to_vec(&("runner_fence", RULE_VERSION, self.mechanism, removed))
            .expect("a runner fence rule is plain data");
        blake3::hash(&bytes).to_hex().to_string()
    }

    /// A command for `program` under the fence, made through
    /// [`oneiron_spawn`]. The caller adds its arguments, environment,
    /// directory and standard streams as for any command. With no mechanism
    /// it is the plain command.
    ///
    /// # Errors
    /// The Linux rule could not be built: a directory on the way to a
    /// removed tree could not be read, or the kernel refused a rule.
    pub fn command(&self, program: impl AsRef<OsStr>) -> io::Result<Command> {
        match self.mechanism {
            RunnerFenceMechanism::Landlock { .. } => self.landlock_command(program.as_ref()),
            RunnerFenceMechanism::Seatbelt => Ok(self.seatbelt_command(program.as_ref())),
            RunnerFenceMechanism::Unavailable => Ok(oneiron_spawn::command(program)),
        }
    }

    #[cfg(target_os = "linux")]
    fn landlock_command(&self, program: &OsStr) -> io::Result<Command> {
        use std::os::fd::AsFd as _;
        use std::os::unix::process::CommandExt as _;
        let allowed = allowed_entries(&self.removed)?;
        let ruleset = crate::landlock_ruleset::<PathBuf, PathBuf>(&[], &allowed)?;
        let mut command = oneiron_spawn::command(program);
        // SAFETY: the closure runs in the child between fork and exec, after
        // oneiron_spawn's own step. It makes two system calls on a
        // descriptor made before the fork and allocates nothing
        // (`landlock_restrict`).
        unsafe {
            command.pre_exec(move || crate::landlock_restrict(ruleset.as_fd()));
        }
        Ok(command)
    }

    #[cfg(not(target_os = "linux"))]
    fn landlock_command(&self, _program: &OsStr) -> io::Result<Command> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Landlock is Linux's alone",
        ))
    }

    /// `sandbox-exec -p <profile> -DREMOVED_<n>=<tree>... -- <program>`.
    /// Each tree rides as a profile parameter and is never parsed as
    /// profile text.
    fn seatbelt_command(&self, program: &OsStr) -> Command {
        let mut command = oneiron_spawn::command(SANDBOX_EXEC);
        command.arg("-p").arg(seatbelt_profile(self.removed.len()));
        for (at, tree) in self.removed.iter().enumerate() {
            let mut param = OsString::from(format!("-DREMOVED_{at}="));
            param.push(tree);
            command.arg(param);
        }
        command.arg("--").arg(program);
        command
    }

    /// Proves the fence on this host. The daemon does so once at its start,
    /// and every runner session until the next proof carries the outcome.
    /// A host with no mechanism, or one whose probe child listed or read a
    /// removed tree or could not list outside them, is unproven.
    #[must_use]
    pub fn prove(&self) -> RunnerFenceOutcome {
        let proven =
            self.mechanism != RunnerFenceMechanism::Unavailable && self.probe().unwrap_or(false);
        RunnerFenceOutcome {
            mechanism: self.mechanism,
            ruleset_hash: self.ruleset_hash(),
            proven,
            sandbox_generation: uuid::Uuid::now_v7().simple().to_string(),
            launcher_digest: self.launcher_digest(),
        }
    }

    /// Whether a probe child under the fence lists a fresh directory outside
    /// the removed trees, and fails to list each removed tree that exists
    /// (at least one of them) and to read a file at its top where it holds
    /// one.
    fn probe(&self) -> io::Result<bool> {
        let outside_dir = tempfile::tempdir()?;
        let outside = resolved(outside_dir.path());
        if self.removed.iter().any(|tree| outside.starts_with(tree))
            || !self.probe_runs(PROBE_LIST, &outside)?
        {
            return Ok(false);
        }
        let mut refused = 0_usize;
        for tree in &self.removed {
            if !tree.is_dir() {
                continue;
            }
            if self.probe_runs(PROBE_LIST, tree)? {
                return Ok(false);
            }
            if let Some(file) = top_file(tree)
                && self.probe_runs(PROBE_READ, &file)?
            {
                return Ok(false);
            }
            refused += 1;
        }
        Ok(refused > 0)
    }

    /// Whether `program` under the fence, given `path`, succeeds.
    fn probe_runs(&self, program: &str, path: &Path) -> io::Result<bool> {
        let status = self
            .command(program)?
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        Ok(status.success())
    }

    /// blake3 of what applies the rule: Landlock's self-restriction at its
    /// ABI, or `sandbox-exec` and its profile text.
    fn launcher_digest(&self) -> String {
        let launcher = match self.mechanism {
            RunnerFenceMechanism::Landlock { abi } => format!("landlock_restrict_self abi {abi}"),
            RunnerFenceMechanism::Seatbelt => {
                format!("{SANDBOX_EXEC} -p {}", seatbelt_profile(self.removed.len()))
            }
            RunnerFenceMechanism::Unavailable => String::new(),
        };
        blake3::hash(launcher.as_bytes()).to_hex().to_string()
    }
}

/// What [`RunnerFence::prove`] found on this host, for each runner session's
/// manifest.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RunnerFenceOutcome {
    pub mechanism: RunnerFenceMechanism,
    /// [`RunnerFence::ruleset_hash`] of the rule proven, or tried.
    pub ruleset_hash: String,
    /// A mechanism applied the rule, and the probe child was refused each
    /// removed tree and listed a directory outside them.
    pub proven: bool,
    /// One id per proof.
    pub sandbox_generation: String,
    /// blake3 of what applies the rule.
    pub launcher_digest: String,
}

impl RunnerFenceOutcome {
    /// The session-manifest receipt of one runner session (canon: "records
    /// the ruleset hash and whether the fence is proven"). `backend` names
    /// the runner (`runner:seat`), `runtime` its program, and `argv` its
    /// whole argument list, program first. A runner keeps the host's
    /// network and has no seccomp filter, so its proof names no route and
    /// no filter.
    #[must_use]
    pub fn session_manifest(
        &self,
        backend: &str,
        runtime: &str,
        argv: &[OsString],
    ) -> SessionManifest {
        let mut digest = blake3::Hasher::new();
        for arg in argv {
            digest.update(arg.as_encoded_bytes());
            digest.update(&[0]);
        }
        let fence_proof = self.proven.then(|| FenceProof {
            ruleset_hash: self.ruleset_hash.clone(),
            seccomp_hash: String::new(),
            network_routes: Vec::new(),
            network_evidence_digest: String::new(),
            sandbox_generation: self.sandbox_generation.clone(),
            launcher_digest: self.launcher_digest.clone(),
        });
        SessionManifest {
            backend: backend.to_owned(),
            runtime: runtime.to_owned(),
            image: String::new(),
            argv_digest: digest.finalize().to_hex().to_string(),
            network: "host".to_owned(),
            seccomp: GuestSeccomp::Unfiltered,
            generation: uuid::Uuid::now_v7().simple().to_string(),
            fence_proof,
            fence_unproven: !self.proven,
            image_release: crate::image_release::ImageReleaseObservation::default(),
        }
    }
}

/// Landlock where the kernel has ABI 3 or later, Seatbelt where
/// `sandbox-exec` exists, else none.
fn host_mechanism() -> RunnerFenceMechanism {
    #[cfg(target_os = "linux")]
    {
        let abi = crate::landlock_abi();
        if abi >= 3 {
            return RunnerFenceMechanism::Landlock { abi };
        }
    }
    #[cfg(target_os = "macos")]
    {
        if Path::new(SANDBOX_EXEC).is_file() {
            return RunnerFenceMechanism::Seatbelt;
        }
    }
    RunnerFenceMechanism::Unavailable
}

/// The Linux rule's allowed entries: in each directory on the way from `/`
/// to a removed tree, every entry that is not on that way and does not
/// resolve into a removed tree or onto the way to one.
#[cfg(target_os = "linux")]
fn allowed_entries(removed: &[PathBuf]) -> io::Result<Vec<PathBuf>> {
    let way: BTreeSet<&Path> = removed.iter().flat_map(|tree| tree.ancestors()).collect();
    let mut allowed = Vec::new();
    for dir in &way {
        if removed.iter().any(|tree| dir.starts_with(tree)) {
            continue;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for entry in entries {
            let path = entry?.path();
            if way.contains(path.as_path()) {
                continue;
            }
            // An entry that resolves into a removed tree or onto the way to
            // one (a link) would allow the tree; one that resolves nowhere (a
            // dangling link) reaches nothing.
            let Ok(real) = std::fs::canonicalize(&path) else {
                continue;
            };
            if !removed
                .iter()
                .any(|tree| real.starts_with(tree) || tree.starts_with(&real))
            {
                allowed.push(path);
            }
        }
    }
    Ok(allowed)
}

/// The Seatbelt profile for `trees` removed trees: everything allowed, then
/// every file read, write, executable map and exec beneath each
/// `REMOVED_<n>` parameter denied. A later rule wins, so the denial stands.
fn seatbelt_profile(trees: usize) -> String {
    let denied: String = (0..trees)
        .map(|at| format!(" (subpath (param \"REMOVED_{at}\"))"))
        .collect();
    format!(
        "(version 1)\n(allow default)\n\
         (deny file-read* file-write* file-map-executable process-exec*{denied})\n"
    )
}

/// A regular file directly in `dir`, read by the daemon itself, for a probe
/// child to fail to read.
fn top_file(dir: &Path) -> Option<PathBuf> {
    std::fs::read_dir(dir).ok()?.flatten().find_map(|entry| {
        let path = entry.path();
        path.is_file().then_some(path)
    })
}

/// `path` as the kernel resolves it: canonical where it exists, else its
/// nearest existing ancestor's canonical form joined with the rest, so a
/// tree made after the fence is named as Landlock and Seatbelt see it
/// (`/var` is `/private/var` on macOS).
fn resolved(path: &Path) -> PathBuf {
    if let Ok(real) = std::fs::canonicalize(path) {
        return real;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => resolved(parent).join(name),
        _ => path.to_path_buf(),
    }
}
