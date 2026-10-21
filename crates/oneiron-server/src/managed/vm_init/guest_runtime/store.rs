//! The vault UID's own image store (FIX 7671): every container CLI call
//! the guest runtime's preparation makes, each run as the vault UID in its
//! delegated cgroup, with no supplementary group and exactly the
//! environment the engine gives its CLI, so the engine's own later calls
//! use the same store, under the container CLI's `HOME` in the encrypted
//! storage. No call is bounded by a clock: the preparation waits for each.

use super::{CLI_PATH, Failed, fail, join_cgroup, open_root_file, sha256_hex};
use oneiron_vault_contract::GuestRuntimeFact as Fact;
use oneiron_vault_contract::vm::{
    VM_GUEST_CONTAINER_HOME, VM_GUEST_CONTAINER_RUNTIME_DIR, VM_GUEST_SUBID_BASE,
    VM_GUEST_SUBID_COUNT, VmGuestImageArchive,
};
use rustix::fs::MemfdFlags;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{ExitStatus, Stdio};

/// The most of a CLI call's output kept for a report, from its end.
const TAIL: usize = 4096;

/// The descriptor's CLI, run as the vault UID in its delegated cgroup.
pub(super) struct Cli<'a> {
    pub(super) program: &'a Path,
    pub(super) uid: u32,
}

/// One CLI call's end: its status, and the tail of each stream.
struct Ran {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

impl Cli<'_> {
    /// One call to its end, with no supplementary group and the engine's
    /// CLI environment: `PATH`, `HOME` and `XDG_RUNTIME_DIR`. Its output goes
    /// to anonymous memory files, never a pipe a child it left could hold.
    fn run(&self, args: &[&OsStr]) -> Result<Ran, String> {
        let shown = self.program.display();
        // A capture file, and the end of it the call writes to.
        let capture = || -> io::Result<(File, File)> {
            let file = File::from(rustix::fs::memfd_create(
                "oneiron-vm-init",
                MemfdFlags::CLOEXEC,
            )?);
            let end = file.try_clone()?;
            Ok((end, file))
        };
        let ((out_end, out), (err_end, err)) = capture()
            .and_then(|out| capture().map(|err| (out, err)))
            .map_err(|error| format!("no capture file for {shown}: {error}"))?;
        let mut command = oneiron_spawn::command(self.program);
        command
            .args(args)
            .env_clear()
            .env("PATH", CLI_PATH)
            .env("HOME", VM_GUEST_CONTAINER_HOME)
            .env("XDG_RUNTIME_DIR", VM_GUEST_CONTAINER_RUNTIME_DIR)
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::from(out_end))
            .stderr(Stdio::from(err_end));
        let uid = self.uid;
        // SAFETY: the hook runs in the forked child before exec and calls
        // only open, write, close, setgroups, setgid and setuid, which are
        // async-signal-safe, then reads errno; it allocates nothing.
        unsafe {
            command.pre_exec(move || {
                join_cgroup()?;
                super::super::drop_privileges(uid)
            });
        }
        let status = command
            .status()
            .map_err(|error| format!("{shown}: {error}"))?;
        Ok(Ran {
            status,
            stdout: tail(out),
            stderr: tail(err),
        })
    }

    /// The UID and GID maps the CLI makes, read inside its user namespace:
    /// they must map 0 to the vault UID and 1 on to its subordinate IDs.
    pub(super) fn mapping(&self) -> Result<(), Failed> {
        let userns = fail(Fact::GuestRuntimeUsernsUnavailable);
        let args = ["unshare", "cat", "/proc/self/uid_map", "/proc/self/gid_map"];
        let ran = self.run(&args.map(OsStr::new)).map_err(&userns)?;
        if !ran.status.success() {
            return Err(userns(format!(
                "{} unshare: {}: {}",
                self.program.display(),
                ran.status,
                ran.stderr
            )));
        }
        let found: Vec<Vec<u64>> = ran
            .stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                line.split_whitespace()
                    .filter_map(|field| field.parse().ok())
                    .collect()
            })
            .collect();
        let (uid, base, count) = (
            u64::from(self.uid),
            u64::from(VM_GUEST_SUBID_BASE),
            u64::from(VM_GUEST_SUBID_COUNT),
        );
        let want = [[0, uid, 1], [1, base, count], [0, uid, 1], [1, base, count]];
        if found != want.map(Vec::from) {
            return Err(userns(format!(
                "{} maps {found:?}, not 0 to {uid} and 1-{count} to {base} for both IDs",
                self.program.display()
            )));
        }
        Ok(())
    }

    /// The id the store answers for image `id` (64 hex), as the CLI names
    /// it without `sha256:`; `None` when the store holds none.
    fn inspect(&self, id: &str) -> Result<Option<String>, String> {
        let args = ["image", "inspect", "--format", "{{.Id}}", id];
        let ran = self.run(&args.map(OsStr::new))?;
        if !ran.status.success() {
            return Ok(None);
        }
        Ok(Some(
            ran.stdout.trim().trim_start_matches("sha256:").to_owned(),
        ))
    }

    /// The `name` guest's image in the vault UID's store: there by its id,
    /// or loaded from its archive, its bytes checked again first, and there
    /// then.
    pub(super) fn import(&self, name: &str, archive: &VmGuestImageArchive) -> Result<(), Failed> {
        let id = &archive.image_id;
        let want = id.trim_start_matches("sha256:");
        let failed = |why: String| {
            fail(Fact::GuestRuntimeImageImportFailed)(format!("the {name} image {id}: {why}"))
        };
        let mismatch = |found: Option<String>| {
            fail(Fact::GuestRuntimeImageIdMismatch)(match found {
                Some(found) => format!("the store answers the {name} image {id} with id {found}"),
                None => format!("the {name} archive loaded, but the store holds no image {id}"),
            })
        };
        match self.inspect(want).map_err(failed)? {
            Some(found) if found == want => return Ok(()),
            Some(found) => return Err(mismatch(Some(found))),
            None => {}
        }
        let shown = archive.guest_path.display();
        let digest = open_root_file(&archive.guest_path)
            .and_then(|file| {
                if file.metadata()?.mode() & 0o222 != 0 {
                    return Err(io::Error::other("it is writable"));
                }
                sha256_hex(file)
            })
            .map_err(|error| failed(format!("{shown}: {error}")))?;
        if digest != archive.sha256 {
            return Err(failed(format!("{shown} is not the bytes the image staged")));
        }
        let args = [
            OsStr::new("load"),
            OsStr::new("--quiet"),
            OsStr::new("--input"),
            archive.guest_path.as_os_str(),
        ];
        let ran = self.run(&args).map_err(failed)?;
        if !ran.status.success() {
            return Err(failed(format!("load: {}: {}", ran.status, ran.stderr)));
        }
        match self.inspect(want).map_err(failed)? {
            Some(found) if found == want => Ok(()),
            found => Err(mismatch(found)),
        }
    }
}

/// The last [`TAIL`] bytes a call wrote to `file`, as text.
fn tail(mut file: File) -> String {
    let mut bytes = Vec::new();
    if file.seek(SeekFrom::Start(0)).is_ok() {
        let _ = file.read_to_end(&mut bytes);
    }
    let from = bytes.len().saturating_sub(TAIL);
    String::from_utf8_lossy(&bytes[from..]).trim().to_owned()
}
