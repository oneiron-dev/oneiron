//! The host half of a BYOA run's staged job (`oneiron::dispatch_byoa`'s
//! staged input): the job is written whole into the directory the host
//! resolved the run's checkout into, before the run reads it. No construction
//! site lives here: whoever wires the BYOA CLI host builds this beside its
//! executor, over the same directory.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{ErrorKind, Write};
use std::path::{Component, Path, PathBuf};

use oneiron::checkout::CheckoutLeaseAct;
use oneiron::dispatch_byoa::{ByoaError, ByoaInputStager, ByoaResult};

/// Stages a run's job under `workdir`: written to a temp file beside its name,
/// then renamed onto it, so the run reads the whole job or none.
#[derive(Debug, Clone)]
pub struct WorkdirStager {
    /// Directory the host resolved the live checkout into: the one the run's
    /// executor runs in.
    pub workdir: PathBuf,
}

impl ByoaInputStager for WorkdirStager {
    fn stage(&mut self, _checkout: &CheckoutLeaseAct, name: &str, bytes: &[u8]) -> ByoaResult<()> {
        let mut parts: Vec<_> = Path::new(name).components().collect();
        let Some(Component::Normal(file_name)) = parts.pop() else {
            return Err(refused("staged input names no file"));
        };
        if parts
            .iter()
            .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(refused(
                "staged input name must be a relative path inside the checkout",
            ));
        }
        // Each directory on the way is made when absent and must be a real
        // directory: a link the run left in its checkout cannot carry the job
        // out of it.
        let mut dir = self.workdir.clone();
        for part in parts {
            dir.push(part);
            match fs::symlink_metadata(&dir) {
                Ok(meta) if meta.is_dir() => {}
                Ok(_) => return Err(refused("staged input path is not a directory")),
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    fs::create_dir(&dir).map_err(|_| failed())?;
                }
                Err(_) => return Err(failed()),
            }
        }
        write_whole(&dir, file_name, bytes).map_err(|_| failed())
    }
}

/// Writes `bytes` to a new temp file in `dir`, then renames it onto
/// `file_name`. A temp name another write holds, or one a stopped write left,
/// is passed over for the next.
fn write_whole(dir: &Path, file_name: &OsStr, bytes: &[u8]) -> std::io::Result<()> {
    let mut attempt = 0_u32;
    let (temp, mut file) = loop {
        let mut temp_name = file_name.to_owned();
        temp_name.push(format!(".{}.{attempt}.tmp", std::process::id()));
        let temp = dir.join(temp_name);
        match File::options().write(true).create_new(true).open(&temp) {
            Ok(file) => break (temp, file),
            Err(error) if error.kind() == ErrorKind::AlreadyExists && attempt < u32::MAX => {
                attempt += 1;
            }
            Err(error) => return Err(error),
        }
    };
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temp, dir.join(file_name)));
    if written.is_err() {
        let _ = fs::remove_file(&temp);
    }
    written
}

fn refused(reason: &str) -> ByoaError {
    ByoaError::Backend(reason.to_owned())
}

fn failed() -> ByoaError {
    ByoaError::Backend("staged input write failed".to_owned())
}
