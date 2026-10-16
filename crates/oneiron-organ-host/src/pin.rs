//! Organs installed from a pinned hub binary (OF-575): the pack names the
//! binary by blake3, the bytes are checked against that pin before they are
//! written, and the spec carries the pin so every start checks the file
//! again ([`OrganSpec::program_hash`]).

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use oneiron_organ_protocol::Hash32;

use crate::error::HostError;
use crate::spec::OrganSpec;

/// Writes a pinned organ binary under `dir`, in a folder named by its hash,
/// executable and read-only, and returns the first-party spec that starts
/// it with the pin set. Bytes that are not the pinned binary are refused
/// before anything is written; a file already there under the pin is
/// checked and reused.
///
/// # Errors
/// The bytes do not match the pin, the name is not a plain file name, or
/// the file could not be written.
pub fn install_pinned_binary(
    dir: &Path,
    name: &str,
    bytes: &[u8],
    pinned: Hash32,
) -> Result<OrganSpec, HostError> {
    if Hash32::of(bytes) != pinned {
        return Err(HostError::Handshake(
            "the organ binary is not the one its pack pins".into(),
        ));
    }
    let plain = Path::new(name)
        .file_name()
        .is_some_and(|file| file == std::ffi::OsStr::new(name));
    if !plain || name.starts_with('.') {
        return Err(HostError::Handshake(format!(
            "organ binary name {name:?} is not a plain file name"
        )));
    }
    let folder = dir.join(blake3::Hash::from_bytes(pinned.0).to_hex().as_str());
    let program: PathBuf = folder.join(name);
    if !fs::read(&program).is_ok_and(|held| Hash32::of(&held) == pinned) {
        fs::create_dir_all(&folder)?;
        let staging = folder.join(format!(".{name}.partial"));
        {
            let mut file = fs::File::create(&staging)?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o555))?;
        fs::rename(&staging, &program)?;
    }
    let mut spec = OrganSpec::first_party(name, program);
    spec.program_hash = Some(pinned);
    Ok(spec)
}
