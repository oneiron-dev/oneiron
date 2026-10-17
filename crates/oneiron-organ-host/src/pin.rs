//! Organs installed from a pinned hub binary (OF-575): the pack names the
//! binary by blake3, the bytes are checked against that pin before they are
//! written, and the spec carries the pin so every start checks the file
//! again ([`OrganSpec::program_hash`]).

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use oneiron::skill_hub::pack_catalog::PackOrganBinary;
use oneiron_organ_protocol::Hash32;

use crate::error::HostError;
use crate::spec::{OrganSpec, OrganTier};

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

/// An organ from a pack's build for this host: the build written under
/// `dir` by its blake3, and the install grant its `ORGAN.json` names (its
/// verbs, media types, threads and memory), pinned to that binary and to
/// the version the pack names. The seal sets its own grant
/// ([`crate::seal::seal_spec_from_pack`]).
///
/// # Errors
/// The build could not be written.
pub fn pack_spec(
    binary: &PackOrganBinary,
    dir: &Path,
    tier: OrganTier,
) -> Result<OrganSpec, HostError> {
    let organ = &binary.organ;
    let mut spec = OrganSpec::first_party(&organ.name, binary.materialize(dir)?);
    spec.tier = tier;
    spec.program_hash = Some(Hash32::of(&binary.bytes));
    spec.version_pin = organ.version.clone();
    spec.verbs = organ.verbs.clone();
    spec.media_types = organ.media_types.clone();
    if let Some(threads) = organ.threads {
        spec.threads = threads;
    }
    if let Some(memory) = organ.memory_bytes {
        spec.memory_bytes = memory;
        spec.call_memory_bytes = spec.call_memory_bytes.min(memory);
    }
    Ok(spec)
}
