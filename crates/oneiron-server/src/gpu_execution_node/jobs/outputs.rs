//! The hash of a launched key's declared outputs: step 3 of its end
//! ([`super::end`]), run after the release, never before.

use std::io::Read as _;
use std::path::Path;
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

use super::node_parts::NodeJobSettings;
use crate::gpu_execution_node::wire::{OutputDigest, OutputsState, WorkloadPin};

/// Hashes the pin's declared outputs beneath `<payload_dir>/out/`: only
/// declared names, only regular files, opened without following a link,
/// each within the key's disk request, within the settings' hash limit in
/// all. An output above the returnable bound is hashed and kept on the node,
/// not returnable.
#[must_use]
pub(super) fn hash_outputs(
    payload_dir: &Path,
    pin: &WorkloadPin,
    settings: &NodeJobSettings,
) -> OutputsState {
    use rustix::fs::{FileType, Mode, OFlags};
    let started = Instant::now();
    let limit = Duration::from_secs(settings.output_hash_limit_secs);
    let directory = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let base = match rustix::fs::open(payload_dir, directory, Mode::empty()) {
        Ok(base) => base,
        Err(rustix::io::Errno::NOENT) => return OutputsState::Hashed(Vec::new()),
        Err(error) => {
            return OutputsState::Failed {
                why: format!("payload_dir: {error}"),
            };
        }
    };
    let out = match rustix::fs::openat(&base, "out", directory, Mode::empty()) {
        Ok(out) => out,
        Err(rustix::io::Errno::NOENT) => return OutputsState::Hashed(Vec::new()),
        Err(error) => {
            return OutputsState::Failed {
                why: format!("out: {error}"),
            };
        }
    };
    let size_bound = pin.request.disk_mib.saturating_mul(1024 * 1024);
    let mut digests = Vec::new();
    for decl in &pin.outputs {
        let name = decl.name.as_str();
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return OutputsState::Failed {
                why: format!("{name}: not a plain file name"),
            };
        }
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let descriptor = match rustix::fs::openat(&out, name, flags, Mode::empty()) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::NOENT) => continue,
            Err(error) => {
                return OutputsState::Failed {
                    why: format!("{name}: {error}"),
                };
            }
        };
        let stat = match rustix::fs::fstat(&descriptor) {
            Ok(stat) => stat,
            Err(error) => {
                return OutputsState::Failed {
                    why: format!("{name}: {error}"),
                };
            }
        };
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return OutputsState::Failed {
                why: format!("{name}: not a regular file"),
            };
        }
        if u64::try_from(stat.st_size).unwrap_or(u64::MAX) > size_bound {
            return OutputsState::Failed {
                why: format!("{name}: larger than the key's disk request"),
            };
        }
        let mut file = std::fs::File::from(descriptor);
        let mut hasher = Sha256::new();
        let mut bytes = 0u64;
        let mut buffer = vec![0u8; 1 << 16];
        loop {
            if started.elapsed() > limit {
                return OutputsState::Failed {
                    why: "hash_time_limit".to_owned(),
                };
            }
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    hasher.update(&buffer[..read]);
                    bytes = bytes.saturating_add(read as u64);
                    if bytes > size_bound {
                        return OutputsState::Failed {
                            why: format!("{name}: larger than the key's disk request"),
                        };
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => {
                    return OutputsState::Failed {
                        why: format!("{name}: {error}"),
                    };
                }
            }
        }
        digests.push(OutputDigest {
            name: name.to_owned(),
            sha256: oneiron_hex::encode(&hasher.finalize()),
            bytes,
            returnable: decl.returnable && bytes <= settings.returnable_bound(),
        });
    }
    OutputsState::Hashed(digests)
}
