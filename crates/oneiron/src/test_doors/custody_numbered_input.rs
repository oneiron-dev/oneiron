//! Doors for `tests/custody_numbered_envelope_input.rs` (FIX 5624): the
//! numbered-envelope custody input (FIX 5521) at its seal, keep and open
//! doors. A door seals a register past one envelope's bound as numbered
//! envelopes in one frame, keeps it whole or in numbered parts, and the
//! holder opens every envelope at its place. Thin wrappers over the input's
//! own seal, keep and open; no envelope logic here. Compiled only under
//! `--cfg oneiron_test_support` (`test_doors`); hidden, never API.

use crate::entity_id::EntityId;
use crate::error::Result;
#[cfg(feature = "sync")]
use crate::vault::Vault;

/// What opening a kept numbered input found.
#[derive(Debug)]
#[doc(hidden)]
pub enum KeptOpen {
    /// No whole row, or no complete part list, is kept: the request stays
    /// pending.
    Missing,
    /// The kept rows do not open under the holder's key and binding, or not
    /// to a register body.
    Invalid,
    /// The register body the holder opened.
    Opened {
        /// The record's value bytes.
        value: Vec<u8>,
        /// The manifest text the body is framed with, if any.
        manifest: Option<String>,
        /// The record's name.
        name: String,
    },
}

/// Seals a register of `name` holding `value`, framed with `manifest`, to
/// the holder's key `seed` names, as a door seals it. Returns the sealed
/// frame, the body length it seals and the frame's envelope count.
///
/// # Errors
///
/// A body that fits one envelope, so nothing numbered is sealed; a seal
/// that fails.
#[doc(hidden)]
pub fn seal_numbered_register(
    holder: EntityId,
    seed: u8,
    name: &str,
    value: &[u8],
    manifest: Option<&str>,
) -> Result<(Vec<u8>, usize, u32)> {
    crate::secret_custody::seal_numbered_register_for_test(holder, seed, name, value, manifest)
}

/// Opens `frame` with the holder's key `seed` names: the register's value,
/// framed manifest text and name. `None` when it does not open, or not to
/// a register body.
#[doc(hidden)]
pub fn open_numbered_as_holder(
    frame: &[u8],
    holder: EntityId,
    seed: u8,
) -> Option<(Vec<u8>, Option<String>, String)> {
    crate::secret_custody::open_numbered_as_holder_for_test(frame, holder, seed)
}

/// The envelope count `frame` states; `None` when it states none.
#[doc(hidden)]
pub fn frame_envelope_count(frame: &[u8]) -> Option<u32> {
    crate::secret_custody::frame_envelope_count_for_test(frame)
}

/// The frame without its first envelope, its stated count kept; `None` for
/// anything but a well-formed frame of two envelopes or more.
#[doc(hidden)]
pub fn drop_first_envelope(frame: &[u8]) -> Option<Vec<u8>> {
    crate::secret_custody::tamper_drop_first_envelope_for_test(frame)
}

/// The frame with its first two envelopes swapped, whole with their
/// lengths; `None` for anything but a well-formed frame of two envelopes
/// or more.
#[doc(hidden)]
pub fn swap_first_two_envelopes(frame: &[u8]) -> Option<Vec<u8>> {
    crate::secret_custody::tamper_swap_first_two_envelopes_for_test(frame)
}

/// The frame stating `count` envelopes over its unchanged envelopes;
/// `None` when `frame` states no count.
#[doc(hidden)]
pub fn rewrite_envelope_count(frame: &[u8], count: u32) -> Option<Vec<u8>> {
    crate::secret_custody::tamper_rewrite_envelope_count_for_test(frame, count)
}

/// Keeps `frame` as the input the digest the request would name, whole or
/// in numbered parts. Returns that digest and how many rows keep it.
///
/// # Errors
///
/// A frame past the part list's bound; storage errors.
#[cfg(feature = "sync")]
#[doc(hidden)]
pub fn keep_numbered(vault: &Vault, frame: &[u8]) -> Result<([u8; 32], u32)> {
    crate::secret_custody::keep_numbered_input_for_test(vault, frame)
}

/// Opens the input kept under `digest` with the holder's key `seed` names.
///
/// # Errors
///
/// Storage errors reading a kept row.
#[cfg(feature = "sync")]
#[doc(hidden)]
pub fn open_kept_numbered(
    vault: &Vault,
    digest: &[u8; 32],
    holder: EntityId,
    seed: u8,
) -> Result<KeptOpen> {
    match crate::secret_custody::open_kept_numbered_for_test(vault, digest, holder, seed)? {
        crate::secret_custody::KeptNumberedOpen::Missing => Ok(KeptOpen::Missing),
        crate::secret_custody::KeptNumberedOpen::Invalid => Ok(KeptOpen::Invalid),
        crate::secret_custody::KeptNumberedOpen::Opened(value, manifest, name) => {
            Ok(KeptOpen::Opened {
                value,
                manifest,
                name,
            })
        }
    }
}

/// Forgets part `index` of the input kept under `digest`. Returns whether
/// a row was kept there.
///
/// # Errors
///
/// Storage errors.
#[cfg(feature = "sync")]
#[doc(hidden)]
pub fn drop_kept_part(vault: &Vault, digest: &[u8; 32], index: u32) -> Result<bool> {
    crate::secret_custody::drop_kept_numbered_part_for_test(vault, digest, index)
}
