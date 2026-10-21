//! The masked copy a reader gets of a marked retained repository blob (FIX
//! 7608 slice 2a). A read never plans, places or mints: the places come
//! from the blob's marks, the copy is rebuilt under the retained repository
//! read (no member, object, depth or byte bound, rule 5), and the rebuilt
//! copy is read again by the same release rules and custody automaton the
//! receive door's plan used. A copy that cannot be rebuilt, or that still
//! reads as secret, is no copy: the reader gets the opaque placeholder,
//! never these bytes and never a terminal refusal.

use zeroize::Zeroizing;

use super::super::super::container::{Stop, masked_retained_repo_copy};
use super::validate_retained_repo_copy;
use crate::secret_custody::KeyPlaces;

/// `bytes` with every span `places` names overwritten, members rebuilt and
/// re-encoded, once the copy reads clean; `None` when no such copy stands.
pub(crate) fn project_marked_retained_repo_blob(
    bytes: &[u8],
    places: &KeyPlaces,
) -> Option<Vec<u8>> {
    if places.is_empty() {
        return None;
    }
    let mut copy = match masked_retained_repo_copy(bytes, places) {
        Ok(copy) => Zeroizing::new(copy),
        Err(Stop::Refuse(_) | Stop::Fail(_)) => return None,
    };
    match validate_retained_repo_copy(&copy) {
        Ok(None) => Some(std::mem::take(&mut *copy)),
        Ok(Some(_)) | Err(_) => None,
    }
}
