//! The staged content of a foreign artifact: every part its admission lands,
//! each with the window it imports into (FIX 3663).
//! The entry point is `StagedParts`.
//! Owned by `super`.
//!
//! A guest's update lands in more than one window once its CLAIMs move to
//! their foreign WORLD copies (`Routes`, FIX 3497): its base CLAIMs to the
//! month windows of the sender's base copy, a WORLD window whole to that
//! world's foreign window. A staged artifact keeps all of them under its one
//! receipt, which binds their bytes by its admitted digest, and its
//! confirmation imports each part into its own window, the update's own
//! first. An unrouted stage keeps one part, in the receipt's window.
//!
//! Encoding: the domain tag, then per part its window key's length (u64 BE),
//! the key, its bytes' length (u64 BE) and the bytes. One encoding per value:
//! a record that does not read back whole, holds no part or names a key that
//! does not parse is refused.

use crate::error::{Error, Result};
use crate::sync::types::WindowKey;

use super::state::AdmittedUpdate;

/// The domain tag every staged content record opens with.
#[cfg(feature = "sync")]
const STAGED_PARTS_DOMAIN: &[u8] = b"oneiron.federation.staged-parts.v1";

/// The parts a staged artifact imports, in import order.
#[cfg(feature = "sync")]
pub(crate) struct StagedParts(Vec<(WindowKey, Vec<u8>)>);

#[cfg(feature = "sync")]
impl StagedParts {
    /// The staged parts `content`, a record [`AdmittedUpdate::into_staged`]
    /// wrote.
    ///
    /// # Errors
    ///
    /// A record that does not read back whole.
    pub(crate) fn decode(content: &[u8]) -> Result<Self> {
        let refused = || Error::CorruptedIndex("staged import parts");
        let mut rest = content
            .strip_prefix(STAGED_PARTS_DOMAIN)
            .ok_or_else(refused)?;
        let mut parts = Vec::new();
        while !rest.is_empty() {
            let (key, after) = split_field(rest).ok_or_else(refused)?;
            let (bytes, after) = split_field(after).ok_or_else(refused)?;
            let key = std::str::from_utf8(key)
                .ok()
                .and_then(WindowKey::try_new)
                .ok_or_else(refused)?;
            parts.push((key, bytes.to_vec()));
            rest = after;
        }
        if parts.is_empty() {
            return Err(refused());
        }
        Ok(Self(parts))
    }

    /// Each part's window and bytes, in import order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&WindowKey, &[u8])> {
        self.0.iter().map(|(key, bytes)| (key, bytes.as_slice()))
    }
}

/// One length-prefixed field of a staged record, and what follows it.
#[cfg(feature = "sync")]
fn split_field(record: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = record.split_first_chunk::<8>()?;
    rest.split_at_checked(usize::try_from(u64::from_be_bytes(*len)).ok()?)
}

#[cfg(feature = "sync")]
impl AdmittedUpdate {
    /// The length of [`Self::into_staged`]'s record.
    pub(crate) fn staged_len(&self) -> usize {
        self.parts().fold(STAGED_PARTS_DOMAIN.len(), |len, part| {
            len + 16 + part.key().as_str().len() + part.bytes().len()
        })
    }

    /// The staged content of this update: every part with the window it
    /// imports into ([`StagedParts`]).
    pub(crate) fn into_staged(self) -> Vec<u8> {
        let mut record = Vec::with_capacity(self.staged_len());
        record.extend_from_slice(STAGED_PARTS_DOMAIN);
        for part in self.parts() {
            for field in [part.key().as_str().as_bytes(), part.bytes()] {
                record.extend_from_slice(&(field.len() as u64).to_be_bytes());
                record.extend_from_slice(field);
            }
        }
        record
    }
}
