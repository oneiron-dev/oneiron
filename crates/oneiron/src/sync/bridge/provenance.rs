//! Commit-bound identity for LMDB-to-Loro entity mirrors.
//! One window commit can mirror many entities; a scalar origin cannot name it.

use std::collections::BTreeMap;

use crate::vault::RevisionRef;
use crate::{EntityId, Error, Result};

use super::BRIDGE_ORIGIN;

/// A committed original or the exact source revision of a mirrored carrier.
/// A mirror without a source is an independent, foreign local contribution.
#[derive(Clone, Debug)]
pub enum RevisionEvent {
    Original(crate::vault::EntityRevisionChange),
    Mirror {
        entity: EntityId,
        source_revision: Option<RevisionRef>,
    },
}

const PREFIX: &str = "bridge:v1:";
// entities_in_learned_range caps a pass at 100,000; cap the origin too.
const MAX_ORIGIN_BYTES: usize = 8 * 1024 * 1024;

pub(in crate::sync) fn origin_for_mirrors(
    sources: &BTreeMap<EntityId, RevisionRef>,
) -> Result<String> {
    if sources.is_empty() {
        return Ok(BRIDGE_ORIGIN.to_owned());
    }
    let mut origin = String::with_capacity(PREFIX.len() + sources.len().saturating_mul(64));
    origin.push_str(PREFIX);
    for (id, revision) in sources {
        origin.push_str(&id.to_hex());
        origin.push_str(&revision.to_hex());
        if origin.len() > MAX_ORIGIN_BYTES {
            return Err(Error::InvariantViolation(
                "bridge source manifest exceeds bound",
            ));
        }
    }
    Ok(origin)
}

/// `None` means a legacy bridge commit without a source identity; fail foreign.
pub(super) fn mirror_sources(origin: &str) -> Option<BTreeMap<EntityId, RevisionRef>> {
    let raw = origin.strip_prefix(PREFIX)?;
    if origin.len() > MAX_ORIGIN_BYTES || raw.is_empty() || raw.len() % 64 != 0 {
        return None;
    }
    let mut sources = BTreeMap::new();
    for pair in raw.as_bytes().chunks_exact(64) {
        let id = EntityId::from_hex(std::str::from_utf8(&pair[..32]).ok()?).ok()?;
        let revision = RevisionRef::from_hex(std::str::from_utf8(&pair[32..]).ok()?).ok()?;
        if sources.insert(id, revision).is_some() {
            return None;
        }
    }
    Some(sources)
}

pub(super) fn is_bridge(origin: &str) -> bool {
    origin == BRIDGE_ORIGIN || mirror_sources(origin).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multi_entity_manifest_is_exact_and_rejects_duplicates() {
        let id = EntityId::from_bytes([0xAA; 16]).unwrap();
        let sources = [(id, RevisionRef([0xBB; 16]))].into();
        let encoded = origin_for_mirrors(&sources).unwrap();
        assert_eq!(mirror_sources(&encoded), Some(sources));
        assert!(mirror_sources(&(encoded.clone() + &encoded[PREFIX.len()..])).is_none());
        assert!(mirror_sources(BRIDGE_ORIGIN).is_none());
    }
}
