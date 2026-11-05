//! The one native state register, shared by readers and native publication.

use loro::{LoroValue, ValueOrContainer};

use super::super::EntityDoc;
use super::codec::SkillStateFact;
use crate::error::{Error, Result};

pub(super) const ROOT: &str = "native_skill_state";
pub(super) const CURRENT: &str = "current";

/// Read only the supplied document; malformed native state is not absence.
/// This validates the codec, not its native source or carrier standing.
pub(super) fn read_fact(doc: &EntityDoc) -> Result<Option<SkillStateFact>> {
    let map = doc.doc.get_map(ROOT);
    let current = map.get(CURRENT);
    if map.len() != usize::from(current.is_some()) {
        return Err(Error::CorruptedIndex("native SKILL state register keys"));
    }
    match current {
        None => Ok(None),
        Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => {
            SkillStateFact::decode(bytes.as_ref()).map(Some)
        }
        Some(_) => Err(Error::CorruptedIndex("native SKILL state register")),
    }
}

/// Exact encoded bytes at this supplied version, including truthful absence
/// before its first native operation. This is not an admitted-source proof.
pub(super) fn current_witness_bytes(doc: &EntityDoc) -> Result<Option<Vec<u8>>> {
    read_fact(doc)?.map(|fact| fact.encode()).transpose()
}
