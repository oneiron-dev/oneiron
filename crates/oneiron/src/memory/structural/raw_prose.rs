//! Prose admission for a bound raw write's NOTE and keyed-value bodies
//! (OF-063, FIX 3734): the one link read their typed writers run, run on the
//! raw bytes through the caller's own [`Memory`], so a raw put earns the
//! same `unlinked` record a typed write of that text would.

use std::collections::HashSet;

use crate::gate::record_references::unlinked_prose_links;
use crate::memory::{Memory, MemoryResult};
use crate::receipt::ReferenceRefusalFacts;
use crate::vault::RawEntityPut;

/// The keyed value's text slot, as `key_value_put` reads it.
#[derive(serde::Serialize)]
struct KeyValueProse<'a> {
    value: &'a serde_json::Value,
}

impl Memory<'_> {
    /// The `unlinked` facts the body each id of `puts` lands with earns: a
    /// NOTE's markdown, a keyed value's nested value, read once. A body a
    /// later put of the same id replaces never lands and is not read. Any
    /// other body, and one these readers cannot decode, earns none: the
    /// batch's own validator judges its shape, as before.
    pub(crate) fn raw_put_prose(
        &self,
        puts: &[RawEntityPut<'_>],
    ) -> MemoryResult<Vec<ReferenceRefusalFacts>> {
        let mut landed = HashSet::new();
        let mut unlinked = Vec::new();
        for put in puts.iter().rev() {
            if landed.insert(put.id) {
                unlinked.extend(self.raw_body_prose(put)?);
            }
        }
        unlinked.reverse();
        Ok(unlinked)
    }

    fn raw_body_prose(&self, put: &RawEntityPut<'_>) -> MemoryResult<Vec<ReferenceRefusalFacts>> {
        match put.entity_type {
            crate::registry::ENTITY_TYPE_NOTE => match crate::note::decode_note_body(put.data) {
                Ok(note) => super::affiliated::note_prose_unlinked(self, &note.markdown),
                Err(_) => Ok(Vec::new()),
            },
            crate::registry::ENTITY_TYPE_CLAIM => {
                let value = crate::claim::decode_claim_body(put.data, true)
                    .ok()
                    .and_then(|body| super::super::key_value::key_value_text_of(&body));
                match value {
                    Some(value) => unlinked_prose_links(
                        self,
                        super::super::key_value::KEY_VALUE_PROSE_ROW,
                        &KeyValueProse { value: &value },
                        &["/value"],
                    ),
                    None => Ok(Vec::new()),
                }
            }
            _ => Ok(Vec::new()),
        }
    }
}
