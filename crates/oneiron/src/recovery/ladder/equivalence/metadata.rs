//! Equality of metadata maps owned only by the recapture comparison.

use std::collections::{BTreeMap, btree_map::IntoIter};

use crate::error::Result;

use super::compare_value;

#[derive(Default)]
pub(super) struct MetadataComparison {
    entries: Option<IntoIter<String, Vec<u8>>>,
}

impl MetadataComparison {
    pub(super) fn advance(
        &mut self,
        actual: &mut BTreeMap<String, Vec<u8>>,
        wanted: &BTreeMap<String, Vec<u8>>,
    ) -> Result<bool> {
        if self.entries.is_none() {
            compare_value(&actual.len(), &wanted.len())?;
            self.entries = Some(std::mem::take(actual).into_iter());
        }
        let entries = self.entries.as_mut().expect("metadata comparison started");
        let Some((key, value)) = entries.next() else {
            self.entries = None;
            return Ok(true);
        };
        // One entry per turn; key lookup and value equality remain whole.
        compare_value(&Some(&value), &wanted.get(&key))?;
        Ok(false)
    }

    pub(super) fn advance_optional(
        &mut self,
        actual: &mut Option<BTreeMap<String, Vec<u8>>>,
        wanted: &Option<BTreeMap<String, Vec<u8>>>,
    ) -> Result<bool> {
        match (actual, wanted) {
            (Some(actual), Some(wanted)) => self.advance(actual, wanted),
            (None, None) => Ok(true),
            (actual, wanted) => {
                compare_value(&actual.is_some(), &wanted.is_some())?;
                Ok(false)
            }
        }
    }
}
