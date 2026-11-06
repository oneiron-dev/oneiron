//! Equality of metadata maps owned only by the recapture comparison.

use std::collections::{BTreeMap, btree_map::IntoIter};

use crate::error::Result;

use super::compare_value;

#[derive(Default)]
pub(super) struct MetadataComparison {
    entries: Option<IntoIter<String, Vec<u8>>>,
    current: Option<(String, Vec<u8>)>,
    byte: usize,
}

impl MetadataComparison {
    pub(super) fn advance(
        &mut self,
        actual: &mut BTreeMap<String, Vec<u8>>,
        wanted: &BTreeMap<String, Vec<u8>>,
        remaining: &mut usize,
    ) -> Result<bool> {
        if self.entries.is_none() {
            compare_value(&actual.len(), &wanted.len())?;
            self.entries = Some(std::mem::take(actual).into_iter());
        }
        if self.current.is_none() {
            self.current = self
                .entries
                .as_mut()
                .expect("metadata comparison started")
                .next();
        }
        let Some((key, value)) = self.current.as_ref() else {
            self.entries = None;
            self.byte = 0;
            *remaining -= 1;
            return Ok(true);
        };
        // Reborrow once per entry/page; native key lookup remains whole.
        let expected = wanted.get(key);
        compare_value(&true, &expected.is_some())?;
        let expected = expected.expect("metadata key compared");
        compare_value(&value.len(), &expected.len())?;
        let count = (*remaining).min(value.len() - self.byte);
        let end = self.byte + count;
        let actual_chunk = &value[self.byte..end];
        let expected_chunk = &expected[self.byte..end];
        compare_value(&actual_chunk, &expected_chunk)?;
        self.byte = end;
        *remaining -= count.max(1);
        if end == value.len() {
            self.current = None;
            self.byte = 0;
        }
        Ok(false)
    }

    pub(super) fn advance_optional(
        &mut self,
        actual: &mut Option<BTreeMap<String, Vec<u8>>>,
        wanted: &Option<BTreeMap<String, Vec<u8>>>,
        remaining: &mut usize,
    ) -> Result<bool> {
        match (actual, wanted) {
            (Some(actual), Some(wanted)) => self.advance(actual, wanted, remaining),
            (None, None) => Ok(true),
            (actual, wanted) => {
                compare_value(&actual.is_some(), &wanted.is_some())?;
                Ok(false)
            }
        }
    }
}
