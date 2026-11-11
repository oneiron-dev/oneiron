//! The receipt reader: governance receipts read back through the public
//! `vault.receipts` verb, newest first, as the caller is allowed to see them.
//! A test asserts on these (Fable, section 4 rule 3: assert on what leaves
//! the door), never on a store row.

use oneiron::memory::{Memory, MemoryResult};
use serde_json::{Value, json};

use crate::door;

/// The page size the reader asks for.
const PAGE: usize = 100;

/// Reads receipts as one caller.
pub struct ReceiptReader<'m, 'v> {
    caller: &'m Memory<'v>,
}

impl std::fmt::Debug for ReceiptReader<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiptReader").finish_non_exhaustive()
    }
}

impl<'m, 'v> ReceiptReader<'m, 'v> {
    /// A reader for `caller` (often [`door::owner`]).
    #[must_use]
    pub fn new(caller: &'m Memory<'v>) -> Self {
        Self { caller }
    }

    /// One page of `vault.receipts`: the gate ledger when `kinds` is empty,
    /// else the receipts of those kinds; `after` is the previous page's
    /// `next_after`. The verb's whole answer.
    ///
    /// # Errors
    /// The verb refuses the caller or the input.
    pub fn page(&self, kinds: &[&str], limit: usize, after: Option<&str>) -> MemoryResult<Value> {
        let mut input = json!({"limit": limit});
        if !kinds.is_empty() {
            input["kinds"] = json!(kinds);
        }
        if let Some(after) = after {
            input["after"] = json!(after);
        }
        door::invoke(self.caller, "vault.receipts", input)
    }

    /// Every receipt the caller can see, newest first, following
    /// `next_after` to the end.
    ///
    /// # Errors
    /// As [`Self::page`].
    pub fn all(&self, kinds: &[&str]) -> MemoryResult<Vec<Value>> {
        let mut receipts = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let page = self.page(kinds, PAGE, after.as_deref())?;
            if let Some(rows) = page.get("receipts").and_then(Value::as_array) {
                receipts.extend(rows.iter().cloned());
            }
            match page.get("next_after").and_then(Value::as_str) {
                Some(next) if after.as_deref() != Some(next) => after = Some(next.to_owned()),
                _ => return Ok(receipts),
            }
        }
    }

    /// The newest receipt of `kinds` (the gate ledger's when empty), if any.
    ///
    /// # Errors
    /// As [`Self::page`].
    pub fn latest(&self, kinds: &[&str]) -> MemoryResult<Option<Value>> {
        let page = self.page(kinds, 1, None)?;
        Ok(page
            .get("receipts")
            .and_then(Value::as_array)
            .and_then(|rows| rows.first())
            .cloned())
    }
}
