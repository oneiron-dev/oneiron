//! The `about` line a reader sees, with the CLAIM ids it stands on (FIX 3515).
//!
//! The text-only [`Vault::person_about`] stays the board's reader. This leaf
//! adds the sourced form its provenance callers need: the same selected line
//! together with the exact fact CLAIM ids that line was written from, never
//! the person's every CLAIM.

use super::{ABOUT_MAX_CHARS, PERSON_ABOUT};
use crate::{EntityId, Result, Vault};

impl Vault {
    /// `person`'s `about` line for a reader whose sensitivity ceiling is
    /// `ceiling`, with the CLAIM ids the line stands on: the line
    /// [`Vault::person_about`] shows, plus its facts. `None` reads no band,
    /// and a person whose facts moved since its lines were written shows
    /// none until the Dreamer writes them again. The text is clipped as the
    /// board prints it.
    pub fn person_about_sourced(
        &self,
        person: EntityId,
        ceiling: Option<u8>,
    ) -> Result<Option<(String, Vec<EntityId>)>> {
        let Some(ceiling) = ceiling else {
            return Ok(None);
        };
        let txn = self.store.env.read_txn()?;
        let Some(row) = PERSON_ABOUT.get(&self.store, &txn, &person)? else {
            return Ok(None);
        };
        if row.moved || row.asked != row.written {
            return Ok(None);
        }
        Ok(row
            .lines
            .iter()
            .rev()
            .find(|line| line.band <= ceiling)
            .map(|line| {
                (
                    line.text.chars().take(ABOUT_MAX_CHARS).collect(),
                    line.fact_claim_ids.clone(),
                )
            }))
    }
}
