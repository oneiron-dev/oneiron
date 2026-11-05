//! The `about` line a reader sees, with the CLAIM ids it stands on (FIX 3515).
//!
//! The text-only [`Vault::person_about`] stays the board's reader. This leaf
//! adds the sourced form its provenance callers need: the same selected line
//! together with the exact fact CLAIM ids that line was written from, never
//! the person's every CLAIM.

use super::{ABOUT_MAX_CHARS, AboutLine, PERSON_ABOUT, PersonAbout};
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
        Ok(
            current_line_in_txn(&self.store, &txn, &row, ceiling)?.map(|line| {
                (
                    line.text.chars().take(ABOUT_MAX_CHARS).collect(),
                    line.fact_claim_ids.clone(),
                )
            }),
        )
    }
}

pub(super) fn current_line_in_txn<'a>(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    row: &'a PersonAbout,
    ceiling: u8,
) -> Result<Option<&'a AboutLine>> {
    if row.moved || row.asked != row.written {
        return Ok(None);
    }
    let Some(line) = row.lines.iter().rev().find(|line| line.band <= ceiling) else {
        return Ok(None);
    };
    // Pending walks withdraw a fact before its batch reaches it.
    for claim in &line.fact_claim_ids {
        if crate::ports::stale_in_txn(store, txn, claim)? {
            return Ok(None);
        }
    }
    Ok(Some(line))
}
