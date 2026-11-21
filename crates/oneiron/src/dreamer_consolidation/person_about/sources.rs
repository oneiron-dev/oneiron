//! The `about` line a reader sees, with the CLAIM ids it stands on (FIX 3515).
//!
//! The text-only [`Vault::person_about`] stays the board's reader. This leaf
//! adds the sourced form its provenance callers need: the same selected line
//! together with the exact fact CLAIM ids that line was written from, never
//! the person's every CLAIM.

use super::super::turn_text::{dreamer_read, snapshot};
use super::{ABOUT_MAX_CHARS, AboutLine, PERSON_ABOUT, PersonAbout};
use crate::{EntityId, Result, Vault};

/// The `about` line a reader at one sensitivity ceiling sees
/// ([`Vault::person_about_line_in`]).
pub(crate) struct ShownAboutLine {
    /// The band the line was written for.
    pub(crate) band: u8,
    /// The line, clipped as the board prints it.
    pub(crate) text: String,
    /// The CLAIM ids the line stands on.
    pub(crate) fact_claim_ids: Vec<EntityId>,
}

impl Vault {
    /// `person`'s `about` line for a reader whose sensitivity ceiling is
    /// `ceiling`, with the CLAIM ids the line stands on: the line
    /// [`Vault::person_about`] shows, plus its facts. `None` reads no band,
    /// and a person whose facts moved since its lines were written, or one of
    /// whose facts the Dreamer no longer reads, shows none until the Dreamer
    /// writes them again. The text is clipped as the board prints it.
    pub fn person_about_sourced(
        &self,
        person: EntityId,
        ceiling: Option<u8>,
    ) -> Result<Option<(String, Vec<EntityId>)>> {
        let Some(ceiling) = ceiling else {
            return Ok(None);
        };
        let txn = snapshot(self)?;
        Ok(self
            .person_about_line_in(&txn, person, ceiling)?
            .map(|line| (line.text, line.fact_claim_ids)))
    }

    /// A snapshot to read `about` lines in
    /// ([`Vault::person_about_line_in`]): the grant clock persisted first, so
    /// a grant's expiry is judged at a real floor.
    ///
    /// # Errors
    /// The grant clock's or the snapshot's.
    pub(crate) fn person_about_snapshot(&self) -> Result<heed::RoTxn<'_>> {
        snapshot(self)
    }

    /// [`Vault::person_about_sourced`] at the ceiling `ceiling`, read in
    /// `txn` ([`Vault::person_about_snapshot`]), with the line's band: the
    /// line of the highest band at or below `ceiling`, shown under the same
    /// freshness rules, or none.
    ///
    /// # Errors
    /// A store or decode failure reading the stored lines or their facts.
    pub(crate) fn person_about_line_in(
        &self,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
        ceiling: u8,
    ) -> Result<Option<ShownAboutLine>> {
        let Some(row) = PERSON_ABOUT.get(&self.store, txn, &person)? else {
            return Ok(None);
        };
        Ok(
            current_line_in_txn(self, txn, &row, ceiling)?.map(|line| ShownAboutLine {
                band: line.band,
                text: line.text.chars().take(ABOUT_MAX_CHARS).collect(),
                fact_claim_ids: line.fact_claim_ids.clone(),
            }),
        )
    }

    /// Every `about` line stored for `person`, read in `txn`
    /// ([`Vault::person_about_snapshot`]): each band's current line and each
    /// line the Dreamer's newest landing replaced, whatever their freshness.
    /// These are the lines a brief staged before now may show, which a
    /// recheck of the held brief judges again
    /// ([`crate::claim::ScopedRead::fallen_own_floor_about_facts`]).
    ///
    /// # Errors
    /// A store or decode failure reading the stored row.
    pub(crate) fn person_about_stored_lines_in(
        &self,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
    ) -> Result<Vec<ShownAboutLine>> {
        let Some(row) = PERSON_ABOUT.get(&self.store, txn, &person)? else {
            return Ok(Vec::new());
        };
        let previous = row.previous.iter().flat_map(|prior| &prior.lines);
        Ok(row
            .lines
            .iter()
            .chain(previous)
            .map(|line| ShownAboutLine {
                band: line.band,
                text: line.text.chars().take(ABOUT_MAX_CHARS).collect(),
                fact_claim_ids: line.fact_claim_ids.clone(),
            })
            .collect())
    }
}

/// The public band: a line of it is written from public facts only.
const PUBLIC_BAND: u8 = 0;

/// `person`'s public `about` line as `txn` reads it: the band-0 line a public
/// reader sees now ([`current_line_in_txn`]), clipped as the board prints it.
/// `None` for a person with no public line, or one whose line is hidden.
///
/// What a PERSON embeds (ruling PERSON-VECTOR-CHOICES, D1): one point read of
/// the person's `about` row, never a walk of its claims (FIX 8660), and only
/// band 0. A vector carries no band, so one built from a higher band's line
/// would rank candidates for a reader below that band (ARCH-0067).
///
/// Every embedding door reads the line here, in its own write, so an
/// ordinary refusal is no line, never an error that fails the door: a
/// deleted person shows none, and nor does any person while the Dreamer's
/// Steward grant or MACHINE binding no longer stands, since its reader then
/// reads nothing ([`crate::Vault::system_agent_reads_live_in`]). A failed
/// read is still an error.
pub(crate) fn public_about_line_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: &EntityId,
) -> Result<Option<String>> {
    if crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, txn, person)?.deleted {
        return Ok(None);
    }
    let Some(row) = PERSON_ABOUT.get(&vault.store, txn, person)? else {
        return Ok(None);
    };
    if !dreamer_read(vault)?.proof_live_in(txn)? {
        return Ok(None);
    }
    Ok(current_line_in_txn(vault, txn, &row, PUBLIC_BAND)?
        .map(|line| line.text.chars().take(ABOUT_MAX_CHARS).collect()))
}

/// The line of `row` a reader at `ceiling` sees, read in `txn`, a grant-clock
/// snapshot (`turn_text::snapshot`), so a grant's expiry is judged at a real floor.
pub(super) fn current_line_in_txn<'a>(
    vault: &Vault,
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
        if crate::ports::stale_in_txn(&vault.store, txn, claim)? {
            return Ok(None);
        }
    }
    // A change that narrowed what the Dreamer reads (a facet, audience,
    // grant or policy change) hides a line standing on a fact its lane no
    // longer reads, until a wake pass writes from the facts left (FIX 12251).
    let readable = dreamer_read(vault)?.get_entities_parts_in_txn(txn, &line.fact_claim_ids)?;
    if readable.iter().any(Option::is_none) {
        return Ok(None);
    }
    Ok(Some(line))
}
