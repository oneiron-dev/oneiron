//! The re-check a kept provider delete owes the claims drawn from the
//! message (FIX 15414; owner MAIL-DELETE = A, 2026-11-03: "The message
//! leaves the live inbox and stays as a labelled source-deleted copy; the
//! claims drawn from it are checked again").
//!
//! The writer that marks a copy source-deleted moves the message's presence
//! generation on, records the re-check it owes and queues the Dreamer's job
//! that judges each claim (`dreamer.claim_source_recheck`), all in that one
//! write. The row names ids only: the message's TURN and MESSAGE revisions
//! and each claim a check settled, never a word of the message. A restore,
//! a later delete or an erase of the message makes a re-check still waiting
//! moot: it settles changing nothing. A claim born later from the kept copy
//! reopens the re-check of the generation the copy stands at
//! ([`owe_claim_recheck_for_cited_in_txn`]). The source's sync status counts
//! its re-checks by where they stand, to the source's own readers.
//!
//! An erased TURN, MESSAGE revision or claim leaves every re-check that
//! names it, whatever it stands at ([`erase_claim_recheck_ids_in_txn`]), and
//! a held rung the owner approves applies only while the re-check that held
//! it is still current ([`claim_recheck_current_in`]).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::state::{MailOccurrence, MailPresence, OCCURRENCES, occurrence_keys_of_row_in};
use crate::dreamer_runner::maintenance::claim_source_recheck::{
    ClaimSourceRecheckDeclaration, queue_claim_source_recheck_in_txn,
};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// The re-checks each source owes, by the source, the BLAKE3 of the
/// provider's id and the presence generation the delete moved the message
/// to.
const RECHECKS: SideTable<(EntityId, [u8; 32], u64), MailClaimRecheck, Named> =
    SideTable::new(&side_table::MAIL_PACK_CLAIM_RECHECK);

/// Each id a re-check names, so an erase of it reaches every re-check that
/// names it: by the id, the source with the BLAKE3 of the provider's id,
/// and the presence generation. The value is when the re-check was owed.
const NAMED: SideTable<(EntityId, (EntityId, [u8; 32]), u64), u64, Named> =
    SideTable::new(&side_table::MAIL_PACK_CLAIM_RECHECK_NAMED);

/// Where one re-check stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MailClaimRecheckState {
    /// Its job has not judged every claim yet.
    Pending,
    /// Every claim it found was judged: each stands, or the Dreamer moved it.
    Checked,
    /// Every claim was judged, and a check waits for the owner's review.
    ReviewNeeded,
    /// A restore, a later delete or an erase of the message made it moot.
    Obsolete,
}

/// One re-check a kept provider delete owes: ids only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MailClaimRecheck {
    /// The message's TURN; `None` once it is erased.
    turn: Option<EntityId>,
    /// Each revision's MESSAGE, oldest first, as the delete found them, less
    /// each one erased.
    messages: Vec<EntityId>,
    /// Moved on each time a claim born later reopens it; only the job of
    /// the latest round settles it.
    round: u64,
    state: MailClaimRecheckState,
    /// Each claim a check of this generation settled, and a weakening's
    /// successor: none is judged again.
    settled: Vec<EntityId>,
    /// How many claims the Dreamer moved down their ladder.
    changed: u64,
    /// How many checks wait for the owner's review.
    review: u64,
    owed_at: u64,
    settled_at: Option<u64>,
}

impl MailClaimRecheck {
    /// Every id the row names: its TURN, its MESSAGE revisions and each
    /// claim it settled.
    fn named(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.turn
            .iter()
            .chain(&self.messages)
            .chain(&self.settled)
            .copied()
    }

    /// The row without `id`, wherever it names it.
    fn scrub(&mut self, id: &EntityId) {
        if self.turn == Some(*id) {
            self.turn = None;
        }
        self.messages.retain(|message| message != id);
        self.settled.retain(|claim| claim != id);
    }
}

/// What one claim's check did, as the re-check counts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MailClaimRecheckOutcome {
    /// The claim stands as it stood, or moved since it was read.
    Unchanged,
    /// The Dreamer moved it one rung down its demotion ladder.
    Changed,
    /// Its check waits for the owner's review.
    ReviewNeeded,
}

/// A re-check still owed, as its job reads it.
pub(crate) struct MailClaimRecheckOwed {
    /// When the provider deleted the message.
    pub(crate) deleted_at: u64,
    /// The claims an earlier check of this generation settled.
    pub(crate) settled: Vec<EntityId>,
}

/// A source's re-checks by where they stand.
pub(super) struct MailClaimRecheckCounts {
    pub(super) pending: u64,
    pub(super) checked: u64,
    pub(super) review_needed: u64,
    pub(super) obsolete: u64,
}

/// Records the re-check the kept delete of the message keyed `key` owes,
/// at the generation `occurrence` now stands at, and queues its job, in the
/// delete's own write.
pub(super) fn owe_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &(EntityId, [u8; 32]),
    occurrence: &MailOccurrence,
    at: u64,
) -> Result<()> {
    let row = owed_row(occurrence, at);
    owe_round_in_txn(vault, txn, key, occurrence, &row, at)
}

/// A fresh re-check of `occurrence`'s rows.
fn owed_row(occurrence: &MailOccurrence, at: u64) -> MailClaimRecheck {
    MailClaimRecheck {
        turn: Some(occurrence.turn),
        messages: occurrence.messages.clone(),
        round: 0,
        state: MailClaimRecheckState::Pending,
        settled: Vec::new(),
        changed: 0,
        review: 0,
        owed_at: at,
        settled_at: None,
    }
}

/// Stores `row` for the generation `occurrence` stands at and queues the
/// job of its round, which names the message's TURN and MESSAGE revisions.
fn owe_round_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &(EntityId, [u8; 32]),
    occurrence: &MailOccurrence,
    row: &MailClaimRecheck,
    at: u64,
) -> Result<()> {
    let generation = occurrence.presence_generation;
    put_named_in_txn(&vault.store, txn, &(key.0, key.1, generation), row)?;
    queue_claim_source_recheck_in_txn(
        vault,
        txn,
        &ClaimSourceRecheckDeclaration {
            source: key.0,
            occurrence: key.1,
            generation,
            round: row.round,
            turn: occurrence.turn,
            messages: occurrence.messages.clone(),
        },
        at,
    )
}

/// Stores `row` under `key` with each id it names, so an erase of any of
/// them reaches it. Only a writer that adds an id needs it.
fn put_named_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    key: &(EntityId, [u8; 32], u64),
    row: &MailClaimRecheck,
) -> Result<()> {
    RECHECKS.put(store, txn, key, row)?;
    for id in row.named() {
        NAMED.put(store, txn, &(id, (key.0, key.1), key.2), &row.owed_at)?;
    }
    Ok(())
}

/// The late-birth seam (FIX 15414): owes, in the caller's write, the
/// re-check of each message deleted at the provider and kept whose TURN or
/// MESSAGE revision `cited` names, at the generation its copy stands at, so
/// a claim drawn from a kept copy after its delete is checked as the claims
/// drawn before it were. A re-check of that generation reopens for a new
/// round: the claims it settled stay settled, and its job judges the rest.
/// A row of a message the provider still holds, or one forgotten, owes
/// nothing.
pub(crate) fn owe_claim_recheck_for_cited_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    cited: &[EntityId],
) -> Result<()> {
    let at = crate::unix_seconds_now();
    let mut owed = BTreeSet::new();
    for id in cited {
        for key in occurrence_keys_of_row_in(&vault.store, txn, id)? {
            let Some(occurrence) = OCCURRENCES.get(&vault.store, txn, &key)? else {
                continue;
            };
            if !matches!(occurrence.presence, MailPresence::SourceDeleted { .. })
                || (occurrence.turn != *id && !occurrence.messages.contains(id))
                || !owed.insert(key)
            {
                continue;
            }
            let generation = occurrence.presence_generation;
            let row = match RECHECKS.get(&vault.store, txn, &(key.0, key.1, generation))? {
                Some(mut row) => {
                    row.round += 1;
                    row.state = MailClaimRecheckState::Pending;
                    row.settled_at = None;
                    row
                }
                None => owed_row(&occurrence, at),
            };
            owe_round_in_txn(vault, txn, &key, &occurrence, &row, at)?;
        }
    }
    Ok(())
}

/// The re-check of the message keyed `(source, occurrence)` at
/// `generation`, while it is still owed: waiting, and the message still
/// the source-deleted copy at that generation. `None` once it is settled
/// or moot.
pub(crate) fn claim_recheck_owed_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
    occurrence: [u8; 32],
    generation: u64,
) -> Result<Option<MailClaimRecheckOwed>> {
    let Some(row) = RECHECKS.get(&vault.store, txn, &(source, occurrence, generation))? else {
        return Ok(None);
    };
    if row.state != MailClaimRecheckState::Pending {
        return Ok(None);
    }
    let Some(current) = OCCURRENCES.get(&vault.store, txn, &(source, occurrence))? else {
        return Ok(None);
    };
    let MailPresence::SourceDeleted { at } = current.presence else {
        return Ok(None);
    };
    if current.presence_generation != generation {
        return Ok(None);
    }
    Ok(Some(MailClaimRecheckOwed {
        deleted_at: at,
        settled: row.settled,
    }))
}

/// Marks `claims` settled by `declaration`'s generation, in the write that
/// lands their check, and counts `outcome` once. A claim erased meanwhile
/// is never named again. False, writing nothing, when the re-check is no
/// longer owed.
pub(crate) fn record_claims_rechecked_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    declaration: &ClaimSourceRecheckDeclaration,
    claims: &[EntityId],
    outcome: MailClaimRecheckOutcome,
) -> Result<bool> {
    if claim_recheck_owed_in(
        vault,
        txn,
        declaration.source,
        declaration.occurrence,
        declaration.generation,
    )?
    .is_none()
    {
        return Ok(false);
    }
    let key = (
        declaration.source,
        declaration.occurrence,
        declaration.generation,
    );
    let Some(mut row) = RECHECKS.get(&vault.store, txn, &key)? else {
        return Ok(false);
    };
    let counted = claims
        .first()
        .is_some_and(|claim| row.settled.contains(claim));
    for claim in claims {
        if !row.settled.contains(claim)
            && matches!(
                crate::vault::live_entity_row_in_txn(&vault.store, txn, claim)?,
                crate::vault::LiveEntityRow::Live { .. }
            )
        {
            row.settled.push(*claim);
        }
    }
    if !counted {
        match outcome {
            MailClaimRecheckOutcome::Unchanged => {}
            MailClaimRecheckOutcome::Changed => row.changed += 1,
            MailClaimRecheckOutcome::ReviewNeeded => row.review += 1,
        }
    }
    put_named_in_txn(&vault.store, txn, &key, &row)?;
    Ok(true)
}

/// Settles `declaration`'s re-check once its job judged every claim it
/// found: review-needed while a check waits for the owner, else checked;
/// obsolete when moot. A later round leaves it waiting for that round's
/// job; one already settled stays as it is.
pub(crate) fn settle_claim_recheck_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    declaration: &ClaimSourceRecheckDeclaration,
    at: u64,
) -> Result<()> {
    let key = (
        declaration.source,
        declaration.occurrence,
        declaration.generation,
    );
    let Some(mut row) = RECHECKS.get(&vault.store, txn, &key)? else {
        return Ok(());
    };
    if row.state != MailClaimRecheckState::Pending {
        return Ok(());
    }
    if claim_recheck_owed_in(
        vault,
        txn,
        declaration.source,
        declaration.occurrence,
        declaration.generation,
    )?
    .is_none()
    {
        row.state = MailClaimRecheckState::Obsolete;
    } else if row.round != declaration.round {
        return Ok(());
    } else if row.review > 0 {
        row.state = MailClaimRecheckState::ReviewNeeded;
    } else {
        row.state = MailClaimRecheckState::Checked;
    }
    row.settled_at = Some(at);
    RECHECKS.put(&vault.store, txn, &key, &row)
}

/// Makes each re-check the message keyed `key` still owes moot, in the
/// write of its restore or its erase: its job settles changing nothing.
pub(super) fn obsolete_rechecks_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    key: &(EntityId, [u8; 32]),
    at: u64,
) -> Result<()> {
    let prefix = [key.0.as_bytes().as_slice(), key.1.as_slice()].concat();
    for (row_key, mut row) in RECHECKS.scan_from(store, txn, &prefix)? {
        if row.state == MailClaimRecheckState::Pending {
            row.state = MailClaimRecheckState::Obsolete;
            row.settled_at = Some(at);
            RECHECKS.put(store, txn, &row_key, &row)?;
        }
    }
    Ok(())
}

/// Whether the re-check a held finding's `recheck` names is still current
/// in the caller's write, for the door that applies the finding once the
/// owner approves it: the message still the source-deleted copy at that
/// generation, its TURN and each MESSAGE revision kept. False once a
/// restore, a later delete, a forget or an erase overtook it, and for a
/// `recheck` that does not read; true for a finding no re-check held.
pub(crate) fn claim_recheck_current_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    recheck: Option<&serde_json::Value>,
) -> Result<bool> {
    let Some(recheck) = recheck else {
        return Ok(true);
    };
    let named = || -> Option<(EntityId, [u8; 32], u64)> {
        let source = EntityId::from_hex(recheck.get("mail_source")?.as_str()?).ok()?;
        let occurrence = blake3::Hash::from_hex(recheck.get("occurrence")?.as_str()?).ok()?;
        let generation = recheck.get("generation")?.as_u64()?;
        Some((source, *occurrence.as_bytes(), generation))
    };
    let Some((source, occurrence, generation)) = named() else {
        return Ok(false);
    };
    let Some(current) = OCCURRENCES.get(&vault.store, txn, &(source, occurrence))? else {
        return Ok(false);
    };
    if !matches!(current.presence, MailPresence::SourceDeleted { .. })
        || current.presence_generation != generation
    {
        return Ok(false);
    }
    for row in std::iter::once(&current.turn).chain(&current.messages) {
        if !matches!(
            crate::vault::live_entity_row_in_txn(&vault.store, txn, row)?,
            crate::vault::LiveEntityRow::Live { .. }
        ) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The entity eraser (deletion/derived_rows.rs, FIX 15414): an erased TURN,
/// MESSAGE revision or claim leaves every re-check that names it, whatever
/// it stands at, and a re-check left naming nothing goes. A re-check still
/// owed settles changing nothing and never names the erased id again: its
/// message's erase made it moot, and an erased claim is found by no check.
/// A no-op for an id no re-check names.
pub(crate) fn erase_claim_recheck_ids_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    for named in NAMED.scan_keys(store, txn, id.as_bytes())? {
        NAMED.delete(store, txn, &named)?;
        let (_, (source, occurrence), generation) = named;
        let key = (source, occurrence, generation);
        let Some(mut row) = RECHECKS.get(store, txn, &key)? else {
            continue;
        };
        row.scrub(id);
        if row.named().next().is_none() {
            RECHECKS.delete(store, txn, &key)?;
        } else {
            RECHECKS.put(store, txn, &key, &row)?;
        }
    }
    Ok(())
}

/// How the provider holds the message `row` landed as, for a judge reading
/// a claim's supports: `present`, `source_deleted` or `forgotten`. `None`
/// for a row that is no imported message's TURN or MESSAGE revision.
pub(crate) fn presence_of_row_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &EntityId,
) -> Result<Option<&'static str>> {
    for key in occurrence_keys_of_row_in(&vault.store, txn, row)? {
        let Some(occurrence) = OCCURRENCES.get(&vault.store, txn, &key)? else {
            continue;
        };
        if occurrence.turn != *row && !occurrence.messages.contains(row) {
            continue;
        }
        return Ok(Some(match occurrence.presence {
            MailPresence::Present => "present",
            MailPresence::SourceDeleted { .. } => "source_deleted",
            MailPresence::Forgotten { .. } => "forgotten",
        }));
    }
    Ok(None)
}

/// `source`'s re-checks by where they stand, for its sync status: the
/// status door reads them to the source's own readers alone.
pub(super) fn counts_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
) -> Result<MailClaimRecheckCounts> {
    let mut counts = MailClaimRecheckCounts {
        pending: 0,
        checked: 0,
        review_needed: 0,
        obsolete: 0,
    };
    for row in RECHECKS.iter_from(&vault.store, txn, source.as_bytes())? {
        let (_, row) = row?;
        let count = match row.state {
            MailClaimRecheckState::Pending => &mut counts.pending,
            MailClaimRecheckState::Checked => &mut counts.checked,
            MailClaimRecheckState::ReviewNeeded => &mut counts.review_needed,
            MailClaimRecheckState::Obsolete => &mut counts.obsolete,
        };
        *count += 1;
    }
    Ok(counts)
}
