//! Bounded pages of the open conflicts a reader may settle (untangle 6.9d
//! PR 1): each `conflict.open` marker still unanswered, with every member it
//! names and every retained alternative a Keep may land, whole.
//!
//! The owner reads under its proof and sees every open conflict. A live
//! Steward reader sees a conflict only when its marker and every member read
//! for it: a conflict with one unread member is absent whole, counted nowhere
//! and never named by a cursor. A conflict the owner holds, or one whose
//! settlement was reverted, is the owner's to answer, so no other reader sees
//! it. A retained alternative whose staged Keep the owner declined is the
//! owner's to keep again, so the page leaves it out, as the parked settlement
//! ask does.

use serde::{Deserialize, Serialize};

use super::strength_observations::{
    observation_reader_scope_for_actor_in_txn, observed_claim_reads_in_txn,
};
use crate::claim::{ClaimReadStatus, ScopedRead, ScopedReadResult, claim_surfaceable};
use crate::dreamer_consolidation::{OpenConflict, open_conflicts_in_txn, rmpv_to_json};
use crate::dreamer_runner::DreamerAttemptBinding;
use crate::federation::Scope;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{EntityId, Result, Vault, WriteActor};

/// The cursor prefix naming the last conflict a page served, by its marker.
const CONFLICTS_CURSOR_PREFIX: &str = "conflicts:";

/// The next page of open conflicts, bounded by the effective snapshot page
/// settings.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConflictsPageRequest {
    /// The preceding page's opaque cursor; absent on the first page.
    pub cursor: Option<String>,
    /// The most conflicts served, capped at the effective page row bound.
    pub limit: Option<u32>,
}

/// One page of open conflicts, oldest marker first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictsPage {
    pub conflicts: Vec<ObservedConflict>,
    /// The cursor after the last served conflict, set only when a later
    /// conflict reads for this caller.
    pub next: Option<String>,
}

/// One open conflict whose marker and members all read for this caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedConflict {
    pub marker: String,
    pub subject: String,
    /// The contested predicates, as the marker records them.
    pub predicates: Vec<String>,
    /// Every stored claim the marker names, in its own order.
    pub members: Vec<ConflictMember>,
    /// The candidates the marker's round dropped that a Keep may still land.
    pub alternatives: Vec<ConflictAlternative>,
    /// A settlement of this conflict was reverted: it waits for the owner.
    /// Only the owner's page serves such a conflict.
    pub reverted: bool,
    /// The conflict exceeds an otherwise empty page's byte bound, so every
    /// member and alternative value is served as null.
    pub values_omitted: bool,
}

/// One stored member as a settlement reads it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictMember {
    pub claim: String,
    /// Whether a Keep may name it: it still stands.
    pub keep: bool,
    pub predicate: String,
    pub value: serde_json::Value,
    pub source: Option<String>,
    pub approval: String,
    pub confidence: f32,
    pub valid_from: Option<u64>,
    pub valid_to: Option<u64>,
}

/// One retained alternative a Keep may land: no stored claim, named by the
/// selector the marker retains it under.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictAlternative {
    pub selector: String,
    pub predicate: String,
    pub value: serde_json::Value,
    pub source: String,
    pub confidence: f32,
}

/// Who reads the page: the proven owner, who answers every open conflict,
/// or a delegate reader within its record scope (`None` is the whole vault).
pub(crate) enum ConflictReader {
    Owner,
    Delegate(Option<Scope>),
}

/// Pages the open conflicts through the caller's live reach and scoped read.
///
/// As with snapshot pages, the byte bound counts encoded conflicts, not the
/// envelope. The open conflicts are listed whole in the page's read and the
/// page skips to its cursor. A conflict too large for an empty page alone is
/// served with its values omitted, so the reader can leave it parked.
///
/// # Errors
///
/// No owner proof or live Steward read grant, an invalid cursor, a byte
/// bound too small even for a conflict with its values omitted, and storage
/// failures.
pub fn conflicts_page(
    memory: &Memory<'_>,
    input: &ConflictsPageRequest,
) -> MemoryResult<ScopedReadResult<ConflictsPage>> {
    bound_conflicts_page(memory, input, None)
}

/// Reads the conflicts page after proving the binding in the page's own
/// read transaction, before any conflict row is read.
///
/// # Errors
///
/// As [`conflicts_page`], and the binding's refusals.
pub(crate) fn conflicts_page_bound(
    memory: &Memory<'_>,
    input: &ConflictsPageRequest,
    binding: &DreamerAttemptBinding,
) -> MemoryResult<ScopedReadResult<ConflictsPage>> {
    bound_conflicts_page(memory, input, Some(binding))
}

/// The shared page body, proving a bound call in its own read transaction.
fn bound_conflicts_page(
    memory: &Memory<'_>,
    input: &ConflictsPageRequest,
    binding: Option<&DreamerAttemptBinding>,
) -> MemoryResult<ScopedReadResult<ConflictsPage>> {
    let vault = memory.vault();
    let owner = memory
        .embedded_owner("vault.consolidation.conflicts.page")
        .ok();
    let bounds = vault.snapshot_read_settings()?;
    let limit = input
        .limit
        .unwrap_or(bounds.page_rows)
        .min(bounds.page_rows)
        .max(1);
    let after = conflict_cursor_key(input.cursor.as_deref())?;
    let read = memory.read_lane(ClaimReadStatus::Recorded)?;
    let _pins = read.prepare_point_read::<MemoryError>()?;
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    memory.prove_read_authority_in_txn(&txn)?;
    if let Some(binding) = binding {
        let _ = binding.check_in_txn(&txn);
    }
    let reader = conflict_reader_in_txn(memory, &txn, owner.as_ref())?;
    let actor = memory.write_actor();
    read.read_projected_in_txn(&txn, &[], None, |txn, _| {
        let mut page = ConflictsPage {
            conflicts: Vec::new(),
            next: None,
        };
        let open = open_conflicts_in_txn(vault, txn, None)?;
        let mut rows = open
            .into_iter()
            .filter(|conflict| after.is_none_or(|cursor| conflict.marker > cursor));
        let mut bytes = 0u64;
        let mut shown = after;
        while let Some(conflict) = rows.next() {
            if !conflict_served_in_txn(vault, txn, &read, &reader, actor, &conflict)? {
                continue;
            }
            let mut observed = observed_conflict_in_txn(vault, txn, &conflict)?;
            let mut size = encoded_len(&observed)?;
            if page.conflicts.is_empty() && size > bounds.page_bytes {
                observed.omit_values();
                size = encoded_len(&observed)?;
                if size > bounds.page_bytes {
                    return Err(MemoryError::bad_request(
                        "the snapshot page byte bound cannot hold the open conflict without its values",
                    ));
                }
            }
            if bytes.saturating_add(size) > bounds.page_bytes {
                page.next = shown.map(conflict_cursor);
                break;
            }
            bytes = bytes.saturating_add(size);
            page.conflicts.push(observed);
            shown = Some(conflict.marker);
            if page.conflicts.len() as u64 >= u64::from(limit) {
                let mut later = false;
                for later_conflict in rows.by_ref() {
                    if conflict_served_in_txn(vault, txn, &read, &reader, actor, &later_conflict)? {
                        later = true;
                        break;
                    }
                }
                page.next = later.then(|| conflict_cursor(conflict.marker));
                break;
            }
        }
        Ok(page)
    })
}

/// The reader the caller is: the owner under its proof, or a non-owner with
/// a live Steward read (or a base agent whose manifest rows still stand in
/// place of a grant).
pub(crate) fn conflict_reader_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    owner: Option<&crate::consent::AuthenticatedOwner>,
) -> MemoryResult<ConflictReader> {
    let vault = memory.vault();
    if let Some(owner) = owner {
        owner.revalidate_as_vault_owner_in_txn(vault, txn)?;
        return Ok(ConflictReader::Owner);
    }
    match observation_reader_scope_for_actor_in_txn(vault, txn, memory.actor())? {
        Some(scope) => Ok(ConflictReader::Delegate(scope)),
        None => Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "open conflicts read for the owner under its proof or a live Steward reader",
            &[],
        )),
    }
}

/// Whether the page serves `conflict` to `reader`: its marker and every
/// member read for the caller, and, for a delegate, no settlement of it was
/// reverted and the owner holds no review of its subject.
pub(crate) fn conflict_served_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    reader: &ConflictReader,
    actor: WriteActor,
    conflict: &OpenConflict,
) -> Result<bool> {
    let scope = match reader {
        ConflictReader::Owner => None,
        ConflictReader::Delegate(scope) => scope.as_ref(),
    };
    for id in std::iter::once(&conflict.marker).chain(&conflict.members) {
        if !observed_claim_reads_in_txn(vault, txn, read, scope, *id)? {
            return Ok(false);
        }
    }
    match reader {
        ConflictReader::Owner => Ok(true),
        ConflictReader::Delegate(_) => Ok(!conflict.reverted
            && crate::memory::conflict_review_held_in(vault, txn, actor, conflict.subject)?
                .is_none()),
    }
}

/// `conflict` as the page serves it: each stored member with the fields a
/// settlement ask shows, then each retained alternative the owner has not
/// declined, every value whole.
fn observed_conflict_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    conflict: &OpenConflict,
) -> Result<ObservedConflict> {
    let mut members = Vec::with_capacity(conflict.members.len());
    for id in &conflict.members {
        let Some(body) = vault.get_claim_in_txn(txn, id)? else {
            continue;
        };
        members.push(ConflictMember {
            claim: id.to_hex(),
            keep: claim_surfaceable(&body),
            value: rmpv_to_json(&body.value),
            source: body.source.map(|source| source.as_str().to_owned()),
            approval: body.approval.as_str().to_owned(),
            confidence: body.confidence,
            valid_from: body.valid_from,
            valid_to: body.valid_to,
            predicate: body.predicate,
        });
    }
    let alternatives = conflict
        .alternatives
        .iter()
        .filter(|alternative| alternative.declined.is_empty())
        .map(|alternative| ConflictAlternative {
            selector: alternative.id.to_hex(),
            predicate: alternative.predicate.clone(),
            value: rmpv_to_json(&alternative.value),
            source: alternative.source.as_str().to_owned(),
            confidence: alternative.confidence,
        })
        .collect();
    Ok(ObservedConflict {
        marker: conflict.marker.to_hex(),
        subject: conflict.subject.to_hex(),
        predicates: conflict.predicates.clone(),
        members,
        alternatives,
        reverted: conflict.reverted,
        values_omitted: false,
    })
}

impl ObservedConflict {
    /// Serves every member and alternative value as null, marking the
    /// conflict as one whose values the page could not hold.
    fn omit_values(&mut self) {
        for member in &mut self.members {
            member.value = serde_json::Value::Null;
        }
        for alternative in &mut self.alternatives {
            alternative.value = serde_json::Value::Null;
        }
        self.values_omitted = true;
    }
}

/// The encoded length a conflict counts against the page's byte bound.
fn encoded_len(conflict: &ObservedConflict) -> MemoryResult<u64> {
    Ok(serde_json::to_vec(conflict)
        .map_err(|error| MemoryError::bad_request(error.to_string()))?
        .len() as u64)
}

fn conflict_cursor(marker: EntityId) -> String {
    format!("{CONFLICTS_CURSOR_PREFIX}{}", marker.to_hex())
}

fn conflict_cursor_key(cursor: Option<&str>) -> MemoryResult<Option<EntityId>> {
    cursor
        .map(|cursor| {
            let hex = cursor
                .strip_prefix(CONFLICTS_CURSOR_PREFIX)
                .ok_or_else(|| MemoryError::bad_request("invalid open conflicts cursor"))?;
            EntityId::from_hex(hex)
                .map_err(|_| MemoryError::bad_request("invalid open conflicts cursor"))
        })
        .transpose()
}
