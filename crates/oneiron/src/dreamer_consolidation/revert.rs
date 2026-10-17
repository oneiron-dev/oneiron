//! The owner's revert of any one Dreamer change (OF-023, owner ruling 10-18:
//! "autoapply + revert rather than holdout"). The Dreamer applies its work
//! at once and keeps the old state as history; the owner takes a change back
//! by its id (`Memory::revert_dreamer_change`), with one Gate receipt.
//!
//! - A CLAIM the Dreamer wrote (a promotion, a merged replacement, a nightly
//!   same-as, conflict or arc output) is retracted. Each claim it superseded
//!   stands again, as a settlement revert stands its members; the answers it
//!   gave the markers its correction closed, and its supersession record,
//!   are retracted with it, so those markers are open again for the owner.
//!   A settlement's `conflict.resolved` answer reverts as its settlement.
//! - An evidence attachment, the `edge.provenance` record the Dreamer wrote
//!   on a support edge, is retracted through the provenance retract, which
//!   re-stamps the edge from the records still live on it. The edge stays,
//!   as a retracted edge does.
//! - A SUMMARY the Dreamer wrote is archived, its scope's projection goes
//!   back to the summary it replaced, and the `merge.summary` header that
//!   landed it is retracted.
//! - A NOTE the Dreamer wrote, a TASK realization's answer, is archived. The
//!   TASK it completed stays done: a TASK never reopens.
//! - A PERSON's `about` lines go back to the lines the Dreamer's newest
//!   landing replaced.
//!
//! Nothing is deleted: a retracted claim and every closed row stay as
//! history, and an archived SUMMARY or NOTE comes back through the owner's
//! cleanup restore.

use super::person_about::{revert_person_about_in_txn, revertible_person_abouts_in_txn};
use super::settle::{
    MemberRestore, RevertSurface, marker_ids, restore_member_in_txn, revert_settlement_in_txn,
    string_at,
};
use super::support::invalid_consolidation;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, PREDICATE_CONFLICT_RESOLVED,
};
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead, TombstoneStoreRead};
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_NOTE, ENTITY_TYPE_PERSON, ENTITY_TYPE_SUMMARY,
};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// The most timeline rows one list of the Dreamer's changes reads, newest
/// first.
const DREAMER_CHANGES_SCAN: usize = 20_000;

/// The record a correction's supersession leaves on its replacement.
const SUPERSESSION_PROVENANCE: &str = "core.supersession.provenance";

const CHANGE_REVERT: RevertSurface = RevertSurface {
    surface: "dreamer_change_revert",
    birth: "dreamer.change_revert",
};

/// What a Dreamer change was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreamerChangeKind {
    /// A claim it wrote.
    Claim,
    /// Its settlement of an open conflict.
    Settlement,
    /// Its evidence attachment: a support edge's provenance record.
    Evidence,
    /// A scope summary.
    Summary,
    /// A NOTE: a TASK realization's answer.
    Note,
    /// A person's `about` lines.
    PersonAbout,
}

impl DreamerChangeKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Settlement => "settlement",
            Self::Evidence => "evidence",
            Self::Summary => "summary",
            Self::Note => "note",
            Self::PersonAbout => "person_about",
        }
    }
}

/// One change the owner may revert: its id, what it is, the claim's
/// predicate or the NOTE's kind, and when it landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerChange {
    pub change: EntityId,
    pub kind: DreamerChangeKind,
    pub label: String,
    pub at: u64,
}

/// The Dreamer's standing changes, newest first, and each person whose
/// newest `about` landing the owner may revert, with when it landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerChanges {
    pub changes: Vec<DreamerChange>,
    pub people: Vec<(EntityId, u64)>,
}

/// What reverting one Dreamer change did: the claims it retracted, the
/// markers open again for the owner, the members standing again in place,
/// the Dreamer's fresh copies of its own MACHINE members as (member, copy),
/// the members a later write closed, the SUMMARY or NOTE archived, and the
/// summary current again in a reverted one's place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevertedDreamerChange {
    pub kind: DreamerChangeKind,
    pub retracted: Vec<EntityId>,
    pub reopened: Vec<EntityId>,
    pub restored: Vec<EntityId>,
    pub copied: Vec<(EntityId, EntityId)>,
    pub left_closed: Vec<EntityId>,
    pub archived: Option<EntityId>,
    pub current: Option<EntityId>,
}

impl RevertedDreamerChange {
    const fn of(kind: DreamerChangeKind) -> Self {
        Self {
            kind,
            retracted: Vec::new(),
            reopened: Vec::new(),
            restored: Vec::new(),
            copied: Vec::new(),
            left_closed: Vec::new(),
            archived: None,
            current: None,
        }
    }
}

/// A revert's durable outcome, with the Gate receipt that recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerRevertReceipt {
    pub change: EntityId,
    pub reverted: RevertedDreamerChange,
    pub receipt_ref: String,
}

/// The Dreamer's standing changes, newest first, at most `limit`, from the
/// newest [`DREAMER_CHANGES_SCAN`] rows, with each revertible `about`.
pub(crate) fn dreamer_changes_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    limit: usize,
) -> Result<DreamerChanges> {
    let dreamer = crate::dreamer_runner::authority::dreamer_actor_id()?;
    let mut changes = Vec::new();
    for entry in vault
        .store
        .port_entity_timeline(
            txn,
            crate::ports::TimelineQuery {
                reverse: true,
                ..Default::default()
            },
        )?
        .take(DREAMER_CHANGES_SCAN)
    {
        if changes.len() >= limit {
            break;
        }
        let entry = entry?;
        let Some(record) = vault.store.port_entity_record(txn, &entry.id)? else {
            continue;
        };
        let change = match record.entity_type {
            ENTITY_TYPE_CLAIM => vault
                .get_claim_in_txn(txn, &entry.id)?
                .filter(|body| claim_stands(body) && author(body) == Some(dreamer))
                .map(|body| (claim_kind(&body), body.predicate)),
            ENTITY_TYPE_SUMMARY => (summary_by(&record.body, dreamer)
                && stands_in_txn(vault, txn, &entry.id)?)
            .then_some((DreamerChangeKind::Summary, String::new())),
            ENTITY_TYPE_NOTE => match note_by_in_txn(vault, txn, &entry.id, &record.body, dreamer)?
            {
                Some(kind) if stands_in_txn(vault, txn, &entry.id)? => {
                    Some((DreamerChangeKind::Note, kind))
                }
                _ => None,
            },
            _ => None,
        };
        if let Some((kind, label)) = change {
            changes.push(DreamerChange {
                change: entry.id,
                kind,
                label,
                at: entry.timestamp,
            });
        }
    }
    Ok(DreamerChanges {
        changes,
        people: revertible_person_abouts_in_txn(vault, txn)?,
    })
}

/// Reverts the Dreamer change `change` names, in the caller's transaction,
/// after the caller has checked the owner's authority; each claim it
/// retracts is retracted as `reverter`'s. Refused for anything the Dreamer
/// did not write and for a change that no longer stands.
pub(crate) fn revert_dreamer_change_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: EntityId,
    reverter: WriteActor,
    now: u64,
) -> Result<RevertedDreamerChange> {
    let dreamer = crate::dreamer_runner::authority::dreamer_actor_id()?;
    let record = vault
        .store
        .port_entity_record(txn, &change)?
        .ok_or(crate::error::Error::EntityNotFound)?;
    match record.entity_type {
        ENTITY_TYPE_CLAIM => {
            let body = vault
                .get_claim_in_txn(txn, &change)?
                .ok_or(crate::error::Error::EntityNotFound)?;
            if author(&body) != Some(dreamer) {
                return Err(invalid_consolidation(
                    "the Dreamer did not write this claim",
                ));
            }
            if !claim_stands(&body) {
                return Err(invalid_consolidation("the change no longer stands"));
            }
            revert_claim_in_txn(vault, txn, change, &body, dreamer, reverter, now)
        }
        ENTITY_TYPE_SUMMARY => {
            if !summary_by(&record.body, dreamer) {
                return Err(invalid_consolidation(
                    "the Dreamer did not write this summary",
                ));
            }
            if !stands_in_txn(vault, txn, &change)? {
                return Err(invalid_consolidation("the change no longer stands"));
            }
            let (current, header) =
                crate::scope_summary::roll_back_summary_in_txn(vault, txn, change)?;
            archive_in_txn(vault, txn, &change)?;
            let mut reverted = RevertedDreamerChange::of(DreamerChangeKind::Summary);
            reverted.archived = Some(change);
            reverted.current = current;
            if let Some(header) = header {
                if vault
                    .get_claim_in_txn(txn, &header)?
                    .is_some_and(|body| body.lifecycle == ClaimLifecycleStatus::Active)
                {
                    vault.retract_claim_in_txn_as(txn, &header, now, Some(reverter))?;
                    reverted.retracted.push(header);
                }
            }
            Ok(reverted)
        }
        ENTITY_TYPE_NOTE => {
            if note_by_in_txn(vault, txn, &change, &record.body, dreamer)?.is_none() {
                return Err(invalid_consolidation("the Dreamer did not write this note"));
            }
            if !stands_in_txn(vault, txn, &change)? {
                return Err(invalid_consolidation("the change no longer stands"));
            }
            archive_in_txn(vault, txn, &change)?;
            let mut reverted = RevertedDreamerChange::of(DreamerChangeKind::Note);
            reverted.archived = Some(change);
            Ok(reverted)
        }
        ENTITY_TYPE_PERSON => {
            if !revert_person_about_in_txn(vault, txn, change)? {
                return Err(invalid_consolidation(
                    "the Dreamer has no about landing to revert for this person",
                ));
            }
            Ok(RevertedDreamerChange::of(DreamerChangeKind::PersonAbout))
        }
        _ => Err(invalid_consolidation("not a change the Dreamer makes")),
    }
}

/// A claim's revert: a settlement's answer reverts as its settlement, and an
/// evidence attachment through the provenance retract; any other claim is
/// retracted with the answers its correction gave and its supersession
/// record, and each claim it superseded stands again.
fn revert_claim_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    claim: EntityId,
    body: &ClaimBody,
    dreamer: EntityId,
    reverter: WriteActor,
    now: u64,
) -> Result<RevertedDreamerChange> {
    if claim_kind(body) == DreamerChangeKind::Settlement {
        let settled = revert_settlement_in_txn(vault, txn, claim, reverter, now)?;
        let mut reverted = RevertedDreamerChange::of(DreamerChangeKind::Settlement);
        reverted.retracted.push(claim);
        reverted.reopened.push(settled.marker);
        reverted.restored = settled.restored;
        reverted.copied = settled.copied;
        reverted.left_closed = settled.left_closed;
        return Ok(reverted);
    }
    if claim_kind(body) == DreamerChangeKind::Evidence {
        vault.retract_edge_provenance_in_txn(txn, &claim, now)?;
        let mut reverted = RevertedDreamerChange::of(DreamerChangeKind::Evidence);
        reverted.retracted.push(claim);
        return Ok(reverted);
    }
    let superseded = superseded_by_in_txn(vault, txn, claim)?;
    vault.retract_claim_in_txn_as(txn, &claim, now, Some(reverter))?;
    let mut reverted = RevertedDreamerChange::of(DreamerChangeKind::Claim);
    reverted.retracted.push(claim);
    if body.predicate == PREDICATE_CONFLICT_RESOLVED {
        reverted
            .reopened
            .extend(marker_ids(&body.value, "open_marker"));
    }
    if let ClaimSubject::Entity(subject) = body.subject {
        for id in vault.claims_for_subject_in_txn(txn, &subject)? {
            let Some(answer) = vault.get_claim_in_txn(txn, &id)? else {
                continue;
            };
            if answer.predicate == PREDICATE_CONFLICT_RESOLVED
                && answer.lifecycle == ClaimLifecycleStatus::Active
                && crate::memory::claim_author(&answer) == Some(dreamer)
                && string_at(&answer.value, "resolution").is_some_and(|resolution| {
                    marker_ids(resolution, "superseded_by").any(|by| by == claim)
                })
            {
                vault.retract_claim_in_txn_as(txn, &id, now, Some(reverter))?;
                reverted.retracted.push(id);
                reverted
                    .reopened
                    .extend(marker_ids(&answer.value, "open_marker"));
            }
        }
    }
    for id in vault.claims_for_subject_in_txn(txn, &claim)? {
        if vault.get_claim_in_txn(txn, &id)?.is_some_and(|record| {
            record.predicate == SUPERSESSION_PROVENANCE
                && record.lifecycle == ClaimLifecycleStatus::Active
        }) {
            vault.retract_claim_in_txn_as(txn, &id, now, Some(reverter))?;
            reverted.retracted.push(id);
        }
    }
    for loser in superseded {
        match restore_member_in_txn(vault, txn, claim, loser, claim, &CHANGE_REVERT, now)? {
            MemberRestore::Restored => reverted.restored.push(loser),
            MemberRestore::Copied(copy) => reverted.copied.push((loser, copy)),
            MemberRestore::LeftClosed => reverted.left_closed.push(loser),
        }
    }
    Ok(reverted)
}

/// The claims `claim` superseded.
fn superseded_by_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim: EntityId,
) -> Result<Vec<EntityId>> {
    let mut superseded = Vec::new();
    for target in vault.port_edge_peers(
        txn,
        &claim,
        EdgeDirection::Out,
        crate::edge::EdgeKind::Supersedes,
    )? {
        if superseded.len() >= crate::vault::MAX_EDGE_QUERY_RESULTS {
            return Err(crate::error::Error::IndexOverflow("superseded claims"));
        }
        superseded.push(target?);
    }
    Ok(superseded)
}

/// Who wrote a claim: its write envelope's actor, or for an edge provenance
/// record, which carries no envelope evidence, the record's own actor.
fn author(body: &ClaimBody) -> Option<EntityId> {
    if body.predicate == crate::provenance::PREDICATE_EDGE_PROVENANCE {
        return crate::provenance::decode_edge_provenance_body(&body.value)
            .ok()
            .map(|record| record.actor_entity_ref);
    }
    crate::memory::claim_author(body)
}

/// Whether a claim still stands to revert: Active and not refused.
fn claim_stands(body: &ClaimBody) -> bool {
    body.lifecycle == ClaimLifecycleStatus::Active && body.approval != ClaimApprovalStatus::Rejected
}

/// A settlement's answer, an evidence attachment, or any other claim.
fn claim_kind(body: &ClaimBody) -> DreamerChangeKind {
    if body.predicate == crate::provenance::PREDICATE_EDGE_PROVENANCE {
        return DreamerChangeKind::Evidence;
    }
    let settlement = body.predicate == PREDICATE_CONFLICT_RESOLVED
        && string_at(&body.value, "resolution")
            .and_then(|resolution| string_at(resolution, "settlement"))
            .is_some();
    if settlement {
        DreamerChangeKind::Settlement
    } else {
        DreamerChangeKind::Claim
    }
}

/// Whether the SUMMARY body `body` is the Dreamer's.
fn summary_by(body: &[u8], dreamer: EntityId) -> bool {
    crate::scope_summary::decode_scope_summary_body(body)
        .is_ok_and(|summary| summary.actor == dreamer.to_hex())
}

/// The NOTE's kind when the Dreamer wrote it.
fn note_by_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: &EntityId,
    body: &[u8],
    dreamer: EntityId,
) -> Result<Option<String>> {
    let live = crate::note::live_body_in_txn(&vault.store, txn, note, ENTITY_TYPE_NOTE, body)?;
    let Ok(note) = crate::note::decode_note_body_in_txn(&vault.store, txn, &live) else {
        return Ok(None);
    };
    Ok((note.author_ref == dreamer).then(|| note.kind.as_str().to_string()))
}

/// Whether `id` is neither deleted nor archived.
fn stands_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(!vault.store.port_deletion_state(txn, id)?.deleted
        && vault.archive_tombstone_in_txn(txn, id)?.is_none())
}

/// Archives the Dreamer's SUMMARY or NOTE `id`: the cleanup-archive marker,
/// body and indexes kept, so the owner's cleanup restore brings it back.
fn archive_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<()> {
    let tombstone = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::ArchivedByCleanup,
        deleted_at: vault.store.clock.now_recorded_at(),
        request_id: uuid::Uuid::from_bytes(vault.store.clock.ulid()?).into_bytes(),
    };
    vault.put_archive_tombstone_in_txn(txn, id, &tombstone)
}
