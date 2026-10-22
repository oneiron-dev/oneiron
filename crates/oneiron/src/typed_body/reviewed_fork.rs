//! A fork landed up to the frontier its review read (FIX 9992). A deck
//! review returns the fork's frontier beside the live head's; its landing
//! applies the fork's document exactly up to that frontier. Work the opener
//! appended after the review stays on the open fork for the next review:
//! the fork's base moves to the reviewed frontier and its commit count to
//! the rest's, so that review sees only what is left. Nothing is refused for
//! the appended work; a frontier that is not this fork's at or past its base
//! is no review of it.

use super::{
    BodyActor, DOCS, FORK_DOCS, FORKS, HEADS, TypedBodyHead, TypedForkState, import, invalid, load,
    require_live, snapshot, validate_actor,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::write_envelope::WriteActor;
use heed::{RoTxn, RwTxn};
use loro::{ExportMode, Frontiers, LoroDoc, VersionVector};

/// What landing a reviewed fork left.
#[derive(Debug, Clone)]
pub(crate) enum ReviewedLanding {
    /// The review read the whole fork: merged, its document gone, as
    /// [`super::merge_typed_body_fork_in_txn`] merges one.
    Whole(TypedBodyHead),
    /// The fork took more work after its review: the head took the reviewed
    /// prefix, and the fork stays open on the rest from `base`, the reviewed
    /// frontier, with the rest's `commits`.
    Prefix {
        head: TypedBodyHead,
        base: Vec<u8>,
        commits: u64,
    },
}

/// `fork`'s document up to `reviewed`, the frontier its review read: the
/// prefix a landing applies, read in `txn`.
pub(crate) fn reviewed_fork_doc_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    fork: &EntityId,
    reviewed: &[u8],
) -> Result<LoroDoc> {
    let key = (*entity, *fork);
    let record = FORKS.get(store, txn, &key)?.ok_or(Error::EntityNotFound)?;
    if record.state != TypedForkState::Open {
        return Err(invalid("the fork is not open"));
    }
    let doc = load(FORK_DOCS.get(store, txn, &key)?, None)?;
    prefix(&doc, &record.base, reviewed).map(|(prefix, _)| prefix)
}

/// `doc` up to `reviewed`, and that prefix's version, when `reviewed` is a
/// frontier of `doc` at or past `base`.
fn prefix(doc: &LoroDoc, base: &[u8], reviewed: &[u8]) -> Result<(LoroDoc, VersionVector)> {
    let not_this = || invalid("the reviewed fork frontier is not this fork's at or past its base");
    let at = Frontiers::decode(reviewed).map_err(|_| not_this())?;
    let vv = doc.frontiers_to_vv(&at).ok_or_else(not_this)?;
    let base = Frontiers::decode(base).map_err(|_| not_this())?;
    let base = doc.frontiers_to_vv(&base).ok_or_else(not_this)?;
    if !vv.includes_vv(&base) {
        return Err(not_this());
    }
    Ok((doc.fork_at(&at).map_err(|_| not_this())?, vv))
}

/// Land `fork` up to `reviewed`: [`super::merge_typed_body_fork_in_txn`]'s
/// checks (open, not the opener, a live actor and body, the head the review
/// read), then only the reviewed prefix's operations imported, with their
/// receipts. A fork with work past the prefix stays open on it.
pub(crate) fn merge_reviewed_fork_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    fork: &EntityId,
    expected_head: &[u8],
    reviewed: &[u8],
    actor: WriteActor,
) -> Result<ReviewedLanding> {
    let key = (*entity, *fork);
    let mut record = FORKS
        .get(&vault.store, txn, &key)?
        .ok_or(Error::EntityNotFound)?;
    if record.state != TypedForkState::Open {
        return Err(invalid("the fork is not open"));
    }
    // "The opener's lineage and its forks never settle their own proposal."
    if record.opener.is(actor.entity_ref()) {
        return Err(invalid("a fork's opener cannot merge it"));
    }
    validate_actor(vault, txn, actor)?;
    require_live(&vault.store, txn, entity)?;
    let mut head = HEADS
        .get(&vault.store, txn, entity)?
        .ok_or(Error::EntityNotFound)?;
    if head.frontier != expected_head {
        return Err(invalid(
            "the body moved since the review; read the fork again",
        ));
    }
    let live = load(DOCS.get(&vault.store, txn, entity)?, Some(&head.frontier))?;
    let proposal = load(FORK_DOCS.get(&vault.store, txn, &key)?, None)?;
    let (reviewed_doc, reviewed_vv) = prefix(&proposal, &record.base, reviewed)?;
    let before = live.oplog_vv();
    // Each fork commit is its own peer's (a fresh peer per call): the
    // prefix's commits are the peers it carries past the head.
    let landed = u64::try_from(
        reviewed_vv
            .iter()
            .filter(|(peer, counter)| before.get(*peer).copied().unwrap_or(0) < **counter)
            .count(),
    )
    .unwrap_or(u64::MAX);
    let updates = reviewed_doc
        .export(ExportMode::updates(&before))
        .map_err(|_| invalid("typed body fork export"))?;
    import(&live, &updates)?;
    head.frontier = live.oplog_frontiers().encode();
    let whole = proposal.oplog_vv() == reviewed_vv;
    head.commits += if whole { record.commits } else { landed };
    DOCS.put(&vault.store, txn, entity, &snapshot(&live)?)?;
    HEADS.put(&vault.store, txn, entity, &head)?;
    if whole {
        record.state = TypedForkState::Merged {
            by: BodyActor::Actor(actor.entity_ref()),
            at: vault.now_recorded_at(),
            head: head.frontier.clone(),
        };
        FORKS.put(&vault.store, txn, &key, &record)?;
        FORK_DOCS.delete(&vault.store, txn, &key)?;
        return Ok(ReviewedLanding::Whole(head));
    }
    // The rest stays open: its base the reviewed frontier, which the head
    // now holds too, and its commits the ones not landed.
    record.base = reviewed.to_vec();
    record.commits = record.commits.saturating_sub(landed);
    FORKS.put(&vault.store, txn, &key, &record)?;
    Ok(ReviewedLanding::Prefix {
        head,
        base: record.base,
        commits: record.commits,
    })
}
