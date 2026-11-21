//! How a member a reverted write superseded stands again: reopened in place,
//! or, where it does not reopen, as a fresh copy written as its original
//! author.
//!
//! Two kinds of member do not reopen. A claim the Dreamer signed keeps a
//! signed history, which never reopens. An unsigned claim at `auto` whose
//! source needs an explicit permit (`generated`, `imported`, `tool_output`)
//! reopens only through a re-put that names no actor, and every such permit
//! is bound to one actor, so the Gate refuses that re-put.
//!
//! The copy carries the member's predicate, value, confidence, window and
//! axes under a new id, and is born of the member and of the reverted write.
//! It derives from the member (a `derived_from` edge), so the policies the
//! member's words were learned under bind the copy as they bind the member:
//! a reader who does not read the member does not read its copy.
//! An unsigned member's copy is written as the writer the engine attested for
//! that exact row (never as an actor its evidence merely names), in the
//! member's own facet and project and over its whole recorded lineage. The
//! Gate judges it as that writer's write of today: a writer whose ceiling or
//! permit no longer stands gets no copy, and the member stays closed. A
//! member whose row is deleted, being deleted or under a use limit is never
//! copied, and neither is one a standing copy already restores (lead ruling
//! 21 Nov, INTENT-17 rows 1+2 = A; FIX DERIVE-REVERT-SIGNED-CLAIM,
//! DERIVE-REVERT-GENERATED-CLAIM).
//!
//! Both attempts run in savepoints that hand their post-commit work to the
//! write's owner ([`crate::batch::savepoint_in_txn`]), so a reopened or
//! copied claim reaches the live windows as any other write does: the copy
//! through the batch door, the reopen through the rows and the removed link
//! the lifecycle queues for it.

use rmpv::Value;

use super::{RESTORED_MARKER_KEY, RevertSurface, marker_ids};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ClaimSubject};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::{Error, GateError, Result};
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::write_envelope::{
    ClaimCandidate, SourceLineage, WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY, WriteActor,
    WriteEnvelope, WriteProvenance,
};
use crate::{ClaimBody, EntityId, TimeRange, Vault};

/// The provenance key naming the member a revert's fresh copy restores.
const RESTORES_KEY: &str = "restores";

/// Reopens `loser` in place after `kept` superseded it
/// ([`Vault::restore_superseded_claim_in_txn`]), in a savepoint of `txn`.
/// `false`, with nothing written, when the lifecycle does not reopen it or
/// the Gate refuses the reopen. `now` is milliseconds.
pub(super) fn reopen_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    kept: EntityId,
    loser: EntityId,
    now: u64,
) -> Result<bool> {
    let reopened = crate::batch::savepoint_in_txn(vault, txn, |attempt| {
        Ok(vault
            .restore_superseded_claim_in_txn(attempt, &kept, &loser, now / 1_000)?
            .then_some(()))
    });
    Ok(unless_refused(reopened)?.is_some())
}

/// `attempt`, with the Gate's refusal of its claim write read as nothing
/// written: its rejected decision, or the source trust check's refusal of an
/// `auto` claim whose source no row answers for. The savepoint the attempt
/// ran in has rolled back.
fn unless_refused<T>(attempt: Result<Option<T>>) -> Result<Option<T>> {
    match attempt {
        Err(Error::Gate(
            GateError::GateWriteRejected { .. } | GateError::SourceNotTrustedForAuto { .. },
        )) => Ok(None),
        attempt => attempt,
    }
}

/// Stands `loser` again as a fresh copy written as its original author, when
/// `kept` superseded it and it is still closed; the copy's id. `None`, with
/// nothing written, for a member that has no such author, that `surface`
/// does not copy, whose row may not be copied, that a standing copy already
/// restores, or, when unsigned, whose copy the Gate refuses. `now` is
/// milliseconds.
pub(super) fn copy_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    kept: EntityId,
    loser: EntityId,
    reverted: EntityId,
    surface: &RevertSurface,
    now: u64,
) -> Result<Option<EntityId>> {
    use crate::ports::EdgeStoreRead;
    let Some(body) = vault.get_claim_in_txn(txn, &loser)? else {
        return Ok(None);
    };
    if body.lifecycle != ClaimLifecycleStatus::Superseded
        || !(surface.edge_subjects || matches!(body.subject, ClaimSubject::Entity(_)))
    {
        return Ok(None);
    }
    let signed = crate::authority::machine_claim_needs_history(&vault.store, txn, &body)?;
    let author = if signed {
        dreamer_author(&body)?
    } else if surface.unsigned_copies {
        attested_author_in_txn(vault, txn, loser, &body)?
    } else {
        None
    };
    let Some(author) = author else {
        return Ok(None);
    };
    if vault
        .port_edge_get(&*txn, &kept, EdgeKind::Supersedes, &loser)?
        .is_none()
        || !crate::batch::ClaimMaterialization::succession_source_live(&vault.store, txn, &loser)?
        || copy_stands_in_txn(vault, txn, loser, &body, author.entity_ref())?
    {
        return Ok(None);
    }
    let source = body.source.unwrap_or(ClaimSource::Generated);
    let copy = MemberCopy {
        loser,
        reverted,
        surface,
        now,
    };
    if signed {
        // The Dreamer's signed copy, as before: its own declared source, the
        // default facet, and a refusal is the revert's error.
        return copy
            .write_in_txn(vault, txn, &body, author, SourceLineage::of(source), false)
            .map(Some);
    }
    let lineage = crate::batch::inherited_lineage(source, &body);
    unless_refused(crate::batch::savepoint_in_txn(vault, txn, |attempt| {
        copy.write_in_txn(vault, attempt, &body, author, lineage, true)
            .map(Some)
    }))
}

/// The actor a fresh copy of the signed member `body` is written as: the
/// Dreamer, for its own claim. `None` for another MACHINE's claim.
fn dreamer_author(body: &ClaimBody) -> Result<Option<WriteActor>> {
    let dreamer = crate::dreamer_runner::authority::dreamer_actor_id()?;
    Ok((crate::memory::claim_author(body) == Some(dreamer))
        .then(|| WriteActor::new(dreamer, EdgeActorClass::System)))
}

/// The actor a fresh copy of the unsigned member `loser` is written as: the
/// writer the engine attested for that exact row
/// ([`crate::batch::authenticated_claim_author_in_txn`]; evidence a raw or
/// replicated put carried is no authorship), when it is an agent or an
/// engine actor whose own row still stands and the member is about an
/// entity. `None` for any other member: a person's claim is never written
/// again in the person's name, and a claim about an edge has no subject
/// index a standing copy is found by.
fn attested_author_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    loser: EntityId,
    body: &ClaimBody,
) -> Result<Option<WriteActor>> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Ok(None);
    }
    let Some(writer) =
        crate::batch::authenticated_claim_author_in_txn(&vault.store, txn, &loser, body)?
    else {
        return Ok(None);
    };
    if !matches!(
        writer.actor_class(),
        EdgeActorClass::Agent | EdgeActorClass::System
    ) || !crate::vault::live_entity_row_in_txn(&vault.store, txn, &writer.entity_ref())?
        .is_live()
    {
        return Ok(None);
    }
    // The writer alone: the authority state and the run its old write was
    // bound to are not today's.
    Ok(Some(WriteActor::new(
        writer.entity_ref(),
        writer.actor_class(),
    )))
}

/// Whether a standing claim about `body`'s subject, written by `author`, is
/// a fresh copy of `loser` already: a second revert that reaches the same
/// member (a batch's `supersede` item and then its `claim` item, or the same
/// batch reverted again) writes no second copy. A copy that was refused, has
/// gone stale or was closed stands for nothing, so the member may be copied
/// again. A member about an edge has no subject index, so none is found for
/// it.
fn copy_stands_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    loser: EntityId,
    body: &ClaimBody,
    author: EntityId,
) -> Result<bool> {
    let ClaimSubject::Entity(subject) = body.subject else {
        return Ok(false);
    };
    Ok(vault
        .find_claim_for_subject_in_txn(txn, &subject, |_, peer| {
            (peer.lifecycle == ClaimLifecycleStatus::Active
                && peer.approval != ClaimApprovalStatus::Rejected
                && !peer.stale
                && crate::memory::claim_author(peer) == Some(author)
                && restores(peer, loser))
            .then_some(())
        })?
        .is_some())
}

/// Whether `body`'s write provenance names `member` as the claim it restores.
fn restores(body: &ClaimBody, member: EntityId) -> bool {
    let Some(Value::Map(fields)) = &body.evidence else {
        return false;
    };
    fields
        .iter()
        .find(|(key, _)| key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY))
        .is_some_and(|(_, provenance)| {
            marker_ids(provenance, RESTORES_KEY).any(|restored| restored == member)
        })
}

/// One fresh copy to write: the member, the reverted write it is born of,
/// where the revert says it came from, and when (milliseconds).
struct MemberCopy<'a> {
    loser: EntityId,
    reverted: EntityId,
    surface: &'a RevertSurface,
    now: u64,
}

impl MemberCopy<'_> {
    /// Writes the copy of `body` as `author` under `lineage`; its id. With
    /// `in_place`, the copy keeps the member's own facet and project stamps;
    /// without, it is born where a write of today is.
    fn write_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        body: &ClaimBody,
        author: WriteActor,
        lineage: SourceLineage,
        in_place: bool,
    ) -> Result<EntityId> {
        let mut candidate = crate::dreamer_consolidation::persistence::on_axes_of(
            ClaimCandidate::new(
                body.predicate.clone(),
                body.subject,
                body.value.clone(),
                body.confidence,
            )
            .with_confidence_details(body.confidence_details())
            .with_validity(body.valid_from, None),
            body,
        );
        if in_place {
            candidate = candidate.with_scope_stamps(body.scope_facet, body.scope_project);
        }
        let mut provenance = vec![
            (Value::from("surface"), Value::from(self.surface.surface)),
            (
                Value::from(RESTORES_KEY),
                Value::Binary(self.loser.as_bytes().to_vec()),
            ),
            (
                Value::from("reverted"),
                Value::Binary(self.reverted.as_bytes().to_vec()),
            ),
        ];
        if let Some(marker) = self.surface.marker {
            provenance.push((
                Value::from(RESTORED_MARKER_KEY),
                Value::Binary(marker.as_bytes().to_vec()),
            ));
        }
        let mut envelope = WriteEnvelope::with_lineage(
            author,
            body.source.unwrap_or(ClaimSource::Generated),
            WriteProvenance::new(Value::Map(provenance))?,
            if body.approval == ClaimApprovalStatus::Proposed {
                ClaimApprovalStatus::Proposed
            } else {
                ClaimApprovalStatus::Auto
            },
            lineage,
        );
        let copy = EntityId::now();
        // A claim's times are Unix seconds; `now` is milliseconds (FIX 10519).
        let at = self.now / 1_000;
        let birth = RowBirth::written(
            envelope.actor(),
            MadeByClass::of_writer(author.actor_class()),
            self.surface.birth,
            &[self.loser, self.reverted],
            &[],
            at,
        );
        vault.sign_retained_machine_claim_in_txn(&*txn, &copy, &candidate, &mut envelope)?;
        vault
            .batch_in()
            .claim_candidate(
                &copy,
                candidate,
                &envelope,
                TimeRange { start: at, end: at },
                at,
            )
            .made_by(&copy, birth)
            // The copy's words are the member's: it derives from the member,
            // so it reads, travels and is held only where the member is, and
            // it is withdrawn when the member's row is purged or erased
            // (review round 1 of #10048). A use limit placed on the member
            // later does not reach a copy that already stands (FIX
            // REVERT-COPY-NOT-BOUND-BY-LATER-USE-LIMIT-ON-ITS-MEMBER).
            .edge(&copy, EdgeKind::DerivedFrom, &self.loser, 1.0)
            .apply(txn)?;
        // The copy stands the member's claim again: about a PERSON under a
        // cleanup archive, it restores her in the revert's transaction
        // (ARCH-0073 §6).
        vault.restore_mentioned_subject_in_txn(txn, body.subject)?;
        Ok(copy)
    }
}
