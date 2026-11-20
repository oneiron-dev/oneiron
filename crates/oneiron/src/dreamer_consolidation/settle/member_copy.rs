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
//! The Gate judges it as its author's write of today, over the member's whole
//! recorded lineage: an author whose ceiling or permit no longer stands gets
//! no copy, and the member stays closed. A member whose row is deleted, being
//! deleted or under a use limit is never copied, and neither is one a
//! standing copy already restores (lead ruling 21 Nov, INTENT-17 rows 1+2 =
//! A; FIX DERIVE-REVERT-SIGNED-CLAIM, DERIVE-REVERT-GENERATED-CLAIM).

use rmpv::Value;

use super::{RESTORED_MARKER_KEY, RevertSurface, marker_ids};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ClaimSubject};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::{Error, GateError, Result};
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::write_envelope::{
    ClaimCandidate, SourceLineage, WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY,
    WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY, WriteActor, WriteEnvelope, WriteProvenance,
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
    let mut attempt = vault.store.env.nested_write_txn(txn)?;
    match vault.restore_superseded_claim_in_txn(&mut attempt, &kept, &loser, now / 1_000) {
        Ok(true) => {
            attempt.commit()?;
            Ok(true)
        }
        Ok(false) => {
            attempt.abort();
            Ok(false)
        }
        Err(error) if gate_refuses(&error) => {
            attempt.abort();
            Ok(false)
        }
        Err(error) => {
            attempt.abort();
            Err(error)
        }
    }
}

/// Whether `error` is the Gate's refusal of a claim write: its rejected
/// decision, or the source trust check's refusal of an `auto` claim whose
/// source no row answers for.
fn gate_refuses(error: &Error) -> bool {
    matches!(
        error,
        Error::Gate(
            GateError::GateWriteRejected { .. } | GateError::SourceNotTrustedForAuto { .. }
        )
    )
}

/// Stands `loser` again as a fresh copy written as its original author, when
/// `kept` superseded it and it is still closed; the copy's id. `None`, with
/// nothing written, for a member that names no such author, whose row may
/// not be copied, that a standing copy already restores, or, when unsigned,
/// whose copy the Gate refuses. `now` is milliseconds.
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
    if body.lifecycle != ClaimLifecycleStatus::Superseded {
        return Ok(None);
    }
    let signed = crate::authority::machine_claim_needs_history(&vault.store, txn, &body)?;
    let Some(author) = copy_author(&body, signed)? else {
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
        // The Dreamer's signed copy, as before: its own declared source, and
        // a refusal is the revert's error.
        return copy
            .write_in_txn(vault, txn, &body, author, SourceLineage::of(source))
            .map(Some);
    }
    let lineage = crate::batch::inherited_lineage(source, &body);
    let mut attempt = vault.store.env.nested_write_txn(txn)?;
    match copy.write_in_txn(vault, &mut attempt, &body, author, lineage) {
        Ok(id) => {
            attempt.commit()?;
            Ok(Some(id))
        }
        Err(error) if gate_refuses(&error) => {
            attempt.abort();
            Ok(None)
        }
        Err(error) => {
            attempt.abort();
            Err(error)
        }
    }
}

/// The actor a fresh copy of the member `body` is written as. A signed
/// member: the Dreamer, for its own. An unsigned member about an entity: the
/// agent or engine actor its write envelope stamped. `None` for any other
/// member: a person's claim is never written again in the person's name, and
/// a claim about an edge has no subject index a standing copy is found by.
fn copy_author(body: &ClaimBody, signed: bool) -> Result<Option<WriteActor>> {
    let Some(author) = crate::memory::claim_author(body) else {
        return Ok(None);
    };
    if signed {
        let dreamer = crate::dreamer_runner::authority::dreamer_actor_id()?;
        return Ok((author == dreamer).then(|| WriteActor::new(dreamer, EdgeActorClass::System)));
    }
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Ok(None);
    }
    Ok(stamped_actor_class(body)
        .filter(|class| matches!(class, EdgeActorClass::Agent | EdgeActorClass::System))
        .map(|class| WriteActor::new(author, class)))
}

/// The actor class the write envelope stamped into `body`'s evidence.
fn stamped_actor_class(body: &ClaimBody) -> Option<EdgeActorClass> {
    let Value::Map(entries) = body.evidence.as_ref()? else {
        return None;
    };
    let mut classes = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY));
    let (_, class) = classes.next()?;
    if classes.next().is_some() {
        return None;
    }
    EdgeActorClass::try_from_u8(u8::try_from(class.as_u64()?).ok()?)
}

/// Whether a standing claim about `body`'s subject, written by `author`, is
/// a revert's fresh copy of `loser` already: a second revert that reaches
/// the same member (a batch's `supersede` item and then its `claim` item, or
/// the same batch reverted again) writes no second copy. A member about an
/// edge has no subject index, so none is found for it.
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
    /// Writes the copy of `body` as `author` under `lineage`; its id.
    fn write_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        body: &ClaimBody,
        author: WriteActor,
        lineage: SourceLineage,
    ) -> Result<EntityId> {
        let candidate = crate::dreamer_consolidation::persistence::on_axes_of(
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
            .apply(txn)?;
        // The copy stands the member's claim again: about a PERSON under a
        // cleanup archive, it restores her in the revert's transaction
        // (ARCH-0073 §6).
        vault.restore_mentioned_subject_in_txn(txn, body.subject)?;
        Ok(copy)
    }
}
