//! A loop decision's own context as the authorised loop read admits it: the
//! loop link its writer stamped (FIX 7500), and the read context it kept for
//! an event that names no entity the reader reads, a candidate that never
//! landed or a claim-free admission (FIX 7499). The context is judged under
//! the reader's live authority each time: never a stored list of readers,
//! and never a row made up to pass the row checks. It only adds events the
//! named-entity route does not admit, and admits none the reader's own
//! authority does not.

use std::collections::BTreeSet;

use super::{LoopDecisionFamily, LoopRead};
use crate::EntityId;
use crate::claim::scoped_read::ScopedRead;
use crate::error::{Error, Result};
use crate::federation::{ScopeAxis, ScopeId};
use crate::gate::ClaimReadView;
use crate::store::{GateDecisionReadContext, GateDecisionRecord, GateLoopFamily, GateReadPosition};

/// What a kept read context admitted: the rows the decision is about, for
/// relevance, and every live row its admission stood on, so a recheck reads
/// the item again when one of them changes.
pub(super) struct KeptAdmission {
    pub(super) about: Vec<EntityId>,
    pub(super) dependencies: Vec<EntityId>,
}

/// The family a stored decision reads as: its tag's, for the direct loop
/// tags, else that of the first loop link its writer stamped on it. A row
/// with neither is no loop decision: no tag joins by its name.
pub(super) fn record_family(record: &GateDecisionRecord) -> Option<LoopDecisionFamily> {
    super::loop_decision_family(&record.content_kind).or_else(|| {
        record.context.links.first().map(|link| match link.family {
            GateLoopFamily::Admission => LoopDecisionFamily::Admission,
            GateLoopFamily::Action => LoopDecisionFamily::Action,
        })
    })
}

impl<'v> ScopedRead<'v> {
    /// What `record`'s kept read context admits, when the reader is admitted
    /// to every read context it kept (a bundle's every member): `None` when
    /// it kept none or one does not admit. A decision on a claim `claim`
    /// that is stored now is judged by its row alone, as before, and so is a
    /// kept record position under a read narrowed to a room, worlds, an
    /// audience, peers or another device.
    pub(super) fn loop_context_admitted_in(
        &self,
        txn: &heed::RoTxn<'_>,
        read: &LoopRead<'v>,
        record: &GateDecisionRecord,
        claim: Option<EntityId>,
    ) -> Result<Option<KeptAdmission>> {
        let contexts = &record.context.read;
        if contexts.is_empty() {
            return Ok(None);
        }
        if let Some(claim) = claim
            && self.entity_record_in(txn, &claim)?.is_some()
        {
            return Ok(None);
        }
        let mut about = BTreeSet::new();
        let mut dependencies = BTreeSet::new();
        for context in contexts {
            if !self.loop_read_context_admitted_in(txn, read, context)? {
                return Ok(None);
            }
            about.extend(context.about.iter().copied());
            dependencies.extend(context.about.iter().copied());
            dependencies.extend(context.record);
            dependencies.extend(context.position.iter().flat_map(position_rows));
        }
        Ok(Some(KeptAdmission {
            about: about.into_iter().collect(),
            dependencies: dependencies.into_iter().collect(),
        }))
    }

    /// One kept read context under the reader's live authority: each row it
    /// is about passes the reader's own full row floor now, audience and
    /// private threads included; a record stored now passes it too, and one
    /// that never landed sits where the reader's Scope, grants and
    /// relationships read it.
    fn loop_read_context_admitted_in(
        &self,
        txn: &heed::RoTxn<'_>,
        read: &LoopRead<'v>,
        context: &GateDecisionReadContext,
    ) -> Result<bool> {
        if context.about.is_empty() && context.position.is_none() {
            return Ok(false);
        }
        for row in &context.about {
            if !self.is_entity_retrievable_held_in(
                txn,
                &read.policy,
                &read.filter,
                row,
                &read.held,
            )? {
                return Ok(false);
            }
        }
        if let Some(record) = context.record
            && self.entity_record_in(txn, &record)?.is_some()
        {
            return self.is_entity_retrievable_held_in(
                txn,
                &read.policy,
                &read.filter,
                &record,
                &read.held,
            );
        }
        match &context.position {
            None => Ok(true),
            Some(position) => {
                self.loop_position_admitted_in(txn, read, context.record.as_ref(), position)
            }
        }
    }

    /// A kept record position under the reader's live authority, as a stored
    /// row's own admission judges it apart from the row: its type in the
    /// reader's bands, the proof live, the credential's records, a guest's
    /// current view, the relationship gate, then the claim selectors (or the
    /// record door) over the kept Scope. No status, evidence or landing is
    /// asked: those govern the claim, not whether its decision may be seen.
    fn loop_position_admitted_in(
        &self,
        txn: &heed::RoTxn<'_>,
        read: &LoopRead<'v>,
        record: Option<&EntityId>,
        position: &GateReadPosition,
    ) -> Result<bool> {
        if self.loop_position_narrowed()
            || !read
                .filter
                .read_scope()
                .bands
                .contains(&position.entity_type)
            || !self.proof_live_in(txn)?
            || record.is_some_and(|record| !self.credential_allows_row_in(txn, record))
        {
            return Ok(false);
        }
        if let Some(proof) = self.actor_key.proof.as_ref()
            && !self
                .vault
                .guest_row_admitted_in_txn(txn, proof.claims(), || Ok(Some(position.scope.clone())))
        {
            return Ok(false);
        }
        let Some(claim) = &position.claim else {
            return Ok(crate::gate::scoped_read_record_allowed(
                &read.policy,
                &self.actor_key,
                &position.scope,
            ));
        };
        let confidence = f32::from_bits(claim.confidence_bits);
        let salience = claim.salience_bits.map(f32::from_bits);
        // The principal audience and the scalar floor an ordinary claim read
        // applies; its status, evidence and landing govern the claim, not
        // whether its decision may be seen.
        if !self.principal_admits(claim.principal)
            || !crate::pipeline::claim_scalars_ceiling_allowed(
                &read.filter,
                claim.sensitivity_band,
                confidence,
                salience,
            )
        {
            return Ok(false);
        }
        if !self.relationship_axes_allowed_in(
            txn,
            claim.relationship,
            claim.private,
            &position.scope,
        )? {
            return Ok(false);
        }
        let scope = match claim.scope.as_deref() {
            None => None,
            Some(mut bytes) => Some(
                rmpv::decode::read_value(&mut bytes)
                    .map_err(|_| Error::CorruptedIndex("gate decision read context"))?,
            ),
        };
        let view = ClaimReadView {
            record: position.scope.clone(),
            scope: scope.as_ref(),
            stale: claim.stale,
            confidence,
            salience,
            facets: &[],
        };
        Ok(crate::gate::scoped_read_claim_view_allowed(
            &read.policy,
            &self.actor_key,
            &view,
            self.actor_key.authority_scope(),
        ))
    }

    /// Whether this read is narrowed past what a kept position can be judged
    /// against without its row: a room or its facets, asked worlds, an
    /// explicit audience, peer reads, or a caller off this device.
    fn loop_position_narrowed(&self) -> bool {
        self.actor_key.room_turn.is_some()
            || self.actor_key.room_facets.is_some()
            || self.actor_key.worlds.is_some()
            || self.audience.is_some()
            || !self.peer_reads.is_empty()
            || self.actor_key.off_device()
    }
}

/// The live rows a kept position's admission stood on: its worlds, facet and
/// project, the claim's relationship and its principal.
fn position_rows(position: &GateReadPosition) -> Vec<EntityId> {
    let scope = &position.scope;
    let mut rows: Vec<EntityId> = [&scope.worlds, &scope.facets, &scope.audience]
        .into_iter()
        .flat_map(|axis| match axis {
            ScopeAxis::Some(ids) => ids.iter().map(|ScopeId(id)| *id).collect::<Vec<_>>(),
            ScopeAxis::Bottom | ScopeAxis::All => Vec::new(),
        })
        .collect();
    if let Some(claim) = &position.claim {
        rows.extend(claim.relationship);
        rows.extend(claim.principal);
    }
    rows
}
