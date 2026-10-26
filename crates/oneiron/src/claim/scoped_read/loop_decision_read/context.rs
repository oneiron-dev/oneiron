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
use crate::gate::ClaimReadView;
use crate::store::{GateDecisionReadContext, GateDecisionRecord, GateLoopFamily, GateReadPosition};

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

impl ScopedRead<'_> {
    /// The rows `record`'s kept read context makes it about, when the reader
    /// is admitted to every read context it kept (a bundle's every member):
    /// `None` when it kept none or one does not admit. A decision on a claim
    /// `claim` that is stored now is judged by its row alone, as before, and
    /// so is a kept record position under a read narrowed to a room, worlds,
    /// an audience, peers or another device.
    pub(super) fn loop_context_about_in(
        &self,
        txn: &heed::RoTxn<'_>,
        read: &LoopRead,
        record: &GateDecisionRecord,
        claim: Option<EntityId>,
    ) -> Result<Option<Vec<EntityId>>> {
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
        for context in contexts {
            if !self.loop_read_context_admitted_in(txn, read, context)? {
                return Ok(None);
            }
            about.extend(context.about.iter().copied());
        }
        Ok(Some(about.into_iter().collect()))
    }

    /// One kept read context under the reader's live authority: each row it
    /// is about passes the reader's own full row floor now, audience and
    /// private threads included, and a record that may never have landed
    /// sits where the reader's Scope, grants and relationships read it.
    fn loop_read_context_admitted_in(
        &self,
        txn: &heed::RoTxn<'_>,
        read: &LoopRead,
        context: &GateDecisionReadContext,
    ) -> Result<bool> {
        if context.about.is_empty() && context.position.is_none() {
            return Ok(false);
        }
        for row in &context.about {
            if !self.is_entity_retrievable_with_policy_in(txn, &read.policy, &read.filter, row)? {
                return Ok(false);
            }
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
        read: &LoopRead,
        record: Option<&EntityId>,
        position: &GateReadPosition,
    ) -> Result<bool> {
        if self.loop_position_narrowed()
            || !read.filter.read_scope().bands.contains(&position.entity_type)
            || !self.proof_live_in(txn)?
            || record.is_some_and(|record| !self.credential_allows_row_in(txn, record))
        {
            return Ok(false);
        }
        if let Some(proof) = self.actor_key.proof.as_ref()
            && !self.vault.guest_row_admitted_in_txn(txn, proof.claims(), || {
                Ok(Some(position.scope.clone()))
            })
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
            confidence: f32::from_bits(claim.confidence_bits),
            salience: claim.salience_bits.map(f32::from_bits),
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
