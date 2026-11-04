//! A loop decision's own context as the authorised loop read admits it: the
//! loop link its writer stamped (FIX 7500), and the read context it kept for
//! an event that names no entity the reader reads, a candidate that never
//! landed or a claim-free admission (FIX 7499), or a stored candidate whose
//! status or evidence the reader's floor refuses (FIX 10999). The context is
//! judged under the reader's live authority each time: never a stored list
//! of readers, and never a row made up to pass the row checks. It only adds
//! events the named-entity route does not admit, and admits none the
//! reader's own authority does not.

use std::collections::BTreeSet;

use super::{LoopDecisionFamily, LoopRead};
use crate::EntityId;
use crate::claim::scoped_read::ScopedRead;
use crate::error::{Error, Result};
use crate::gate::ClaimReadView;
use crate::store::{
    GateDecisionReadContext, GateDecisionRecord, GateLoopFamily, GateReadAnchors, GateReadPosition,
};
use oneiron_authority::federation::{ScopeAxis, ScopeId};

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
    /// that is stored now is judged by its row's audience, facet and guest
    /// conjuncts plus the position its writer kept for it, with no status,
    /// evidence or landing asked, so a Proposed or evidence-refused
    /// candidate's event reads (FIX 10999). One whose writer kept no
    /// position for that claim is judged by its row alone, as before, and so
    /// is a kept record position under a read narrowed to a room, worlds, an
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
            && !contexts
                .iter()
                .any(|context| context.record == Some(claim) && context.position.is_some())
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
            // FIX 11000 PARTLY: the admission stands on the anchor ids too,
            // so a recheck reads the item again when one of them changes.
            // Empty anchors (old rows) add nothing.
            dependencies.extend(
                context
                    .anchors
                    .threads()
                    .iter()
                    .flat_map(|anchor| [anchor.root, anchor.turn]),
            );
            dependencies.extend(context.anchors.reached().iter().copied());
            dependencies.extend(context.anchors.rooms().iter().copied());
            dependencies.extend(context.anchors.worlds().iter().copied());
        }
        Ok(Some(KeptAdmission {
            about: about.into_iter().collect(),
            dependencies: dependencies.into_iter().collect(),
        }))
    }

    /// One kept read context under the reader's live authority: each row it
    /// is about passes the reader's own full row floor now, audience and
    /// private threads included; a record stored now passes it too, or, when
    /// its writer kept the record's position, passes its row's audience,
    /// facet and guest conjuncts and that position, with no status, evidence
    /// or landing asked (FIX 10999); and one that never landed sits where the
    /// reader's Scope, grants and relationships read it. Writer anchors
    /// (FIX 11000 PARTLY) bind the writer-proof arms: incomplete anchors
    /// deny, and complete anchors additionally meet today's live conjuncts;
    /// the stored-row arm keeps today's verdicts.
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
            && let Some(row) = self.entity_record_in(txn, &record)?
        {
            if self.is_entity_retrievable_held_in(
                txn,
                &read.policy,
                &read.filter,
                &record,
                &read.held,
            )? {
                return Ok(true);
            }
            let Some(position) = &context.position else {
                return Ok(false);
            };
            // FIX 10999: the stored row's own audience, facet and guest
            // conjuncts, then the position its writer kept. Its status,
            // evidence and landing govern the claim, not whether its
            // decision may be seen.
            let raw = row.encode();
            if !self.audience_readable_raw_in(txn, &record, &raw, &read.held)?
                || !self.facets_allow_in(txn, &record, &raw)?
                || !self.guest_bound_admits_in(txn, &record, &raw)
            {
                return Ok(false);
            }
            // FIX 11000 PARTLY: the kept position also stands on the
            // writer's anchors. The row conjuncts above keep today's
            // verdicts; only the writer-proof step below is anchor-bound.
            if !self.loop_anchors_admitted_in(txn, &context.anchors)? {
                return Ok(false);
            }
            return self.loop_position_admitted_in(txn, read, Some(&record), position);
        }
        match &context.position {
            // FIX 11000 PARTLY: a context with no position admits only
            // past the writer's anchors; anchor-less contexts keep Ok(true).
            None => self.loop_anchors_admitted_in(txn, &context.anchors),
            Some(position) => {
                if !self.loop_anchors_admitted_in(txn, &context.anchors)? {
                    return Ok(false);
                }
                self.loop_position_admitted_in(txn, read, context.record.as_ref(), position)
            }
        }
    }

    /// Writer anchors on the kept position's admission (FIX 11000 PARTLY).
    /// True when the writer attached none, so old rows keep today's
    /// verdicts. Otherwise only complete anchors with nonempty worlds
    /// admit, and every anchor id meets today's live audience/peer/thread
    /// device conjuncts (`audience_readable_in`: device, private threads,
    /// own entry, and past narrowing the room/world ceilings with the
    /// audience and peer reads). Incomplete or empty-world anchors deny, as
    /// a missing ancestry does today. Anchor worlds contribute the nonempty
    /// gate; their window-time refinement stays PARTLY. Content-free: only
    /// id readability is asked, never body text.
    fn loop_anchors_admitted_in(
        &self,
        txn: &heed::RoTxn<'_>,
        anchors: &GateReadAnchors,
    ) -> Result<bool> {
        if anchors.is_empty() {
            return Ok(true);
        }
        if !anchors.is_complete() || anchors.worlds().is_empty() {
            return Ok(false);
        }
        for id in anchors
            .threads()
            .iter()
            .flat_map(|anchor| [anchor.root, anchor.turn])
            .chain(anchors.reached().iter().copied())
            .chain(anchors.rooms().iter().copied())
        {
            if !self.audience_readable_in(txn, &id)? {
                return Ok(false);
            }
        }
        Ok(true)
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
            claim.relationship.clone(),
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
/// project, the claim's relationships and its principal.
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
        rows.extend(claim.relationship.iter().flatten().copied());
        rows.extend(claim.principal);
    }
    rows
}
