//! The ARCH-0055 r7 proposal-resolution lane: scope derivation, the amendment
//! codec and its narrowing bounds, and the vault door that rules a parked
//! `Proposed` event.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::claim::{ClaimApprovalStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::entity_type_registry_entry;
use crate::vault::Vault;

use super::MAX_IDENTITY_TOPOLOGY_EVENT_BODY_BYTES;
use super::event_body_codec::{decode_action, decode_str_field, encode_action_entries};
use super::ledger_fold::{IdentityTopologyAction, fold_identity_topology_log};
use super::op_apply::{IdentityOpOutcome, IdentityOpWrite};
use super::op_vocabulary::{IdentityOpEvidence, IdentityTopologyOp, MergeOp, SplitOp};
use super::reassignment_map::{ReassignmentEntry, ReassignmentTarget};
use super::stored_event::{StoredIdentityOpAction, StoredIdentityOpEvent};
use super::transition_table::{
    IdentityTopologyRejection, ProposalOutcome, ProposalRuling, ProposalScope,
};
use super::wire_keys::{
    BODY_KEY_KIND, EVENT_KIND_MERGE, EVENT_KIND_SPLIT, PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED,
};

/// The op's primary target — the entity whose registry class names the
/// ramp scope: the merge SURVIVOR (what the merged records become) and the
/// split ORIGINAL (what is being divided).
pub(super) fn proposal_scope_target(op: &IdentityTopologyOp) -> Result<EntityId> {
    match op {
        IdentityTopologyOp::Merge(merge) => Ok(merge.survivor),
        IdentityTopologyOp::Split(split) => Ok(split.entity),
        IdentityTopologyOp::Facet(_) | IdentityTopologyOp::AssertDistinct(_) => {
            Err(Error::IdentityTopologyUnarmed("resolution of this op kind"))
        }
    }
}

/// The amendment-scope pin (ARCH-0055 r7): an amendment ADJUSTS the
/// reviewed decision, it never becomes a different one.
///
/// Two bounds, both necessary. Same op KIND: approving a merge must not
/// silently apply a split. Subject SUBSET: the amendment may drop or narrow
/// subjects the decider saw, never reach an entity the proposal never named
/// — otherwise "approve this merge, amended" would be a capability to merge
/// anything at all.
///
/// On a SPLIT the subject walk is not the whole reach: the reassignment map
/// also picks routes. A row's `Head` TARGET is where an item flows, and an
/// EDGE item is replayed by moving the edge itself — so both endpoints and
/// every head target stay bounded to the proposal's named set, and an
/// amendment may narrow the map but never route through an entity the
/// decider never saw. Bare claim items are not routes ([`reassignment_entry_in_scope`]).
pub(super) fn assert_amendment_in_scope(
    proposed: &IdentityTopologyOp,
    amended: &IdentityTopologyOp,
) -> Result<()> {
    if std::mem::discriminant(proposed) != std::mem::discriminant(amended) {
        return Err(Error::IdentityProposalAmendmentOutOfScope(
            "amended body is a different op kind",
        ));
    }
    let proposed_subjects: BTreeSet<EntityId> = proposed.participants().into_iter().collect();
    let in_scope = |entity: &EntityId| proposed_subjects.contains(entity);
    if !amended.participants().iter().all(in_scope) {
        return Err(Error::IdentityProposalAmendmentOutOfScope(
            "amended body names a subject outside the proposal",
        ));
    }
    if let IdentityTopologyOp::Split(split) = amended
        && split
            .reassignment
            .entries
            .iter()
            .any(|entry| !reassignment_entry_in_scope(entry, &proposed_subjects))
    {
        return Err(Error::IdentityProposalAmendmentOutOfScope(
            "amended split map references an entity outside the proposal",
        ));
    }
    Ok(())
}

/// Every entity one map row might ROUTE TO is bounded to the proposal's
/// participant set: `Head` targets, and either side of an edge ITEM —
/// ONE-1745 replays reassignments by moving the edge, so an edge endpoint
/// outside the named set is an out-of-scope route. Row items naming a bare
/// claim (an `Entity` subject) are not routes: a split's map moves claims
/// freely across the split's own heads whether or not the proposal named
/// each one, which is how the verdict itself reviews them. Facet targets
/// are op-internal indices and residue names nothing, so neither reaches
/// an entity the proposal did not.
fn reassignment_entry_in_scope(
    entry: &ReassignmentEntry,
    proposed_subjects: &BTreeSet<EntityId>,
) -> bool {
    let item_in_scope = match &entry.item {
        ClaimSubject::Entity(_) => true,
        ClaimSubject::Edge { source, target, .. } => {
            proposed_subjects.contains(source) && proposed_subjects.contains(target)
        }
    };
    let target_in_scope = match &entry.target {
        ReassignmentTarget::Head(head) => proposed_subjects.contains(head),
        ReassignmentTarget::Facet { .. } | ReassignmentTarget::Residue => true,
    };
    item_in_scope && target_in_scope
}

/// The scope tuple one proposal row derives: op kind, registry class of the
/// op's primary target, and the PROPOSAL's actor ref. Pure so the wire
/// check below and the vault stamp share ONE derivation.
fn proposal_scope_of(record: &StoredIdentityOpEvent, target_class: &str) -> ProposalScope {
    ProposalScope {
        op_kind: record.action.kind_str(),
        target_class: target_class.to_owned(),
        actor: record.actor.map_or_else(
            || PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED.to_owned(),
            |actor| actor.entity_ref().to_hex(),
        ),
    }
}

/// Stateless wire-legality of a resolution row's stamped ramp scope: the
/// tuple's op kind must be THE PROPOSAL'S recorded action kind, never an
/// amendable kind claimed about a non-op row (a resolution of an undo row,
/// say). Needs no store, so it rides the stateless decode path every
/// admission — local door and sync replay alike — passes through.
pub(super) fn validate_resolution_scope_stateless(record: &StoredIdentityOpEvent) -> Result<()> {
    let StoredIdentityOpAction::ProposalResolution { scope, .. } = &record.action else {
        return Ok(());
    };
    let proposal_is_op = matches!(scope.op_kind, EVENT_KIND_MERGE | EVENT_KIND_SPLIT);
    if !proposal_is_op {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology proposal resolution scope names a non-op kind",
        ));
    }
    Ok(())
}

/// The AMENDABLE op kinds: only the two ops whose apply door is armed and
/// whose subject set is expressible on the wire. A resolution's scope
/// `op_kind` is one of these by construction (a proposal of an unarmed kind
/// never reaches the ledger), so a stored value outside the set is
/// malformed.
pub(super) fn decode_amendable_kind(value: &str) -> Result<&'static str> {
    match value {
        EVENT_KIND_MERGE => Ok(EVENT_KIND_MERGE),
        EVENT_KIND_SPLIT => Ok(EVENT_KIND_SPLIT),
        _ => Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology proposal scope op kind is unknown",
        )),
    }
}

/// Encodes an amended op body: the SAME pinned MessagePack action shape the
/// ledger stores, minus the event envelope (seq/at/actor/consent are the
/// resolution's own, never the amendment's).
///
/// One codec, two directions — a decider builds the amended body with this
/// and [`decode_identity_op_amendment`] parses it back at the door, so an
/// amendment can never carry a shape the ledger cannot store.
pub fn encode_identity_op_amendment(op: &IdentityTopologyOp) -> Result<Vec<u8>> {
    let action = match op {
        IdentityTopologyOp::Merge(merge) => StoredIdentityOpAction::Merge {
            sources: merge.sources.clone(),
            survivor: merge.survivor,
        },
        IdentityTopologyOp::Split(split) => StoredIdentityOpAction::Split {
            entity: split.entity,
            heads: split.heads.clone(),
            reassignment: split.reassignment.canonicalized(),
            // An amendment is a PROPOSED body, not an applied record: it has
            // recorded nothing yet, and the counts it carries would be the
            // decider's claim about an application that has not happened.
            applied_assigned: 0,
            applied_residue: 0,
        },
        // A facet op has no propose lane (see `apply_identity_topology_op`),
        // so it has no park to amend either.
        IdentityTopologyOp::Facet(_) | IdentityTopologyOp::AssertDistinct(_) => {
            return Err(Error::IdentityTopologyUnarmed("amendment of this op kind"));
        }
    };
    let mut entries = vec![(Value::from(BODY_KEY_KIND), Value::from(action.kind_str()))];
    encode_action_entries(&action, &mut entries);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(entries)).map_err(|_| {
        Error::InvalidIdentityTopologyEventBody("identity topology amendment encode failed")
    })?;
    Ok(data)
}

/// Decodes an amended op body, fail-closed and canonical: the bytes must
/// re-encode identically, so a decider cannot smuggle a non-canonical
/// encoding past the scope check and have the ledger store different bytes
/// than were validated.
pub fn decode_identity_op_amendment(data: &[u8]) -> Result<IdentityTopologyOp> {
    const AMENDMENT_CONTEXT: &str = "identity topology amendment";
    if data.len() > MAX_IDENTITY_TOPOLOGY_EVENT_BODY_BYTES {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology amendment exceeds the size limit",
        ));
    }
    let mut cursor = data;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidIdentityTopologyEventBody(AMENDMENT_CONTEXT))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology amendment carries trailing bytes",
        ));
    }
    let map = value
        .as_map()
        .ok_or(Error::InvalidIdentityTopologyEventBody(AMENDMENT_CONTEXT))?;
    let kind = decode_str_field(map, BODY_KEY_KIND, AMENDMENT_CONTEXT)?;
    let action = decode_action(kind, map)?;
    let op = match action.to_fold_action() {
        IdentityTopologyAction::Apply(op) => op,
        // undo / resolution rows are not ops a proposal can name, so they
        // are not amendable shapes either.
        IdentityTopologyAction::Undo { .. } | IdentityTopologyAction::ResolveProposal { .. } => {
            return Err(Error::InvalidIdentityTopologyEventBody(
                "identity topology amendment is not an op",
            ));
        }
    };
    if encode_identity_op_amendment(&op)? != data {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology amendment is not canonical",
        ));
    }
    Ok(op)
}

impl Vault {
    /// Resolves a parked `Proposed` identity-topology event (ARCH-0055 r7):
    /// applies the proposed op (`Approve`), applies an AMENDED form of it
    /// (`AmendThenApprove`), or retires the park with zero topology effects
    /// (`Reject`). All three paths append exactly ONE proposal-resolution
    /// event in the same write txn, which is both the retirement of the park
    /// and the substrate the `ProposalOutcome` receipt projects from.
    ///
    /// An approving ruling applies through the ordinary
    /// [`Vault::apply_identity_topology_op`] machinery under
    /// `ClaimApprovalStatus::Approved`, so the applied op lands as its own
    /// ordinary ledger event with its own effects — the resolution row
    /// records the DECISION, never a second copy of the effect. The park
    /// itself is never rewritten (r1).
    ///
    /// An amendment may only NARROW what the decider reviewed: the amended
    /// body must decode to the same op kind and name a subset of the
    /// proposal's subjects, else
    /// [`Error::IdentityProposalAmendmentOutOfScope`] and nothing is
    /// written. This is the pin that keeps amendment from being an
    /// op-substitution capability.
    ///
    /// `write` carries the RULER's consent axes (which must be effective —
    /// a ruling is the act of deciding, so it cannot itself be parked);
    /// the ramp scope stamped on the receipt describes the PROPOSER.
    ///
    /// Returns the recorded outcome and the resolution event's id, which is
    /// also the receipt handle.
    pub fn resolve_identity_proposal(
        &self,
        proposal: &EntityId,
        ruling: ProposalRuling<'_>,
        write: &IdentityOpWrite,
        now: u64,
    ) -> Result<(ProposalOutcome, EntityId)> {
        let mut wtxn = self.store.env.write_txn()?;
        let resolved =
            self.resolve_identity_proposal_in_txn(&mut wtxn, proposal, ruling, write, now)?;
        wtxn.commit()?;
        Ok(resolved)
    }

    /// Transaction-composable [`Vault::resolve_identity_proposal`].
    pub(crate) fn resolve_identity_proposal_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        proposal: &EntityId,
        ruling: ProposalRuling<'_>,
        write: &IdentityOpWrite,
        now: u64,
    ) -> Result<(ProposalOutcome, EntityId)> {
        if !write.is_effective() {
            return Err(Error::IdentityTopologyRejected(
                IdentityTopologyRejection::ProposalRulingNotEffective,
            ));
        }
        self.validate_identity_op_actor_in_txn(&*wtxn, write)?;

        let record = self
            .identity_topology_event_in_txn(&*wtxn, proposal)?
            .ok_or(Error::EntityNotFound)?;
        // The resolution rule, shared with replicated admission: the park
        // is still open, the fold has not retired it, and the ruling's own
        // axis is effective. The replicated replay of the row this door is
        // about to write re-derives exactly these cells from the ledger.
        let proposed_op = self.validate_identity_proposal_resolution_in_txn(
            &*wtxn,
            proposal,
            &record,
            write.approval,
            None,
        )?;

        // Validate the amendment BEFORE anything is written: an out-of-scope
        // body must leave the park open and untouched.
        let amended = match ruling {
            ProposalRuling::AmendThenApprove(body) => {
                let amended_op = decode_identity_op_amendment(body).map_err(|_| {
                    Error::IdentityProposalAmendmentOutOfScope("amended body is malformed")
                })?;
                assert_amendment_in_scope(&proposed_op, &amended_op)?;
                Some((amended_op, body.to_vec()))
            }
            ProposalRuling::Approve | ProposalRuling::Reject => None,
        };

        let scope = self.proposal_scope_in_txn(&*wtxn, &record, &proposed_op)?;
        let proposer_evidence = record.evidence.as_ref();
        let (outcome, amended_body) = match (&ruling, amended) {
            (ProposalRuling::Reject, _) => (ProposalOutcome::Rejected, None),
            (ProposalRuling::Approve, _) => {
                self.apply_resolved_identity_op_in_txn(
                    wtxn,
                    &proposed_op,
                    proposer_evidence,
                    write,
                    now,
                )?;
                (ProposalOutcome::ApprovedUntouched, None)
            }
            (ProposalRuling::AmendThenApprove(_), Some((amended_op, body))) => {
                self.apply_resolved_identity_op_in_txn(
                    wtxn,
                    &amended_op,
                    proposer_evidence,
                    write,
                    now,
                )?;
                (ProposalOutcome::ApprovedAmended, Some(body))
            }
            // `amended` is Some exactly when the ruling is AmendThenApprove.
            (ProposalRuling::AmendThenApprove(_), None) => {
                return Err(Error::InvariantViolation(
                    "identity proposal amendment decode state",
                ));
            }
        };

        // MS-06 (ONE-1748): the ledger row is truth, so it lands first; the
        // ramp's per-scope counters are a projection folded from it in the same
        // transaction. This is the ONE site that feeds the ramp from this
        // family, and it MEASURES only — merge/split can never graduate, and
        // no apply path here consults the ramp (r7 §5, oracle
        // `ms06_merge_split_never_gated_by_ramp`).
        let ramp_scope = crate::consent_graduation::RampScope::from(&scope);
        let event = self.write_identity_event_in_txn(
            wtxn,
            EntityId::now(),
            write,
            now,
            StoredIdentityOpAction::ProposalResolution {
                proposal: *proposal,
                outcome,
                scope,
                amended_body,
            },
            None,
            Vec::new(),
            Vec::new(),
        )?;
        crate::consent_graduation::record_ramp_outcome_in_txn(
            self,
            wtxn,
            &ramp_scope,
            outcome,
            now,
        )?;
        let IdentityOpOutcome::Applied {
            event: event_id, ..
        } = event
        else {
            // The effective-consent check at the top of this door makes the
            // parked/no-op shapes unreachable.
            return Err(Error::InvariantViolation(
                "identity proposal resolution must be effective",
            ));
        };
        Ok((outcome, event_id))
    }

    /// Applies the op a ruling approved, under `Approved` consent — the
    /// decider's ruling IS the approval, whatever axis the original
    /// proposal carried. The proposal row's evidence rides along: the
    /// stored-action codec reconstructs an op without it
    /// (`to_fold_action` carries no envelope data), and an approved ruling
    /// must not silently sever the decision from the refs and rationale
    /// that motivated it.
    fn apply_resolved_identity_op_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        op: &IdentityTopologyOp,
        proposer_evidence: Option<&IdentityOpEvidence>,
        write: &IdentityOpWrite,
        now: u64,
    ) -> Result<()> {
        let applied_write = IdentityOpWrite {
            approval: ClaimApprovalStatus::Approved,
            ..*write
        };
        let op = match (proposer_evidence, op) {
            (Some(evidence), IdentityTopologyOp::Merge(merge)) => {
                IdentityTopologyOp::Merge(MergeOp {
                    evidence: evidence.clone(),
                    ..merge.clone()
                })
            }
            (Some(evidence), IdentityTopologyOp::Split(split)) => {
                IdentityTopologyOp::Split(SplitOp {
                    evidence: evidence.clone(),
                    ..split.clone()
                })
            }
            _ => op.clone(),
        };
        self.apply_identity_topology_op_in_txn(wtxn, &op, &applied_write, now)?;
        Ok(())
    }

    /// Stamps the DEC-0006 ramp scope of a resolved proposal: the op kind,
    /// the registry class name of the op's primary target, and the
    /// PROPOSING actor.
    fn proposal_scope_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        record: &StoredIdentityOpEvent,
        op: &IdentityTopologyOp,
    ) -> Result<ProposalScope> {
        let target = proposal_scope_target(op)?;
        let target_class = self
            .get_entity_type_in_txn(rtxn, &target)?
            .and_then(entity_type_registry_entry)
            .ok_or(Error::EntityNotFound)?
            .kind;
        Ok(proposal_scope_of(record, target_class))
    }

    /// THE proposal-resolution rule, run by BOTH doors a resolution row can
    /// enter through — the local [`Vault::resolve_identity_proposal_in_txn`]
    /// ruling and replicated type-76 admission. One validator, never two
    /// drifting copies: the local door enforces exactly what a remote peer's
    /// replay of the same row must later re-derive.
    ///
    /// All four cells, evaluated in ONE read against the store:
    /// the named park EXISTS and is still `Proposed` (an op row, never an
    /// undo or a resolution); the fold has not already retired it; the
    /// RULING's consent axis is effective — `ruling_approval` is the
    /// resolution's own axis (`write.approval` at the local door,
    /// `record.approval` on the wire), because deciding is itself an
    /// effective act and a resolution authored under a parked or consent-
    /// rejected axis is no ruling at all; and the stamped ramp scope is
    /// DERIVED from the proposal's own row, so a row cannot carry a scope
    /// it was never ruled under. Returns the decoded proposed op (the door
    /// applies it; replicated admission only checks, never applies).
    pub(super) fn validate_identity_proposal_resolution_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        proposal: &EntityId,
        proposal_record: &StoredIdentityOpEvent,
        ruling_approval: ClaimApprovalStatus,
        stamped: Option<&ProposalScope>,
    ) -> Result<IdentityTopologyOp> {
        if !matches!(
            ruling_approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        ) {
            return Err(Error::IdentityTopologyRejected(
                IdentityTopologyRejection::ProposalRulingNotEffective,
            ));
        }
        if proposal_record.approval != ClaimApprovalStatus::Proposed {
            return Err(Error::IdentityTopologyRejected(
                IdentityTopologyRejection::NotProposed { event: *proposal },
            ));
        }
        let IdentityTopologyAction::Apply(proposed_op) = proposal_record.action.to_fold_action()
        else {
            // Undo and resolution rows are never `Proposed`-parked ops a
            // ruling can act on; the approval check above already excludes
            // them, so this is defence at the type seam.
            return Err(Error::IdentityTopologyRejected(
                IdentityTopologyRejection::NotProposed { event: *proposal },
            ));
        };
        // The fold a fresh resolution is judged against EXCLUDES the row
        // being admitted — a replicated event validates against history
        // alone, and the local door runs this before its own row exists.
        let fold =
            fold_identity_topology_log(&self.fold_effective_identity_topology_events_in_txn(rtxn)?);
        if fold.resolved_proposals.contains_key(proposal) {
            return Err(Error::IdentityTopologyRejected(
                IdentityTopologyRejection::ProposalAlreadyResolved {
                    proposal: *proposal,
                },
            ));
        }
        if let Some(stamped) = stamped {
            let derived = self.proposal_scope_in_txn(rtxn, proposal_record, &proposed_op)?;
            if stamped.op_kind != derived.op_kind
                || stamped.target_class != derived.target_class
                || stamped.actor != derived.actor
            {
                return Err(Error::IdentityTopologyRejected(
                    IdentityTopologyRejection::ResolutionRuleMismatch {
                        reason: "stamped ramp scope is not the proposal's derived tuple",
                    },
                ));
            }
        }
        Ok(proposed_op)
    }
}
