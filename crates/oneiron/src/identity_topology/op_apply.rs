//! The apply door: the per-write consent metadata, the door outcome, the
//! merge/split/facet/assert_distinct dispatch, facet minting, and the shared
//! event+effects commit chokepoint every door in this family writes through.

use std::collections::{BTreeMap, BTreeSet};

use crate::batch::{BatchOp, apply_ops};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT};
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

use super::MAX_IDENTITY_TOPOLOGY_EVENT_FACETS;
use super::distinct_claim::distinct_pair_key;
use super::encode_identity_topology_event_body;
use super::lifecycle_state::EntityLifecycleState;
use super::op_vocabulary::{FacetOp, IdentityOpEvidence, IdentityTopologyOp};
use super::reassignment_map::ReassignmentStats;
use super::store_entity_helpers::topology_edge_weight;
use super::stored_event::{StoredIdentityOpAction, StoredIdentityOpEvent};
use super::transition_table::{IdentityTopologyRejection, evaluate_transition};
use super::{ReassignmentContext, apply_reassignment_in_txn};

/// Write metadata for one identity-topology op: the consent axes the ledger
/// event record carries. AUTO is the family default (r3); the propose lane
/// is the caller dialing `approval` to `Proposed` for the three exception
/// conditions (§6) — never an engine-imposed gate.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IdentityOpWrite {
    /// Provenance source stamped on the event record.
    pub source: ClaimSource,
    /// Consent axis: `Auto`/`Approved` apply, `Proposed` parks with zero
    /// topology effects, `Rejected` is the consent no-op.
    pub approval: ClaimApprovalStatus,
    /// Confidence stamped on the event record, finite in `[0, 1]`.
    pub confidence: f32,
    /// Deciding actor recorded on the event (r1); validated at the door
    /// (existence + type/class fit) when bound.
    pub actor: Option<WriteActor>,
}

impl IdentityOpWrite {
    /// The r3 default: auto-approved, full confidence, no bound actor.
    #[must_use]
    pub const fn auto(source: ClaimSource) -> Self {
        Self {
            source,
            approval: ClaimApprovalStatus::Auto,
            confidence: 1.0,
            actor: None,
        }
    }

    /// Binds the deciding actor recorded on the ledger event.
    #[must_use]
    pub const fn with_actor(mut self, actor: WriteActor) -> Self {
        self.actor = Some(actor);
        self
    }

    pub(super) const fn is_effective(&self) -> bool {
        is_effective_approval(self.approval)
    }
}

/// The consent axis the fold APPLIES (r3): `Auto`/`Approved` carry topology
/// effects, `Proposed` parks with none, `Rejected` is the no-op.
///
/// One derivation, two readers: the local apply door reaches it through
/// [`IdentityOpWrite::is_effective`], and the stateless replicated-body
/// admission reads it off the stored record — so a rule keyed on "did this
/// event apply anything?" cannot drift between the two doors.
pub(super) const fn is_effective_approval(approval: ClaimApprovalStatus) -> bool {
    matches!(
        approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    )
}

/// Receipt of one identity-topology door call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityOpOutcome {
    /// `Auto`/`Approved`: topology written, event recorded.
    Applied {
        /// The ledger event record written for this op.
        event: EntityId,
        /// Lifecycle assignments the op performed, in role order.
        transitions: Vec<(EntityId, EntityLifecycleState)>,
    },
    /// `Proposed`: the event is recorded for legibility, but no edge and no
    /// lifecycle state moved — zero topology effects until approved.
    ///
    /// ONE-1746 exception, by design: a `Proposed` `assert_distinct` DOES
    /// mint its `entity.distinct_from` claim, in the `Proposed` state. That
    /// claim is the assertion's own consent surface — it suppresses nothing
    /// until approved, and a proposal with no row could never be approved.
    Parked {
        /// The parked ledger event record.
        event: EntityId,
    },
    /// `Rejected`: the consent no-op — nothing validated, nothing written.
    Noop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum IdentityTopologyParticipantValidation {
    Complete,
    Deferred,
    Invalid(IdentityTopologyRejection),
}

impl Vault {
    /// Applies one identity-topology op in ONE write transaction: validates
    /// the bound actor (existence + type/class fit, the provenance rule),
    /// the storage guards, and the (state, op) transition table; then per
    /// the consent axis writes the canonical shell edges plus the type-76
    /// ledger event (`Auto`/`Approved`), parks the event with zero topology
    /// effects (`Proposed`), or no-ops (`Rejected`). Fail-closed — nothing
    /// is written on any rejection. No participant is tombstoned and no
    /// claim subject is rewritten (r1/r6).
    ///
    /// An `assert_distinct` op writes its `entity.distinct_from` CLAIM
    /// through the ordinary claim door (ONE-1746) and is idempotent: a live
    /// claim for the pair is adopted rather than duplicated. Unlike the
    /// topology arms, its consent axis lands ON that claim's `appr` column
    /// rather than being withheld from it — a `Proposed` assertion IS a
    /// proposed claim, which suppresses nothing until it is ruled. The
    /// ruling door is a later EFFECTIVE assertion of the same pair, which
    /// promotes the parked row in place and hands back its id. Withholding
    /// the row instead would strand the proposal outright:
    /// `proposal_scope_target` is
    /// unarmed for this op kind, so
    /// [`Vault::resolve_identity_proposal`] can never reach the park.
    pub fn apply_identity_topology_op(
        &self,
        op: &IdentityTopologyOp,
        write: &IdentityOpWrite,
        now: u64,
    ) -> Result<IdentityOpOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.apply_identity_topology_op_in_txn(&mut wtxn, op, write, now)?;
        wtxn.commit()?;
        Ok(outcome)
    }

    /// Transaction-composable [`Vault::apply_identity_topology_op`].
    pub(crate) fn apply_identity_topology_op_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        op: &IdentityTopologyOp,
        write: &IdentityOpWrite,
        now: u64,
    ) -> Result<IdentityOpOutcome> {
        if write.approval == ClaimApprovalStatus::Rejected {
            return Ok(IdentityOpOutcome::Noop);
        }
        // ARCH-0055 §6 re-proposal suppression (ONE-1746). Propose and apply
        // are ONE door, separated only by `write.approval`, so the gate sits
        // here behind `!is_effective()`: a PROPOSED merge over a pair an
        // effective `entity.distinct_from` claim covers is refused, while an
        // `Auto`/`Approved` merge — an owner ruling on the pair — passes
        // untouched. It cannot live in `evaluate_transition`: that fn is pure
        // and sees neither the approval axis nor a txn to read claims from.
        if !write.is_effective()
            && let IdentityTopologyOp::Merge(merge) = op
            && let Some((a, b)) = self.suppressed_merge_pair_in_txn(&*wtxn, merge)?
        {
            return Err(Error::IdentityTopologyRejected(
                IdentityTopologyRejection::DistinctPairSuppressed { a, b },
            ));
        }
        self.validate_identity_op_actor_in_txn(&*wtxn, write)?;

        let participants = op.participants();
        match self.validate_identity_op_participants_in_txn(&*wtxn, op)? {
            IdentityTopologyParticipantValidation::Complete => {}
            IdentityTopologyParticipantValidation::Deferred => {
                return Err(Error::EntityNotFound);
            }
            IdentityTopologyParticipantValidation::Invalid(rejection) => {
                return Err(Error::IdentityTopologyRejected(rejection));
            }
        }
        // Folded ONCE for the whole op: the zero-head-shell witness is the
        // same for every participant, and folding per participant would pay
        // the family scan N times.
        let zero_head_shells = self.zero_head_split_shells_in_txn(&*wtxn)?;
        let mut states = BTreeMap::new();
        for participant in &participants {
            states.insert(
                *participant,
                self.entity_lifecycle_state_with_zero_head_shells_in_txn(
                    &*wtxn,
                    participant,
                    Some(&zero_head_shells),
                )?,
            );
        }
        let transitions =
            evaluate_transition(&states, op).map_err(Error::IdentityTopologyRejected)?;

        // Minted in the arm rather than at the write chokepoint: the
        // reassignment index files each row under the event that stated it,
        // so the event's identity has to exist before its effects do.
        let event_id = EntityId::now();
        match op {
            IdentityTopologyOp::Merge(merge) => {
                let action = StoredIdentityOpAction::Merge {
                    sources: merge.sources.clone(),
                    survivor: merge.survivor,
                };
                let mut effects = Vec::new();
                if write.is_effective() {
                    let weight = topology_edge_weight(EdgeKind::MergedInto)?;
                    for source in &merge.sources {
                        effects.push(BatchOp::EdgeWithCreatedAt {
                            src: *source,
                            kind: EdgeKind::MergedInto,
                            tgt: merge.survivor,
                            weight,
                            created_at: now,
                            vad: crate::affect::Vad::NEUTRAL,
                            provenance: None,
                        });
                    }
                }
                self.write_identity_event_in_txn(
                    wtxn,
                    event_id,
                    write,
                    now,
                    action,
                    Some(merge.evidence.clone()),
                    effects,
                    transitions,
                )
            }
            IdentityTopologyOp::Split(split) => {
                let mut effects = Vec::new();
                let mut stats = ReassignmentStats::default();
                if write.is_effective() {
                    let weight = topology_edge_weight(EdgeKind::SplitInto)?;
                    for head in &split.heads {
                        effects.push(BatchOp::EdgeWithCreatedAt {
                            src: split.entity,
                            kind: EdgeKind::SplitInto,
                            tgt: *head,
                            weight,
                            created_at: now,
                            vad: crate::affect::Vad::NEUTRAL,
                            provenance: None,
                        });
                    }
                    stats = apply_reassignment_in_txn(
                        &self.store,
                        wtxn,
                        &event_id,
                        &split.entity,
                        &split.reassignment,
                        ReassignmentContext::Heads(&split.heads),
                        &mut effects,
                        now,
                    )?;
                }
                let action = StoredIdentityOpAction::Split {
                    entity: split.entity,
                    heads: split.heads.clone(),
                    reassignment: split.reassignment.canonicalized(),
                    applied_assigned: stats.assigned as u64,
                    applied_residue: stats.residue as u64,
                };
                self.write_identity_event_in_txn(
                    wtxn,
                    event_id,
                    write,
                    now,
                    action,
                    Some(split.evidence.clone()),
                    effects,
                    transitions,
                )
            }
            IdentityTopologyOp::Facet(facet) => {
                // The propose lane is not armed for this kind: a parked facet
                // event would have to name masks it never minted, and the
                // resolution door has no scope target for it
                // ([`proposal_scope_target`]) — so the park could never be
                // ruled on. Refusing to record it is the honest answer;
                // recording an unresolvable one is the ledger corruption this
                // door exists to prevent.
                if !write.is_effective() {
                    return Err(Error::IdentityTopologyUnarmed("facet proposal"));
                }
                if facet.facets.len() > MAX_IDENTITY_TOPOLOGY_EVENT_FACETS {
                    return Err(Error::InvalidIdentityTopologyEventBody(
                        "identity topology event mints too many facets",
                    ));
                }
                let (minted, mut effects) = self.mint_facets_in_txn(facet, now)?;
                let stats = apply_reassignment_in_txn(
                    &self.store,
                    wtxn,
                    &event_id,
                    &facet.entity,
                    &facet.reassignment,
                    ReassignmentContext::Facets(&minted),
                    &mut effects,
                    now,
                )?;
                let action = StoredIdentityOpAction::Facet {
                    entity: facet.entity,
                    facets: minted,
                    reassignment: facet.reassignment.canonicalized(),
                    applied_assigned: stats.assigned as u64,
                    applied_residue: stats.residue as u64,
                };
                self.write_identity_event_in_txn(
                    wtxn,
                    event_id,
                    write,
                    now,
                    action,
                    Some(facet.evidence.clone()),
                    effects,
                    transitions,
                )
            }
            IdentityTopologyOp::AssertDistinct(distinct) => {
                let pair = distinct_pair_key(distinct.a, distinct.b);
                let claim = self.assert_distinct_claim_in_txn(wtxn, write, pair, now)?;
                self.write_identity_event_in_txn(
                    wtxn,
                    event_id,
                    write,
                    now,
                    StoredIdentityOpAction::AssertDistinct {
                        a: pair.0,
                        b: pair.1,
                        claim,
                    },
                    // The reason is the decision's rationale, recorded where
                    // every other op in this family records one.
                    Some(IdentityOpEvidence {
                        refs: Vec::new(),
                        rationale: distinct.reason.clone(),
                    }),
                    Vec::new(),
                    transitions,
                )
            }
        }
    }

    /// Mints one ARCH-0022 FACET (type-13) entity per spec and wires each to
    /// its base with a `has_facet` edge, returning the minted ids in SPEC
    /// ORDER — the order every [`ReassignmentTarget::Facet`](super::ReassignmentTarget::Facet) index addresses,
    /// and the order the ledger event stores.
    ///
    /// Mints nothing but FACET ids (r6): the base entity is untouched, the
    /// op's only new rows are the masks themselves. The label is the FACET
    /// body — runtime data, stored where a reader of that entity finds it,
    /// never on the ledger event.
    fn mint_facets_in_txn(
        &self,
        facet: &FacetOp,
        now: u64,
    ) -> Result<(Vec<EntityId>, Vec<BatchOp>)> {
        let weight = topology_edge_weight(EdgeKind::HasFacet)?;
        let mut minted = Vec::with_capacity(facet.facets.len());
        let mut ops = Vec::with_capacity(facet.facets.len() * 2);
        for spec in &facet.facets {
            let id = EntityId::now();
            minted.push(id);
            ops.push(BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_FACET,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                data: spec.label.as_bytes().to_vec(),
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            });
            ops.push(BatchOp::EdgeWithCreatedAt {
                src: facet.entity,
                kind: EdgeKind::HasFacet,
                tgt: id,
                weight,
                created_at: now,
                vad: crate::affect::Vad::NEUTRAL,
                provenance: None,
            });
        }
        Ok((minted, ops))
    }

    /// Stamps `seq`, writes the type-76 event record under the caller's
    /// `event_id` plus the staged effect ops atomically, and shapes the
    /// outcome from the consent axis.
    ///
    /// The id is the CALLER's because an op's effects may have to be filed
    /// under it before the record exists — the ONE-1745 assignment index
    /// keys every row by the event that stated it.
    #[expect(
        clippy::too_many_arguments,
        reason = "single internal chokepoint for the door's event+effects commit"
    )]
    pub(super) fn write_identity_event_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        event_id: EntityId,
        write: &IdentityOpWrite,
        now: u64,
        action: StoredIdentityOpAction,
        evidence: Option<IdentityOpEvidence>,
        effects: Vec<BatchOp>,
        transitions: Vec<(EntityId, EntityLifecycleState)>,
    ) -> Result<IdentityOpOutcome> {
        let seq = self.next_identity_topology_seq_in_txn(wtxn)?;
        let record = StoredIdentityOpEvent {
            seq,
            at: now,
            actor: write.actor,
            source: write.source,
            approval: write.approval,
            confidence: write.confidence,
            evidence,
            action,
        };
        let mut ops = vec![BatchOp::Put {
            id: event_id,
            entity_type: ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            data: encode_identity_topology_event_body(&record)?,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }];
        // Order matters inside the batch: a facet op's minted FACET rows
        // precede the `facet_of` stamps that point at them, and ONE-1645's
        // write-time table fails closed on a stamp whose endpoint has no row.
        ops.extend(effects);
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        if write.is_effective() {
            // ONE-1744 redirect maintenance, AFTER the edges land: the
            // projection derives each row from the post-op shell edges (plus
            // the ledger for the zero-head arm), so running it before
            // `apply_ops` would project the topology this event replaces.
            // A parked event moves no topology and maintains nothing.
            let touched: BTreeSet<EntityId> =
                transitions.iter().map(|(entity, _)| *entity).collect();
            // The zero-head witness comes from the ACTION, not a fold: this
            // door already knows whether the op it just wrote is a zero-head
            // split, and folding the event family here would make a run of N
            // topology ops O(N²).
            let zero_head_shells: BTreeSet<EntityId> = match &record.action {
                StoredIdentityOpAction::Split { entity, heads, .. } if heads.is_empty() => {
                    BTreeSet::from([*entity])
                }
                _ => BTreeSet::new(),
            };
            crate::identity_redirect::maintain_redirect_projection_in_txn(
                &self.store,
                wtxn,
                &touched,
                &zero_head_shells,
            )?;
            Ok(IdentityOpOutcome::Applied {
                event: event_id,
                transitions,
            })
        } else {
            Ok(IdentityOpOutcome::Parked { event: event_id })
        }
    }
}
