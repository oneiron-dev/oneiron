//! The type-76 wire record types: one stored ledger event, the action payload
//! it carries, and their pinned MessagePack encode/decode.

use rmpv::Value;

use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::write_envelope::WriteActor;

use super::event_body_codec::{
    decode_action, decode_actor, decode_evidence, decode_str_field, decode_u64_field,
    encode_action_entries, id_value, ids_value, map_field,
};
use super::ledger_fold::IdentityTopologyAction;
use super::op_vocabulary::{
    AssertDistinctOp, FacetOp, FacetSpec, IdentityOpEvidence, IdentityTopologyOp, MergeOp, SplitOp,
    SurvivorshipPlan,
};
use super::reassignment_map::{ReassignmentMap, ReassignmentStats};
use super::transition_table::{ProposalOutcome, ProposalScope};
use super::wire_keys::{
    BODY_KEY_ACTOR, BODY_KEY_ACTOR_CLASS, BODY_KEY_APPROVAL, BODY_KEY_AT, BODY_KEY_CONFIDENCE,
    BODY_KEY_EVIDENCE, BODY_KEY_KIND, BODY_KEY_SEQ, BODY_KEY_SOURCE, EVENT_KIND_ASSERT_DISTINCT,
    EVENT_KIND_FACET, EVENT_KIND_MERGE, EVENT_KIND_PROPOSAL_RESOLUTION, EVENT_KIND_SPLIT,
    EVENT_KIND_UNDO, EVIDENCE_KEY_RATIONALE, EVIDENCE_KEY_REFS,
};

/// Action payload of one stored ledger event. The split map is carried
/// CANONICALLY (never discarded) so ONE-1745 replays exactly what the
/// decision stated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredIdentityOpAction {
    /// A merge event.
    Merge {
        /// Losing entities.
        sources: Vec<EntityId>,
        /// Surviving canonical head.
        survivor: EntityId,
    },
    /// A split event carrying its full reassignment map.
    Split {
        /// The split original.
        entity: EntityId,
        /// Head entities.
        heads: Vec<EntityId>,
        /// Canonically ordered reassignment map.
        reassignment: ReassignmentMap,
        /// Map rows the apply door recorded against a head (ONE-1745).
        applied_assigned: u64,
        /// Map rows it recorded as explicit ambiguous residue.
        applied_residue: u64,
    },
    /// A facet event and the masks it minted (ARCH-0022 type-13, ONE-1745).
    /// Every stored facet event is an APPLIED one: the propose lane is not
    /// armed for this kind (see [`Vault::apply_identity_topology_op`](crate::Vault::apply_identity_topology_op)), so
    /// `facets` is never empty and always names live FACET entities.
    Facet {
        /// The entity whose masks were partitioned; stays `Active` (r6).
        entity: EntityId,
        /// Minted FACET entity ids, in the op's spec order — the order every
        /// [`ReassignmentTarget::Facet`](super::ReassignmentTarget::Facet) index addresses.
        facets: Vec<EntityId>,
        /// Canonically ordered scoping map.
        reassignment: ReassignmentMap,
        /// Map rows the apply door scoped to a mask.
        applied_assigned: u64,
        /// Map rows it left unscoped.
        applied_residue: u64,
    },
    /// An anti-merge assertion and the CLAIM it is carried by (ONE-1746).
    /// The pair is stored NORMALIZED ([`distinct_pair_key`](super::distinct_pair_key)), so the ledger
    /// speaks the same single shape the claim does.
    AssertDistinct {
        /// Lexicographically-first side of the pair; also the claim subject.
        a: EntityId,
        /// Lexicographically-last side of the pair.
        b: EntityId,
        /// The `entity.distinct_from` CLAIM this event asserted through —
        /// newly minted, or the live one a re-assertion adopted.
        claim: EntityId,
    },
    /// A counter-event reverting `target`.
    Undo {
        /// The reverted ledger event.
        target: EntityId,
    },
    /// The r7 resolution of a parked `Proposed` event (ONE-1747). Appending
    /// this row IS the retirement of the park: a proposal carrying one is
    /// already resolved and refuses a second ruling. The resolution itself
    /// moves no lifecycle state — on an approving ruling the APPLIED op is
    /// recorded as its own ordinary event, and this row records the
    /// decision about it.
    ProposalResolution {
        /// The resolved type-76 `Proposed` event.
        proposal: EntityId,
        /// Which of the three r7 states the ruling produced.
        outcome: ProposalOutcome,
        /// The DEC-0006 ramp scope, stamped from the resolved proposal.
        scope: ProposalScope,
        /// The encoded amended op body, present ONLY on
        /// [`ProposalOutcome::ApprovedAmended`] — preserved verbatim as the
        /// producer artifact ED-01 (ONE-1757) diffs against the proposal.
        amended_body: Option<Vec<u8>>,
    },
}

impl StoredIdentityOpAction {
    /// The pinned wire/receipt kind string for this action.
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::Merge { .. } => EVENT_KIND_MERGE,
            Self::Split { .. } => EVENT_KIND_SPLIT,
            Self::Facet { .. } => EVENT_KIND_FACET,
            Self::AssertDistinct { .. } => EVENT_KIND_ASSERT_DISTINCT,
            Self::Undo { .. } => EVENT_KIND_UNDO,
            Self::ProposalResolution { .. } => EVENT_KIND_PROPOSAL_RESOLUTION,
        }
    }

    /// The reassignment map this action carries, if its op kind has one —
    /// the DECLARED decision (ARCH-0055 r2/r5).
    #[must_use]
    pub const fn reassignment_map(&self) -> Option<&ReassignmentMap> {
        match self {
            Self::Split { reassignment, .. } | Self::Facet { reassignment, .. } => {
                Some(reassignment)
            }
            Self::Merge { .. }
            | Self::AssertDistinct { .. }
            | Self::Undo { .. }
            | Self::ProposalResolution { .. } => None,
        }
    }

    /// What the apply door actually RECORDED for that map (ONE-1745), which
    /// may be less than the map declared: a row naming an item the vault
    /// holds no CLAIM for records nothing.
    ///
    /// Stamped onto the event at apply time precisely so this read needs no
    /// vault — the receipt projector is a pure function of the record.
    #[must_use]
    pub const fn applied_reassignment_stats(&self) -> Option<ReassignmentStats> {
        match self {
            Self::Split {
                applied_assigned,
                applied_residue,
                ..
            }
            | Self::Facet {
                applied_assigned,
                applied_residue,
                ..
            } => Some(ReassignmentStats {
                assigned: *applied_assigned as usize,
                residue: *applied_residue as usize,
            }),
            Self::Merge { .. }
            | Self::AssertDistinct { .. }
            | Self::Undo { .. }
            | Self::ProposalResolution { .. } => None,
        }
    }

    /// Reconstructs the fold-grade action. Evidence and survivorship plan
    /// do not participate in transition evaluation; the split map rides
    /// along verbatim.
    ///
    /// Facet SPEC LABELS are reconstructed as placeholders, for the same
    /// reason evidence is: the transition table reads only the mask COUNT
    /// (`facets.is_empty()` and the index bound), never a label. The labels
    /// themselves are runtime data on the minted FACET entity bodies, which
    /// is where a reader wanting them looks. An assert_distinct REASON is a
    /// placeholder for the identical reason — it rides the event's evidence
    /// rationale, which is where a reader wanting it looks.
    #[must_use]
    pub fn to_fold_action(&self) -> IdentityTopologyAction {
        match self {
            Self::Merge { sources, survivor } => {
                IdentityTopologyAction::Apply(IdentityTopologyOp::Merge(MergeOp {
                    sources: sources.clone(),
                    survivor: *survivor,
                    evidence: IdentityOpEvidence::default(),
                    survivorship_plan: SurvivorshipPlan::ReadThrough,
                }))
            }
            Self::Split {
                entity,
                heads,
                reassignment,
                ..
            } => IdentityTopologyAction::Apply(IdentityTopologyOp::Split(SplitOp {
                entity: *entity,
                heads: heads.clone(),
                reassignment: reassignment.clone(),
                evidence: IdentityOpEvidence::default(),
            })),
            Self::Facet {
                entity,
                facets,
                reassignment,
                ..
            } => IdentityTopologyAction::Apply(IdentityTopologyOp::Facet(FacetOp {
                entity: *entity,
                facets: facets
                    .iter()
                    .map(|_| FacetSpec {
                        label: String::new(),
                    })
                    .collect(),
                reassignment: reassignment.clone(),
                evidence: IdentityOpEvidence::default(),
            })),
            Self::AssertDistinct { a, b, .. } => IdentityTopologyAction::Apply(
                IdentityTopologyOp::AssertDistinct(AssertDistinctOp {
                    a: *a,
                    b: *b,
                    reason: String::new(),
                }),
            ),
            Self::Undo { target } => IdentityTopologyAction::Undo { target: *target },
            Self::ProposalResolution {
                proposal, outcome, ..
            } => IdentityTopologyAction::ResolveProposal {
                proposal: *proposal,
                outcome: *outcome,
            },
        }
    }
}

/// One identity-topology ledger event as stored in a type-76 maintenance
/// record body (engine-pinned MessagePack map).
///
/// Engine-authored ONLY: public puts of the type byte are rejected
/// (`MaintenanceKindNotWritable`), so every stored record passed this
/// module's door — the fold and the receipt projection therefore read the
/// family fail-closed (a malformed body is corruption, never skipped).
#[derive(Debug, Clone, PartialEq)]
pub struct StoredIdentityOpEvent {
    /// Engine-stamped monotonic causality sequence.
    pub seq: u64,
    /// Caller-supplied event time (Unix seconds) — data, never ordering.
    pub at: u64,
    /// Deciding actor, validated at the door when bound (r1).
    pub actor: Option<WriteActor>,
    /// Provenance source of the decision.
    pub source: ClaimSource,
    /// Consent axis the event was recorded under.
    pub approval: ClaimApprovalStatus,
    /// Decision confidence, finite in `[0, 1]`.
    pub confidence: f32,
    /// Decision evidence; absent on undo counter-events.
    pub evidence: Option<IdentityOpEvidence>,
    /// The recorded action.
    pub action: StoredIdentityOpAction,
}

impl StoredIdentityOpEvent {
    /// Encodes the record into its pinned MessagePack map value. Split
    /// reassignment entries are canonicalized (sorted by item bytes).
    #[must_use]
    pub fn encode_value(&self) -> Value {
        let mut entries = Vec::new();
        entries.push((
            Value::from(BODY_KEY_KIND),
            Value::from(self.action.kind_str()),
        ));
        entries.push((Value::from(BODY_KEY_SEQ), Value::from(self.seq)));
        entries.push((Value::from(BODY_KEY_AT), Value::from(self.at)));
        if let Some(actor) = self.actor {
            entries.push((Value::from(BODY_KEY_ACTOR), id_value(&actor.entity_ref())));
            entries.push((
                Value::from(BODY_KEY_ACTOR_CLASS),
                Value::from(actor.actor_class().gate_actor_class()),
            ));
        }
        entries.push((
            Value::from(BODY_KEY_SOURCE),
            Value::from(self.source.as_str()),
        ));
        entries.push((
            Value::from(BODY_KEY_APPROVAL),
            Value::from(self.approval.as_str()),
        ));
        entries.push((
            Value::from(BODY_KEY_CONFIDENCE),
            Value::F32(self.confidence),
        ));
        if let Some(evidence) = &self.evidence {
            entries.push((
                Value::from(BODY_KEY_EVIDENCE),
                Value::Map(vec![
                    (Value::from(EVIDENCE_KEY_REFS), ids_value(&evidence.refs)),
                    (
                        Value::from(EVIDENCE_KEY_RATIONALE),
                        Value::from(evidence.rationale.as_str()),
                    ),
                ]),
            ));
        }
        encode_action_entries(&self.action, &mut entries);
        Value::Map(entries)
    }

    /// Decodes a stored record value, fail-closed on any malformed field.
    pub fn decode_value(value: &Value) -> Result<Self> {
        let map = value
            .as_map()
            .ok_or(Error::InvalidIdentityTopologyEventBody(
                "identity topology event must be a map",
            ))?;
        let kind = decode_str_field(map, BODY_KEY_KIND, "identity topology event kind")?;
        let seq = decode_u64_field(map, BODY_KEY_SEQ, "identity topology event seq")?;
        let at = decode_u64_field(map, BODY_KEY_AT, "identity topology event at")?;
        let actor = decode_actor(map)?;
        let source = map_field(map, BODY_KEY_SOURCE)
            .and_then(Value::as_str)
            .and_then(ClaimSource::parse)
            .ok_or(Error::InvalidIdentityTopologyEventBody(
                "identity topology event source",
            ))?;
        let approval = map_field(map, BODY_KEY_APPROVAL)
            .and_then(Value::as_str)
            .and_then(ClaimApprovalStatus::parse)
            .ok_or(Error::InvalidIdentityTopologyEventBody(
                "identity topology event approval",
            ))?;
        let confidence = map_field(map, BODY_KEY_CONFIDENCE)
            .and_then(Value::as_f64)
            .ok_or(Error::InvalidIdentityTopologyEventBody(
                "identity topology event confidence",
            ))? as f32;
        if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
            return Err(Error::InvalidIdentityTopologyEventBody(
                "identity topology event confidence",
            ));
        }
        let evidence = match map_field(map, BODY_KEY_EVIDENCE) {
            None => None,
            Some(value) => Some(decode_evidence(value)?),
        };
        Ok(Self {
            seq,
            at,
            actor,
            source,
            approval,
            confidence,
            evidence,
            action: decode_action(kind, map)?,
        })
    }
}
