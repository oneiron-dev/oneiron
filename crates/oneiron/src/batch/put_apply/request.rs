//! The one typed request `apply_put` takes: the row, the options that govern
//! how it is admitted, and the borrowed context it is judged against.

use super::{BaseWriteOrigin, CompanionRetiredHistoryOverlay};
use crate::batch::{ApplyOpsGateMode, BatchOp};
use crate::entity_id::EntityId;
use crate::store::GateDecisionId;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};

/// One entity put through the `apply_put` chokepoint.
pub(in crate::batch) struct PutRequest<'a> {
    pub(in crate::batch) row: PutRow<'a>,
    pub(in crate::batch) options: PutOptions,
    pub(in crate::batch) context: PutContext<'a>,
}

/// The row as queued: its id, type byte, timestamps and body.
pub(in crate::batch) struct PutRow<'a> {
    pub(in crate::batch) id: EntityId,
    pub(in crate::batch) entity_type: u8,
    pub(in crate::batch) occurred: TimeRange,
    pub(in crate::batch) learned_at: u64,
    pub(in crate::batch) data: &'a [u8],
}

/// Every flag a put is admitted under, grouped by what it governs.
///
/// The default is the plain `put_entity` path: a local, unreserved, non-hub
/// put whose claim gate records no decision in apply (the committing
/// terminal's preflight does), persists a pending consent, and has no later
/// text op in its batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(in crate::batch) struct PutOptions {
    pub(in crate::batch) replication: Replication,
    pub(in crate::batch) hub: HubImport,
    pub(in crate::batch) decision: DecisionRecording,
    pub(in crate::batch) consent: ConsentHandling,
    pub(in crate::batch) indexing: TextIndexing,
}

/// Which admit bands the put opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(in crate::batch) struct Replication {
    /// Sync replay of a row a peer already authored: skips the local claim
    /// gate and the local-only birth laws, and (ONE-1141) deindexes the
    /// loser's BM25F postings on a body-changing overwrite in the same
    /// transaction (ARCH-0031 amendment).
    pub(in crate::batch) replicated: bool,
    /// The D17 reserved `edge.*` predicate namespace on a CLAIM body.
    pub(in crate::batch) reserved_predicate: bool,
}

/// The ONE-1736 hub-sync SKILL import inlet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(in crate::batch) struct HubImport {
    /// The body is an imported SKILL the hub-sync policy door accepted.
    pub(in crate::batch) sync_imported: bool,
}

/// How a local CLAIM put meets the claim gate and its decision ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(in crate::batch) struct DecisionRecording {
    /// Record the gate decision from inside apply.
    pub(in crate::batch) record: bool,
    /// The gate already authorized this put in this transaction; only the
    /// duplicate evaluation is skipped.
    pub(in crate::batch) prechecked: bool,
    /// Feed the claim's source into the gate input.
    pub(in crate::batch) include_source_in_gate_input: bool,
    /// An engine-internal lexical query hint, which the gate does not judge.
    pub(in crate::batch) internal_lexical_query_hint: bool,
    /// The receipt a same-transaction preflight already recorded for it.
    pub(in crate::batch) preflight: Option<GateDecisionId>,
}

/// How the claim gate treats a pending consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::batch) struct ConsentHandling {
    /// Persist a consent the gate leaves pending.
    pub(in crate::batch) persist_pending: bool,
    /// A consent was already pending for this id when the batch began, so
    /// this put may resolve it.
    pub(in crate::batch) can_resolve_pending: bool,
}

impl Default for ConsentHandling {
    fn default() -> Self {
        Self {
            persist_pending: true,
            can_resolve_pending: false,
        }
    }
}

/// How the put's body relates to the text index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(in crate::batch) struct TextIndexing {
    /// A later text op in the same batch covers this id, so a local
    /// body-changing overwrite leaves deindexing to it.
    pub(in crate::batch) later_text_op_covers: bool,
}

impl PutOptions {
    /// The options the batch apply builds for one queued op: the op's own
    /// admit flags and the batch's gate mode. What the batch derives per op
    /// — a later covering text op, a consent pending at batch start, a
    /// preflight receipt — the caller sets on the result. An op that stages
    /// no entity put carries no admit flags.
    pub(in crate::batch) fn for_batch_op(op: &BatchOp, mode: &ApplyOpsGateMode) -> Self {
        let mut options = Self {
            decision: DecisionRecording {
                record: mode.record_decisions,
                prechecked: mode.claim_gate_prechecked,
                include_source_in_gate_input: mode.include_source_in_gate_input,
                ..DecisionRecording::default()
            },
            consent: ConsentHandling {
                persist_pending: mode.persist_pending_consent,
                can_resolve_pending: false,
            },
            ..Self::default()
        };
        match op {
            BatchOp::Put {
                allow_maintenance,
                allow_reserved_predicate,
                hub_sync_imported,
                ..
            } => {
                // `replicated_put_op` is the SINGLE constructor that opens
                // BOTH admit bands at once (see its doc), so both-flags-set
                // identifies the sync replay doors (`put_replicated`).
                options.replication = Replication {
                    replicated: *allow_maintenance && *allow_reserved_predicate,
                    reserved_predicate: *allow_reserved_predicate,
                };
                options.hub.sync_imported = *hub_sync_imported;
            }
            BatchOp::ClaimCandidate {
                internal_lexical_query_hint,
                ..
            } => {
                options.decision.internal_lexical_query_hint = *internal_lexical_query_hint;
            }
            _ => {}
        }
        options
    }

    /// The claim-gate write mode these options select.
    pub(super) fn gate_write_mode(&self) -> crate::gate::GateWriteMode {
        crate::gate::GateWriteMode {
            record_decision: self.decision.record,
            persist_pending_consent: self.consent.persist_pending,
            resolve_pending: true,
            can_resolve_pending_consent: self.consent.can_resolve_pending,
            include_source_in_gate_input: self.decision.include_source_in_gate_input,
        }
    }
}

/// What a put is judged against, borrowed from its batch.
#[derive(Clone, Copy)]
pub(in crate::batch) struct PutContext<'a> {
    /// Why this batch may touch the id (ARCH-0052 D2).
    pub(in crate::batch) origin: BaseWriteOrigin<'a>,
    /// The policy snapshot a local claim is gated against.
    pub(in crate::batch) write_policy: Option<&'a crate::gate::PolicyManifestResolution>,
    /// The envelope that authored the claim, when one did.
    pub(in crate::batch) write_envelope: Option<&'a WriteEnvelope>,
    /// The bootstrap proof a hub SKILL admission presents.
    pub(in crate::batch) hub_admission: Option<&'a crate::skill_hub::HubAdmissionProof>,
    /// Companion histories this batch retracts, for the identity-facet check.
    pub(in crate::batch) companion_retired_histories: Option<&'a CompanionRetiredHistoryOverlay>,
}

/// One claim candidate through `apply_claim_candidate`: the candidate and its
/// envelope, the row timestamps, and the claim-gate options its put carries.
/// A candidate never opens an admit band or the hub inlet, so those option
/// groups are not part of it.
pub(in crate::batch) struct ClaimCandidateRequest<'a> {
    pub(in crate::batch) id: EntityId,
    pub(in crate::batch) candidate: ClaimCandidate,
    pub(in crate::batch) envelope: &'a WriteEnvelope,
    pub(in crate::batch) occurred: TimeRange,
    pub(in crate::batch) learned_at: u64,
    pub(in crate::batch) decision: DecisionRecording,
    pub(in crate::batch) consent: ConsentHandling,
    pub(in crate::batch) indexing: TextIndexing,
    pub(in crate::batch) write_policy: Option<&'a crate::gate::PolicyManifestResolution>,
}
