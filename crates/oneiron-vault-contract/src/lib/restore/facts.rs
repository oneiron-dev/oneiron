//! The receipt of a verified cold managed restore: the attempt it answers,
//! the engine's report, and everything the restore verified of its source,
//! custody and recipients, kept apart from what the plan expected. Public
//! facts only: ids, digests, positions and labels, never a key, a sealed
//! head or a released secret. The engine serializes it once; its bytes ride
//! the result pipe in chunks and `restore_status` pages, and its id is
//! BLAKE3 of exactly those bytes.
//!
//! A verified receipt names a kept destination, not a serving vault and not
//! a finished job: delivery of the escrow reports, the purge and the control
//! plane's own completion are the supervisor's to prove.

use serde::{Deserialize, Serialize};

use super::framing::ManagedRestoreDestination;
use super::plan::{
    EscrowRole, RestoreArtifactKind, RestoreEvidence, RestorePlan, RestoreSourceExpectation,
};

/// The one [`ManagedRestoreReceipt`] schema this crate writes.
pub const RESTORE_RECEIPT_SCHEMA_VERSION: u32 = 1;

/// Which attempt a frame, a receipt or a status answers: the plan's own
/// four identifiers, never substituted for one another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRestoreIdentity {
    pub restore_id: String,
    #[serde(with = "super::hex::array")]
    pub plan_digest: [u8; 32],
    pub attempt_id: String,
    pub generation: u64,
}

impl ManagedRestoreIdentity {
    /// The identity `plan` names.
    #[must_use]
    pub fn of(plan: &RestorePlan) -> Self {
        Self {
            restore_id: plan.restore_id.clone(),
            plan_digest: plan.plan_digest,
            attempt_id: plan.attempt_id.clone(),
            generation: plan.generation,
        }
    }
}

/// What a verified cold managed restore reports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRestoreReceipt {
    /// [`RESTORE_RECEIPT_SCHEMA_VERSION`].
    pub schema_version: u32,
    pub identity: ManagedRestoreIdentity,
    pub vault_name: String,
    #[serde(with = "super::hex::array")]
    pub derivation_owner: [u8; 32],
    /// The engine build's own identity, `null` where the build carries none;
    /// never the build the plan names.
    pub engine_build: Option<String>,
    /// [`CONTRACT_VERSION`](crate::CONTRACT_VERSION).
    pub contract_version: u32,
    /// The vault clock, in seconds, when the receipt was sealed.
    pub completed_at: u64,
    /// `committed_not_serving`: the receipt is sealed before the vault
    /// signals ready, and whether it serves is the ready byte's and `Ping`'s
    /// to say.
    pub destination_state: ManagedRestoreDestination,
    pub report: RestoreReportWire,
    pub admission: RestoreAdmissionWire,
    /// The plan's evidence references, as it named them.
    pub evidence: RestoreEvidence,
    /// Where each added recipient's escrow report stands at this start.
    pub escrow_spool: Vec<RestoreSpoolObservation>,
}

/// The engine's restore report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreReportWire {
    /// The restored checkpoint's id, as the vault's restore log names it.
    pub checkpoint_id: String,
    pub restored_at: u64,
    pub rebuilt_entities: u64,
    pub rebuilt_text_documents: u64,
    pub pending_embeddings: u64,
    /// Claim-bound gate decisions dropped because their keys stayed behind,
    /// by id (hex), in full.
    pub dropped_gate_decisions: Vec<String>,
    pub custody_note: Option<String>,
    pub training_note: Option<String>,
}

/// Everything the restore verified, beside what the plan expected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreAdmissionWire {
    pub expected: RestoreSourceExpectation,
    pub source: VerifiedSourceWire,
    pub custody: CustodyAdmissionWire,
    pub recipients: RecipientAdmissionWire,
}

/// What the restore verified of its source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedSourceWire {
    #[serde(with = "super::hex::array")]
    pub engine_vault_id: [u8; 32],
    #[serde(with = "super::hex::array")]
    pub data_key_commitment: [u8; 32],
    pub kind: RestoreArtifactKind,
    #[serde(with = "super::hex::array")]
    pub artifact_digest: [u8; 32],
    pub artifact_size: u64,
    #[serde(with = "super::hex::array")]
    pub snapshot: [u8; 32],
    #[serde(with = "super::hex::array")]
    pub checkpoint_id: [u8; 32],
    /// BLAKE3 of the exact signed commitment bytes.
    #[serde(with = "super::hex::array")]
    pub commitment_digest: [u8; 32],
    pub sequence: u64,
    /// The commitment's crypto epoch; not the custody writer epoch, the
    /// recipient epoch or the generation.
    pub crypto_epoch: u64,
    #[serde(with = "super::hex::option_array")]
    pub predecessor: Option<[u8; 32]>,
    pub created_at: u64,
    /// The pinned signer that signed it.
    #[serde(with = "super::hex::array")]
    pub signer_install: [u8; 16],
    /// BLAKE3 over the canonical external pin set the signature was checked
    /// against.
    #[serde(with = "super::hex::array")]
    pub pin_set_digest: [u8; 32],
    /// The artifact carried a registry binding, and it is the plan's;
    /// `false` where it carried none.
    pub registry_bound: bool,
}

/// One custody log position: public structure, never a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyPositionWire {
    #[serde(with = "super::hex::array")]
    pub vault: [u8; 32],
    #[serde(with = "super::hex::array")]
    pub namespace: [u8; 16],
    pub epoch: u64,
    pub seq: u64,
    #[serde(with = "super::hex::array")]
    pub tip: [u8; 32],
}

/// How the restore took its image's custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyRouteWire {
    /// A head was admitted and landed beside the destination.
    Landed,
    /// The custody is on this host, or the image binds none.
    Local,
    /// No head was found: claim rows whose keys stayed behind dropped.
    NoHead,
}

/// What the restore proved of the head's currency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorDispositionWire {
    ConfiguredVerified,
    /// No anchor configured: the head was used as it is.
    UnsetRollbackNotProven,
    /// No head was admitted.
    NotApplicable,
}

/// What the restore admitted of its custody, read after its own changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyAdmissionWire {
    pub route: CustodyRouteWire,
    /// The position the image's manifest required.
    pub image_position: Option<CustodyPositionWire>,
    /// The head's own position, before reconciliation with its anchor.
    pub head_position: Option<CustodyPositionWire>,
    /// The position admitted and landed.
    pub admitted_position: Option<CustodyPositionWire>,
    pub anchor: AnchorDispositionWire,
    /// BLAKE3 of the anchor record admission read.
    #[serde(with = "super::hex::option_array")]
    pub anchor_read_digest: Option<[u8; 32]>,
    /// BLAKE3 of the record the takeover fence advanced the anchor to.
    #[serde(with = "super::hex::option_array")]
    pub anchor_advanced_digest: Option<[u8; 32]>,
    /// The writer epoch the restored vault took the lineage over at.
    pub takeover_epoch: Option<u64>,
    /// Retirement facts the landing carried, ids and subjects.
    pub retired_ids: u64,
    /// Every claim-bound decision dropped because its key stayed behind, by
    /// id (hex), in full.
    pub dropped_gate_decisions: Vec<String>,
    /// The custody publication status once the restore's own retirements
    /// were journaled, as `oneiron backup` prints it; `null` when it could
    /// not be read.
    pub publication: Option<serde_json::Value>,
    pub custody_note: Option<String>,
    pub training_note: Option<String>,
}

/// A fresh recipient the restored key was wrapped to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddedRecipientWire {
    pub label: String,
    pub role: EscrowRole,
    #[serde(with = "super::hex::array")]
    pub fingerprint: [u8; 32],
    pub wrap_id: String,
    /// The escrow capsule's report id, BLAKE3 of its bytes in hex, as the
    /// spool names it.
    pub report_id: String,
}

/// Why a recipient retired in the restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetiredByWire {
    /// The plan named it released.
    Plan,
    /// The custody log retired it earlier; the image still carried its wrap.
    CustodyLog,
}

/// The vault's own receipt for one retirement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementReceiptWire {
    pub receipt_id: String,
    pub label: String,
    /// The vault still carried the wrap, and the retirement removed it.
    pub removed_wrap: bool,
    /// The vault clock, in seconds, when it was retired.
    pub retired_at: u64,
}

/// One recipient the restore retired.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredRecipientWire {
    pub label: String,
    #[serde(with = "super::hex::option_array")]
    pub fingerprint: Option<[u8; 32]>,
    pub retired_by: RetiredByWire,
    /// The plan's host-recipient epoch for a released one.
    pub recipient_epoch: Option<u64>,
    pub receipt: RetirementReceiptWire,
}

/// Where the restore's recipient retirements are durable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecipientDispositionWire {
    /// In the custody log, one frame each, at the takeover writer epoch.
    Journaled { epoch: u64, seqs: Vec<u64> },
    /// In the restored key header only, for the reason `note` says.
    LocalOnly { note: String },
}

/// What the restore did to the restored key's wraps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientAdmissionWire {
    pub added: Vec<AddedRecipientWire>,
    pub retired: Vec<RetiredRecipientWire>,
    pub disposition: RecipientDispositionWire,
}

/// Where one added recipient's escrow report stands at this start.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreSpoolObservation {
    pub label: String,
    pub report_id: String,
    pub state: RestoreSpoolState,
}

/// An escrow report's spool state. Spooled is not delivered: the
/// supervisor's registry acknowledgement is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreSpoolState {
    /// Written to the escrow outbox.
    Spooled,
    /// Not written: the next start spools it. The vault serves either way.
    EscrowSpoolPending,
    /// The supervisor named no escrow outbox (`--escrow-outbox-dir`).
    NoOutbox,
}
