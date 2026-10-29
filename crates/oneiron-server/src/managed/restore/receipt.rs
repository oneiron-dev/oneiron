//! The engine's restore facts on the contract's wire: total, field by field
//! projections, never a parse of prose. The receipt a verified restore keeps
//! for `restore_status`, and the typed reasons, phases and destination
//! states of a refusal.

use std::collections::BTreeSet;

use oneiron::recovery::checkpoint::{
    AnchorDisposition, ArtifactKind, CheckpointSequenceBelowFloor, CheckpointSigner,
    CustodyPositionFact, CustodyRouteFact, RecipientRetirementDisposition, RestoreAdmission,
    RestoreAdmissionError, RestoreAdmissionReason, RestoreDestinationState, RestorePhase,
    RestoreReport, RetiredBy, SourceExpectation,
};
use oneiron_vault_contract::restore::facts::{
    AddedRecipientWire, AnchorDispositionWire, CustodyAdmissionWire, CustodyPositionWire,
    CustodyRouteWire, RecipientAdmissionWire, RecipientDispositionWire, RestoreAdmissionWire,
    RestoreReportWire, RestoreSpoolObservation, RestoreSpoolState, RetiredByWire,
    RetiredRecipientWire, RetirementReceiptWire, VerifiedSourceWire,
};
use oneiron_vault_contract::restore::plan::{
    ManagedRestorePlan, RestoreArtifactKind, RestoreSignerPin, RestoreSourceExpectation,
};
use oneiron_vault_contract::restore::{
    ManagedRestoreDestination, ManagedRestoreIdentity, ManagedRestorePhase, ManagedRestoreReceipt,
    RESTORE_RECEIPT_SCHEMA_VERSION, RestoreFailureReason, RestoreHostHoldsStatus, RestoreStatus,
};

use crate::managed::ManagedError;

/// A verified restore as this process keeps it for `restore_status`: the
/// attempt and its receipt's exact bytes.
#[derive(Debug)]
pub(in crate::managed) struct RestoreOutcome {
    identity: ManagedRestoreIdentity,
    receipt: Vec<u8>,
}

impl RestoreOutcome {
    pub(super) fn new(identity: ManagedRestoreIdentity, receipt: Vec<u8>) -> Self {
        Self { identity, receipt }
    }

    pub(super) fn identity(&self) -> &ManagedRestoreIdentity {
        &self.identity
    }

    pub(super) fn receipt(&self) -> &[u8] {
        &self.receipt
    }

    /// What this process answers `restore_status` for `identity` with: a
    /// page of the receipt for the attempt it restored, from `cursor`, and
    /// `not_this_attempt` for any other attempt or when it restored none.
    pub(in crate::managed) fn status(
        outcome: Option<&Self>,
        identity: &ManagedRestoreIdentity,
        cursor: Option<u64>,
    ) -> Result<RestoreStatus, ManagedError> {
        match outcome {
            Some(outcome) if outcome.identity == *identity => {
                RestoreStatus::verified_page(identity, &outcome.receipt, cursor).map_err(|error| {
                    ManagedError::CtlRequestRefused {
                        reason: error.to_string(),
                    }
                })
            }
            _ => Ok(RestoreStatus::NotThisAttempt),
        }
    }
}

/// The receipt's parts this start knows apart from the restore's facts.
pub(super) struct ReceiptContext<'a> {
    pub(super) identity: &'a ManagedRestoreIdentity,
    pub(super) plan: &'a ManagedRestorePlan,
    /// The report ids the escrow spool holds; `None` without an outbox.
    pub(super) spooled: Option<&'a BTreeSet<String>>,
    pub(super) completed_at: u64,
    /// Where the restored vault's host-order legal holds came from.
    pub(super) host_holds: RestoreHostHoldsStatus,
}

/// This engine build's own identity (FIX 6581), as `build.rs` compiled it
/// in: the commit it was built from, `None` when its build knew none.
fn engine_build() -> Option<&'static str> {
    Some(env!("ONEIRON_ENGINE_BUILD")).filter(|build| *build != "unknown")
}

/// The receipt of a verified restore; refused when the report names no
/// checkpoint sequence, which a restore of a signed artifact always has.
pub(super) fn receipt(
    context: &ReceiptContext<'_>,
    report: &RestoreReport,
    admission: &RestoreAdmission,
) -> anyhow::Result<ManagedRestoreReceipt> {
    let checkpoint_sequence = report
        .checkpoint_sequence
        .ok_or_else(|| anyhow::anyhow!("the restore's report names no checkpoint sequence"))?;
    let escrow_spool = admission
        .recipients
        .added
        .iter()
        .map(|added| RestoreSpoolObservation {
            label: added.label.clone(),
            report_id: added.report_id.clone(),
            state: match context.spooled {
                None => RestoreSpoolState::NoOutbox,
                Some(spooled) if spooled.contains(&added.report_id) => RestoreSpoolState::Spooled,
                Some(_) => RestoreSpoolState::EscrowSpoolPending,
            },
        })
        .collect();
    Ok(ManagedRestoreReceipt {
        schema_version: RESTORE_RECEIPT_SCHEMA_VERSION,
        identity: context.identity.clone(),
        vault_name: context.plan.vault_name.clone(),
        derivation_owner: context.plan.derivation_owner,
        engine_build: engine_build().map(str::to_owned),
        contract_version: oneiron_vault_contract::CONTRACT_VERSION,
        completed_at: context.completed_at,
        destination_state: ManagedRestoreDestination::CommittedNotServing,
        report: RestoreReportWire {
            checkpoint_id: report.epoch.checkpoint_id.clone(),
            checkpoint_sequence,
            restored_at: report.epoch.restored_at,
            rebuilt_entities: report.rebuilt_entities as u64,
            rebuilt_text_documents: report.rebuilt_text_documents as u64,
            pending_embeddings: report.pending_embeddings as u64,
            dropped_gate_decisions: report.dropped_gate_decisions.clone(),
            custody_note: report.custody_note.clone(),
            training_note: report.training_note.clone(),
            pad_notes: report.pad_notes.iter().map(ToString::to_string).collect(),
            credential_notes: report
                .credential_notes
                .iter()
                .map(ToString::to_string)
                .collect(),
        },
        admission: admission_wire(admission),
        wake_sequence_floor: context.plan.wake_sequence_floor,
        evidence: context.plan.evidence.clone(),
        escrow_spool,
        host_holds: context.host_holds,
    })
}

fn admission_wire(admission: &RestoreAdmission) -> RestoreAdmissionWire {
    let source = &admission.source;
    let custody = &admission.custody;
    let recipients = &admission.recipients;
    RestoreAdmissionWire {
        expected: expectation_wire(&admission.expected),
        source: VerifiedSourceWire {
            engine_vault_id: source.engine_vault_id,
            data_key_commitment: source.data_key_commitment,
            kind: kind_wire(source.kind),
            artifact_digest: source.artifact_digest,
            artifact_size: source.artifact_size,
            snapshot: source.snapshot,
            checkpoint_id: source.checkpoint_id,
            commitment_digest: source.commitment_digest,
            sequence: source.sequence,
            crypto_epoch: source.crypto_epoch,
            predecessor: source.predecessor,
            created_at: source.created_at,
            signer_install: source.signer_install,
            pin_set_digest: source.pin_set_digest,
            mode_root_policy_digest: source.policy_digest,
            registry_bound: source.registry_bound,
        },
        custody: CustodyAdmissionWire {
            route: match custody.route {
                CustodyRouteFact::Landed => CustodyRouteWire::Landed,
                CustodyRouteFact::Local => CustodyRouteWire::Local,
                CustodyRouteFact::NoHead => CustodyRouteWire::NoHead,
            },
            image_position: custody.image_position.as_ref().map(position_wire),
            head_position: custody.head_position.as_ref().map(position_wire),
            admitted_position: custody.admitted_position.as_ref().map(position_wire),
            anchor: match custody.anchor {
                AnchorDisposition::ConfiguredVerified => AnchorDispositionWire::ConfiguredVerified,
                AnchorDisposition::UnsetRollbackNotProven => {
                    AnchorDispositionWire::UnsetRollbackNotProven
                }
                AnchorDisposition::NotApplicable => AnchorDispositionWire::NotApplicable,
            },
            anchor_read_digest: custody.anchor_read_digest,
            anchor_advanced_digest: custody.anchor_advanced_digest,
            takeover_epoch: custody.takeover_epoch,
            retired_ids: custody.retired_ids as u64,
            dropped_gate_decisions: custody.dropped_gate_decisions.clone(),
            publication: custody
                .publication
                .as_ref()
                .and_then(|status| serde_json::to_value(status).ok()),
            custody_note: custody.custody_note.clone(),
            training_note: custody.training_note.clone(),
        },
        recipients: RecipientAdmissionWire {
            added: recipients
                .added
                .iter()
                .map(|added| AddedRecipientWire {
                    label: added.label.clone(),
                    role: added.role,
                    fingerprint: added.fingerprint,
                    wrap_id: added.wrap_id.clone(),
                    report_id: added.report_id.clone(),
                })
                .collect(),
            retired: recipients
                .retired
                .iter()
                .map(|retired| RetiredRecipientWire {
                    label: retired.label.clone(),
                    fingerprint: retired.fingerprint,
                    retired_by: match retired.retired_by {
                        RetiredBy::Plan => RetiredByWire::Plan,
                        RetiredBy::CustodyLog => RetiredByWire::CustodyLog,
                    },
                    recipient_epoch: retired.recipient_epoch,
                    receipt: RetirementReceiptWire {
                        receipt_id: retired.receipt.receipt_id.clone(),
                        label: retired.receipt.label.clone(),
                        removed_wrap: retired.receipt.removed_wrap,
                        retired_at: retired.receipt.retired_at,
                    },
                })
                .collect(),
            disposition: match &recipients.disposition {
                RecipientRetirementDisposition::Journaled { epoch, seqs } => {
                    RecipientDispositionWire::Journaled {
                        epoch: *epoch,
                        seqs: seqs.clone(),
                    }
                }
                RecipientRetirementDisposition::LocalOnly { note } => {
                    RecipientDispositionWire::LocalOnly {
                        note: (*note).to_owned(),
                    }
                }
            },
        },
    }
}

fn position_wire(position: &CustodyPositionFact) -> CustodyPositionWire {
    CustodyPositionWire {
        vault: position.vault,
        namespace: position.namespace,
        epoch: position.epoch,
        seq: position.seq,
        tip: position.tip,
    }
}

fn kind_wire(kind: ArtifactKind) -> RestoreArtifactKind {
    match kind {
        ArtifactKind::Checkpoint => RestoreArtifactKind::Checkpoint,
        ArtifactKind::Backup => RestoreArtifactKind::Backup,
    }
}

/// The plan's expectation as the engine checks it: the same fields, the
/// signers' keys as they are.
pub(super) fn expectation(source: &RestoreSourceExpectation) -> SourceExpectation {
    SourceExpectation {
        engine_vault_id: source.engine_vault_id,
        data_key_commitment: source.data_key_commitment,
        artifact_digest: source.artifact_digest,
        kind: match source.kind {
            RestoreArtifactKind::Checkpoint => ArtifactKind::Checkpoint,
            RestoreArtifactKind::Backup => ArtifactKind::Backup,
        },
        snapshot: source.snapshot,
        checkpoint_id: source.checkpoint_id,
        signer_pins: source
            .signer_pins
            .iter()
            .map(|pin| CheckpointSigner {
                install: pin.install,
                ed25519: pin.ed25519,
                slhdsa: pin.slhdsa.clone(),
            })
            .collect(),
        registry_id: source.registry_id.clone(),
    }
}

fn expectation_wire(expected: &SourceExpectation) -> RestoreSourceExpectation {
    RestoreSourceExpectation {
        engine_vault_id: expected.engine_vault_id,
        data_key_commitment: expected.data_key_commitment,
        artifact_digest: expected.artifact_digest,
        snapshot: expected.snapshot,
        checkpoint_id: expected.checkpoint_id,
        kind: kind_wire(expected.kind),
        signer_pins: expected
            .signer_pins
            .iter()
            .map(|pin| RestoreSignerPin {
                install: pin.install,
                ed25519: pin.ed25519,
                slhdsa: pin.slhdsa.clone(),
            })
            .collect(),
        registry_id: expected.registry_id.clone(),
    }
}

/// An engine refusal's reason on the wire: a signed checkpoint sequence
/// below the plan's floor with its two numbers, which the engine carries as
/// a storage error, else its admission reason.
pub(super) fn refusal_reason(error: &RestoreAdmissionError) -> RestoreFailureReason {
    match CheckpointSequenceBelowFloor::of(error.error()) {
        Some(below) => RestoreFailureReason::CheckpointSequenceBelowFloor {
            floor: below.floor,
            observed: below.observed,
        },
        None => reason_wire(error.reason),
    }
}

/// A refusal's reason on the wire.
pub(super) fn reason_wire(reason: RestoreAdmissionReason) -> RestoreFailureReason {
    use RestoreAdmissionReason as A;
    use RestoreFailureReason as W;
    match reason {
        A::SourceIdentityMismatch => W::SourceIdentityMismatch,
        A::DataKeyMismatch => W::DataKeyMismatch,
        A::ArtifactIdentityMismatch => W::ArtifactIdentityMismatch,
        A::ArtifactKindMismatch => W::ArtifactKindMismatch,
        A::SignerUntrusted => W::SignerUntrusted,
        A::SignatureInvalid => W::SignatureInvalid,
        A::ArtifactIntegrityInvalid => W::ArtifactIntegrityInvalid,
        A::CodecInvalid => W::CodecInvalid,
        A::BackupRegistryBindingMismatch => W::BackupRegistryBindingMismatch,
        A::CustodyRequirementInvalid => W::CustodyRequirementInvalid,
        A::CustodyLineageMismatch => W::CustodyLineageMismatch,
        A::CustodyHeadInvalid => W::CustodyHeadInvalid,
        A::AnchorUnavailable => W::AnchorUnavailable,
        A::AnchorMissing => W::AnchorMissing,
        A::AnchorInvalid => W::AnchorInvalid,
        A::CustodyLogIncomplete => W::CustodyLogIncomplete,
        A::CustodyDiverged => W::CustodyDiverged,
        A::CustodyHeadTooOld => W::CustodyHeadTooOld,
        A::CustodyKeyMissing => W::CustodyKeyMissing,
        A::CustodyOwnerKeyRequired => W::CustodyOwnerKeyRequired,
        A::BodyCustodyUnavailable => W::BodyCustodyUnavailable,
        A::ClaimReceiptInvalid => W::ClaimReceiptInvalid,
        A::AnchorMoved => W::AnchorMoved,
        A::CustodyLandingFailed => W::CustodyLandingFailed,
        A::ManagedDekMacMismatch => W::ManagedDekMacMismatch,
        A::DerivationOwnerMismatch => W::DerivationOwnerMismatch,
        A::PageCustodyInvalid => W::PageCustodyInvalid,
        A::RecipientBindingInvalid => W::RecipientBindingInvalid,
        A::RecipientReused => W::RecipientReused,
        A::LastWrap => W::LastWrap,
        A::RetirementAuthorityInvalid => W::RetirementAuthorityInvalid,
        A::StorageIo => W::StorageIo,
        A::StartupFailed => W::StartupFailed,
    }
}

/// A refusal's phase on the wire.
pub(super) fn phase_wire(phase: RestorePhase) -> ManagedRestorePhase {
    match phase {
        RestorePhase::SourceCheck => ManagedRestorePhase::SourceCheck,
        RestorePhase::ArtifactOpen => ManagedRestorePhase::ArtifactOpen,
        RestorePhase::CustodyAdmission => ManagedRestorePhase::CustodyAdmission,
        RestorePhase::RowsLanding => ManagedRestorePhase::RowsLanding,
        RestorePhase::Finish => ManagedRestorePhase::Finish,
        RestorePhase::TakeoverFence => ManagedRestorePhase::TakeoverFence,
        RestorePhase::Recipients => ManagedRestorePhase::Recipients,
        RestorePhase::PageCustody => ManagedRestorePhase::PageCustody,
        RestorePhase::CommitMarker => ManagedRestorePhase::CommitMarker,
    }
}

/// A refusal's destination state on the wire.
pub(super) fn destination_wire(destination: RestoreDestinationState) -> ManagedRestoreDestination {
    match destination {
        RestoreDestinationState::Removed => ManagedRestoreDestination::Removed,
        RestoreDestinationState::CommittedNotServing => {
            ManagedRestoreDestination::CommittedNotServing
        }
        RestoreDestinationState::Uncertain => ManagedRestoreDestination::Uncertain,
    }
}

/// The reason an engine error's own type names, as the restore types one
/// no branch named: a disk or storage failure, an undecodable record, and
/// anything else a startup failure. Never a guessed precise cause.
pub(super) fn by_kind(error: &oneiron::Error) -> RestoreAdmissionReason {
    match error {
        oneiron::Error::Io(_) | oneiron::Error::Storage(_) | oneiron::Error::MapFull => {
            RestoreAdmissionReason::StorageIo
        }
        oneiron::Error::CorruptedIndex(_) | oneiron::Error::InvalidKey => {
            RestoreAdmissionReason::CodecInvalid
        }
        _ => RestoreAdmissionReason::StartupFailed,
    }
}
