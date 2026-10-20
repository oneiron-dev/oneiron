//! What a cold managed restore is asked to do and what it verified (LC FIX
//! 5384/5385): the plan's expected source and recipients, the facts it
//! returns beside [`RestoreReport`](super::super::RestoreReport), and the
//! facts its after-keep step is handed. Public facts only: ids, digests,
//! positions and labels, never a key, a sealed head or a released secret.
//! The externally expected facts and the verified ones are named apart.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::super::{ArtifactKind, CheckpointKey, CheckpointSigner, CustodyRecovery, CustodyStatus};
use crate::VaultConfig;
use crate::world_keys::EscrowRetirement;

/// What the plan says the artifact is, from a record kept apart from it:
/// nothing here is read from the artifact being checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceExpectation {
    /// The engine vault id the backup prelude must name.
    pub engine_vault_id: [u8; 32],
    /// The data-key commitment the key header names, and the delivered
    /// key's own.
    pub data_key_commitment: [u8; 32],
    /// BLAKE3 of every byte of the artifact (the catalog's object digest).
    pub artifact_digest: [u8; 32],
    pub kind: ArtifactKind,
    /// The snapshot id the prelude and commitment name.
    pub snapshot: [u8; 32],
    /// The checkpoint id: BLAKE3 of the canonical image, not the snapshot.
    pub checkpoint_id: [u8; 32],
    /// The signers the catalog pins, from outside the artifact; the only
    /// signers the commitment is checked against.
    pub signer_pins: Vec<CheckpointSigner>,
    /// The registry's id for the vault (the managed vault's name), checked
    /// against a registry binding the artifact carries; never the DNS slug,
    /// the engine vault id or the custody namespace.
    pub registry_id: String,
}

/// The escrow role a managed recipient serves; its label is
/// `<role>.<first 16 hex of BLAKE3(public key)>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EscrowRole {
    Managed,
    BreakGlass,
}

impl EscrowRole {
    /// The label prefix a wrap of this role carries.
    pub fn label_prefix(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::BreakGlass => "break-glass",
        }
    }
}

/// A recipient whose secret the restore's key release used: its label,
/// role, full fingerprint and host-recipient epoch, as the plan maps them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleasedRecipient {
    pub label: String,
    pub role: EscrowRole,
    /// BLAKE3 of the recipient's public key bytes.
    pub fingerprint: [u8; 32],
    /// The host recipient's epoch, carried to the receipt; never the custody
    /// writer epoch or the checkpoint's crypto epoch.
    pub epoch: u64,
}

/// A fresh recipient the restored key is wrapped to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FreshRecipient {
    pub label: String,
    pub role: EscrowRole,
    /// The hybrid public key's bytes, as the supervisor names them.
    pub public_key: Vec<u8>,
}

/// The plan's restore-specific scope: who asked, and the recipients it
/// adds and retires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestorePlan {
    pub restore_id: String,
    pub plan_digest: [u8; 32],
    pub attempt_id: String,
    /// The process generation; never an epoch.
    pub generation: u64,
    pub released: Vec<ReleasedRecipient>,
    pub fresh: Vec<FreshRecipient>,
}

/// One cold managed restore's inputs
/// ([`Vault::restore_checkpoint_admitted`](crate::Vault::restore_checkpoint_admitted)).
pub struct AdmittedRestore<'a> {
    pub artifact: &'a Path,
    /// The key [`CheckpointKey::from_delivered`] made for this plan.
    pub key: &'a CheckpointKey,
    pub destination: &'a Path,
    pub config: VaultConfig,
    pub restored_at: u64,
    pub recovery: &'a CustodyRecovery<'a>,
    pub plan: &'a RestorePlan,
}

/// What the restore verified of its source, apart from what was expected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSource {
    pub engine_vault_id: [u8; 32],
    pub data_key_commitment: [u8; 32],
    pub kind: ArtifactKind,
    pub artifact_digest: [u8; 32],
    pub artifact_size: u64,
    pub snapshot: [u8; 32],
    pub checkpoint_id: [u8; 32],
    /// BLAKE3 of the exact signed commitment bytes.
    pub commitment_digest: [u8; 32],
    pub sequence: u64,
    /// The commitment's crypto epoch; not the custody writer epoch, the
    /// recipient epoch or the generation.
    pub crypto_epoch: u64,
    pub predecessor: Option<[u8; 32]>,
    pub created_at: u64,
    /// The pinned signer that signed it.
    pub signer_install: [u8; 16],
    /// BLAKE3 over the canonical external pin set the signature was checked
    /// against.
    pub pin_set_digest: [u8; 32],
    /// The artifact carried a registry binding, and it is the plan's;
    /// `false` where it carried none.
    pub registry_bound: bool,
}

/// One custody log position: public structure, never a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustodyPositionFact {
    pub vault: [u8; 32],
    pub namespace: [u8; 16],
    pub epoch: u64,
    pub seq: u64,
    pub tip: [u8; 32],
}

/// How the restore took its image's custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyRouteFact {
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
pub enum AnchorDisposition {
    ConfiguredVerified,
    /// No anchor configured: the head was used as it is.
    UnsetRollbackNotProven,
    /// No head was admitted.
    NotApplicable,
}

/// What the restore admitted of its custody, read after its own changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyAdmissionFacts {
    pub route: CustodyRouteFact,
    /// The position the image's manifest required.
    pub image_position: Option<CustodyPositionFact>,
    /// The head's own position, before reconciliation with its anchor.
    pub head_position: Option<CustodyPositionFact>,
    /// The position admitted and landed.
    pub admitted_position: Option<CustodyPositionFact>,
    pub anchor: AnchorDisposition,
    /// BLAKE3 of the anchor record admission read.
    pub anchor_read_digest: Option<[u8; 32]>,
    /// BLAKE3 of the record the takeover fence advanced the anchor to.
    pub anchor_advanced_digest: Option<[u8; 32]>,
    /// The writer epoch the restored vault took the lineage over at.
    pub takeover_epoch: Option<u64>,
    /// Retirement facts the landing carried, ids and subjects.
    pub retired_ids: usize,
    /// Every claim-bound decision dropped because its key stayed behind,
    /// by id (hex), in full.
    pub dropped_gate_decisions: Vec<String>,
    /// The custody publication status once the restore's own retirements
    /// were journaled; `None` when it could not be read (logged).
    pub publication: Option<CustodyStatus>,
    pub custody_note: Option<String>,
    pub training_note: Option<String>,
}

/// A fresh recipient the restored key was wrapped to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddedRecipient {
    pub label: String,
    pub role: EscrowRole,
    pub fingerprint: [u8; 32],
    pub wrap_id: String,
    /// The escrow capsule's report id, BLAKE3 of its bytes in hex, as the
    /// spool names it; spooled at the next start, never here.
    pub report_id: String,
}

/// Why a recipient retired in the restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetiredBy {
    /// The plan named it released.
    Plan,
    /// The custody log retired it earlier; the image still carried its wrap.
    CustodyLog,
}

/// One recipient the restore retired, with the vault's own receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetiredRecipient {
    pub label: String,
    pub fingerprint: Option<[u8; 32]>,
    pub retired_by: RetiredBy,
    /// The plan's host-recipient epoch for a released one.
    pub recipient_epoch: Option<u64>,
    pub receipt: EscrowRetirement,
}

/// Where the restore's recipient retirements are durable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecipientRetirementDisposition {
    /// In the custody log, one frame each, at the takeover writer epoch.
    Journaled { epoch: u64, seqs: Vec<u64> },
    /// In the restored key header only: no custody head was admitted.
    LocalOnly { note: &'static str },
}

/// What the restore did to the restored key's wraps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientAdmissionFacts {
    pub added: Vec<AddedRecipient>,
    pub retired: Vec<RetiredRecipient>,
    pub disposition: RecipientRetirementDisposition,
}

/// Everything a cold managed restore verified, beside its report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreAdmission {
    pub expected: SourceExpectation,
    pub source: VerifiedSource,
    pub custody: CustodyAdmissionFacts,
    pub recipients: RecipientAdmissionFacts,
}

/// What the after-keep step (L14's commit marker) is handed, once every
/// keep is done.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreCommitFacts {
    pub restore_id: String,
    pub plan_digest: [u8; 32],
    pub attempt_id: String,
    pub generation: u64,
    pub checkpoint_id: [u8; 32],
    pub checkpoint_sequence: u64,
    /// The checkpoint commitment's crypto epoch.
    pub checkpoint_crypto_epoch: u64,
    /// The kept vault's directory, held by the returned vault.
    pub destination: PathBuf,
}
