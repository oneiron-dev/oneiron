//! The result pipe (`--restore-result-fd`) and the `restore_status` answer.
//!
//! The pipe carries UTF-8 NDJSON: one [`ManagedRestoreResultFrame`] per
//! line, each line's JSON at most [`MAX_CTL_LINE`] bytes, its newline
//! outside. For an input that parsed, in this order: one `started`, then
//! `progress` frames, then either the receipt in `receipt_chunk` frames and
//! one `verified`, or one `failed`; then EOF. An input that did not parse
//! gets one `failed` with no identity. A lost or missing terminal frame is
//! never success: the supervisor decides it by `restore_status` and `Ping`,
//! else by its own attempt record, the destination and the commit marker.
//!
//! A receipt spans as many frames and pages as its bytes need: each chunk is
//! the next run of its JSON bytes as lowercase hex at a byte offset, sized to
//! fit the line, and no item of it is ever dropped.

use serde::{Deserialize, Serialize};

use super::facts::ManagedRestoreIdentity;
use crate::{CtlResponse, MAX_CTL_LINE};

/// Why a cold managed restore failed; snake_case. The engine's own
/// admission reasons, then the managed start's. Each is a string but
/// `checkpoint_sequence_below_floor`, which carries its two numbers;
/// [`Self::as_str`] names every one as a string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RestoreFailureReason {
    SourceIdentityMismatch,
    DataKeyMismatch,
    ArtifactIdentityMismatch,
    ArtifactKindMismatch,
    SignerUntrusted,
    SignatureInvalid,
    ArtifactIntegrityInvalid,
    CodecInvalid,
    BackupRegistryBindingMismatch,
    /// The artifact's signed checkpoint sequence (`observed`) is below the
    /// plan's `wake_sequence_floor` (`floor`), refused before its manifest
    /// opens (FIX 969): `{"checkpoint_sequence_below_floor":{"floor":N,
    /// "observed":M}}`, both required.
    CheckpointSequenceBelowFloor {
        floor: u64,
        observed: u64,
    },
    CustodyRequirementInvalid,
    CustodyLineageMismatch,
    CustodyHeadInvalid,
    AnchorUnavailable,
    AnchorMissing,
    AnchorInvalid,
    CustodyLogIncomplete,
    CustodyDiverged,
    CustodyHeadTooOld,
    CustodyKeyMissing,
    CustodyOwnerKeyRequired,
    BodyCustodyUnavailable,
    ClaimReceiptInvalid,
    AnchorMoved,
    CustodyLandingFailed,
    ManagedDekMacMismatch,
    DerivationOwnerMismatch,
    PageCustodyInvalid,
    RecipientBindingInvalid,
    RecipientReused,
    LastWrap,
    RetirementAuthorityInvalid,
    StorageIo,
    StartupFailed,
    /// The input pipe, its object or a binding it names against argv.
    RestoreInputInvalid,
    /// The credential frame or the anchor credential pipe.
    CredentialsRejected,
    /// Two delivered descriptors name one number.
    DescriptorAlias,
    /// The isolation a real tenant needs is not proven for the destination.
    IsolationUnproven,
    /// Something already sits where the restore makes its destination.
    DestinationNotFresh,
    /// Another writer holds the destination's lease.
    WriterLeaseHeld,
    /// The destination is no longer the directory the restore made.
    DestinationMoved,
    /// The destination's disk is out of room.
    DiskCapacity,
    /// The restore was stopped before it finished.
    Cancelled,
    /// Whether the last step happened is not known.
    OutcomeUncertain,
    /// An added recipient's escrow report waits for the next start; a
    /// receipt's spool state, never a failed restore by itself.
    EscrowSpoolPending,
}

impl RestoreFailureReason {
    /// The reason's snake_case name, a string for every one, for a log
    /// field or a record keyed by reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceIdentityMismatch => "source_identity_mismatch",
            Self::DataKeyMismatch => "data_key_mismatch",
            Self::ArtifactIdentityMismatch => "artifact_identity_mismatch",
            Self::ArtifactKindMismatch => "artifact_kind_mismatch",
            Self::SignerUntrusted => "signer_untrusted",
            Self::SignatureInvalid => "signature_invalid",
            Self::ArtifactIntegrityInvalid => "artifact_integrity_invalid",
            Self::CodecInvalid => "codec_invalid",
            Self::BackupRegistryBindingMismatch => "backup_registry_binding_mismatch",
            Self::CheckpointSequenceBelowFloor { .. } => "checkpoint_sequence_below_floor",
            Self::CustodyRequirementInvalid => "custody_requirement_invalid",
            Self::CustodyLineageMismatch => "custody_lineage_mismatch",
            Self::CustodyHeadInvalid => "custody_head_invalid",
            Self::AnchorUnavailable => "anchor_unavailable",
            Self::AnchorMissing => "anchor_missing",
            Self::AnchorInvalid => "anchor_invalid",
            Self::CustodyLogIncomplete => "custody_log_incomplete",
            Self::CustodyDiverged => "custody_diverged",
            Self::CustodyHeadTooOld => "custody_head_too_old",
            Self::CustodyKeyMissing => "custody_key_missing",
            Self::CustodyOwnerKeyRequired => "custody_owner_key_required",
            Self::BodyCustodyUnavailable => "body_custody_unavailable",
            Self::ClaimReceiptInvalid => "claim_receipt_invalid",
            Self::AnchorMoved => "anchor_moved",
            Self::CustodyLandingFailed => "custody_landing_failed",
            Self::ManagedDekMacMismatch => "managed_dek_mac_mismatch",
            Self::DerivationOwnerMismatch => "derivation_owner_mismatch",
            Self::PageCustodyInvalid => "page_custody_invalid",
            Self::RecipientBindingInvalid => "recipient_binding_invalid",
            Self::RecipientReused => "recipient_reused",
            Self::LastWrap => "last_wrap",
            Self::RetirementAuthorityInvalid => "retirement_authority_invalid",
            Self::StorageIo => "storage_io",
            Self::StartupFailed => "startup_failed",
            Self::RestoreInputInvalid => "restore_input_invalid",
            Self::CredentialsRejected => "credentials_rejected",
            Self::DescriptorAlias => "descriptor_alias",
            Self::IsolationUnproven => "isolation_unproven",
            Self::DestinationNotFresh => "destination_not_fresh",
            Self::WriterLeaseHeld => "writer_lease_held",
            Self::DestinationMoved => "destination_moved",
            Self::DiskCapacity => "disk_capacity",
            Self::Cancelled => "cancelled",
            Self::OutcomeUncertain => "outcome_uncertain",
            Self::EscrowSpoolPending => "escrow_spool_pending",
        }
    }
}

/// The step of a cold managed restore a frame names; snake_case. A
/// `progress` frame names one the engine observes as it starts it:
/// `validating_input`, `source_check`, `restoring`, `commit_marker` and
/// `starting_service`. A `failed` frame names the step that failed,
/// including the steps inside the restore (`artifact_open` through
/// `page_custody`), which are never reported as progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRestorePhase {
    /// The input, its bindings against argv, the credentials and the
    /// destination's isolation, before anything is written.
    ValidatingInput,
    /// The delivered key, the artifact's identity and its signed commitment.
    SourceCheck,
    /// The artifact opened whole: its manifest, frames, image and digests.
    ArtifactOpen,
    /// The custody head, its anchor and log, admitted and landed.
    CustodyAdmission,
    /// The image's rows and bodies landed and the vault reopened.
    RowsLanding,
    /// The managed checks before the takeover fence: isolation, DEK MAC and
    /// derivation owner.
    Finish,
    /// The anchor's advance to the takeover writer epoch.
    TakeoverFence,
    /// The fresh escrow wraps and the released recipients' retirement.
    Recipients,
    /// The restored vault's page-seal custody read back.
    PageCustody,
    /// The commit marker, after every keep.
    CommitMarker,
    /// The restore itself, from the artifact's open to its keep.
    Restoring,
    /// The ordinary start of the kept vault, up to its ready byte.
    StartingService,
}

/// What a cold managed restore left at its destination; snake_case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRestoreDestination {
    /// Nothing was kept: the restore made nothing, or removed what it made.
    Removed,
    /// The restore was kept and is not serving: the destination and its
    /// custody stay, never rolled back.
    CommittedNotServing,
    /// What the destination holds is not known: it stays, never opened as
    /// ordinary or overwritten.
    Uncertain,
}

/// One line on the result pipe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagedRestoreResultFrame {
    /// The input parsed: the attempt it names.
    Started { identity: ManagedRestoreIdentity },
    /// A step the engine starts.
    Progress {
        identity: ManagedRestoreIdentity,
        phase: ManagedRestorePhase,
    },
    /// The receipt's bytes from `offset`, as lowercase hex.
    ReceiptChunk {
        identity: ManagedRestoreIdentity,
        offset: u64,
        data: String,
    },
    /// The restore is verified and kept: the receipt is `receipt_bytes`
    /// long and `receipt_id` is BLAKE3 of its bytes, in hex.
    Verified {
        identity: ManagedRestoreIdentity,
        receipt_id: String,
        receipt_bytes: u64,
        destination_state: ManagedRestoreDestination,
    },
    /// The restore failed: why, at which step, and what the destination
    /// holds. `identity` is `null` when the input did not parse.
    Failed {
        identity: Option<ManagedRestoreIdentity>,
        reason: RestoreFailureReason,
        phase: ManagedRestorePhase,
        destination_state: ManagedRestoreDestination,
    },
}

impl ManagedRestoreResultFrame {
    /// The frame as one NDJSON line, newline included; refused when its JSON
    /// is longer than [`MAX_CTL_LINE`].
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        let mut line = serde_json::to_vec(self)?;
        anyhow::ensure!(
            line.len() <= MAX_CTL_LINE,
            "a restore result frame is longer than a line"
        );
        line.push(b'\n');
        Ok(line)
    }

    /// The frames a verified restore ends with: its receipt's bytes in
    /// chunks, in order, then `verified`.
    pub fn verified(
        identity: &ManagedRestoreIdentity,
        receipt: &[u8],
    ) -> anyhow::Result<Vec<Self>> {
        let mut frames = Vec::new();
        let mut offset = 0;
        while offset < receipt.len() {
            let chunk = |data: String| Self::ReceiptChunk {
                identity: identity.clone(),
                offset: offset as u64,
                data,
            };
            let room = line_room(&chunk(String::new()))?;
            let end = receipt.len().min(offset + room);
            frames.push(chunk(crate::hex(&receipt[offset..end])));
            offset = end;
        }
        frames.push(Self::Verified {
            identity: identity.clone(),
            receipt_id: receipt_id(receipt),
            receipt_bytes: receipt.len() as u64,
            destination_state: ManagedRestoreDestination::CommittedNotServing,
        });
        Ok(frames)
    }
}

/// The receipt id: BLAKE3 of its exact bytes, in lowercase hex.
#[must_use]
pub fn receipt_id(receipt: &[u8]) -> String {
    blake3::hash(receipt).to_hex().to_string()
}

/// How many receipt bytes fit as hex in a line that holds `empty` with no
/// data yet; refused when not even one does. A host-order family's pages
/// (`host_holds`) are sized by it too.
pub(super) fn line_room(empty: &impl Serialize) -> anyhow::Result<usize> {
    let room = MAX_CTL_LINE.saturating_sub(serde_json::to_vec(empty)?.len()) / 2;
    anyhow::ensure!(room > 0, "a restore's identity leaves no room in a line");
    Ok(room)
}

/// The answer to `restore_status`
/// ([`CtlRequest::RestoreStatus`](crate::CtlRequest::RestoreStatus)): what
/// this process knows of the attempt asked about. Only `verified`, with
/// every receipt byte read back and its id checked, is success: every other
/// state, an unknown one, a refusal, EOF or no answer is not, and never
/// permission to open the destination as ordinary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RestoreStatus {
    /// This process restored no vault, or another attempt's.
    NotThisAttempt,
    /// The attempt is verified and kept. `data` is the receipt's bytes from
    /// `offset` as lowercase hex; `next_cursor` is the offset to ask for
    /// next, `null` once this page reaches the end.
    Verified {
        identity: ManagedRestoreIdentity,
        receipt_id: String,
        receipt_bytes: u64,
        offset: u64,
        data: String,
        next_cursor: Option<u64>,
    },
    /// The attempt failed in this process.
    Failed {
        identity: ManagedRestoreIdentity,
        reason: RestoreFailureReason,
        phase: ManagedRestorePhase,
        destination_state: ManagedRestoreDestination,
    },
    /// The cursor asked for is past the receipt's end: refused, never read
    /// from the start.
    CursorInvalid {
        identity: ManagedRestoreIdentity,
        receipt_bytes: u64,
    },
}

impl RestoreStatus {
    /// The page of `receipt` at `cursor` (its start for none), sized so the
    /// whole `restore_status` answer fits a ctl line.
    pub fn verified_page(
        identity: &ManagedRestoreIdentity,
        receipt: &[u8],
        cursor: Option<u64>,
    ) -> anyhow::Result<Self> {
        let receipt_bytes = receipt.len() as u64;
        let offset = cursor.unwrap_or(0);
        let Some(start) = usize::try_from(offset)
            .ok()
            .filter(|start| *start <= receipt.len())
        else {
            return Ok(Self::CursorInvalid {
                identity: identity.clone(),
                receipt_bytes,
            });
        };
        let page = |data: String, next_cursor: Option<u64>| Self::Verified {
            identity: identity.clone(),
            receipt_id: receipt_id(receipt),
            receipt_bytes,
            offset,
            data,
            next_cursor,
        };
        let room = line_room(&CtlResponse::RestoreStatus {
            restore_status: page(String::new(), Some(u64::MAX)),
        })?;
        let end = receipt.len().min(start + room);
        let next_cursor = (end < receipt.len()).then_some(end as u64);
        Ok(page(crate::hex(&receipt[start..end]), next_cursor))
    }

    /// Checks a `verified` page's shape: its id, its hex, and that its
    /// offset, length and next cursor agree with the receipt's length and
    /// move forward.
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Self::Verified {
            receipt_id,
            receipt_bytes,
            offset,
            data,
            next_cursor,
            ..
        } = self
        {
            let lower_hex = |text: &str| {
                text.bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            };
            anyhow::ensure!(
                receipt_id.len() == 64 && lower_hex(receipt_id),
                "a restore receipt id is 64 lowercase hex digits"
            );
            anyhow::ensure!(
                data.len().is_multiple_of(2) && lower_hex(data),
                "a restore receipt page is lowercase hex"
            );
            let end = offset
                .checked_add((data.len() / 2) as u64)
                .filter(|end| end <= receipt_bytes)
                .ok_or_else(|| anyhow::anyhow!("a restore receipt page runs past its receipt"))?;
            anyhow::ensure!(
                match next_cursor {
                    Some(next) => *next == end && end > *offset && end < *receipt_bytes,
                    None => end == *receipt_bytes,
                },
                "a restore receipt page's next cursor does not follow it"
            );
        }
        Ok(())
    }
}

/// Whether every frame and `restore_status` page naming `identity` fits a
/// line, with room for receipt bytes: the input's codec bound, refused
/// before anything is touched when it does not hold.
#[must_use]
pub fn identity_fits(identity: &ManagedRestoreIdentity) -> bool {
    let chunk = ManagedRestoreResultFrame::ReceiptChunk {
        identity: identity.clone(),
        offset: u64::MAX,
        data: String::new(),
    };
    // The longest reason on the wire: its two numbers at their widest.
    let failed = ManagedRestoreResultFrame::Failed {
        identity: Some(identity.clone()),
        reason: RestoreFailureReason::CheckpointSequenceBelowFloor {
            floor: u64::MAX,
            observed: u64::MAX,
        },
        phase: ManagedRestorePhase::CustodyAdmission,
        destination_state: ManagedRestoreDestination::CommittedNotServing,
    };
    let page = CtlResponse::RestoreStatus {
        restore_status: RestoreStatus::Verified {
            identity: identity.clone(),
            receipt_id: receipt_id(&[]),
            receipt_bytes: u64::MAX,
            offset: u64::MAX,
            data: String::new(),
            next_cursor: Some(u64::MAX),
        },
    };
    line_room(&chunk).is_ok() && line_room(&page).is_ok() && failed.encode().is_ok()
}
