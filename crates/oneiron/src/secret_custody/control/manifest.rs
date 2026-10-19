//! A sealed register whose surface stated no `manifest_ref` (CALLS
//! CUSTODY_MANIFEST_UNSTATED). Its recorder sees only ciphertext, so it
//! cannot read which manifest the record names. It attaches the vault's one
//! current approved manifest beside the envelope, under the digest the
//! request names, or binds an explicit "no manifest" mark there instead. The
//! holder checks a record that names the attached manifest against it, as
//! for a stated one (CALLS CUSTODY_MANIFEST_RECHECK), and registers any other
//! knowingly, without a manifest check. Nothing that registered before is
//! refused.

use super::input::{Attached, attach_current_manifest, attach_no_manifest};
use crate::Vault;
use crate::authority::OwnerWorkRefusal;
use crate::secret_custody::SecretCustodyRecord;

/// What a sealed register whose surface stated no `manifest_ref` is checked
/// against (CALLS CUSTODY_MANIFEST_UNSTATED).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyManifestUnstated {
    /// The recorder attaches the vault's one current approved manifest: the
    /// manifest file at the commit the vault publishes now for a branch of a
    /// repository it serves, when exactly one such commit holds one. When
    /// none does, or several do, it binds an explicit "no manifest" mark
    /// under the digest instead, and the receipt says the secret registers
    /// without a manifest check. The holder checks a record that names the
    /// attached manifest against it in its committing transaction; a record
    /// that names none, or another, registers without a manifest check, as
    /// before. A snapshot the surface sealed beside the record stays the one
    /// checked. Nothing asks where the holder runs.
    AttachCurrentApprovedOrRecordNone,
}

const CUSTODY_MANIFEST_UNSTATED: CustodyManifestUnstated =
    CustodyManifestUnstated::AttachCurrentApprovedOrRecordNone;

/// What the holder of a register the owner's surface sealed without stating
/// a `manifest_ref` checks its record against (CALLS
/// CUSTODY_MANIFEST_UNSTATED).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyManifestCheck {
    /// The vault's one current approved manifest, by its `manifest_ref`,
    /// attached for the holder: a record that names it is checked against
    /// it.
    Current(String),
    /// No current approved manifest applies: the secret registers without a
    /// manifest check.
    Unchecked,
}

/// The input a recorder records for a sealed register whose surface stated
/// no `manifest_ref`, and what its holder checks the record against: the
/// envelope with the vault's one current approved manifest attached, else
/// with the "no manifest" mark. It never refuses: past one input's bound the
/// envelope goes bare (`None`), unchecked as before.
pub(super) fn unstated_input(
    vault: &Vault,
    envelope: &[u8],
) -> (Option<Vec<u8>>, CustodyManifestCheck) {
    match CUSTODY_MANIFEST_UNSTATED {
        CustodyManifestUnstated::AttachCurrentApprovedOrRecordNone => {
            if let Some(current) = vault.current_origin_secret_manifest()
                && let Ok(input) =
                    attach_current_manifest(envelope, &current.manifest_ref, &current.text)
            {
                return (
                    Some(input),
                    CustodyManifestCheck::Current(current.manifest_ref),
                );
            }
            (
                attach_no_manifest(envelope).ok(),
                CustodyManifestCheck::Unchecked,
            )
        }
    }
}

/// The manifest text a holder checks `record`, a register opened from its
/// input, against: the snapshot `framed` beside the record in its sealed
/// body, else what its recorder `attached` (CALLS CUSTODY_MANIFEST_RECHECK):
/// the manifest resolved for a stated ref, which must be the record's, or,
/// for a surface that stated none, the vault's current approved manifest
/// when the record names it (CALLS CUSTODY_MANIFEST_UNSTATED). `None`: no
/// manifest check. `Err`: the holder refuses.
pub(super) fn register_snapshot(
    framed: Option<String>,
    attached: Option<Attached>,
    record: &SecretCustodyRecord,
) -> Result<Option<String>, OwnerWorkRefusal> {
    match (framed, attached) {
        (framed, None | Some(Attached::NoManifest)) => Ok(framed),
        (None, Some(Attached::Stated(stated))) if stated.manifest_ref == record.manifest_ref => {
            Ok(Some(stated.text))
        }
        (_, Some(Attached::Stated(_))) => Err(OwnerWorkRefusal::InvalidInput),
        (Some(framed), Some(Attached::Current(_))) => Ok(Some(framed)),
        (None, Some(Attached::Current(current))) => match CUSTODY_MANIFEST_UNSTATED {
            CustodyManifestUnstated::AttachCurrentApprovedOrRecordNone => {
                Ok((current.manifest_ref == record.manifest_ref).then_some(current.text))
            }
        },
    }
}
