//! A sealed register whose surface stated no `manifest_ref` (CALLS
//! CUSTODY_MANIFEST_UNSTATED). Its recorder sees only ciphertext, so it
//! cannot read which manifest the record names. It attaches the vault's one
//! current approved manifest beside the envelope, under the digest the
//! request names, or binds an explicit "no manifest" mark there instead. The
//! holder checks a record that names the attached manifest against it. It
//! registers every other one, and one that disagrees, without a manifest
//! check, and says so: an unstated register never refuses on a manifest
//! mismatch, it reports it. A stated `manifest_ref` keeps its refusal (CALLS
//! CUSTODY_MANIFEST_RECHECK).

use super::super::owner_door::recheck_manifest_snapshot_in_txn;
use super::input::{Attached, attach_current_manifest, attach_no_manifest};
use crate::Vault;
use crate::authority::OwnerWorkRefusal;
use crate::error::Result;
use crate::secret_custody::SecretCustodyRecord;
use crate::store::Store;

/// What a sealed register whose surface stated no `manifest_ref` is checked
/// against (CALLS CUSTODY_MANIFEST_UNSTATED).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyManifestUnstated {
    /// The recorder attaches the vault's one current approved manifest: the
    /// manifest file at the commit the vault publishes now for a branch of a
    /// repository it serves, when exactly one such commit holds one. When
    /// none does, or several do, it binds an explicit "no manifest" mark
    /// under the digest instead. The holder checks a record that names the
    /// attached manifest against it in its committing transaction. A record
    /// that names none, names another, or disagrees with it registers without
    /// a manifest check, and the receipt says which: an unstated register
    /// never refuses on a manifest mismatch, it reports it (Engine 10-19
    /// 15:0x). A snapshot the surface sealed beside the record stays the one
    /// checked, with its refusal. Nothing asks where the holder runs.
    AttachCurrentApprovedOrRecordNone,
}

const CUSTODY_MANIFEST_UNSTATED: CustodyManifestUnstated =
    CustodyManifestUnstated::AttachCurrentApprovedOrRecordNone;

/// What the holder of a register the owner's surface sealed without stating
/// a `manifest_ref` checked its record against, or will (CALLS
/// CUSTODY_MANIFEST_UNSTATED). Manifest refs only, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyManifestCheck {
    /// The vault's one current approved manifest, by its `manifest_ref`,
    /// attached for a holder that is not this install: it checks a record
    /// that names it against it, and registers any other unchecked.
    Current(String),
    /// The record names the vault's one current approved manifest and agrees
    /// with it.
    Checked(String),
    /// No current approved manifest applied, or the record names none:
    /// registered without a manifest check.
    Unchecked,
    /// The record names another manifest than the one the vault publishes:
    /// registered without a manifest check.
    OtherManifest {
        /// The `manifest_ref` the record names.
        record: String,
        /// The one the vault publishes now.
        published: String,
    },
    /// The record names the manifest the vault publishes but disagrees with
    /// it: registered without a manifest check.
    Disagrees(String),
}

impl CustodyManifestCheck {
    /// Whether the record is, or will be, registered without a manifest
    /// check.
    #[must_use]
    pub fn unchecked(&self) -> bool {
        matches!(
            self,
            Self::Unchecked | Self::OtherManifest { .. } | Self::Disagrees(_)
        )
    }

    /// The words a surface shows, naming the manifests involved.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Current(published) => format!(
                "this vault publishes {published}; the holder checks a record that names it \
                 against it, and registers any other without a manifest check"
            ),
            Self::Checked(published) => {
                format!("checked against {published}, which this vault publishes")
            }
            Self::Unchecked => "registered without a manifest check".to_owned(),
            Self::OtherManifest { record, published } => format!(
                "the record names {record}, this vault publishes {published}; registered \
                 without a manifest check"
            ),
            Self::Disagrees(published) => format!(
                "the record disagrees with {published}, which this vault publishes; registered \
                 without a manifest check"
            ),
        }
    }
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

/// What a holder makes of a register it opened against its manifest.
pub(super) enum RegisterVerdict {
    /// Register it; for a surface that stated no `manifest_ref`, what it was
    /// checked against.
    Register(Option<CustodyManifestCheck>),
    /// Refuse it.
    Refuse(OwnerWorkRefusal),
}

/// Checks `record`, a register opened from its input, in the holder's
/// committing transaction `txn`: against the snapshot `framed` beside it in
/// its sealed body, else against what its recorder `attached`. The snapshot
/// sealed in, or resolved for a stated ref, which must be the record's, is
/// checked with its refusal (CALLS CUSTODY_MANIFEST_RECHECK). For a surface
/// that stated none, the vault's current approved manifest is checked when
/// the record names it, and any mismatch registers unchecked and says so
/// (CALLS CUSTODY_MANIFEST_UNSTATED).
pub(super) fn check_register_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    framed: Option<String>,
    attached: Option<Attached>,
    record: &SecretCustodyRecord,
) -> Result<RegisterVerdict> {
    let strict = |snapshot: Option<&str>| -> Result<RegisterVerdict> {
        Ok(
            match recheck_manifest_snapshot_in_txn(store, txn, record, snapshot)? {
                Some(refusal) => RegisterVerdict::Refuse(refusal),
                None => RegisterVerdict::Register(None),
            },
        )
    };
    match (framed, attached) {
        (framed, None) => strict(framed.as_deref()),
        (None, Some(Attached::Stated(stated))) if stated.manifest_ref == record.manifest_ref => {
            strict(Some(stated.text.as_str()))
        }
        (_, Some(Attached::Stated(_))) => {
            Ok(RegisterVerdict::Refuse(OwnerWorkRefusal::InvalidInput))
        }
        (Some(framed), Some(Attached::Current(_) | Attached::NoManifest)) => {
            strict(Some(framed.as_str()))
        }
        (None, Some(Attached::NoManifest)) => Ok(RegisterVerdict::Register(Some(
            CustodyManifestCheck::Unchecked,
        ))),
        (None, Some(Attached::Current(current))) => {
            let check = match CUSTODY_MANIFEST_UNSTATED {
                CustodyManifestUnstated::AttachCurrentApprovedOrRecordNone => {
                    if record.manifest_ref.is_empty() {
                        CustodyManifestCheck::Unchecked
                    } else if record.manifest_ref != current.manifest_ref {
                        CustodyManifestCheck::OtherManifest {
                            record: record.manifest_ref.clone(),
                            published: current.manifest_ref,
                        }
                    } else if recheck_manifest_snapshot_in_txn(
                        store,
                        txn,
                        record,
                        Some(current.text.as_str()),
                    )?
                    .is_some()
                    {
                        CustodyManifestCheck::Disagrees(current.manifest_ref)
                    } else {
                        CustodyManifestCheck::Checked(current.manifest_ref)
                    }
                }
            };
            Ok(RegisterVerdict::Register(Some(check)))
        }
    }
}
