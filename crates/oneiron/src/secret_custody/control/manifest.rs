//! A sealed register whose surface stated no `manifest_ref` (CALLS
//! CUSTODY_MANIFEST_UNSTATED, CUSTODY_MANIFEST_UNSTATED_MULTI). Its recorder
//! sees only ciphertext, so it cannot read which manifest the record names.
//! It attaches every secret manifest the vault publishes beside the envelope,
//! under the digest the request names, or binds an explicit "no manifest" or
//! "unread" mark there instead. The holder selects the one the record names
//! and checks the record against it. It registers every other one, and one
//! that disagrees, without a manifest check, and its signed result says so:
//! an unstated register never refuses on a manifest mismatch, it reports it.
//! A stated `manifest_ref` keeps its refusal (CALLS
//! CUSTODY_MANIFEST_RECHECK).

use oneiron_authority::authority::{CustodyRegisterCheck, CustodyUncheckedReason};

use super::super::owner_door::recheck_manifest_snapshot_in_txn;
use super::input::{
    Attached, AttachedManifest, attach_no_manifest, attach_published_manifests, attach_unread,
};
use crate::Vault;
use crate::authority::OwnerWorkRefusal;
use crate::error::Result;
use crate::secret_custody::SecretCustodyRecord;
use crate::store::Store;

/// What a sealed register whose surface stated no `manifest_ref` meets on a
/// manifest mismatch (CALLS CUSTODY_MANIFEST_UNSTATED).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyManifestUnstated {
    /// It never refuses on one: a record that names no manifest, names one
    /// the vault does not publish, or disagrees with the one it names
    /// registers without a manifest check, and its holder's signed result
    /// says which (Engine 10-19 15:0x). A snapshot the surface sealed beside
    /// the record stays the one checked, with its refusal. Nothing asks
    /// where the holder runs.
    ReportNeverRefuse,
}

const CUSTODY_MANIFEST_UNSTATED: CustodyManifestUnstated =
    CustodyManifestUnstated::ReportNeverRefuse;

/// Which manifests the recorder of an unstated register attaches, and which
/// one its holder checks (CALLS CUSTODY_MANIFEST_UNSTATED_MULTI).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyManifestUnstatedMulti {
    /// The recorder attaches every secret manifest the vault publishes now:
    /// the manifest file at the commit it publishes for each branch of each
    /// repository it serves, ordered by `manifest_ref`. It caps no count and
    /// leaves none out: past one row's bound the input travels in numbered
    /// parts (Rule 5). With none published it binds a "no manifest" mark,
    /// and when they cannot be read an "unread" mark. The holder selects the
    /// one whose ref the record names and checks the record against it in
    /// its committing transaction. What the recorder attached is its
    /// evidence (`Published`); the holder's signed result is the judgment.
    AttachEveryPublishedHolderSelects,
}

const CUSTODY_MANIFEST_UNSTATED_MULTI: CustodyManifestUnstatedMulti =
    CustodyManifestUnstatedMulti::AttachEveryPublishedHolderSelects;

/// What the holder of a register the owner's surface sealed without stating
/// a `manifest_ref` checked its record against, or what its recorder
/// attached for it (CALLS CUSTODY_MANIFEST_UNSTATED_MULTI). Manifest refs
/// only, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyManifestCheck {
    /// The recorder's evidence, for a holder that is not this install: every
    /// secret manifest the vault publishes now, by its `manifest_ref`,
    /// attached beside the envelope. The holder checks a record that names
    /// one of them against it, and registers any other unchecked.
    Published(Vec<String>),
    /// What the record was, or will be, registered on: the holder's
    /// judgment, as its signed result carries it, or for a recorder that
    /// attached no manifest, the one judgment its holder can reach.
    Judged(CustodyRegisterCheck),
}

impl CustodyManifestCheck {
    /// Whether the record is, or will be, registered without a manifest
    /// check.
    #[must_use]
    pub fn unchecked(&self) -> bool {
        matches!(self, Self::Judged(check) if check.unchecked())
    }

    /// The words a surface shows, naming the manifests involved.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Published(published) => format!(
                "this vault publishes {}; the holder checks a record that names one of them \
                 against it, and registers any other without a manifest check",
                published.join(", ")
            ),
            Self::Judged(check) => judgment_text(check),
        }
    }
}

/// The words a surface shows for a holder's judgment, naming the manifests
/// it involves.
pub(super) fn judgment_text(check: &CustodyRegisterCheck) -> String {
    let (reason, refs) = match check {
        CustodyRegisterCheck::Checked { manifest_ref } => {
            return format!("checked against {manifest_ref}, which this vault publishes");
        }
        CustodyRegisterCheck::Unchecked { reason, refs } => (reason, refs.split_first()),
    };
    let found = match (reason, refs) {
        (CustodyUncheckedReason::NoneNamed, _) => "the record names no manifest".to_owned(),
        (CustodyUncheckedReason::NonePublished, _) => {
            "this vault publishes no secret manifest".to_owned()
        }
        (CustodyUncheckedReason::Unread, _) => {
            "this vault's published secret manifests could not be read".to_owned()
        }
        (CustodyUncheckedReason::OtherManifest, Some((record, []))) => {
            format!("the record names {record}, which this vault does not publish")
        }
        (CustodyUncheckedReason::OtherManifest, Some((record, published))) => format!(
            "the record names {record}, which this vault does not publish (it publishes {})",
            published.join(", ")
        ),
        (CustodyUncheckedReason::Disagrees, Some((named, _))) => {
            format!("the record disagrees with {named}, which this vault publishes")
        }
        (CustodyUncheckedReason::OtherManifest | CustodyUncheckedReason::Disagrees, None) => {
            "the record's manifest did not check".to_owned()
        }
    };
    format!("{found}; registered without a manifest check")
}

/// A judgment that the record registers without a manifest check, for
/// `reason`, naming `refs`.
fn unchecked(reason: CustodyUncheckedReason, refs: Vec<String>) -> CustodyRegisterCheck {
    CustodyRegisterCheck::Unchecked { reason, refs }
}

/// The input a recorder records for a sealed register whose surface stated
/// no `manifest_ref`, and what it attached for its holder (CALLS
/// CUSTODY_MANIFEST_UNSTATED_MULTI): the envelope with every secret manifest
/// the vault publishes, else with the "no manifest" mark, or the "unread"
/// mark when they cannot be read. It never refuses a register for its
/// manifests and never leaves one out: past one row's bound the input
/// travels in numbered parts.
///
/// # Errors
/// Only an attachment past its own frame (a length beyond a `u32`).
pub(super) fn unstated_input(
    vault: &Vault,
    envelope: &[u8],
) -> Result<(Vec<u8>, CustodyManifestCheck)> {
    match CUSTODY_MANIFEST_UNSTATED_MULTI {
        CustodyManifestUnstatedMulti::AttachEveryPublishedHolderSelects => {
            match vault.published_origin_secret_manifests() {
                Ok(published) if !published.is_empty() => {
                    let input = {
                        let attached: Vec<(&str, &str)> = published
                            .iter()
                            .map(|manifest| {
                                (manifest.manifest_ref.as_str(), manifest.text.as_str())
                            })
                            .collect();
                        attach_published_manifests(envelope, &attached)?
                    };
                    let refs = published
                        .into_iter()
                        .map(|manifest| manifest.manifest_ref)
                        .collect();
                    Ok((input, CustodyManifestCheck::Published(refs)))
                }
                Ok(_) => Ok((
                    attach_no_manifest(envelope)?,
                    CustodyManifestCheck::Judged(unchecked(
                        CustodyUncheckedReason::NonePublished,
                        Vec::new(),
                    )),
                )),
                Err(error) => {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "the vault's published secret manifests were not read; the register \
                         is taken without a manifest check"
                    );
                    Ok((
                        attach_unread(envelope)?,
                        CustodyManifestCheck::Judged(unchecked(
                            CustodyUncheckedReason::Unread,
                            Vec::new(),
                        )),
                    ))
                }
            }
        }
    }
}

/// What a holder makes of a register it opened against its manifest.
pub(super) enum RegisterVerdict {
    /// Register it; for a surface that stated no `manifest_ref`, what it was
    /// checked against: the judgment its result signs.
    Register(Option<CustodyRegisterCheck>),
    /// Refuse it.
    Refuse(OwnerWorkRefusal),
}

/// Checks `record`, a register opened from its input, in the holder's
/// committing transaction `txn`: against the snapshot `framed` beside it in
/// its sealed body, else against what its recorder `attached`. The snapshot
/// sealed in, or resolved for a stated ref, which must be the record's, is
/// checked with its refusal (CALLS CUSTODY_MANIFEST_RECHECK). For a surface
/// that stated none, the published manifest the record names is checked, and
/// any mismatch registers unchecked and says why (CALLS
/// CUSTODY_MANIFEST_UNSTATED, CUSTODY_MANIFEST_UNSTATED_MULTI).
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
        (Some(framed), Some(Attached::Published(_) | Attached::NoManifest | Attached::Unread)) => {
            strict(Some(framed.as_str()))
        }
        (None, Some(Attached::NoManifest)) => Ok(RegisterVerdict::Register(Some(unchecked(
            CustodyUncheckedReason::NonePublished,
            Vec::new(),
        )))),
        (None, Some(Attached::Unread)) => Ok(RegisterVerdict::Register(Some(unchecked(
            CustodyUncheckedReason::Unread,
            Vec::new(),
        )))),
        (None, Some(Attached::Published(published))) => {
            let check = match (CUSTODY_MANIFEST_UNSTATED_MULTI, CUSTODY_MANIFEST_UNSTATED) {
                (
                    CustodyManifestUnstatedMulti::AttachEveryPublishedHolderSelects,
                    CustodyManifestUnstated::ReportNeverRefuse,
                ) => judge_unstated_in_txn(store, txn, record, published)?,
            };
            Ok(RegisterVerdict::Register(Some(check)))
        }
    }
}

/// The holder's judgment of an unstated register against every manifest its
/// recorder attached: it selects the one whose ref the record names and
/// checks the record against it. A record that names none, names one not
/// attached, or disagrees registers without a manifest check, and the
/// judgment says why, by refs alone.
fn judge_unstated_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &SecretCustodyRecord,
    mut published: Vec<AttachedManifest>,
) -> Result<CustodyRegisterCheck> {
    if record.manifest_ref.is_empty() {
        return Ok(unchecked(CustodyUncheckedReason::NoneNamed, Vec::new()));
    }
    let Some(index) = published
        .iter()
        .position(|manifest| manifest.manifest_ref == record.manifest_ref)
    else {
        let refs = std::iter::once(record.manifest_ref.clone())
            .chain(published.into_iter().map(|manifest| manifest.manifest_ref))
            .collect();
        return Ok(unchecked(CustodyUncheckedReason::OtherManifest, refs));
    };
    let named = published.swap_remove(index);
    let disagrees =
        recheck_manifest_snapshot_in_txn(store, txn, record, Some(named.text.as_str()))?.is_some();
    Ok(if disagrees {
        unchecked(CustodyUncheckedReason::Disagrees, vec![named.manifest_ref])
    } else {
        CustodyRegisterCheck::Checked {
            manifest_ref: named.manifest_ref,
        }
    })
}
