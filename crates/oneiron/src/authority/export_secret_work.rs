//! Holder-mediated export (FIX 4624(b)): what an owner export records for
//! each custody secret its install could not open, and where each stands.
//!
//! An owner's whole-vault export reads every custody record it carries in
//! its snapshot. A record the export may carry as a value but whose value
//! does not open here (this install holds the row, not the key) goes as its
//! handle, as before, and is named here by id and generation alone. After
//! the copy is made, in the export's audit write, each such secret becomes
//! one export secret request ([`OwnerWorkBody::ExportSecret`]) carrying the
//! export's own act exactly as its door authenticated it, linked to the
//! export's signed `ExportAct` when there is one, naming the install that
//! holds the secret ([`export_secret_executor`]) and the recipient machine
//! the owner chose. Its holder seals the value to that recipient alone
//! (`crate::secret_custody::holder_export`); this install never holds it.
//!
//! Nothing here holds the copy back: the archive, its handles and its
//! warnings are the export's as before. A secret no request could be
//! recorded for says why ([`HolderExportUnassigned`]); one whose write failed
//! says it was not recorded, never that it is queued.

use serde::{Deserialize, Serialize};

use crate::authority::{
    AuthorityEntryHash, AuthorityFold, ExportSecretWork, OwnerAct, OwnerWorkBody,
};
use crate::batch::export::ArchiveSecretCustody;
use crate::world_keys::{OwnerWorkReceipt, OwnerWorkStatus, OwnerWorkUnassigned};
use crate::{EntityId, Vault};

/// One custody secret an export's snapshot met that this install could not
/// open: value-free, for the export's audit write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct HolderExportNeed {
    pub(crate) secret: EntityId,
    /// The custody generation the snapshot read.
    pub(crate) generation: u32,
}

/// One custody secret an owner export could not open here, and where its
/// holder's sealed copy stands (FIX 4624(b)). Ids and a generation only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HolderExportRequest {
    /// The secret's custody record id; the archive carries it as its handle.
    pub secret: EntityId,
    /// The custody generation the export met.
    pub generation: u32,
    pub state: HolderExportState,
}

/// Where one holder export request stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum HolderExportState {
    /// Recorded for its holder: the request's signed authority-log entry,
    /// as hex, the install that holds the secret, and its status as the
    /// fold read it. Enacted means its holder committed the sealed copy,
    /// never that the owner fetched it.
    Recorded {
        request: String,
        holder: EntityId,
        status: OwnerWorkStatus,
    },
    /// No request was recorded, for the reason given; the archive's handle
    /// stands.
    Unassigned { reason: HolderExportUnassigned },
    /// The export's audit write did not record it (logged): nothing waits
    /// for a holder.
    Unrecorded,
}

/// Why an export recorded no request for a secret's holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HolderExportUnassigned {
    /// The export's door records no owner act (an embedded or raw door):
    /// no act exists to carry to a holder.
    NoOwnerAct,
    /// The exporting owner is no live owner of the vault any more.
    OwnerNotLive,
    /// The owner named no machine to receive the sealed copy.
    NoRecipient,
    /// The machine the owner named is no live linked install with an
    /// encryption key that imports.
    RecipientNotLinked,
    /// No linked install is known to hold the secret at this generation.
    NoHolder,
    /// This install has no live machine profile to carry the owner's act.
    NoCarrier,
}

impl HolderExportUnassigned {
    /// The words a surface shows.
    #[must_use]
    pub fn text(self) -> &'static str {
        match self {
            Self::NoOwnerAct => "this export recorded no owner act to carry to a holder",
            Self::OwnerNotLive => "the exporting owner is no live owner of the vault",
            Self::NoRecipient => "no machine was named to receive the sealed copy",
            Self::RecipientNotLinked => "the named recipient is not a linked install",
            Self::NoHolder => "no linked install is known to hold this secret",
            Self::NoCarrier => "this install cannot carry the owner's act",
        }
    }
}

impl HolderExportRequest {
    fn unassigned(need: HolderExportNeed, reason: HolderExportUnassigned) -> Self {
        Self {
            secret: need.secret,
            generation: need.generation,
            state: HolderExportState::Unassigned { reason },
        }
    }

    fn unrecorded(need: HolderExportNeed) -> Self {
        Self {
            secret: need.secret,
            generation: need.generation,
            state: HolderExportState::Unrecorded,
        }
    }

    /// The entry for `need` from the recorder's receipt: recorded, or no
    /// holder to name.
    fn of_receipt(need: HolderExportNeed, receipt: &OwnerWorkReceipt) -> Self {
        let state = match (&receipt.request, receipt.executor) {
            (Some(request), Some(holder)) => HolderExportState::Recorded {
                request: request.clone(),
                holder,
                status: receipt.status,
            },
            _ => HolderExportState::Unassigned {
                reason: HolderExportUnassigned::NoHolder,
            },
        };
        Self {
            secret: need.secret,
            generation: need.generation,
            state,
        }
    }

    /// This entry as `fold` stands now: a recorded request's status read
    /// again; every other entry as it was.
    #[must_use]
    pub(crate) fn refreshed(mut self, fold: &AuthorityFold) -> Self {
        if let HolderExportState::Recorded {
            request, status, ..
        } = &mut self.state
            && let Some(receipt) =
                entry_of_hex(request).and_then(|entry| OwnerWorkReceipt::of(fold, entry))
        {
            *status = receipt.status;
        }
        self
    }

    /// The request's signed entry, once recorded.
    #[must_use]
    pub fn request_entry(&self) -> Option<AuthorityEntryHash> {
        match &self.state {
            HolderExportState::Recorded { request, .. } => entry_of_hex(request),
            HolderExportState::Unassigned { .. } | HolderExportState::Unrecorded => None,
        }
    }
}

/// The entry hash a receipt's lowercase hex names.
fn entry_of_hex(hex: &str) -> Option<AuthorityEntryHash> {
    blake3::Hash::from_hex(hex).ok().map(|hash| *hash.as_bytes())
}

/// One export secret request as its owner reads it (FIX 4624(b)): where it
/// stands and, once its holder sealed it and this install keeps the copy,
/// the sealed copy itself. Ids, digests and ciphertext only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportSecretSupplement {
    /// The request's signed authority-log entry, as hex.
    pub request: String,
    pub secret: EntityId,
    pub generation: u32,
    /// The export it supplements, as its audit row names it.
    pub export: EntityId,
    /// The install that holds the secret and seals it.
    pub holder: EntityId,
    /// The machine the copy is sealed to: only it opens the copy.
    pub recipient: EntityId,
    pub status: OwnerWorkStatus,
    /// BLAKE3 of the sealed copy, lowercase hex, as its signed result names
    /// it; `None` before the holder sealed it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// The sealed copy, standard base64, when this install keeps it; `None`
    /// before it is sealed, or when only its holder keeps it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed: Option<String>,
}

/// One export secret supplement the recipient opened: the archive row of
/// its secret, its value in it, for the owner's import. Wiped when dropped.
pub struct OpenedSecretSupplement {
    pub(crate) row: ArchiveSecretCustody,
}

impl std::fmt::Debug for OpenedSecretSupplement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedSecretSupplement")
            .field("row", &self.row)
            .finish()
    }
}

impl Drop for OpenedSecretSupplement {
    fn drop(&mut self) {
        if let Some(body) = self.row.body.as_mut() {
            zeroize::Zeroize::zeroize(body);
        }
    }
}

/// What the owner's import of one opened supplement did with its secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretSupplementImport {
    /// Restored under its own id.
    Restored,
    /// The same record is already here: unchanged.
    Unchanged,
    /// Left as it is: an admitted revoke ended it, or the record here under
    /// its id could not be compared.
    Skipped,
}

/// What an owner export names for its holders, in its audit write.
pub(crate) struct HolderExportBasis<'a> {
    /// The export's act, as its door authenticated it; `None` for a door
    /// that records none.
    pub(crate) act: Option<OwnerAct>,
    /// The export's id, as its audit row names it.
    pub(crate) export: EntityId,
    /// BLAKE3 of the archive, where its door read it back.
    pub(crate) digest: Option<[u8; 32]>,
    /// The export's signed `ExportAct` entry, when its carrier signed one.
    pub(crate) export_act: Option<AuthorityEntryHash>,
    /// The machine the owner named to receive the sealed copies.
    pub(crate) recipient: Option<EntityId>,
    pub(crate) needs: &'a [HolderExportNeed],
}

/// The install an export secret request names as executor: one the fold
/// proves holds the secret at the generation the export met (CALLS
/// CUSTODY_EXECUTOR's holder, read back from its enacted request), a live
/// head's first, whose proof key stands here. Never a recipient a value was
/// merely sealed to, and never invented: with none, no request is recorded.
pub(crate) fn export_secret_executor(
    fold: &AuthorityFold,
    work: &ExportSecretWork,
) -> std::result::Result<EntityId, OwnerWorkUnassigned> {
    fold.custody_value_holders(work.secret, work.generation)
        .into_iter()
        .find(|holder| fold.machine_proof_key(*holder).is_some())
        .ok_or(OwnerWorkUnassigned::NoCustodyHolder)
}

impl Vault {
    /// Records one export secret request for each of `basis`'s needs in the
    /// export's audit write `txn`, each in a savepoint of its own, best
    /// effort: a fault is logged, leaves `txn` as it was and reads as
    /// unrecorded. Each carries the export's act exactly as its door made
    /// it, its owner checked a live vault owner here first. Nothing here
    /// reaches the copy, which has left.
    pub(crate) fn record_holder_export_requests_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        basis: HolderExportBasis<'_>,
    ) -> Vec<HolderExportRequest> {
        let all = |reason| {
            basis
                .needs
                .iter()
                .map(|need| HolderExportRequest::unassigned(*need, reason))
                .collect()
        };
        if basis.needs.is_empty() {
            return Vec::new();
        }
        let Some(act) = basis.act else {
            return all(HolderExportUnassigned::NoOwnerAct);
        };
        let Some(recipient) = basis.recipient else {
            return all(HolderExportUnassigned::NoRecipient);
        };
        let unrecorded = |error: &crate::Error| {
            tracing::warn!(
                kind = ?error.kind(),
                "an export's holder requests were not recorded; its handles stand"
            );
            basis
                .needs
                .iter()
                .map(|need| HolderExportRequest::unrecorded(*need))
                .collect()
        };
        match crate::policy_model::is_live_vault_owner_in_txn(self, txn, &act.owner) {
            Ok(true) => {}
            Ok(false) => return all(HolderExportUnassigned::OwnerNotLive),
            Err(error) => return unrecorded(&error),
        }
        let fold = match self.authority_view_readonly_in_txn(txn) {
            Ok(fold) => fold,
            Err(error) => return unrecorded(&error),
        };
        match self.owner_work_carrier_in_txn(txn, &fold) {
            Ok(Some(_)) => {}
            Ok(None) => return all(HolderExportUnassigned::NoCarrier),
            Err(error) => return unrecorded(&error),
        }
        let Some(permit) = crate::secret_custody::holder_export::recipient_permit(&fold, recipient)
        else {
            return all(HolderExportUnassigned::RecipientNotLinked);
        };
        drop(fold);
        basis
            .needs
            .iter()
            .map(|need| {
                let work = OwnerWorkBody::ExportSecret(ExportSecretWork {
                    secret: need.secret,
                    generation: need.generation,
                    export: basis.export,
                    digest: basis.digest,
                    export_act: basis.export_act,
                    recipient: permit,
                });
                match self.record_export_secret_in_savepoint(txn, act, work) {
                    Ok(receipt) => HolderExportRequest::of_receipt(*need, &receipt),
                    Err(error) => {
                        tracing::warn!(
                            secret = %need.secret.to_hex(),
                            kind = ?error.kind(),
                            "an export secret request was not recorded; its handle stands"
                        );
                        HolderExportRequest::unrecorded(*need)
                    }
                }
            })
            .collect()
    }

    fn record_export_secret_in_savepoint(
        &self,
        txn: &mut heed::RwTxn<'_>,
        act: OwnerAct,
        work: OwnerWorkBody,
    ) -> crate::Result<OwnerWorkReceipt> {
        let mut savepoint = self.store.env.nested_write_txn(txn)?;
        let receipt = self.record_owner_work_with_act_in_txn(&mut savepoint, act, work)?;
        savepoint.commit()?;
        Ok(receipt)
    }

    /// Each of `requests` as this install's fold stands now: a recorded
    /// request's status read again (an owner's read of an export receipt).
    pub(crate) fn refreshed_holder_export_requests(
        &self,
        requests: Vec<HolderExportRequest>,
    ) -> Vec<HolderExportRequest> {
        if requests.is_empty() {
            return requests;
        }
        let fold = self
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)
            .and_then(|txn| self.authority_view_readonly_in_txn(&txn));
        match fold {
            Ok(fold) => requests
                .into_iter()
                .map(|request| request.refreshed(&fold))
                .collect(),
            Err(_) => requests,
        }
    }
}
