//! An export secret request's sealed copy as it is kept and relayed (FIX
//! 11843): a label, the second its holder sealed it at, whose month's base
//! window carries it, the request's entry hash, then the copy, `OXS1`, as
//! the holder sealed it.
//!
//! The holder keeps it under the request's entry in the commit of the result
//! that names its digest. Each other install of the owner's keeps the copy a
//! window relays to it once it folds that result, on a secret no admitted
//! revoke ended and no erase here fenced, so the owner reads it from
//! whichever install serves him ([`Vault::export_secret_supplement`]). No
//! install that keeps or relays it can open it: only the recipient machine
//! the owner chose does. A copy past one row rides in numbered parts, which
//! the receiver joins before it judges the copy (FIX 12063,
//! `sync::custody::export_output`).

use super::OUTPUTS;
use crate::Vault;
use crate::authority::AuthorityEntryHash;
#[cfg(feature = "sync")]
use crate::authority::{AuthorityFold, OwnerWorkBody};
#[cfg(feature = "sync")]
use crate::entity_id::EntityId;
use crate::error::Result;

/// The label every kept copy starts with.
const LABEL: &[u8] = b"oneiron/export-secret-output/v1\0";

/// The most bytes one relayed row of a kept copy carries, as for a custody
/// transition or input row. A longer copy rides in numbered parts (FIX
/// 12063).
#[cfg(feature = "sync")]
pub(crate) const MAX_RELAYED_OUTPUT_BYTES: usize = 4 << 20;

/// One sealed copy as it is kept and relayed.
pub(crate) struct KeptExportOutput {
    pub(crate) sealed_at: u64,
    pub(crate) request: AuthorityEntryHash,
    /// The copy, sealed to the recipient machine alone.
    pub(crate) sealed: Vec<u8>,
}

// Never print the ciphertext.
impl std::fmt::Debug for KeptExportOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeptExportOutput")
            .field("sealed_at", &self.sealed_at)
            .field("bytes", &self.sealed.len())
            .finish_non_exhaustive()
    }
}

impl KeptExportOutput {
    /// The label, the second it was sealed at, the request, then the copy.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(LABEL.len() + 8 + 32 + self.sealed.len());
        out.extend_from_slice(LABEL);
        out.extend_from_slice(&self.sealed_at.to_be_bytes());
        out.extend_from_slice(&self.request);
        out.extend_from_slice(&self.sealed);
        out
    }

    /// The length of the frame of a copy `sealed` bytes long: its head, then
    /// the copy, as [`Self::encode`] writes it (FIX 12294).
    #[cfg(feature = "sync")]
    pub(crate) fn frame_len(sealed: u64) -> Option<u64> {
        sealed.checked_add(u64::try_from(LABEL.len() + 8 + 32).ok()?)
    }

    /// The second a kept or relayed copy was sealed at and its request, from
    /// its head alone, as [`Self::decode`] reads them.
    #[cfg(feature = "sync")]
    fn head(bytes: &[u8]) -> Option<(u64, &AuthorityEntryHash)> {
        let rest = bytes.strip_prefix(LABEL)?;
        let (sealed_at, rest) = rest.split_first_chunk::<8>()?;
        let (request, _) = rest.split_first_chunk::<32>()?;
        Some((u64::from_be_bytes(*sealed_at), request))
    }

    /// Decodes a kept or relayed copy strictly; `None` without its label, for
    /// a short frame, a zero request or an empty copy. The copy is read, not
    /// judged: `Self::stands` judges it.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.strip_prefix(LABEL)?;
        let (sealed_at, rest) = rest.split_first_chunk::<8>()?;
        let (request, sealed) = rest.split_first_chunk::<32>()?;
        if *request == [0; 32] || sealed.is_empty() {
            return None;
        }
        Some(Self {
            sealed_at: u64::from_be_bytes(*sealed_at),
            request: *request,
            sealed: sealed.to_vec(),
        })
    }

    /// The secret the request this copy answers is for, as `fold` holds it:
    /// `None` when it folds no export secret request under its entry.
    #[cfg(feature = "sync")]
    fn secret(&self, fold: &AuthorityFold) -> Option<EntityId> {
        match &fold.owner_work_request(&self.request)?.work {
            OwnerWorkBody::ExportSecret(work) => Some(work.secret),
            _ => None,
        }
    }

    /// Whether `fold`'s signed result for this copy's request names it: the
    /// copy's digest and length.
    #[cfg(feature = "sync")]
    fn named_by(&self, fold: &AuthorityFold) -> bool {
        fold.owner_work_result(&self.request)
            .and_then(|answer| answer.outcome.sealed_output())
            .is_some_and(|output| {
                output.digest == *blake3::hash(&self.sealed).as_bytes()
                    && usize::try_from(output.bytes).is_ok_and(|bytes| bytes == self.sealed.len())
            })
    }

    /// Whether this copy is kept and relayed on `fold`: it folds the export
    /// secret request it answers and the signed result that names it, on a
    /// secret no admitted revoke ended and `fenced` does not name.
    #[cfg(feature = "sync")]
    pub(crate) fn stands(&self, fold: &AuthorityFold, fenced: impl Fn(&EntityId) -> bool) -> bool {
        self.secret(fold)
            .is_some_and(|secret| !fold.custody_revoked(&secret) && !fenced(&secret))
            && self.named_by(fold)
    }

    /// Whether a window's row of this copy is due to leave it: its
    /// request's rows are ([`Self::request_rows_done`]), or `fold` folds a
    /// result for it that does not name this copy. A row whose request or
    /// result this vault has not folded yet stays.
    #[cfg(feature = "sync")]
    pub(crate) fn row_done(
        &self,
        fold: &AuthorityFold,
        fenced: impl Fn(&EntityId) -> bool,
    ) -> bool {
        Self::request_rows_done(fold, &self.request, fenced)
            || (fold.owner_work_request(&self.request).is_some()
                && fold.owner_work_result(&self.request).is_some()
                && !self.named_by(fold))
    }

    /// Whether every window row of a copy for `request`, whole or one of its
    /// parts (FIX 12063), is due to leave it whatever the copy: `fold` folds
    /// the request refused, as no export secret request, or on a secret an
    /// admitted revoke ended or `fenced` names. A request this vault has not
    /// folded yet keeps its rows.
    #[cfg(feature = "sync")]
    pub(crate) fn request_rows_done(
        fold: &AuthorityFold,
        request: &AuthorityEntryHash,
        fenced: impl Fn(&EntityId) -> bool,
    ) -> bool {
        if fold.refused_owner_work().contains(request) {
            return true;
        }
        match fold.owner_work_request(request) {
            None => false,
            Some(folded) => match &folded.work {
                OwnerWorkBody::ExportSecret(work) => {
                    fold.custody_revoked(&work.secret) || fenced(&work.secret)
                }
                _ => true,
            },
        }
    }
}

/// The copy kept under request `request`, when it decodes as one for it.
pub(super) fn kept_output_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &AuthorityEntryHash,
) -> Result<Option<KeptExportOutput>> {
    Ok(OUTPUTS
        .get(&vault.store, txn, request)?
        .and_then(|bytes| KeptExportOutput::decode(&bytes))
        .filter(|kept| kept.request == *request))
}

/// The second the copy this install keeps under `request` was sealed at,
/// read from its head alone, the copy lent and never copied (FIX 12294):
/// `None` when it keeps none for it.
#[cfg(feature = "sync")]
pub(crate) fn kept_export_output_sealed_at_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &AuthorityEntryHash,
) -> Result<Option<u64>> {
    Ok(OUTPUTS
        .get_borrowed(&vault.store, txn, request)?
        .and_then(|bytes| {
            KeptExportOutput::head(&bytes)
                .filter(|(_, kept)| *kept == request)
                .map(|(sealed_at, _)| sealed_at)
        }))
}

/// Every copy this install keeps that decodes as one for its key.
#[cfg(feature = "sync")]
pub(crate) fn held_export_outputs(vault: &Vault) -> Result<Vec<KeptExportOutput>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(OUTPUTS
        .scan(&vault.store, &rtxn)?
        .into_iter()
        .filter_map(|(request, bytes)| {
            KeptExportOutput::decode(&bytes).filter(|kept| kept.request == request)
        })
        .collect())
}

/// Whether this install keeps `output`, a copy a window relayed, in `txn`:
/// it keeps no copy for its request yet, and the copy stands on `fold`, read
/// in `txn`, with this install's erase fences.
#[cfg(feature = "sync")]
pub(crate) fn relayed_export_output_due_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    output: &KeptExportOutput,
) -> Result<bool> {
    let fenced = |secret: &EntityId| vault.store.credential_fenced_in_txn(txn, secret);
    Ok(output.stands(fold, fenced) && !OUTPUTS.contains(&vault.store, txn, &output.request)?)
}

/// Keeps `output`, a copy a window relayed, under its request when it is due
/// in `wtxn` ([`relayed_export_output_due_in_txn`]), checked again here
/// against `fold`, read in `wtxn`. Returns whether it kept it.
#[cfg(feature = "sync")]
pub(crate) fn keep_relayed_export_output_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    fold: &AuthorityFold,
    output: &KeptExportOutput,
) -> Result<bool> {
    if !relayed_export_output_due_in_txn(vault, wtxn, fold, output)? {
        return Ok(false);
    }
    OUTPUTS.put(&vault.store, wtxn, &output.request, &output.encode())?;
    Ok(true)
}
