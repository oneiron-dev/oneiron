//! An export secret request's sealed copy as it is kept and relayed (FIX
//! 11843): a label, the second its holder sealed it at, whose month's base
//! window carries it, the request's entry hash, the copy's witness, then the
//! copy, `OXS1`, as the holder sealed it.
//!
//! The holder keeps it under the request's entry in the commit of the result
//! that names its digest. Each other install of the owner's keeps the copy a
//! window relays to it once a signed result names it, on a secret no
//! admitted revoke ended and no erase here fenced, so the owner reads it from
//! whichever install serves him ([`Vault::export_secret_supplement`]). No
//! install that keeps or relays it can open it: only the recipient machine
//! the owner chose does. A copy past one row rides in numbered parts, which
//! the receiver joins before it judges the copy (FIX 12063,
//! `sync::custody::export_output`).
//!
//! Its witness is that result's signed entry (FIX 12312), so an install that
//! has not folded the result yet still judges the copy: the signature, the
//! signer by the rule the fold's own result arm applies, and the copy's
//! digest and length. The holder keeps its own copy before the result is
//! signed, with no witness; its relay reads the result from its log.

use super::OUTPUTS;
use crate::Vault;
use crate::authority::AuthorityEntryHash;
#[cfg(feature = "sync")]
use crate::authority::{
    AuthorityFold, AuthorityKey, AuthorityOp, OwnerWorkBody, SealedWorkOutput,
    authority_entry_hash, decode_authority_log_entry_body, encode_authority_log_entry_body,
    owner_act_signer_admits, stored_authority_row,
};
#[cfg(feature = "sync")]
use crate::entity_id::EntityId;
use crate::error::Result;

/// The label every kept copy starts with.
const LABEL: &[u8] = b"oneiron/export-secret-output/v1\0";

/// The bytes before a copy's witness and the copy: its label, the second it
/// was sealed at, the request and the witness's length.
const HEAD_BYTES: usize = LABEL.len() + 8 + 32 + 4;

/// The most bytes one relayed row of a kept copy carries, as for a custody
/// transition or input row. A longer copy rides in numbered parts (FIX
/// 12063).
#[cfg(feature = "sync")]
pub(crate) const MAX_RELAYED_OUTPUT_BYTES: usize = 4 << 20;

/// The most bytes of a copy's witness (FIX 12312): one signed result entry,
/// a few KiB at most with every parent the log allows.
pub(crate) const MAX_EXPORT_OUTPUT_WITNESS_BYTES: usize = 16 << 10;

/// One sealed copy as it is kept and relayed.
pub(crate) struct KeptExportOutput {
    pub(crate) sealed_at: u64,
    pub(crate) request: AuthorityEntryHash,
    /// The request's signed result, canonical, which names the copy (FIX
    /// 12312); empty on the holder's own copy, kept before it was signed.
    pub(crate) witness: Vec<u8>,
    /// The copy, sealed to the recipient machine alone.
    pub(crate) sealed: Vec<u8>,
}

// Never print the ciphertext.
impl std::fmt::Debug for KeptExportOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeptExportOutput")
            .field("sealed_at", &self.sealed_at)
            .field("witness", &self.witness.len())
            .field("bytes", &self.sealed.len())
            .finish_non_exhaustive()
    }
}

impl KeptExportOutput {
    /// The label, the second it was sealed at, the request, the witness's
    /// length (a big-endian `u32`) and the witness, then the copy.
    pub(crate) fn encode(&self) -> Vec<u8> {
        self.encode_with(&self.witness)
    }

    /// The frame its numbered parts cut: [`Self::encode`] with no witness,
    /// as each part's head carries the witness itself (FIX 12312).
    #[cfg(feature = "sync")]
    pub(crate) fn copy_frame(&self) -> Vec<u8> {
        self.encode_with(&[])
    }

    fn encode_with(&self, witness: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEAD_BYTES + witness.len() + self.sealed.len());
        out.extend_from_slice(LABEL);
        out.extend_from_slice(&self.sealed_at.to_be_bytes());
        out.extend_from_slice(&self.request);
        // A witness is within its bound, far inside a `u32`.
        out.extend_from_slice(&(witness.len() as u32).to_be_bytes());
        out.extend_from_slice(witness);
        out.extend_from_slice(&self.sealed);
        out
    }

    /// The length of the frame of a copy `sealed` bytes long with no
    /// witness, as [`Self::copy_frame`] writes it: what its numbered parts
    /// cut (FIX 12294, 12312).
    #[cfg(feature = "sync")]
    pub(crate) fn frame_len(sealed: u64) -> Option<u64> {
        sealed.checked_add(u64::try_from(HEAD_BYTES).ok()?)
    }

    /// Whether a copy `sealed` bytes long rides in numbered parts: its frame
    /// with the largest witness passes one row's bound. Its sealed length
    /// alone decides it, so a receiver knows it from the result that names
    /// the copy (FIX 12294, 12312).
    #[cfg(feature = "sync")]
    pub(crate) fn rides_in_parts(sealed: u64) -> bool {
        Self::frame_len(sealed).is_none_or(|frame| {
            frame.saturating_add(MAX_EXPORT_OUTPUT_WITNESS_BYTES as u64)
                > MAX_RELAYED_OUTPUT_BYTES as u64
        })
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
    /// a short frame, a zero request, a witness past its bound or an empty
    /// copy. The copy and its witness are read, not judged: `Self::stands`
    /// judges them.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.strip_prefix(LABEL)?;
        let (sealed_at, rest) = rest.split_first_chunk::<8>()?;
        let (request, rest) = rest.split_first_chunk::<32>()?;
        let (witness_len, rest) = rest.split_first_chunk::<4>()?;
        let witness_len = usize::try_from(u32::from_be_bytes(*witness_len))
            .ok()
            .filter(|len| *len <= MAX_EXPORT_OUTPUT_WITNESS_BYTES)?;
        let (witness, sealed) = rest.split_at_checked(witness_len)?;
        if *request == [0; 32] || sealed.is_empty() {
            return None;
        }
        Some(Self {
            sealed_at: u64::from_be_bytes(*sealed_at),
            request: *request,
            witness: witness.to_vec(),
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

    /// Whether a signed result of this copy's request names it, as `fold`
    /// judges it: the one its witness carries ([`witnessed_output`]), which
    /// must match the result `fold` folds when it folds one, names the
    /// copy's digest and length (FIX 12065, 12312).
    #[cfg(feature = "sync")]
    pub(crate) fn named_by(&self, fold: &AuthorityFold) -> bool {
        witnessed_output(fold, &self.request, &self.witness)
            .is_some_and(|output| names_copy(&output, &self.sealed))
    }

    /// Whether this copy is kept and relayed on `fold`: it folds the export
    /// secret request it answers, on a secret no admitted revoke ended and
    /// `fenced` does not name, and a signed result names the copy
    /// ([`Self::named_by`]), whether or not it folds that result yet.
    #[cfg(feature = "sync")]
    pub(crate) fn stands(&self, fold: &AuthorityFold, fenced: impl Fn(&EntityId) -> bool) -> bool {
        self.secret(fold)
            .is_some_and(|secret| !fold.custody_revoked(&secret) && !fenced(&secret))
            && self.named_by(fold)
    }

    /// Whether a window's row of this copy is due to leave it: its
    /// request's rows are ([`Self::request_rows_done`]), or no signed result
    /// names it on `fold` ([`Self::named_by`]): its witness is missing, does
    /// not verify, names another copy, or disagrees with the result `fold`
    /// folds (FIX 12065, 12312). Such a row is admitted and never kept. A
    /// row its witness names stays while this vault has not folded its
    /// request yet.
    #[cfg(feature = "sync")]
    pub(crate) fn row_done(
        &self,
        fold: &AuthorityFold,
        fenced: impl Fn(&EntityId) -> bool,
    ) -> bool {
        Self::request_rows_done(fold, &self.request, fenced) || !self.named_by(fold)
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

/// Whether `output`, what a signed result names, is the copy `sealed`: its
/// length and digest.
#[cfg(feature = "sync")]
fn names_copy(output: &SealedWorkOutput, sealed: &[u8]) -> bool {
    usize::try_from(output.bytes).is_ok_and(|bytes| bytes == sealed.len())
        && output.digest == *blake3::hash(sealed).as_bytes()
}

/// The copy `witness`, the signed result an export copy of `request` carries
/// beside it, names, as `fold` judges it (FIX 12312): a canonical entry of
/// this vault whose signature verifies, the result of `request` with a
/// sealed copy, by the executor the request names when `fold` folds it, and
/// signed by an install key of that executor's as the fold's own result arm
/// admits one (the one carrier rule, [`owner_act_signer_admits`], read on
/// `fold`), or the very result `fold` folds. While `fold` folds a result for
/// `request`, the witness must name the copy that result names. `None` for
/// a witness that names no copy so.
#[cfg(feature = "sync")]
pub(crate) fn witnessed_output(
    fold: &AuthorityFold,
    request: &AuthorityEntryHash,
    witness: &[u8],
) -> Option<SealedWorkOutput> {
    let entry = decode_authority_log_entry_body(witness).ok()?;
    let (AuthorityOp::OwnerWorkResult(result), AuthorityKey::Ed25519(key)) =
        (&entry.op, entry.signer_key())
    else {
        return None;
    };
    let output = *result.outcome.sealed_output()?;
    let folded = fold.owner_work_result(request);
    let shaped = fold.vault_id.is_some()
        && entry.vault_id == fold.vault_id
        && result.request == *request
        && fold
            .owner_work_request(request)
            .is_none_or(|asked| asked.executor == result.executor)
        && folded.is_none_or(|answer| answer.outcome.sealed_output() == Some(&output));
    let signed = || {
        folded.is_some_and(|answer| {
            authority_entry_hash(&entry).is_ok_and(|hash| hash == answer.entry)
        }) || owner_act_signer_admits(fold.machine(result.executor), &fold.roster, key)
    };
    (shaped && signed()).then_some(output)
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

/// Every copy this install keeps that decodes as one for its key, each with
/// its witness (FIX 12312): the one kept beside it, or for the holder's own
/// copy, kept before its result was signed, the result `fold` folds for its
/// request as this install's log stores it ([`result_witness_in_txn`]).
#[cfg(feature = "sync")]
pub(crate) fn held_export_outputs(
    vault: &Vault,
    fold: &AuthorityFold,
) -> Result<Vec<KeptExportOutput>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut held = Vec::new();
    for (request, bytes) in OUTPUTS.scan(&vault.store, &rtxn)? {
        let Some(mut kept) =
            KeptExportOutput::decode(&bytes).filter(|kept| kept.request == request)
        else {
            continue;
        };
        if kept.witness.is_empty() {
            kept.witness = result_witness_in_txn(vault, &rtxn, fold, &request)?;
        }
        held.push(kept);
    }
    Ok(held)
}

/// The signed result `fold` folds for `request`, canonical, as this
/// install's log stores it: an export copy's witness (FIX 12312). Empty when
/// it folds none, stores none, or the entry outgrows a witness's bound.
#[cfg(feature = "sync")]
fn result_witness_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    request: &AuthorityEntryHash,
) -> Result<Vec<u8>> {
    let Some(answer) = fold.owner_work_result(request) else {
        return Ok(Vec::new());
    };
    let Some(entry) = stored_authority_row(&vault.store, txn, &answer.entry)? else {
        return Ok(Vec::new());
    };
    let witness = encode_authority_log_entry_body(&entry)?;
    Ok(if witness.len() <= MAX_EXPORT_OUTPUT_WITNESS_BYTES {
        witness
    } else {
        Vec::new()
    })
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
/// in `wtxn` ([`relayed_export_output_due_in_txn`]) and `fold` holds no
/// import mark of its request, both checked again here against `fold`, read
/// in `wtxn`. It is kept with the witness it came with. Returns whether it
/// kept it.
#[cfg(feature = "sync")]
pub(crate) fn keep_relayed_export_output_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    fold: &AuthorityFold,
    output: &KeptExportOutput,
) -> Result<bool> {
    // A copy the owner marked imported after the read side looked is not
    // kept: its relay is over (FIX 12062, 12292).
    if fold.export_supplement_imported(&output.request)
        || !relayed_export_output_due_in_txn(vault, wtxn, fold, output)?
    {
        return Ok(false);
    }
    OUTPUTS.put(&vault.store, wtxn, &output.request, &output.encode())?;
    Ok(true)
}
