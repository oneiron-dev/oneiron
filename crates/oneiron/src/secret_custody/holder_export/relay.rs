//! An export secret request's sealed copy as it is kept and relayed (FIX
//! 11843): a label, the second its holder sealed it at, whose month's base
//! window carries it, the request's entry hash, the copy's witness, the
//! holder's signature of each numbered part when it rides in parts (FIX
//! 12373), then the copy, `OXS1`, as the holder sealed it.
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
//! signed, with no witness; its relay reads the result from its log. A copy
//! that rides in parts keeps, from the same commit, the signature of each
//! part by the key that signed that result (`part_signature`), and every
//! install that keeps a relayed copy keeps the signatures it came with, so
//! it relays the parts onward while the holder is away. Before any install
//! keeps or relays such a copy, whole or joined, every one of its part
//! signatures verifies over its own frame by that result's signer
//! (`KeptExportOutput::proof`): a copy with one missing or bad is
//! disproven, never kept, so no relay writes parts nobody verified.
//!
//! A relayed row is judged in three states (FIX 12352; the unknown-signer
//! rule of CALLS CUSTODY_INPUT_PRUNE): proven ([`ProofState::Proven`]), the
//! only state any reader or keeper takes; unproven, its signatures, shape
//! and copy binding sound but this install not yet holding the vault, the
//! holder's profile or the holder's exact key, with nothing it holds
//! against it, so the row waits in its window, never read or kept, until it
//! proves itself or its base window retires; and disproven, so it leaves.

use super::OUTPUTS;
#[cfg(feature = "sync")]
use super::part_signature::{OutputPartBinding, parts_verify};
use crate::Vault;
use crate::authority::{AuthorityEntryHash, AuthorityVaultId};
use crate::authority::{
    AuthorityFold, AuthorityKey, AuthorityOp, SealedWorkOutput, authority_entry_hash,
    decode_authority_log_entry_body, owner_act_signer_admits,
};
#[cfg(feature = "sync")]
use crate::authority::{OwnerWorkBody, encode_authority_log_entry_body, stored_authority_row};
use crate::entity_id::EntityId;
use crate::error::Result;

/// The label a kept copy with no part signatures starts with, and the frame
/// its numbered parts cut ([`KeptExportOutput::copy_frame`]).
const LABEL: &[u8] = b"oneiron/export-secret-output/v1\0";

/// The label a kept copy with its holder's part signatures starts with (FIX
/// 12373): after its witness, their count (a big-endian `u32`, at least one)
/// and each signature, then the copy.
const SIGNED_LABEL: &[u8] = b"oneiron/export-secret-output/v2\0";

/// The bytes of one part signature.
const SIGNATURE_BYTES: usize = 64;

/// The bytes before a copy's witness and the copy: its label, the second it
/// was sealed at, the request and the witness's length.
const HEAD_BYTES: usize = LABEL.len() + 8 + 32 + 4;

/// The most bytes one relayed row of a kept copy carries, as for a custody
/// transition or input row. A longer copy rides in numbered parts (FIX
/// 12063).
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
    /// The signature of each numbered part the copy rides in, in order, by
    /// the key that signed its result (FIX 12373), kept and relayed as the
    /// holder made them, each verified before a copy that rides in parts
    /// stands (`Self::proof`). Empty for a copy that rides whole, and for
    /// one kept with no part evidence, which never rides in parts.
    pub(crate) part_signatures: Vec<[u8; SIGNATURE_BYTES]>,
    /// The copy, sealed to the recipient machine alone.
    pub(crate) sealed: Vec<u8>,
}

// Never print the ciphertext.
impl std::fmt::Debug for KeptExportOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeptExportOutput")
            .field("sealed_at", &self.sealed_at)
            .field("witness", &self.witness.len())
            .field("part_signatures", &self.part_signatures.len())
            .field("bytes", &self.sealed.len())
            .finish_non_exhaustive()
    }
}

impl KeptExportOutput {
    /// The label, the second it was sealed at, the request, the witness's
    /// length (a big-endian `u32`) and the witness, its part signatures'
    /// count and each signature when it carries any (under
    /// [`SIGNED_LABEL`], FIX 12373), then the copy.
    pub(crate) fn encode(&self) -> Vec<u8> {
        self.encode_with(&self.witness, &self.part_signatures)
    }

    /// The frame its numbered parts cut: [`Self::encode`] with no witness
    /// and no part signatures, as each part's head carries the witness and
    /// its own signature itself (FIX 12312, 12373).
    pub(crate) fn copy_frame(&self) -> Vec<u8> {
        self.encode_with(&[], &[])
    }

    fn encode_with(&self, witness: &[u8], signatures: &[[u8; SIGNATURE_BYTES]]) -> Vec<u8> {
        let signed = !signatures.is_empty();
        let signed_bytes = if signed {
            4 + SIGNATURE_BYTES * signatures.len()
        } else {
            0
        };
        let mut out =
            Vec::with_capacity(HEAD_BYTES + witness.len() + signed_bytes + self.sealed.len());
        out.extend_from_slice(if signed { SIGNED_LABEL } else { LABEL });
        out.extend_from_slice(&self.sealed_at.to_be_bytes());
        out.extend_from_slice(&self.request);
        // A witness is within its bound, far inside a `u32`.
        out.extend_from_slice(&(witness.len() as u32).to_be_bytes());
        out.extend_from_slice(witness);
        if signed {
            // One signature per part, and a `u32` counts the parts.
            out.extend_from_slice(&(signatures.len() as u32).to_be_bytes());
            for signature in signatures {
                out.extend_from_slice(signature);
            }
        }
        out.extend_from_slice(&self.sealed);
        out
    }

    /// The length of the frame of a copy `sealed` bytes long with no
    /// witness, as [`Self::copy_frame`] writes it: what its numbered parts
    /// cut (FIX 12294, 12312).
    pub(crate) fn frame_len(sealed: u64) -> Option<u64> {
        sealed.checked_add(u64::try_from(HEAD_BYTES).ok()?)
    }

    /// Whether a copy `sealed` bytes long rides in numbered parts: its frame
    /// with the largest witness passes one row's bound. Its sealed length
    /// alone decides it, so a receiver knows it from the result that names
    /// the copy (FIX 12294, 12312), and its holder signs its parts when it
    /// seals it (FIX 12373).
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
        let rest = bytes
            .strip_prefix(SIGNED_LABEL)
            .or_else(|| bytes.strip_prefix(LABEL))?;
        let (sealed_at, rest) = rest.split_first_chunk::<8>()?;
        let (request, _) = rest.split_first_chunk::<32>()?;
        Some((u64::from_be_bytes(*sealed_at), request))
    }

    /// Decodes a kept or relayed copy strictly; `None` without either label,
    /// for a short frame, a zero request, an empty copy, or a signed copy
    /// that counts no signature or is short of the ones it counts. The copy,
    /// its witness and its part signatures are read, not judged:
    /// `Self::stands` judges the copy and its witness, a witness past its
    /// bound among them, so such a row is admitted, never kept and pruned,
    /// never a refused update (L03 06:5x). `Self::proof` verifies the part
    /// signatures of a copy that rides in parts; each relayed part proves
    /// its own where it rides (FIX 12373).
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let (signed, rest) = match bytes.strip_prefix(SIGNED_LABEL) {
            Some(rest) => (true, rest),
            None => (false, bytes.strip_prefix(LABEL)?),
        };
        let (sealed_at, rest) = rest.split_first_chunk::<8>()?;
        let (request, rest) = rest.split_first_chunk::<32>()?;
        let (witness_len, rest) = rest.split_first_chunk::<4>()?;
        let witness_len = usize::try_from(u32::from_be_bytes(*witness_len)).ok()?;
        let (witness, rest) = rest.split_at_checked(witness_len)?;
        let (part_signatures, sealed) = if signed {
            decode_signatures(rest)?
        } else {
            (Vec::new(), rest)
        };
        if *request == [0; 32] || sealed.is_empty() {
            return None;
        }
        Some(Self {
            sealed_at: u64::from_be_bytes(*sealed_at),
            request: *request,
            witness: witness.to_vec(),
            part_signatures,
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

    /// What `fold` makes of this copy (FIX 12352): the state of its witness
    /// ([`assess_witness`]) when the signed result it carries names the
    /// copy's digest and length and, for a copy that rides in parts, every
    /// part signature verifies under that result ([`Self::parts_signed_by`]);
    /// disproven when it names another copy, a part signature is missing or
    /// does not verify, or the witness is disproven. An unproven copy is
    /// never read or kept.
    #[cfg(feature = "sync")]
    pub(crate) fn proof(&self, fold: &AuthorityFold) -> ProofState {
        match assess_witness(fold, &self.request, &self.witness).candidate() {
            Some((result, state))
                if names_copy(&result.output, &self.sealed) && self.parts_signed_by(&result) =>
            {
                state
            }
            _ => ProofState::Disproven,
        }
    }

    /// Whether this copy carries its holder's signature of every part it
    /// rides in, each verifying by `result`'s own signer over `result`'s
    /// vault and entry, the copy it names, this copy's request and sealing
    /// second, the part count, the part's index and its run of this copy's
    /// own frame ([`Self::copy_frame`], cut as its parts are), as a relayed
    /// part proves itself (`part_signature`, FIX 12373). A copy that rides
    /// whole needs none, so its signatures are not read.
    #[cfg(feature = "sync")]
    fn parts_signed_by(&self, result: &WitnessedResult) -> bool {
        !Self::rides_in_parts(self.sealed.len() as u64)
            || parts_verify(
                &OutputPartBinding {
                    vault_id: result.vault_id,
                    request: self.request,
                    result: result.entry,
                    output: result.output,
                    sealed_at: self.sealed_at,
                },
                &result.signer,
                &self.copy_frame(),
                &self.part_signatures,
            )
    }

    /// Whether a signed result of this copy's request names it, as `fold`
    /// judges it: the one its witness carries ([`witnessed_output`]), which
    /// must match the result `fold` folds when it folds one, names the
    /// copy's digest and length (FIX 12065, 12312). Only a proven copy
    /// ([`Self::proof`]).
    #[cfg(feature = "sync")]
    pub(crate) fn named_by(&self, fold: &AuthorityFold) -> bool {
        self.proof(fold) == ProofState::Proven
    }

    /// Whether this copy is kept and relayed on `fold`: it folds the export
    /// secret request it answers, on a secret no admitted revoke ended and
    /// `fenced` does not name, and a signed result names the copy
    /// ([`Self::named_by`]), whether or not it folds that result yet. An
    /// unproven copy never stands (FIX 12352).
    #[cfg(feature = "sync")]
    pub(crate) fn stands(&self, fold: &AuthorityFold, fenced: impl Fn(&EntityId) -> bool) -> bool {
        self.secret(fold)
            .is_some_and(|secret| !fold.custody_revoked(&secret) && !fenced(&secret))
            && self.named_by(fold)
    }

    /// Whether a window's row of this copy is due to leave it: its
    /// request's rows are ([`Self::request_rows_done`]), or `fold` disproves
    /// it ([`Self::proof`]): its witness is missing, does not verify, names
    /// another copy, disagrees with the result or the request `fold` folds,
    /// or is signed by a key the carrier rule excludes here, or the copy
    /// rides in parts and a part signature is missing or does not verify
    /// (FIX 12065, 12312, 12352, 12373). Such a row is admitted and never
    /// kept. An unproven row stays in its sealing month's base window, never
    /// kept, until it proves itself or leaves on one of these signals or
    /// with that window; a row its witness names stays while this vault has
    /// not folded its request yet.
    #[cfg(feature = "sync")]
    pub(crate) fn row_done(
        &self,
        fold: &AuthorityFold,
        fenced: impl Fn(&EntityId) -> bool,
    ) -> bool {
        Self::request_rows_done(fold, &self.request, fenced)
            || self.proof(fold) == ProofState::Disproven
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

/// The part signatures a signed copy carries after its witness, and the
/// bytes after them: their count, at least one, then each signature (FIX
/// 12373). `None` for a count of none or bytes short of the count.
fn decode_signatures(bytes: &[u8]) -> Option<(Vec<[u8; SIGNATURE_BYTES]>, &[u8])> {
    let (count, rest) = bytes.split_first_chunk::<4>()?;
    let count = usize::try_from(u32::from_be_bytes(*count))
        .ok()
        .filter(|count| *count > 0)?;
    let (signed, rest) = rest.split_at_checked(count.checked_mul(SIGNATURE_BYTES)?)?;
    let signatures = signed
        .chunks_exact(SIGNATURE_BYTES)
        .map(|signature| <[u8; SIGNATURE_BYTES]>::try_from(signature).ok())
        .collect::<Option<Vec<_>>>()?;
    Some((signatures, rest))
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
/// a witness that names no copy so, or one past
/// [`MAX_EXPORT_OUTPUT_WITNESS_BYTES`], and for one `fold` does not prove
/// yet ([`assess_witness`], FIX 12352).
pub(crate) fn witnessed_output(
    fold: &AuthorityFold,
    request: &AuthorityEntryHash,
    witness: &[u8],
) -> Option<SealedWorkOutput> {
    witnessed_result(fold, request, witness).map(|result| result.output)
}

/// What a copy's witness proves on a fold (FIX 12312, 12373): the copy the
/// signed result names, that result's canonical entry hash, the key that
/// signed it and the vault it is of. Each numbered part of the copy is
/// signed by that key over that entry (`part_signature`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) struct WitnessedResult {
    pub(crate) output: SealedWorkOutput,
    pub(crate) entry: AuthorityEntryHash,
    pub(crate) signer: [u8; 32],
    pub(crate) vault_id: AuthorityVaultId,
}

/// [`witnessed_output`] with what else the witness proves: the result's
/// entry hash, its signer's key and its vault (FIX 12373), judged by the
/// same rules. A proven witness only ([`assess_witness`]).
pub(crate) fn witnessed_result(
    fold: &AuthorityFold,
    request: &AuthorityEntryHash,
    witness: &[u8],
) -> Option<WitnessedResult> {
    assess_witness(fold, request, witness).proven()
}

/// What a fold makes of a relayed row, the copy whole, one of its parts or
/// the witness either carries (FIX 12352).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofState {
    /// It proves itself on the fold: the only state a reader or a keeper
    /// takes.
    Proven,
    /// Its signatures, its shape and its binding to the copy verify, but the
    /// fold holds no evidence yet of the vault, the holder's profile, or the
    /// holder's exact install key, and nothing it holds contradicts the
    /// row. The row waits in its window, never read, joined or kept.
    Unproven,
    /// The fold holds what contradicts it: the row leaves its window.
    Disproven,
}

/// What a copy's witness is on a fold ([`assess_witness`]), with the signed
/// result it carries while the fold does not disprove it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) enum WitnessAssessment {
    Proven(WitnessedResult),
    /// The result as the witness names it, its vault the entry's own: the
    /// candidate a row's copy and parts are checked against, never trusted.
    Unproven(WitnessedResult),
    Disproven,
}

#[cfg_attr(not(feature = "sync"), allow(dead_code))]
impl WitnessAssessment {
    /// The result a proven witness names.
    fn proven(self) -> Option<WitnessedResult> {
        match self {
            Self::Proven(result) => Some(result),
            Self::Unproven(_) | Self::Disproven => None,
        }
    }

    /// The result the witness names and its state, proven or unproven;
    /// `None` for a disproven witness.
    pub(crate) fn candidate(self) -> Option<(WitnessedResult, ProofState)> {
        match self {
            Self::Proven(result) => Some((result, ProofState::Proven)),
            Self::Unproven(result) => Some((result, ProofState::Unproven)),
            Self::Disproven => None,
        }
    }
}

/// What `fold` makes of `witness`, the signed result an export copy of
/// `request` carries (FIX 12312, 12352). Disproven: past
/// [`MAX_EXPORT_OUTPUT_WITNESS_BYTES`], not a canonical entry whose
/// signature verifies, not an Ed25519-signed result with a sealed copy, of
/// no vault or another vault than `fold`'s, the result of another request,
/// by another executor than the one the request names when `fold` folds it,
/// naming another copy than the result `fold` folds, or signed by a key the
/// carrier rule excludes ([`carrier_proof`]). Proven: the very result `fold`
/// folds, or signed by an install key of the executor's the carrier rule
/// admits. Unproven otherwise: `fold` folds no vault yet, or no profile or
/// live key revision of the executor's that names the signing key.
pub(crate) fn assess_witness(
    fold: &AuthorityFold,
    request: &AuthorityEntryHash,
    witness: &[u8],
) -> WitnessAssessment {
    if witness.len() > MAX_EXPORT_OUTPUT_WITNESS_BYTES {
        return WitnessAssessment::Disproven;
    }
    let Ok(entry) = decode_authority_log_entry_body(witness) else {
        return WitnessAssessment::Disproven;
    };
    let (AuthorityOp::OwnerWorkResult(result), AuthorityKey::Ed25519(key)) =
        (&entry.op, entry.signer_key())
    else {
        return WitnessAssessment::Disproven;
    };
    // A decoded entry re-encodes to its canonical bytes, so its hash holds.
    let (Some(output), Some(vault_id), Ok(hash)) = (
        result.outcome.sealed_output().copied(),
        entry.vault_id,
        authority_entry_hash(&entry),
    ) else {
        return WitnessAssessment::Disproven;
    };
    let folded = fold.owner_work_result(request);
    let contradicted = fold
        .vault_id
        .is_some_and(|folded_vault| folded_vault != vault_id)
        || result.request != *request
        || fold
            .owner_work_request(request)
            .is_some_and(|asked| asked.executor != result.executor)
        || folded.is_some_and(|answer| answer.outcome.sealed_output() != Some(&output));
    if contradicted {
        return WitnessAssessment::Disproven;
    }
    let candidate = WitnessedResult {
        output,
        entry: hash,
        signer: *key,
        vault_id,
    };
    let state = if fold.vault_id.is_none() {
        ProofState::Unproven
    } else if folded.is_some_and(|answer| answer.entry == hash) {
        ProofState::Proven
    } else {
        carrier_proof(fold, result.executor, key)
    };
    match state {
        ProofState::Proven => WitnessAssessment::Proven(candidate),
        ProofState::Unproven => WitnessAssessment::Unproven(candidate),
        ProofState::Disproven => WitnessAssessment::Disproven,
    }
}

/// The one carrier rule ([`owner_act_signer_admits`]) for `key` as an
/// install key of `executor` on `fold`, in three states (FIX 12352): proven
/// where it admits the key; disproven where it excludes the key on what
/// `fold` holds: the authority roster names the key (a roster key acts as
/// nobody), or a chain of `executor`'s removed the machine (only removal
/// ends a linked install); unproven otherwise: `fold` folds no profile of
/// `executor`'s, or no live chain of it names this exact key yet. A machine
/// this install knows under another key alone does not disprove a key
/// revision it has not folded.
fn carrier_proof(fold: &AuthorityFold, executor: EntityId, key: &[u8; 32]) -> ProofState {
    let machine = fold.machine(executor);
    if owner_act_signer_admits(machine, &fold.roster, key) {
        return ProofState::Proven;
    }
    let removed = machine.is_some_and(|folded| folded.chains().any(|(_, chain)| chain.removed));
    if removed || fold.roster.contains_key(&AuthorityKey::Ed25519(*key)) {
        ProofState::Disproven
    } else {
        ProofState::Unproven
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
/// in `wtxn`. It is kept with the witness and the part signatures it came
/// with, each verified when it rides in parts ([`KeptExportOutput::proof`]),
/// never signed again here (FIX 12373). Returns whether it kept it.
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
