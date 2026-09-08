//! ED-04 miner reads, watermark and row codec.

use serde::Serialize;

use super::config::{
    MINER_WATERMARK_KEY, ROW_VERSION, SKILL_EDIT_KEY_PREFIX, SKILL_EDIT_ROW_LABEL,
    WATERMARK_ROW_LABEL,
};
use super::model::{
    MinedSkillEditDecision, MinedSkillEditProposal, MinedSkillEditVerdict, MinerWatermark,
    StoredSkillEdit, StoredSkillEditDecision,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Mint-marks, proposals, watermark
// ---------------------------------------------------------------------------

/// Every mined skill-edit proposal still awaiting an answer, in proposal-id
/// order — ONE-1448's inbox.
///
/// Answered proposals are excluded: they are still readable by id (the cooldown
/// reads them there), but a decided proposal is not work.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn pending_substitution_skill_edits(vault: &Vault) -> Result<Vec<MinedSkillEditProposal>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, SKILL_EDIT_KEY_PREFIX)?
    {
        let (key, raw) = entry?;
        let handle = key
            .get(SKILL_EDIT_KEY_PREFIX.len()..)
            .ok_or(Error::CorruptedIndex(SKILL_EDIT_ROW_LABEL))?;
        let proposal = decode_skill_edit(handle, &raw)?;
        if proposal.decision.is_none() {
            out.push(proposal);
        }
    }
    Ok(out)
}

/// One mined skill-edit proposal, answered or not, or `None`.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn mined_skill_edit(
    vault: &Vault,
    proposal_id: &EntityId,
) -> Result<Option<MinedSkillEditProposal>> {
    let rtxn = vault.store.env.read_txn()?;
    mined_skill_edit_in_txn(vault, &rtxn, proposal_id)
}

pub(super) fn mined_skill_edit_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    proposal_id: &EntityId,
) -> Result<Option<MinedSkillEditProposal>> {
    let key = meta_key(SKILL_EDIT_KEY_PREFIX, proposal_id.as_bytes());
    let Some(raw) = vault.store.vault_meta.get(txn, &key)? else {
        return Ok(None);
    };
    decode_skill_edit(proposal_id.as_bytes(), &raw).map(Some)
}

/// Records the decider's answer to a mined skill-edit proposal — the seam
/// ONE-1448's gated apply closes, and the only thing that lets the miner tell a
/// refusal from an acceptance.
///
/// Re-answering is allowed and the latest verdict stands: a decider is
/// permitted to change their mind, and a rejection's cooldown then runs from
/// the answer that is actually current.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when no such proposal exists — an answer to a
/// question nobody asked is a caller bug, not a row to invent. Storage errors.
pub fn resolve_mined_skill_edit(
    vault: &Vault,
    proposal_id: &EntityId,
    verdict: MinedSkillEditVerdict,
    at: u64,
) -> Result<()> {
    let key = meta_key(SKILL_EDIT_KEY_PREFIX, proposal_id.as_bytes());
    vault.with_write_txn(|wtxn| {
        let Some(raw) = vault.store.vault_meta.get(&*wtxn, &key)? else {
            return Err(Error::EntityNotFound);
        };
        let mut row: StoredSkillEdit = decode_row(&raw, SKILL_EDIT_ROW_LABEL)?;
        if row.v != ROW_VERSION {
            return Err(Error::CorruptedIndex(SKILL_EDIT_ROW_LABEL));
        }
        row.decision = Some(StoredSkillEditDecision {
            outcome: verdict.as_str().to_owned(),
            at,
        });
        let encoded = encode_row(&row, SKILL_EDIT_ROW_LABEL)?;
        vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok(())
    })
}

fn decode_skill_edit(handle: &[u8], raw: &[u8]) -> Result<MinedSkillEditProposal> {
    let row: StoredSkillEdit = decode_row(raw, SKILL_EDIT_ROW_LABEL)?;
    if row.v != ROW_VERSION {
        return Err(Error::CorruptedIndex(SKILL_EDIT_ROW_LABEL));
    }
    let bytes: [u8; 16] = handle
        .try_into()
        .map_err(|_| Error::CorruptedIndex(SKILL_EDIT_ROW_LABEL))?;
    let decision = row
        .decision
        .map(|decision| -> Result<MinedSkillEditDecision> {
            Ok(MinedSkillEditDecision {
                verdict: MinedSkillEditVerdict::from_token(&decision.outcome)
                    .ok_or(Error::CorruptedIndex(SKILL_EDIT_ROW_LABEL))?,
                at: decision.at,
            })
        })
        .transpose()?;
    Ok(MinedSkillEditProposal {
        proposal_id: EntityId::from_bytes(bytes)
            .map_err(|_| Error::CorruptedIndex(SKILL_EDIT_ROW_LABEL))?,
        skill: EntityId::from_hex(&row.skill)
            .map_err(|_| Error::CorruptedIndex(SKILL_EDIT_ROW_LABEL))?,
        scope: row.scope,
        from: row.from,
        to: row.to,
        evidence_receipts: row.evidence_receipts,
        rationale: row.rationale,
        at: row.at,
        decision,
    })
}

/// Reads the work gate.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on a malformed row.
pub fn miner_watermark(vault: &Vault) -> Result<MinerWatermark> {
    let rtxn = vault.store.env.read_txn()?;
    watermark_in_txn(vault, &rtxn)
}

fn watermark_in_txn(vault: &Vault, rtxn: &heed::RoTxn<'_>) -> Result<MinerWatermark> {
    let Some(raw) = vault.store.vault_meta.get(rtxn, MINER_WATERMARK_KEY)? else {
        return Ok(MinerWatermark::default());
    };
    let bytes: [u8; 16] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(WATERMARK_ROW_LABEL))?;
    let (at, boundary) = bytes.split_at(8);
    Ok(MinerWatermark {
        at: u64::from_be_bytes(at.try_into().expect("an 8-byte half of 16 bytes")),
        boundary: u64::from_be_bytes(boundary.try_into().expect("an 8-byte half of 16 bytes")),
    })
}

/// Advances the work gate, never rewinds it.
///
/// Monotone because a pass that saw LESS than the last one saw is a pass over a
/// ledger that lost rows, and the last pass's bound is still the honest one. A
/// re-scanned amendment costs one bucket fold and is stopped from re-proposing
/// by its mint-mark, which is the guard that actually matters.
pub(super) fn advance_watermark_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    observed: MinerWatermark,
) -> Result<()> {
    if observed.advances(watermark_in_txn(vault, &*wtxn)?) {
        let mut row = [0_u8; 16];
        row[..8].copy_from_slice(&observed.at.to_be_bytes());
        row[8..].copy_from_slice(&observed.boundary.to_be_bytes());
        vault
            .store
            .vault_meta
            .put(wtxn, MINER_WATERMARK_KEY, &row)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub(super) fn encode_row<T: Serialize>(row: &T, label: &'static str) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row).map_err(|_| Error::InvariantViolation(label))
}

pub(super) fn decode_row<T: serde::de::DeserializeOwned>(
    raw: &[u8],
    label: &'static str,
) -> Result<T> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex(label))
}

pub(super) fn meta_key(prefix: &[u8], handle: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + handle.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(handle);
    key
}
