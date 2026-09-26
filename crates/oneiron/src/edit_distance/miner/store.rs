//! ED-04 miner reads, watermark and row codec.

use serde::Serialize;

use super::config::{ROW_VERSION, SKILL_EDIT_ROW_LABEL, WATERMARK_ROW_LABEL};
use super::model::{
    MinedSkillEditDecision, MinedSkillEditProposal, MinedSkillEditVerdict, MinerWatermark,
    StoredSkillEdit, StoredSkillEditDecision,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

/// Mined skill-edit proposal awaiting owner decision, keyed by proposal id.
pub(super) const SKILL_EDIT: SideTable<EntityId, StoredSkillEdit, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_MINER_SKILL_EDIT);

/// Global work-gate watermark for the substitution-miner pass.
const WATERMARK: SideTable<(), MinerWatermark, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_MINER_WATERMARK);

impl RawValue for StoredSkillEdit {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_row(self, SKILL_EDIT_ROW_LABEL)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let row: StoredSkillEdit = decode_row(bytes, SKILL_EDIT_ROW_LABEL)?;
        if row.v != ROW_VERSION {
            return Err(CodecError::Value(Error::CorruptedIndex(
                SKILL_EDIT_ROW_LABEL,
            )));
        }
        Ok(row)
    }
}

impl RawValue for MinerWatermark {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut row = [0_u8; 16];
        row[..8].copy_from_slice(&self.at.to_be_bytes());
        row[8..].copy_from_slice(&self.boundary.to_be_bytes());
        Ok(row.to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let bytes: [u8; 16] = bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex(WATERMARK_ROW_LABEL))?;
        let (at, boundary) = bytes.split_at(8);
        Ok(Self {
            at: u64::from_be_bytes(at.try_into().expect("an 8-byte half of 16 bytes")),
            boundary: u64::from_be_bytes(boundary.try_into().expect("an 8-byte half of 16 bytes")),
        })
    }
}

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
    for (id, row) in SKILL_EDIT.scan(&vault.store, &rtxn)? {
        let proposal = decode_skill_edit(id, row)?;
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
    let Some(row) = SKILL_EDIT.get(&vault.store, txn, proposal_id)? else {
        return Ok(None);
    };
    decode_skill_edit(*proposal_id, row).map(Some)
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
    vault.with_write_txn(|wtxn| {
        let Some(mut row) = SKILL_EDIT.get(&vault.store, &*wtxn, proposal_id)? else {
            return Err(Error::EntityNotFound);
        };
        row.decision = Some(StoredSkillEditDecision {
            outcome: verdict.as_str().to_owned(),
            at,
        });
        SKILL_EDIT.put(&vault.store, wtxn, proposal_id, &row)?;
        Ok(())
    })
}

fn decode_skill_edit(
    proposal_id: EntityId,
    row: StoredSkillEdit,
) -> Result<MinedSkillEditProposal> {
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
        principal: row.principal,
        proposal_id,
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
    Ok(WATERMARK.get(&vault.store, rtxn, &())?.unwrap_or_default())
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
        WATERMARK.put(&vault.store, wtxn, &(), &observed)?;
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
