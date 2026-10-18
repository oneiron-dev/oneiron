//! Identity-preserving replay of a stored TURN through the continuous sieve.
//! A replay owes the original TURN a read. The sieve's reading digest decides
//! whether anything changed; no new TURN, carrier, tag or conclusion is minted.
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::error::Error;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SieveEvidenceRequest {
    pub turn: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SieveEvidenceCursor {
    pub learned_at: u64,
    pub turn: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SieveEvidenceView {
    /// The original ingress identity, unchanged by a replay.
    pub turn: EntityId,
    /// The sieve's digest of the source chunks it read, not a text-match key.
    pub reading: Option<[u8; 32]>,
    pub cursor: Option<SieveEvidenceCursor>,
    pub owed: bool,
    pub continuing: bool,
}

fn evidence_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: EntityId,
) -> Result<SieveEvidenceView> {
    let row = vault
        .store
        .port_entity_record(txn, &turn)?
        .ok_or(Error::EntityNotFound)?;
    if row.entity_type != ENTITY_TYPE_TURN {
        return Err(Error::InvalidConfig(
            "sieve evidence must name a TURN".into(),
        ));
    }
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &turn)?.is_live() {
        return Err(Error::EntityNotFound);
    }
    Ok(SieveEvidenceView {
        turn,
        reading: READ.get(&vault.store, txn, &turn)?.map(|read| read.reading),
        cursor: CURSOR
            .get(&vault.store, txn, &())?
            .map(|cursor| SieveEvidenceCursor {
                learned_at: cursor.learned_at,
                turn: cursor.turn,
            }),
        owed: OWED.contains(&vault.store, txn, &turn)?,
        continuing: CONTINUE.contains(&vault.store, txn, &turn)?,
    })
}

pub fn evidence_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SieveEvidenceRequest,
) -> Result<SieveEvidenceView> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_as_vault_owner_in_txn(vault, &txn)?;
    evidence_in_txn(vault, &txn, input.turn)
}

pub fn replay_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SieveEvidenceRequest,
) -> Result<SieveEvidenceView> {
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_as_vault_owner_in_txn(vault, txn)?;
        evidence_in_txn(vault, txn, input.turn)?;
        if !sieved_turn_in_txn(vault, txn, &input.turn)? {
            return Err(Error::InvalidConfig(
                "TURN is not continuous-sieve evidence".into(),
            ));
        }
        owe_read_in_txn(&vault.store, txn, &input.turn)?;
        evidence_in_txn(vault, txn, input.turn)
    })
}
