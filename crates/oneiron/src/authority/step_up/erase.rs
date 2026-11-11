//! The step-up rows an erase, or a passkey's removal or replacement,
//! drops: passkeys, open ceremonies and completed step-ups.

use heed::RwTxn;

use super::{CHALLENGES, PASSKEYS, RECORDS, StepUpFactor};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// An erase of `actor` drops every passkey they enrolled.
pub(crate) fn erase_step_up_passkeys_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let keys: Vec<(EntityId, [u8; 32])> = PASSKEYS
        .scan_from(&vault.store, wtxn, actor.as_bytes())?
        .into_iter()
        .map(|(key, _)| key)
        .filter(|(holder, _)| holder == actor)
        .collect();
    for key in keys {
        PASSKEYS.delete(&vault.store, wtxn, &key)?;
    }
    Ok(())
}

/// An erase of `actor` drops every ceremony they opened.
pub(crate) fn erase_step_up_challenges_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let keys: Vec<[u8; 32]> = CHALLENGES
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(_, pending)| pending.holder == *actor)
        .map(|(key, _)| key)
        .collect();
    for key in keys {
        CHALLENGES.delete(&vault.store, wtxn, &key)?;
    }
    Ok(())
}

/// Drops every step-up `holder` made with the passkey whose credential id
/// hashes to `credential`, in the writer that removes or replaces that
/// passkey: a step-up stands only with the enrollment that verified it,
/// never with a later one under the same credential id.
pub(super) fn drop_step_ups_with_passkey_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    holder: EntityId,
    credential: &[u8; 32],
) -> Result<()> {
    let keys: Vec<[u8; 32]> = RECORDS
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(_, record)| {
            record.holder == holder
                && record.factor == StepUpFactor::Passkey
                && record.credential == *credential
        })
        .map(|(key, _)| key)
        .collect();
    for key in keys {
        RECORDS.delete(&vault.store, wtxn, &key)?;
    }
    Ok(())
}

/// An erase of `actor` drops every step-up they made.
pub(crate) fn erase_step_up_records_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let keys: Vec<[u8; 32]> = RECORDS
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(_, record)| record.holder == *actor)
        .map(|(key, _)| key)
        .collect();
    for key in keys {
        RECORDS.delete(&vault.store, wtxn, &key)?;
    }
    Ok(())
}

/// An explicit passkey reset leaves authenticator-app step-ups alone.
pub(super) fn erase_step_up_passkey_records_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    for (key, record) in RECORDS.scan(&vault.store, wtxn)? {
        if record.holder == *actor && record.factor == StepUpFactor::Passkey {
            RECORDS.delete(&vault.store, wtxn, &key)?;
        }
    }
    Ok(())
}
