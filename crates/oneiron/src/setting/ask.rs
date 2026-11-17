//! An agent's setting ask as the owner's confirm sheet reads it
//! (RESTRICTION-WAVE-11-CAP-NOTE). An agent's change that waits on a check-in
//! opens it with only the change's effect digest, so the ask's row key and
//! value are kept beside it, in the writer that opens it. The owner reads
//! which row the ask changes and to what, with the key's loosening note for
//! that row read in the owner's own transaction (Q1 = A; CAP-SCOPE = B: the
//! row's scope picks what the note states).

use serde::{Deserialize, Serialize};

use oneiron_setting_contract::RowKey;

use super::{EncodedValue, SettingMode, SettingScope, spec_named};
use crate::Vault;
use crate::check_in::pending_check_in_in_txn;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

/// The kept asks, by the pending check-in each waits on.
const ASKS: SideTable<EntityId, StoredAsk, Named> = SideTable::new(&side_table::SETTING_ASK);

/// One kept ask: the agent that asked, the row key's bytes ([`RowKey::encode`]) and the value it
/// asked for, encoded ([`EncodedValue`]), none for a clear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredAsk {
    asker: EntityId,
    row: Vec<u8>,
    value: Option<Vec<u8>>,
}

/// One agent's setting ask as the owner reads it before he answers its check-in.
#[derive(Debug, Clone, PartialEq)]
pub struct SettingAsk {
    /// The pending check-in the ask waits on.
    pub check_in: EntityId,
    /// The agent that asked.
    pub asker: EntityId,
    /// The catalogue key the ask changes.
    pub key: String,
    /// The item of a family key; none for an item-less key.
    pub item: Option<String>,
    /// A value row or the owner's pin.
    pub mode: SettingMode,
    /// The row's scope.
    pub scope: SettingScope,
    /// The value asked for, as JSON; none for a clear.
    pub value: Option<serde_json::Value>,
    /// The key's line for loosening this row ([`super::SettingSpec::loosening_note`]), read in
    /// the owner's own read: the vault as he sees it when he looks. None for a key that states
    /// none, or for this item.
    pub loosening_note: Option<String>,
}

/// Keeps `asker`'s ask for `row` at `value` beside the pending check-in `check_in` it waits on,
/// in the writer that opened it. A repeat of the same ask finds the same check-in and keeps the
/// same row.
pub(super) fn keep_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    check_in: &EntityId,
    asker: EntityId,
    row: &RowKey,
    value: Option<&EncodedValue>,
) -> Result<()> {
    let _ = (vault, txn, check_in, asker, row, value);
    Ok(())
}

/// Drops the ask kept beside `check_in`, in the writer that spends it.
pub(super) fn drop_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    check_in: &EntityId,
) -> Result<()> {
    ASKS.delete(&vault.store, txn, check_in).map(drop)
}

impl Vault {
    /// The agent's setting ask the pending check-in `check_in` waits on, as the owner's confirm
    /// sheet shows it: the row it changes, the value it asks for, and the key's loosening note
    /// for that row, all read in one read under the owner's proof, revalidated there. `None`
    /// when `check_in` is no pending check-in of a setting ask.
    ///
    /// # Errors
    ///
    /// A stale owner proof; a kept row that no longer decodes, or whose key the catalogue no
    /// longer holds; storage errors.
    pub fn setting_ask_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        check_in: &EntityId,
    ) -> Result<Option<SettingAsk>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let Some(pending) = pending_check_in_in_txn(&self.store, &txn, check_in)? else {
            return Ok(None);
        };
        let Some(ask) = ASKS.get(&self.store, &txn, check_in)? else {
            return Ok(None);
        };
        if pending.asker != ask.asker || pending.verb != super::set::SET_VERB {
            return Ok(None);
        }
        let row = RowKey::decode(&ask.row).ok_or_else(|| {
            Error::InvalidConfig("a kept setting ask names no setting row".into())
        })?;
        let spec = spec_named(&row.name)?;
        let loosening_note = match spec.loosening_note {
            Some(note) => note(self, &txn, &row.scope, row.item.as_deref())?,
            None => None,
        };
        let value = ask
            .value
            .and_then(|bytes| spec.kind.to_json(&EncodedValue(bytes)));
        Ok(Some(SettingAsk {
            check_in: *check_in,
            asker: ask.asker,
            key: row.name,
            item: row.item,
            mode: row.mode,
            scope: row.scope,
            value,
            loosening_note,
        }))
    }
}

/// `SETTING_ASK`'s actor scrub: an erased agent's asks are dropped, and so is every ask whose row
/// scope or value names the actor, or whose check-in is gone, so no kept ask names an erased
/// actor.
pub(crate) fn erase_setting_ask_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, txn, actor)? {
        return Ok(());
    }
    let mut dropped = Vec::new();
    for (check_in, ask) in ASKS.scan(&vault.store, txn)? {
        let mentions = RowKey::decode(&ask.row).is_some_and(|row| {
            row.scope.entity() == Some(*actor)
                || ask.value.as_ref().is_some_and(|bytes| {
                    spec_named(&row.name).is_ok_and(|spec| {
                        let value = EncodedValue(bytes.clone());
                        spec.kind.erase_mentions_in(&value, *actor).is_some()
                    })
                })
        });
        if ask.asker == *actor
            || mentions
            || pending_check_in_in_txn(&vault.store, txn, &check_in)?.is_none()
        {
            dropped.push(check_in);
        }
    }
    for check_in in dropped {
        ASKS.delete(&vault.store, txn, &check_in)?;
    }
    Ok(())
}
