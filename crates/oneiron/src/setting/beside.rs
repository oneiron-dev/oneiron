//! Setting values beside their acts (stage 7c-1; DESIGN 1.6, "What travels": inline or beside).
//!
//! The owner's change of a key that travels ([`super::project::travels`]) carries its value inside
//! its signed act where the key's value type is closed and the value's JSON holds at most
//! [`POLICY_SETTING_INLINE_MAX`] bytes. Any other value travels beside the act: the act keeps only
//! BLAKE3 over the value's JSON bytes ([`setting_value_digest`]), and the same write stores those
//! bytes as one immutable ASSET row, whose id is derived from the act's target and that digest
//! ([`beside_row_id`]). The log is append-only and no door erases a row of it, so free text never
//! goes on the log. An ASSET row is on the data plane: the sync window carries it to every machine
//! of the vault, and an erase can reach it. Its id names the row as well as the value, so a digest
//! never picks up another key's equal value, and an erase of one row's value reaches no other
//! key's.
//!
//! The row's body is [`BESIDE_VALUE_TAG`] and then the value's JSON bytes. The tag lets a put of
//! the row, local or a peer's, note the projection pass that reads it ([`is_beside_value_body`]).
//!
//! A machine reads a head that keeps only a digest through that row ([`beside_row_read_in_txn`]):
//! - here, and its bytes match the digest: the value;
//! - not here: the act has not fully arrived, so the row reads as it did before it, `Pending`,
//!   until the row arrives;
//! - here and not matching the digest, or erased here: unreadable, so the key's strictest value,
//!   `Quarantined` (DESIGN 1.6, "Fold states"). The erase door that writes the clear or a new
//!   value in the same write is ARCH-0038's; until it lands, an erased value reads strictest.
//!
//! A projection records each row it read and what that row held ([`BesideHeld`]), and a later
//! pass reads the target again once one holds otherwise: the value arrived, was erased here, or
//! no longer matches its act. The put of a row notes that pass; an erase here is read at the next
//! one (the next authority commit, or the open).

use oneiron_authority::authority::{
    POLICY_SETTING_INLINE_MAX, setting_slot_target, setting_value_digest,
};
use oneiron_setting_contract::RowKey;
use serde::{Deserialize, Serialize};

use super::SettingSpec;
use super::project::travels;
use crate::Vault;
use crate::authority::SlotValue;
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::SETTING_BESIDE_VALUE;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_ASSET;
use crate::temporal::TimeRange;

/// What a beside row's body starts with; the value's JSON bytes follow it.
const BESIDE_VALUE_TAG: &[u8] = b"oneiron.setting.beside_value.v1\n";

/// How the owner's change of a key reaches the vault's other machines, as `vault.settings.list`
/// shows it (DESIGN 1.6, "What travels"). The build derives it from the key's value type and
/// `sync`; nobody picks it by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SettingTravel {
    /// Inside the signed act: a closed value. One whose JSON is longer than an act carries
    /// (4096 bytes) travels beside it.
    Inline,
    /// Beside the signed act: one immutable row addressed by the value's digest, which an erase
    /// can reach. A value with free text, or of any other type that is not closed.
    Beside,
    /// Not at all: a key that stays on its install, or a learned key, whose seed weight does not
    /// travel yet.
    Local,
}

impl SettingTravel {
    /// How the owner's change of `spec` travels.
    pub(super) fn of(spec: &SettingSpec) -> Self {
        if !travels(spec) {
            Self::Local
        } else if spec.kind.travels_inline() {
            Self::Inline
        } else {
            Self::Beside
        }
    }
}

/// The id of the row that holds the value whose JSON bytes have BLAKE3 `digest`, beside an act on
/// the row `slot`: derived from the act's target and the digest.
///
/// # Errors
///
/// A derived id in the reserved range (never in practice).
pub(super) fn beside_row_id(slot: &RowKey, digest: &[u8; 32]) -> Result<EntityId> {
    let target = setting_slot_target(slot)?;
    Ok(EntityId::derive(
        SETTING_BESIDE_VALUE,
        &[target.as_bytes().as_slice(), digest.as_slice()],
    )?)
}

/// The value one row of an owner's act on `slot` of `spec` leaves, from its JSON bytes `json`
/// (`None` for a clear), in the act's write `txn`: inside the act where the key's value type is
/// closed and the JSON holds at most [`POLICY_SETTING_INLINE_MAX`] bytes, else beside it, its row
/// written here in the same write unless it is here already.
///
/// # Errors
///
/// Storage errors, and the put's refusal.
pub(super) fn slot_value_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    spec: &SettingSpec,
    slot: &RowKey,
    json: Option<Vec<u8>>,
) -> Result<SlotValue> {
    let Some(json) = json else {
        return Ok(SlotValue::Clear);
    };
    if spec.kind.travels_inline() && json.len() <= POLICY_SETTING_INLINE_MAX {
        return Ok(SlotValue::Inline(json));
    }
    let digest = setting_value_digest(&json);
    let row = beside_row_id(slot, &digest)?;
    if !matches!(
        beside_row_read_in_txn(vault, txn, row, digest)?,
        BesideRead::Here(_)
    ) {
        put_beside_row_in_txn(vault, txn, row, &json)?;
    }
    Ok(SlotValue::Beside(digest))
}

/// Puts the ASSET row `id` holding the JSON bytes `json` beside an act, in `txn`.
fn put_beside_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    json: &[u8],
) -> Result<()> {
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let mut body = Vec::with_capacity(BESIDE_VALUE_TAG.len() + json.len());
    body.extend_from_slice(BESIDE_VALUE_TAG);
    body.extend_from_slice(json);
    vault
        .batch_in()
        .put(
            &id,
            ENTITY_TYPE_ASSET,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &body,
        )
        .apply(txn)
}

/// What the row beside an act holds on this install.
pub(super) enum BesideRead {
    /// The value's JSON bytes, which match the act's digest.
    Here(Vec<u8>),
    /// No row, and no mark that one was erased here: the value has not arrived.
    Absent,
    /// A row that does not hold the act's value (another tag, bytes that do not match its
    /// digest), or one erased here.
    Unreadable,
}

impl BesideRead {
    /// What the row held, as a projection records it.
    pub(super) fn held(&self) -> BesideHeld {
        match self {
            Self::Here(_) => BesideHeld::Value,
            Self::Absent => BesideHeld::Absent,
            Self::Unreadable => BesideHeld::Unreadable,
        }
    }
}

/// What a row beside an act held when a projection read it ([`BesideRead`] without the bytes):
/// a later pass reads the target again once the row holds otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum BesideHeld {
    /// The act's value.
    Value,
    /// Nothing yet: the value has not arrived.
    Absent,
    /// Something that is not the act's value, or an erase here.
    Unreadable,
}

/// The row `row` beside an act whose value's JSON bytes have BLAKE3 `digest`, as `txn` holds it.
///
/// # Errors
///
/// Storage and filesystem errors.
pub(super) fn beside_row_read_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: EntityId,
    digest: [u8; 32],
) -> Result<BesideRead> {
    Ok(match beside_body_in_txn(vault, txn, row)? {
        Some(body) => match body.strip_prefix(BESIDE_VALUE_TAG) {
            Some(json) if setting_value_digest(json) == digest => BesideRead::Here(json.to_vec()),
            _ => BesideRead::Unreadable,
        },
        None if erased_in_txn(vault, txn, row)? => BesideRead::Unreadable,
        None => BesideRead::Absent,
    })
}

/// Whether `body`, an ASSET row's, holds a setting value beside its act: a put of it notes the
/// setting projection pass (`batch::put_apply`).
pub(crate) fn is_beside_value_body(body: &[u8]) -> bool {
    body.starts_with(BESIDE_VALUE_TAG)
}

/// The readable body of the ASSET row `id`; `None` where none is here.
fn beside_body_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<Vec<u8>>> {
    vault.with_asset_body_reader_in_txn(txn, &id, |read| {
        let mut body = Vec::new();
        read.read_to_end(&mut body)?;
        Ok(body)
    })
}

/// Whether the row `id` was erased here: a hard delete's marker or a row deletion fence.
fn erased_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<bool> {
    crate::deletion::row_deletion_marked(&vault.store, txn, &id, None)
}

/// The row that holds the value whose JSON bytes are `json` beside an act on `slot` (stage 7c-1
/// tests).
///
/// # Errors
///
/// As [`beside_row_id`].
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn beside_row_of(slot: &RowKey, json: &[u8]) -> Result<EntityId> {
    beside_row_id(slot, &setting_value_digest(json))
}

/// Puts, in a write of its own, the row for the value whose JSON bytes are `json` beside an act
/// on `slot`, holding `held` (`json` itself, or other bytes: a row that does not match its
/// digest), as a peer's row lands: through the batch door, whose commit runs the setting
/// projection (stage 7c-1 tests).
///
/// # Errors
///
/// Storage errors, and the put's refusal.
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn land_beside_row(
    vault: &Vault,
    slot: &RowKey,
    json: &[u8],
    held: &[u8],
) -> Result<()> {
    let id = beside_row_of(slot, json)?;
    vault.with_write_txn_grouped(|txn| put_beside_row_in_txn(vault, txn, id, held))
}

/// The JSON bytes the row for the value whose JSON bytes are `json` beside an act on `slot` holds
/// here; `None` when none is readable here (stage 7c-1 tests).
///
/// # Errors
///
/// Storage and filesystem errors.
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn beside_row_json(
    vault: &Vault,
    slot: &RowKey,
    json: &[u8],
) -> Result<Option<Vec<u8>>> {
    let txn = vault.store.env.read_txn()?;
    let body = beside_body_in_txn(vault, &txn, beside_row_of(slot, json)?)?;
    Ok(body.map(|body| match body.strip_prefix(BESIDE_VALUE_TAG) {
        Some(json) => json.to_vec(),
        None => body,
    }))
}
