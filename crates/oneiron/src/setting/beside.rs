//! Setting values beside their acts (stage 7c-1; DESIGN 1.6, "What travels": inline or beside).
//!
//! The owner's change of a key that travels ([`super::project::travels`]) carries its value inside
//! its signed act where the key's value type is closed and the value's JSON holds at most
//! [`POLICY_SETTING_INLINE_MAX`] bytes. Any other value travels beside the act: the act keeps only
//! BLAKE3 over the value's JSON bytes ([`setting_value_digest`]), and the same write stores those
//! bytes as one immutable ASSET row, whose id is derived from the act's target, that digest and
//! the act itself ([`beside_row_id`]). The log is append-only and no door erases a row of it, so
//! free text never goes on the log. An ASSET row is on the data plane: the sync window carries it
//! to every machine of the vault, and an erase can reach it. Its id names the act as well as the
//! value, so a digest never picks up another key's equal value, an erase of one act's value
//! reaches no other act's, and an erased value never keeps the owner from setting the same value
//! again: that is a new act, with a row of its own.
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
//! no longer matches its act. It also names each such row in [`WATCH`]: a put of
//! a row named there, or of any row whose body is a value beside an act, notes that pass, whatever
//! the row's body ([`notes_projection_pass_in_txn`]), and so does an erase of a row named there,
//! which also takes the value out of the setting history (`change::erase_setting_entity_in_txn`).
//!
//! A pack's table of defaults travels beside its head act the same way (stage 7c-3c; DESIGN 1.6,
//! "Packs across machines": "The table's bytes travel beside the act"): one ASSET row per pack
//! and table digest ([`pack_table_row_id`]), its body [`PACK_TABLE_TAG`] and then the table's
//! bytes, which the pack's reader checks against the digest the head names
//! ([`pack_table_read_in_txn`]). Its put notes the projection pass too.

use oneiron_authority::authority::{
    AuthorityEntryHash, POLICY_SETTING_INLINE_MAX, setting_pack_target, setting_slot_target,
    setting_value_digest,
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
use crate::side_table::{self, Named, SideTable, SideTableDbs};
use crate::temporal::TimeRange;

/// The rows beside acts that a target's last projection read, each with that target
/// ([`watch_rows_in_txn`]).
const WATCH: SideTable<EntityId, EntityId, Named> =
    SideTable::new(&side_table::SETTING_BESIDE_WATCH);

/// What a beside row's body starts with; the value's JSON bytes follow it.
const BESIDE_VALUE_TAG: &[u8] = b"oneiron.setting.beside_value.v1\n";

/// What the body of a pack's table beside its head starts with; the table's bytes follow it
/// (stage 7c-3c).
const PACK_TABLE_TAG: &[u8] = b"oneiron.setting.pack_table.v1\n";

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

/// The id of the row that holds the value whose JSON bytes have BLAKE3 `digest`, beside the act
/// `act` on the row `slot`: derived from the act's target, the digest and the act, so each act's
/// value has a row of its own (module doc).
///
/// # Errors
///
/// A derived id in the reserved range (never in practice).
pub(super) fn beside_row_id(
    slot: &RowKey,
    digest: &[u8; 32],
    act: &AuthorityEntryHash,
) -> Result<EntityId> {
    let target = setting_slot_target(slot)?;
    Ok(EntityId::derive(
        SETTING_BESIDE_VALUE,
        &[
            target.as_bytes().as_slice(),
            digest.as_slice(),
            act.as_slice(),
        ],
    )?)
}

/// The value one row of an owner's act on `spec` leaves, from its JSON bytes `json` (`None` for a
/// clear): inside the act where the key's value type is closed and the JSON holds at most
/// [`POLICY_SETTING_INLINE_MAX`] bytes, else beside it, with the JSON bytes its row holds once
/// the act is appended ([`put_beside_value_in_txn`]).
pub(super) fn slot_value(
    spec: &SettingSpec,
    json: Option<Vec<u8>>,
) -> (SlotValue, Option<Vec<u8>>) {
    let Some(json) = json else {
        return (SlotValue::Clear, None);
    };
    if spec.kind.travels_inline() && json.len() <= POLICY_SETTING_INLINE_MAX {
        return (SlotValue::Inline(json), None);
    }
    (SlotValue::Beside(setting_value_digest(&json)), Some(json))
}

/// Puts the row that holds the JSON bytes `json` beside the act `act` on the row `slot`, in the
/// act's write `txn` ([`slot_value`]).
///
/// # Errors
///
/// Storage errors, and the put's refusal.
pub(super) fn put_beside_value_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (slot, act): (&RowKey, &AuthorityEntryHash),
    json: &[u8],
) -> Result<()> {
    let row = beside_row_id(slot, &setting_value_digest(json), act)?;
    put_beside_body_in_txn(vault, txn, row, (BESIDE_VALUE_TAG, json))
}

/// Names in [`WATCH`] the rows beside acts `rows` that the projection of `target` read, in
/// `txn`, in place of the rows its last projection read (`last`): a put of one notes the
/// projection pass whatever its body ([`notes_projection_pass_in_txn`]).
///
/// # Errors
///
/// Storage errors.
pub(super) fn watch_rows_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut heed::RwTxn<'_>,
    target: EntityId,
    (last, rows): (&[EntityId], &[EntityId]),
) -> Result<()> {
    for row in last {
        if !rows.contains(row) {
            WATCH.delete(dbs, txn, row)?;
        }
    }
    for row in rows {
        WATCH.put(dbs, txn, row, &target)?;
    }
    Ok(())
}

/// Whether the put of the ASSET row `id` whose body is `body` notes the setting projection pass
/// (`batch::put_apply`): a value beside an act, or any body at a row a target's last projection
/// read, so a row that does not hold its act's value is read at once too.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn notes_projection_pass_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    (id, body): (&EntityId, &[u8]),
) -> Result<bool> {
    Ok(is_beside_value_body(body) || WATCH.contains(dbs, txn, id)?)
}

/// The target whose last projection read the row beside an act `row` ([`WATCH`]); `None` where
/// none reads it now.
///
/// # Errors
///
/// Storage errors.
pub(super) fn watched_target_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    row: &EntityId,
) -> Result<Option<EntityId>> {
    WATCH.get(dbs, txn, row)
}

/// Whether a target's last projection read the row `id` beside an act: its erase notes the
/// projection pass, which reads the target again once the erase commits.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn beside_row_watched_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    WATCH.contains(dbs, txn, id)
}

/// The id of the row that holds `pack`'s table of defaults whose digest is `digest`, beside its
/// head acts (stage 7c-3c): derived from the pack's target and the digest.
///
/// # Errors
///
/// A derived id in the reserved range (never in practice).
pub(super) fn pack_table_row_id(pack: &str, digest: &[u8; 32]) -> Result<EntityId> {
    let target = setting_pack_target(pack)?;
    Ok(EntityId::derive(
        SETTING_BESIDE_VALUE,
        &[target.as_bytes().as_slice(), digest.as_slice()],
    )?)
}

/// Puts `pack`'s table `table` (its bytes), whose digest is `digest`, beside its head acts in
/// `txn`, unless a row of it is here already (stage 7c-3c).
///
/// # Errors
///
/// Storage errors, and the put's refusal.
pub(super) fn put_pack_table_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (pack, digest): (&str, &[u8; 32]),
    table: &[u8],
) -> Result<()> {
    let row = pack_table_row_id(pack, digest)?;
    if beside_body_in_txn(vault, txn, row)?.is_none() {
        put_beside_body_in_txn(vault, txn, row, (PACK_TABLE_TAG, table))?;
    }
    Ok(())
}

/// What the row of `pack`'s table whose digest is `digest` holds here (stage 7c-3c): its bytes
/// where `matches` takes them as that table, else unreadable; absent where no row is here and
/// none was erased here.
///
/// # Errors
///
/// Storage and filesystem errors.
pub(super) fn pack_table_read_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (pack, digest): (&str, &[u8; 32]),
    matches: impl FnOnce(&[u8]) -> bool,
) -> Result<BesideRead> {
    let row = pack_table_row_id(pack, digest)?;
    Ok(match beside_body_in_txn(vault, txn, row)? {
        Some(body) => match body.strip_prefix(PACK_TABLE_TAG) {
            Some(table) if matches(table) => BesideRead::Here(table.to_vec()),
            _ => BesideRead::Unreadable,
        },
        None if erased_in_txn(vault, txn, row)? => BesideRead::Unreadable,
        None => BesideRead::Absent,
    })
}

/// Puts the ASSET row `id` holding `tag` and then `bytes` beside an act, in `txn`.
fn put_beside_body_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    (tag, bytes): (&[u8], &[u8]),
) -> Result<()> {
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let mut body = Vec::with_capacity(tag.len() + bytes.len());
    body.extend_from_slice(tag);
    body.extend_from_slice(bytes);
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

/// Whether `body`, an ASSET row's, holds a setting value beside its act, or a pack's table
/// beside its head (stage 7c-3c): a put of it notes the setting projection pass
/// ([`notes_projection_pass_in_txn`]).
fn is_beside_value_body(body: &[u8]) -> bool {
    body.starts_with(BESIDE_VALUE_TAG) || body.starts_with(PACK_TABLE_TAG)
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

/// The row that holds the value whose JSON bytes are `json` beside the act `act` on `slot`
/// (stage 7c-1 tests).
///
/// # Errors
///
/// As [`beside_row_id`].
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn beside_row_for(
    slot: &RowKey,
    json: &[u8],
    act: &AuthorityEntryHash,
) -> Result<EntityId> {
    beside_row_id(slot, &setting_value_digest(json), act)
}

/// The row that holds the value whose JSON bytes are `json` beside the live act on `slot` that
/// keeps only its digest, in `vault` (stage 7c-1 tests).
///
/// # Errors
///
/// No live act on `slot` keeps that value beside it; storage errors.
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn beside_row_of(vault: &Vault, slot: &RowKey, json: &[u8]) -> Result<EntityId> {
    let digest = setting_value_digest(json);
    let target = setting_slot_target(slot)?;
    let txn = vault.store.env.read_txn()?;
    for act in vault.setting_slot_live_in_txn(&txn, target)? {
        let head = vault.setting_slot_head_in_txn(&txn, target, act)?;
        if head
            .set
            .is_some_and(|set| set.value == Some(digest) && set.inline.is_none())
        {
            return beside_row_id(slot, &digest, &act);
        }
    }
    Err(crate::error::Error::InvariantViolation(
        "no live act on the row keeps this value beside it",
    ))
}

/// Puts, in a write of its own, the row `row` beside an act holding `held` after the value tag
/// (the act's value's JSON bytes, or other bytes: a row that does not match its digest), or,
/// where `tagged` is false, `held` alone (a row that holds no setting value), as a peer's row
/// lands: through the batch door, whose commit runs the setting projection when the put notes
/// it (stage 7c-1 tests).
///
/// # Errors
///
/// Storage errors, and the put's refusal.
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn land_beside_row(
    vault: &Vault,
    row: EntityId,
    (held, tagged): (&[u8], bool),
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        if tagged {
            return put_beside_body_in_txn(vault, txn, row, (BESIDE_VALUE_TAG, held));
        }
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        vault
            .batch_in()
            .put(
                &row,
                ENTITY_TYPE_ASSET,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                held,
            )
            .apply(txn)
    })
}

/// Puts, in a write of its own, the row of `pack`'s table whose digest is `digest` holding `held`
/// (the table's bytes, or other bytes: a row that does not match its digest), as a peer's row
/// lands: through the batch door, whose commit runs the setting projection (stage 7c-3c tests).
///
/// # Errors
///
/// Storage errors, and the put's refusal.
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn land_pack_table(
    vault: &Vault,
    (pack, digest, _act): (&str, &[u8; 32], &AuthorityEntryHash),
    held: &[u8],
) -> Result<EntityId> {
    let id = pack_table_row_id(pack, digest)?;
    vault.with_write_txn_grouped(|txn| {
        put_beside_body_in_txn(vault, txn, id, (PACK_TABLE_TAG, held))
    })?;
    Ok(id)
}

/// Red pin door (the base's one row per pack and digest; the act is not part of the id).
#[cfg(all(oneiron_test_support, feature = "test-support", feature = "sync"))]
pub(crate) fn land_pack_table_from_peer(
    vault: &Vault,
    (pack, digest, _act): (&str, &[u8; 32], &AuthorityEntryHash),
    held: &[u8],
) -> Result<EntityId> {
    let id = pack_table_row_id(pack, digest)?;
    let mut body = PACK_TABLE_TAG.to_vec();
    body.extend_from_slice(held);
    vault.with_write_txn_grouped(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        vault
            .batch_in()
            .put_replicated(
                &id,
                ENTITY_TYPE_ASSET,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                None,
                &body,
            )
            .apply(txn)
    })?;
    Ok(id)
}

/// Red pin door: the base's one row per pack and digest.
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn land_pack_table_shared_row(
    vault: &Vault,
    (pack, digest): (&str, &[u8; 32]),
    held: &[u8],
) -> Result<()> {
    let id = pack_table_row_id(pack, digest)?;
    vault.with_write_txn_grouped(|txn| {
        put_beside_body_in_txn(vault, txn, id, (PACK_TABLE_TAG, held))
    })
}

/// The bytes the row of `pack`'s table whose digest is `digest` holds here after its tag; `None`
/// when no row is here (stage 7c-3c tests).
///
/// # Errors
///
/// Storage and filesystem errors.
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn pack_table_bytes(
    vault: &Vault,
    (pack, digest, _act): (&str, &[u8; 32], &AuthorityEntryHash),
) -> Result<Option<Vec<u8>>> {
    let txn = vault.store.env.read_txn()?;
    let body = beside_body_in_txn(vault, &txn, pack_table_row_id(pack, digest)?)?;
    Ok(body.map(|body| match body.strip_prefix(PACK_TABLE_TAG) {
        Some(table) => table.to_vec(),
        None => body,
    }))
}

/// The JSON bytes the row `row` beside an act holds here after the value tag; `None` when no
/// row is readable here (stage 7c-1 tests).
///
/// # Errors
///
/// Storage and filesystem errors.
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn beside_row_json(vault: &Vault, row: EntityId) -> Result<Option<Vec<u8>>> {
    let txn = vault.store.env.read_txn()?;
    let body = beside_body_in_txn(vault, &txn, row)?;
    Ok(body.map(|body| match body.strip_prefix(BESIDE_VALUE_TAG) {
        Some(json) => json.to_vec(),
        None => body,
    }))
}
