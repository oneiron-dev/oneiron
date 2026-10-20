//! Reading a declared table's rows with its own codec, and splitting the
//! actors a row names out of an owner's content.

use heed::RoTxn;

use super::super::corrupt;
use super::{ActorPart, Captured, OwnerRef, RowDb, RowLocator, RowPart, Unresolved, frame};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::side_table::{SideCodec, SideKey, SideTable, SideTableDbs};

/// One row of a declared table, read with the table's own codec.
pub(crate) struct TypedRow<K, V> {
    pub(crate) at: RowLocator,
    pub(crate) key: K,
    pub(crate) value: V,
    /// The value's stored bytes.
    pub(crate) bytes: Vec<u8>,
}

/// Every row of `table` in key order, each read with its own codec. A row
/// whose key or value does not read is recorded unclassified in `out`.
pub(crate) fn typed_rows<K: SideKey, V, C: SideCodec<V>>(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    table: SideTable<K, V, C>,
    out: &mut Captured,
) -> Result<Vec<TypedRow<K, V>>> {
    let decl = table.decl();
    let mut rows = Vec::new();
    for row in table.iter_raw_from(dbs, txn, &[])? {
        let (key, bytes) = row?;
        let mut full = decl.prefix.to_vec();
        full.extend_from_slice(&key);
        let at = RowLocator::row(RowDb::of(decl), full);
        match (K::decode_key(&key), table.decode_value(&bytes)) {
            (Some(key), Ok(value)) => rows.push(TypedRow {
                at,
                key,
                value,
                bytes,
            }),
            _ => out.unclassified(at, None, Unresolved::Undecodable),
        }
    }
    Ok(rows)
}

/// Refuses `value` at `at` unless it is a row of `table` its own codec
/// reads.
pub(crate) fn check_row<K: SideKey, V, C: SideCodec<V>>(
    table: SideTable<K, V, C>,
    at: &RowLocator,
    value: &[u8],
) -> Result<()> {
    let decl = table.decl();
    if at.db != RowDb::of(decl) {
        return Err(corrupt());
    }
    let key = at.key.strip_prefix(decl.prefix).ok_or_else(corrupt)?;
    K::decode_key(key).ok_or_else(corrupt)?;
    table.decode_value(value)?;
    Ok(())
}

/// Whether `table`'s codec spells `row`'s value back to its stored bytes, so
/// a split of the row and the join after it are lossless.
pub(crate) fn spells_back<K: SideKey, V, C: SideCodec<V>>(
    table: SideTable<K, V, C>,
    row: &TypedRow<K, V>,
) -> bool {
    table
        .encode_value(&row.value)
        .is_ok_and(|bytes| bytes == row.bytes)
}

/// Splits `row`'s actors out into `owner`'s rows: `take` moves each actor
/// out of the decoded value, leaving the family's no-one form, and names its
/// field. The content keeps that no-one form and each actor becomes an actor
/// part naming it; a row naming no one stays exact, and one its codec does
/// not spell back is unclassified.
pub(crate) fn split_actors<K: SideKey, V, C: SideCodec<V>>(
    out: &mut Captured,
    owner: OwnerRef,
    table: SideTable<K, V, C>,
    row: TypedRow<K, V>,
    take: impl FnOnce(&mut V) -> Vec<(String, EntityId)>,
) -> Result<()> {
    if !spells_back(table, &row) {
        out.unclassified(
            row.at,
            Some(owner),
            Unresolved::ActorSplit(NOT_SPELLED_BACK),
        );
        return Ok(());
    }
    let TypedRow {
        at,
        mut value,
        bytes,
        ..
    } = row;
    let actors = take(&mut value);
    if actors.is_empty() {
        out.exact(owner, at, bytes);
        return Ok(());
    }
    let content = table.encode_value(&value)?;
    let rows = out.owner(owner);
    for (field, actor) in actors {
        rows.actor_parts.push(ActorPart {
            actor_entity: actor,
            content_locator: at.clone(),
            field,
            bytes: actor.as_bytes().to_vec(),
        });
    }
    rows.rows.push(RowPart::NoActor { at, value: content });
    Ok(())
}

/// The carrier a split refuses: a row its codec would not write back
/// byte for byte.
pub(crate) const NOT_SPELLED_BACK: &str = "a row its codec does not spell back";

/// How a family's own split and join must give a row back (FIX 6072,
/// Engine R1): one value per family, beside its adapter. The helpers above
/// stay byte for byte; only a family that names this policy uses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RoundTripPolicy {
    /// The joined row is the stored bytes.
    ByteExact,
    /// The joined row may be another Loro encoding of the stored history:
    /// the same operations, ids, dependencies, timestamps, Lamport values
    /// and messages, which the family's proof compares as typed history,
    /// never as rendered text.
    HistoryEquivalent,
}

/// Admits a family's split once its all-open join gave `joined` for the
/// stored `original`: `ByteExact` wants the same bytes, and
/// `HistoryEquivalent` always runs `prove_history`, even when the bytes
/// match. A proof that fails refuses the split; nothing falls back to
/// comparing text.
pub(crate) fn admit_round_trip(
    policy: RoundTripPolicy,
    original: &[u8],
    joined: &[u8],
    prove_history: impl FnOnce(&[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    match policy {
        RoundTripPolicy::ByteExact if original == joined => Ok(()),
        RoundTripPolicy::ByteExact => Err(corrupt()),
        RoundTripPolicy::HistoryEquivalent => prove_history(original, joined),
    }
}

/// A no-one-form row with its opened actor parts put back by `put` (the
/// part's field and actor): the decoded value, for the getter's own rule on
/// what stays.
pub(crate) fn join_actors<K: SideKey, V, C: SideCodec<V>>(
    table: SideTable<K, V, C>,
    value: &[u8],
    parts: &[&ActorPart],
    mut put: impl FnMut(&mut V, &str, EntityId) -> Result<()>,
) -> Result<V> {
    let mut decoded = table.decode_value(value)?;
    for part in parts {
        let id: [u8; 16] = part.bytes.as_slice().try_into().map_err(|_| corrupt())?;
        let actor = EntityId::from_bytes(id)?;
        if actor != part.actor_entity {
            return Err(corrupt());
        }
        put(&mut decoded, part.field.as_str(), actor)?;
    }
    Ok(decoded)
}

/// Splits out a row whose key or value names `actor`: `owner`'s content
/// keeps a placeholder naming only `table_key` (the row key's leading bytes
/// before anything naming the actor) and a slot, and the actor part holds the
/// row's key and value.
pub(crate) fn actor_keyed(
    out: &mut Captured,
    owner: OwnerRef,
    actor: EntityId,
    at: &RowLocator,
    table_key: &[u8],
    value: &[u8],
) -> Result<()> {
    let rows = out.owner(owner);
    let slot = RowLocator {
        db: at.db,
        key: table_key.to_vec(),
        path: format!(
            "actor-keyed {} {}",
            bytes_to_hex_lower(&owner.owner32),
            rows.rows.len()
        ),
    };
    rows.actor_parts.push(ActorPart {
        actor_entity: actor,
        content_locator: slot.clone(),
        field: ACTOR_KEYED_ROW.to_owned(),
        bytes: frame::frame_row(&at.key, value)?,
    });
    rows.rows.push(RowPart::ActorKeyed { at: slot });
    Ok(())
}

/// The field an actor-keyed row's actor part fills: the whole row.
pub(crate) const ACTOR_KEYED_ROW: &str = "row";
