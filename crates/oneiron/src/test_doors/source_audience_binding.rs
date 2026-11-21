//! Test doors for a restored source-audience binding whose live policy is absent,
//! and for a witnessed TURN bound to a source policy after it landed.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use crate::source_audience::{self, ReplicationScope, SourceAudienceBirth};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

/// Writes a mail-style CONVERSATION under a new source policy read by `reader`.
/// Uses the landing's `SourceAudienceBirth` stamp, `put_source_bound`, and
/// `bind_record_in_txn` in one write, so the stored bytes carry the obligation.
/// Returns the row id and its policy id.
///
/// # Errors
///
/// Storage, encoding, or source-audience admission failures.
pub fn bound_row(vault: &Vault, reader: EntityId) -> Result<(EntityId, EntityId)> {
    let row = EntityId::now();
    let policy = bound_row_read_by(vault, row, &[reader])?;
    Ok((row, policy))
}

/// [`bound_row`] with the id `row`, under a new source policy read by each
/// of `readers`; the first one makes it. Returns the policy id.
///
/// # Errors
///
/// No reader, or storage, encoding, or source-audience admission failures.
pub fn bound_row_read_by(vault: &Vault, row: EntityId, readers: &[EntityId]) -> Result<EntityId> {
    vault.with_write_txn(|txn| {
        let policy = put_unbound_row_in_txn(vault, txn, row, readers)?;
        source_audience::bind_record_in_txn(vault, txn, &row, &policy)?;
        Ok(policy)
    })
}

/// [`bound_row_read_by`] without its binding: the row lands stamped with
/// its source's birth, as a mail landing writes it before the binding lands
/// in a later write ([`bind_row`]). Returns the policy id.
///
/// # Errors
///
/// No reader, or storage, encoding, or source-audience admission failures.
pub fn unbound_row_read_by(vault: &Vault, row: EntityId, readers: &[EntityId]) -> Result<EntityId> {
    vault.with_write_txn(|txn| put_unbound_row_in_txn(vault, txn, row, readers))
}

/// Lands the binding of the stamped row `row` to `policy`
/// (`bind_record_in_txn`), as the binding of an [`unbound_row_read_by`] row
/// lands.
///
/// # Errors
///
/// The binding's refusal, or storage failures.
pub fn bind_row(vault: &Vault, row: EntityId, policy: EntityId) -> Result<()> {
    vault.with_write_txn(|txn| source_audience::bind_record_in_txn(vault, txn, &row, &policy))
}

/// Puts the mail-style CONVERSATION `row` under a new source policy read by
/// each of `readers`, stamped with that source's birth and not bound yet.
fn put_unbound_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: EntityId,
    readers: &[EntityId],
) -> Result<EntityId> {
    let by = *readers
        .first()
        .ok_or_else(|| Error::InvalidConfig("a source policy needs a reader".into()))?;
    let at = vault.now_recorded_at();
    let body = conversation_body(&row)?;
    let policy = source_audience::create_source_policy_in_txn(
        vault,
        txn,
        readers.iter().copied().collect(),
        false,
        by,
        at,
    )?;
    let birth = SourceAudienceBirth::mint_in(vault, txn, &policy)?;
    let stamped = birth.stamp_in_txn(vault, txn, &row, &body)?;
    vault
        .batch_in()
        .put_source_bound(
            &row,
            ENTITY_TYPE_CONVERSATION,
            TimeRange { start: at, end: at },
            at,
            &stamped,
            &birth,
        )
        .apply(txn)?;
    Ok(policy)
}

/// The body of the mail-style CONVERSATION `row`.
fn conversation_body(row: &EntityId) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![
            (
                rmpv::Value::from("import_source"),
                rmpv::Value::from("mail"),
            ),
            (
                rmpv::Value::from("import_conversation"),
                rmpv::Value::from(row.to_hex()),
            ),
            (
                rmpv::Value::from("import_kind"),
                rmpv::Value::from("mail_thread"),
            ),
        ]),
    )
    .map_err(|_| Error::InvalidConfig("encode source-audience conversation fixture".into()))?;
    Ok(body)
}

/// Writes a mail-style CONVERSATION learned at `learned_at`, bound to the
/// thread policy of a new source policy that `reader` reads. It binds the
/// row as a mail landing does: the birth is minted from the source, and the
/// binding is on the thread (fix list row 17211). Returns the row, the
/// source policy and the thread policy.
///
/// # Errors
///
/// Storage, encoding, or source-audience admission failures.
pub fn thread_bound_row(
    vault: &Vault,
    reader: EntityId,
    learned_at: u64,
) -> Result<(EntityId, EntityId, EntityId)> {
    let row = EntityId::now();
    let at = vault.now_recorded_at();
    let body = conversation_body(&row)?;
    vault.with_write_txn(|txn| {
        let source = source_audience::create_source_policy_in_txn(
            vault,
            txn,
            [reader].into_iter().collect(),
            false,
            reader,
            at,
        )?;
        let thread =
            source_audience::thread_policy_in_txn(vault, txn, &source, &row.to_hex(), reader, at)?;
        let birth = SourceAudienceBirth::mint_in(vault, txn, &source)?;
        let stamped = birth.stamp_in_txn(vault, txn, &row, &body)?;
        vault
            .batch_in()
            .put_source_bound(
                &row,
                ENTITY_TYPE_CONVERSATION,
                TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                &stamped,
                &birth,
            )
            .apply(txn)?;
        source_audience::bind_record_in_txn(vault, txn, &row, &thread)?;
        Ok((row, source, thread))
    })
}

/// Binds the witnessed TURN `turn` to a new source policy read by each of
/// `readers`, the first one making it, as a source landing binds a turn it
/// lands: the turn's own body is re-put stamped with the obligation under
/// the policy's birth proof, then bound, in one write. Its MESSAGEs read
/// under their TURN's floor (read lineage), so the turn's words read only to
/// `readers`. Returns the policy id.
///
/// # Errors
///
/// No reader, a row that is no TURN, or storage, encoding, or
/// source-audience admission failures.
pub fn bind_turn_read_by(vault: &Vault, turn: EntityId, readers: &[EntityId]) -> Result<EntityId> {
    let by = *readers
        .first()
        .ok_or_else(|| Error::InvalidConfig("a source policy needs a reader".into()))?;
    let at = vault.now_recorded_at();
    vault.with_write_txn(|txn| {
        let raw = vault
            .store
            .port_entity_raw(txn, &turn)?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw)
            .filter(|header| header.entity_type == ENTITY_TYPE_TURN)
            .ok_or_else(|| Error::InvalidConfig("the row to bind is no TURN".into()))?;
        let body = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .unwrap_or_default()
            .to_vec();
        let policy = source_audience::create_source_policy_in_txn(
            vault,
            txn,
            readers.iter().copied().collect(),
            false,
            by,
            at,
        )?;
        let birth = SourceAudienceBirth::mint_in(vault, txn, &policy)?;
        let stamped = birth.stamp_in_txn(vault, txn, &turn, &body)?;
        vault
            .batch_in()
            .put_source_bound(
                &turn,
                ENTITY_TYPE_TURN,
                TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
                &stamped,
                &birth,
            )
            .apply(txn)?;
        source_audience::bind_record_in_txn(vault, txn, &turn, &policy)?;
        Ok(policy)
    })
}

/// The keys of `policy`'s revisions that `doc`'s source-audience map
/// carries. It reads the document only, and a document without the map
/// carries none.
#[cfg(feature = "sync")]
pub fn carried_policy_revisions(doc: &loro::LoroDoc, policy: EntityId) -> Vec<String> {
    use crate::sync::source_audiences::SOURCE_AUDIENCES_MAP;

    let holds_map = matches!(
        doc.get_value(),
        loro::LoroValue::Map(roots) if roots.contains_key(SOURCE_AUDIENCES_MAP)
    );
    if !holds_map {
        return Vec::new();
    }
    let prefix = crate::source_audience::carried::policy_prefix(&policy);
    let mut keys = Vec::new();
    doc.get_map(SOURCE_AUDIENCES_MAP).for_each(|map_key, _| {
        if map_key.starts_with(&prefix) {
            keys.push(map_key.to_owned());
        }
    });
    keys
}

/// [`carried_policy_revisions`] of the snapshot the window `window`
/// persisted (`d:w:`); none when it persisted no snapshot.
///
/// # Errors
///
/// Storage failures; a snapshot that does not decode.
#[cfg(feature = "sync")]
pub fn persisted_policy_revisions(
    vault: &Vault,
    window: &str,
    policy: EntityId,
) -> Result<Vec<String>> {
    let Some(snapshot) = vault.sync_state_get(&format!("d:w:{window}"))? else {
        return Ok(Vec::new());
    };
    let doc = crate::store::loro_document::doc_from_snapshot(&snapshot)?;
    Ok(carried_policy_revisions(&doc, policy))
}

/// Deletes only the policy's SOURCE_AUDIENCE_POLICY row through the private
/// binding shim, leaving its events, any thread index, binding, and entity intact.
///
/// # Errors
///
/// Storage failures.
pub fn remove_policy_row(vault: &Vault, policy: EntityId) -> Result<()> {
    source_audience::binding_door::remove_policy_row(vault, policy)
}

/// Whether `viewers` read the stored row through `readable_with_read_in`, the
/// source-audience conjunct used by real scoped reads, including its lineage walk.
///
/// # Errors
///
/// A missing row, or storage and read-walk failures.
pub fn reads(vault: &Vault, row: EntityId, viewers: &[EntityId]) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let dbs = vault.store.read();
    let raw = dbs
        .port_entity_raw(&txn, &row)?
        .ok_or(Error::EntityNotFound)?;
    source_audience::readable_with_read_in(vault, &dbs, &txn, row, &raw, viewers)
}

/// Whether the row passes `withheld_from_replication_in` on
/// `ReplicationScope::FullOwnerWindow`. This reaches `LineagePass`'s replication
/// judge, which computes `travels_under` from the binding and `publishable_in`.
///
/// # Errors
///
/// Storage and replication-walk failures.
pub fn travels(vault: &Vault, row: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(!source_audience::withheld_from_replication_in(
        vault,
        &txn,
        &row,
        ReplicationScope::FullOwnerWindow,
    )?)
}
