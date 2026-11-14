//! Test doors for a restored source-audience binding whose live policy is absent.

use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CONVERSATION;
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
    let at = vault.now_recorded_at();
    let body = conversation_body(&row)?;
    vault.with_write_txn(|txn| {
        let policy = source_audience::create_source_policy_in_txn(
            vault,
            txn,
            [reader].into_iter().collect(),
            false,
            reader,
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
        source_audience::bind_record_in_txn(vault, txn, &row, &policy)?;
        Ok((row, policy))
    })
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
