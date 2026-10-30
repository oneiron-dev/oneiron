//! What a folder's note-import MACHINE's stored record says: the importer
//! its body names, the trust its notes carry, and whether its birth names
//! that importer as its maker.

use super::{IMPORT_DOOR, IMPORT_MACHINE_NAME};
use crate::claim::ClaimSource;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::{EntityId, Vault};

/// The owner `author` imports for, when it is a folder's note-import
/// MACHINE: the reader its notes are written for. `None` for every other
/// author.
///
/// # Errors
/// A storage error.
pub(crate) fn note_importer_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    author: &EntityId,
) -> Result<Option<EntityId>> {
    Ok(import_machine_field(store, txn, author, "importer")?
        .and_then(|hex| EntityId::from_hex(&hex).ok()))
}

/// The member a folder's note-import MACHINE `author` writes for in a
/// shared vault: the importer its body names, when its birth names that same
/// importer as the actor who made it through the import door. `None` for
/// every other author, and for a folder MACHINE whose stored maker is not its
/// named importer.
///
/// # Errors
/// A storage error, or a stored birth that does not decode.
pub(crate) fn folder_import_creator_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    author: &EntityId,
) -> Result<Option<EntityId>> {
    let Some(importer) = note_importer_in_txn(store, txn, author)? else {
        return Ok(None);
    };
    let made =
        crate::provenance::birth::row_birth_in_txn(store, txn, author)?.is_some_and(|birth| {
            birth.made_by.process.actor == importer && birth.made_by.process.identity == IMPORT_DOOR
        });
    Ok(made.then_some(importer))
}

/// The claim source the words of a note `author` wrote carry as evidence,
/// when it is a folder's note-import MACHINE: the trust its source's
/// registry row gave it, `Imported` for every folder source (G2). `None` for
/// every other author, whose notes are their own words.
///
/// # Errors
/// A storage error.
pub(crate) fn imported_note_source_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    author: &EntityId,
) -> Result<Option<ClaimSource>> {
    Ok(import_machine_field(store, txn, author, "trust")?
        .and_then(|trust| ClaimSource::parse(&trust)))
}

/// The string `name` holds in `author`'s body, when `author` is a folder's
/// note-import MACHINE: the one its folder derives, never another MACHINE
/// that copies its fields.
fn import_machine_field(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    author: &EntityId,
    name: &str,
) -> Result<Option<String>> {
    use crate::ports::EntityStoreRead;
    let Some(record) = store.port_entity_record(txn, author)? else {
        return Ok(None);
    };
    if record.entity_type != ENTITY_TYPE_MACHINE {
        return Ok(None);
    }
    let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut record.body.as_slice()) else {
        return Ok(None);
    };
    let field = |wanted: &str| {
        fields
            .iter()
            .find(|(key, _)| key.as_str() == Some(wanted))
            .and_then(|(_, value)| value.as_str())
    };
    if field("name") != Some(IMPORT_MACHINE_NAME) {
        return Ok(None);
    }
    // Only the id the folder derives is that folder's importer.
    let Some(folder) = field("folder") else {
        return Ok(None);
    };
    if Vault::imported_note_author(folder)? != *author {
        return Ok(None);
    }
    Ok(field(name).map(str::to_owned))
}
