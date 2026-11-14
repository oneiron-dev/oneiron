//! SIDE-1 retained side-table rows: the inert envelope that carries one archived source row
//! with its table name and original key suffix and value bytes, the identity hash over them, and
//! the collection, secret, import and erase passes over them.

use std::collections::BTreeMap;
use std::io::{Read, Seek};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::archive_index::{IndexedArchive, Loc, Tag};
use super::archive_side_dispositions::{omitted_decls, retained_decl, retained_decls};
use super::{
    ArchiveSideFamily, ArchiveSideRow, ImportOmissionReason, RetainedSideImportSummary,
    RetainedSideTableCount, SideRowBytes,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::serialize::{ExportBodyFile, null_document_tree_row};
use crate::side_table::{CodecName, Named, SideKey, SideTable};
use crate::store::Store;

/// One archived source-table row kept inert: its table's name with the row's original key suffix
/// and value bytes. No live reader reads these rows; the next archive carries them again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveRetainedSideRow {
    /// The declared source table's name.
    pub source_table: String,
    /// The stored key after the source table's declared prefix.
    #[serde(with = "bytes")]
    pub source_key: Vec<u8>,
    /// The stored value bytes, exactly as the source table holds them.
    #[serde(with = "bytes")]
    pub source_value: Vec<u8>,
}

/// Byte fields as MessagePack bin, so the archive side tree reads them as bytes.
mod bytes {
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(value: &[u8], out: S) -> Result<S::Ok, S::Error> {
        out.serialize_bytes(value)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(input: D) -> Result<Vec<u8>, D::Error> {
        struct Bytes;

        impl serde::de::Visitor<'_> for Bytes {
            type Value = Vec<u8>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bytes")
            }

            fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<Vec<u8>, E> {
                Ok(value.to_vec())
            }

            fn visit_byte_buf<E: serde::de::Error>(self, value: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(value)
            }
        }

        input.deserialize_bytes(Bytes)
    }
}

/// The domain of [`retained_side_row_key`].
const RETAINED_SIDE_ROW_DOMAIN: &[u8] = b"oneiron.archive.retained_side_row.v1";

/// The physical key of one retained row: BLAKE3 over the domain and the length-framed logical
/// identity (the source table name bytes, the source key bytes, the 32-byte value hash), each
/// part as a u64 little-endian length followed by its bytes.
pub(crate) fn retained_side_row_key(row: &ArchiveRetainedSideRow) -> [u8; 32] {
    let value_hash = blake3::hash(&row.source_value);
    let mut hasher = blake3::Hasher::new();
    hasher.update(RETAINED_SIDE_ROW_DOMAIN);
    for part in [
        row.source_table.as_bytes(),
        row.source_key.as_slice(),
        value_hash.as_bytes().as_slice(),
    ] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// The inert retained rows, keyed by [`retained_side_row_key`].
const RETAINED_SIDE_ROWS: SideTable<[u8; 32], ArchiveRetainedSideRow, Named> =
    SideTable::new(&crate::side_table::ARCHIVE_RETAINED_SIDE_ROW);

/// Whether one stored retained row reads back through its table: it decodes as the [`Named`]
/// envelope and re-encodes to its stored bytes. `false` holds the row out as not portable; a row
/// whose source table is no retained table, or whose key is not its envelope identity, is an
/// invalid archive.
pub(crate) fn retained_row_portable(key: &[u8], value: &[u8]) -> Result<bool> {
    if key.len() != 32 {
        return Ok(false);
    }
    let Ok(envelope) = RETAINED_SIDE_ROWS.decode_value(value) else {
        return Ok(false);
    };
    let Ok(encoded) = RETAINED_SIDE_ROWS.encode_value(&envelope) else {
        return Ok(false);
    };
    if encoded != value {
        return Ok(false);
    }
    if retained_decl(&envelope.source_table).is_none() {
        return Err(invalid("retained side row names no retained source table"));
    }
    if key != retained_side_row_key(&envelope).as_slice() {
        return Err(invalid(
            "retained side row key is not its envelope identity",
        ));
    }
    Ok(true)
}

/// The source table one stored retained row names, when it decodes as the envelope.
pub(crate) fn retained_envelope_source_table(value: &[u8]) -> Option<String> {
    RETAINED_SIDE_ROWS
        .decode_value(value)
        .ok()
        .map(|envelope| envelope.source_table)
}

/// Every retained row this export carries, in physical key order: the live rows of the 103
/// retained source tables read raw, unioned with the envelopes already stored, deduplicated by
/// [`retained_side_row_key`]. Collected into memory like the 41-family writer.
pub(crate) fn collect_retained_side_rows_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
) -> Result<Vec<SideRowBytes>> {
    let mut rows: BTreeMap<[u8; 32], SideRowBytes> = BTreeMap::new();
    for decl in retained_decls() {
        for row in decl.iter_raw(store, rtxn)? {
            let (source_key, source_value) = row?;
            let envelope = ArchiveRetainedSideRow {
                source_table: decl.name.to_owned(),
                source_key,
                source_value,
            };
            let key = retained_side_row_key(&envelope);
            let value = RETAINED_SIDE_ROWS.encode_value(&envelope)?;
            rows.entry(key).or_insert(SideRowBytes {
                family: ArchiveSideFamily::RetainedSideRow,
                key: key.to_vec(),
                value,
                owner: None,
                carriers: Vec::new(),
            });
        }
    }
    for row in RETAINED_SIDE_ROWS.iter_raw_from(store, rtxn, &[])? {
        let (key, value) = row?;
        if !retained_row_portable(&key, &value)? {
            return Err(invalid(
                "stored retained side row does not read as its envelope",
            ));
        }
        let envelope = RETAINED_SIDE_ROWS.decode_value(&value)?;
        rows.entry(retained_side_row_key(&envelope))
            .or_insert(SideRowBytes {
                family: ArchiveSideFamily::RetainedSideRow,
                key,
                value,
                owner: None,
                carriers: Vec::new(),
            });
    }
    Ok(rows.into_values().collect())
}

/// The row count of every omitted table, sorted by table name: all 23, zero-row tables included,
/// read raw without decoding.
pub(crate) fn omitted_side_table_counts_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
) -> Result<Vec<(&'static str, ImportOmissionReason, u64)>> {
    let mut counts = Vec::new();
    for (decl, reason) in omitted_decls() {
        let mut rows: u64 = 0;
        for row in decl.iter_raw(store, rtxn)? {
            row?;
            rows += 1;
        }
        counts.push((decl.name, reason, rows));
    }
    counts.sort_by(|left, right| left.0.cmp(right.0));
    Ok(counts)
}

/// Whether one retained row carries a credential in its source key or value: the export holds
/// such a row out of every archive, the owner's secrets-included archive too. The source value is
/// read through its source table's declared codec and judged as the MessagePack families' tree;
/// a `Raw` value, an unknown source table, or bytes that do not decode are opaque and read as
/// bytes. A row that does not decode as the envelope is withheld.
pub(crate) fn retained_side_row_withholds_credential(row: &SideRowBytes) -> bool {
    let Ok(envelope) = RETAINED_SIDE_ROWS.decode_value(&row.value) else {
        return true;
    };
    if key_withholds_credential(&envelope.source_key) {
        return true;
    }
    match retained_decl(&envelope.source_table).map(|decl| decl.codec) {
        Some(CodecName::Named | CodecName::LegacyCompact) => {
            tree_withholds_credential(&envelope.source_value, 0)
        }
        Some(CodecName::VersionedNamed) => tree_withholds_credential(&envelope.source_value, 1),
        Some(CodecName::LegacyJson) => match serde_json::from_slice(&envelope.source_value) {
            Ok(value) => json_withholds_credential(&value),
            Err(_) => opaque_withholds_credential(&envelope.source_value),
        },
        Some(CodecName::Raw) | None => opaque_withholds_credential(&envelope.source_value),
    }
}

/// Whether one source key carries a credential: read as a JSON string when it is UTF-8, else as
/// bytes.
fn key_withholds_credential(key: &[u8]) -> bool {
    match std::str::from_utf8(key) {
        Ok(text) => {
            let json = serde_json::Value::String(text.to_owned());
            json_withholds_credential(&json)
        }
        Err(_) => opaque_withholds_credential(key),
    }
}

/// Whether one decoded MessagePack value carries a credential: the value as the archive tree
/// reads it, with every attached file's bytes read as bytes.
fn tree_withholds_credential(value: &[u8], version_bytes: usize) -> bool {
    let Some(body) = value.get(version_bytes..) else {
        return opaque_withholds_credential(value);
    };
    let mut cursor = std::io::Cursor::new(body);
    let Ok(decoded) = rmpv::decode::read_value(&mut cursor) else {
        return opaque_withholds_credential(value);
    };
    if cursor.position() != body.len() as u64 {
        return opaque_withholds_credential(value);
    }
    let mut files = Vec::new();
    let Some(tree) = super::archive_side_tables::tree(&decoded, &mut files) else {
        return opaque_withholds_credential(value);
    };
    let Ok(json) = serde_json::to_value(&tree) else {
        return opaque_withholds_credential(value);
    };
    if json_withholds_credential(&json) {
        return true;
    }
    files.iter().any(|bytes| opaque_withholds_credential(bytes))
}

/// Whether one JSON value reads as a credential under the document pass.
fn json_withholds_credential(value: &serde_json::Value) -> bool {
    null_document_tree_row(value) != *value
}

/// Whether opaque bytes read as a credential, as an `Opaque` side value does.
fn opaque_withholds_credential(bytes: &[u8]) -> bool {
    crate::batch::secret_scan::scan_file_content("", bytes).is_some()
}

/// The retained-family rows of one archive, kept inert in the retained table in the import's
/// write transaction: a row already stored equal is unchanged, an absent row is put, and a row
/// colliding with different stored bytes is an invalid archive. Writes only the retained table:
/// no source table, no effect, no live-row check.
pub(crate) fn retain_side_rows_in_txn<R: Read + Seek>(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    archive: &IndexedArchive<'_, R>,
) -> Result<RetainedSideImportSummary> {
    let mut files = |file: &ExportBodyFile| file.read(&archive.files);
    let mut inserted_rows = 0usize;
    let mut unchanged_rows = 0usize;
    let mut tables: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut after: Option<Vec<u8>> = None;
    while let Some((key, value)) = archive.index.next(Tag::Side, &[], after.as_deref())? {
        let row = archive
            .spool
            .parse::<ArchiveSideRow>(Loc::decode(&value)?)?
            .stored(&mut files)?;
        if row.family != ArchiveSideFamily::RetainedSideRow {
            after = Some(key);
            continue;
        }
        let envelope = RETAINED_SIDE_ROWS
            .decode_value(&row.value)
            .map_err(|_| invalid("retained side row does not decode as its envelope"))?;
        let expected = retained_side_row_key(&envelope);
        let typed = <[u8; 32] as SideKey>::decode_key(&row.key)
            .ok_or_else(|| invalid("retained side row key"))?;
        if typed != expected {
            return Err(invalid(
                "retained side row key is not its envelope identity",
            ));
        }
        match RETAINED_SIDE_ROWS.get_bytes(store, wtxn, &typed)? {
            Some(stored) if stored == row.value => {
                unchanged_rows += 1;
                tables.entry(envelope.source_table.clone()).or_default().1 += 1;
            }
            Some(_) => {
                return Err(invalid(
                    "retained side row collides with a different stored row",
                ));
            }
            None => {
                RETAINED_SIDE_ROWS.put(store, wtxn, &typed, &envelope)?;
                inserted_rows += 1;
                tables.entry(envelope.source_table.clone()).or_default().0 += 1;
            }
        }
        after = Some(key);
    }
    Ok(RetainedSideImportSummary {
        inserted_rows,
        unchanged_rows,
        tables: tables
            .into_iter()
            .map(
                |(source_table, (inserted_rows, unchanged_rows))| RetainedSideTableCount {
                    source_table,
                    inserted_rows,
                    unchanged_rows,
                },
            )
            .collect(),
        omissions: archive.manifest.side_table_omissions.clone(),
    })
}

/// An actor's erase over the retained rows: deletes each retained copy whose source table's
/// declaration names an actor scrub and whose source key or value holds the actor's 16 id bytes
/// or its lowercase hex text. Rows of source tables without an actor scrub stay, as does a sealed
/// copy the byte-or-hex match cannot see.
pub(crate) fn erase_retained_side_row_actor_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let hex = actor.to_hex();
    let mut erase: Vec<[u8; 32]> = Vec::new();
    for row in RETAINED_SIDE_ROWS.iter_raw_from(vault, wtxn, &[])? {
        let (key, value) = row?;
        let (Some(typed), Ok(envelope)) = (
            <[u8; 32] as SideKey>::decode_key(&key),
            RETAINED_SIDE_ROWS.decode_value(&value),
        ) else {
            continue;
        };
        let names_actor = retained_decl(&envelope.source_table).is_some_and(|decl| {
            decl.actor.is_some()
                && (contains_bytes(&envelope.source_key, actor.as_bytes())
                    || contains_bytes(&envelope.source_key, hex.as_bytes())
                    || contains_bytes(&envelope.source_value, actor.as_bytes())
                    || contains_bytes(&envelope.source_value, hex.as_bytes()))
        });
        if names_actor {
            erase.push(typed);
        }
    }
    for key in &erase {
        RETAINED_SIDE_ROWS.delete(vault, wtxn, key)?;
    }
    Ok(())
}

/// Whether `haystack` holds `needle`.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("whole-vault side row: {reason}"))
}
