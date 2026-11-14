//! Retained side-table envelopes carry source table names, original key suffixes and value
//! bytes, with identity hashes and collection, credential, import and erase passes. The owner
//! door installs tables with a landing group and retains the rest; other doors retain only.

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
/// reads it, and every binary, extension or byte-array payload read as bytes.
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
    json_withholds_credential(&json) || payload_withholds_credential(&decoded)
}

/// Whether a binary, extension or byte-array payload anywhere in `value` reads as a credential.
/// The archive tree writes such a payload as hex, inline when it is short, which the document
/// pass cannot read (REVIEW-7706), so each is scanned here as bytes, the attached ones too.
fn payload_withholds_credential(value: &rmpv::Value) -> bool {
    use rmpv::Value as Mp;
    match value {
        Mp::Binary(bytes) | Mp::Ext(_, bytes) => opaque_withholds_credential(bytes),
        Mp::Array(items) => match super::archive_side_tables::byte_values(items) {
            Some(bytes) => opaque_withholds_credential(&bytes),
            None => items.iter().any(payload_withholds_credential),
        },
        Mp::Map(entries) => entries.iter().any(|(key, value)| {
            payload_withholds_credential(key) || payload_withholds_credential(value)
        }),
        _ => false,
    }
}

/// Whether one JSON value reads as a credential under the document pass.
fn json_withholds_credential(value: &serde_json::Value) -> bool {
    null_document_tree_row(value) != *value
}

/// Whether opaque bytes read as a credential, as an `Opaque` side value does.
fn opaque_withholds_credential(bytes: &[u8]) -> bool {
    crate::batch::secret_scan::scan_file_content("", bytes).is_some()
}

/// Installs the owner's supported source tables and otherwise keeps envelopes inert in the
/// import transaction; actor and actorless doors retain only, with the original inert counts.
pub(crate) fn install_or_retain_side_rows_in_txn<R: Read + Seek>(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    archive: &IndexedArchive<'_, R>,
    permit: Option<&super::OwnerArchiveRestorePermit>,
    refresh: &mut super::archive_side_install::ArchivedSideRowRefresh,
) -> Result<RetainedSideImportSummary> {
    use super::archive_side_install::{
        ArchivedSideGroup, ArchivedSideRowOutcome, archived_side_group,
        land_archived_side_group_in_txn,
    };

    let mut files = |file: &ExportBodyFile| file.read(&archive.files);
    let mut tables: BTreeMap<String, RetainedSideTableCount> = BTreeMap::new();
    let mut groups: BTreeMap<ArchivedSideGroup, Vec<([u8; 32], Vec<u8>, ArchiveRetainedSideRow)>> =
        BTreeMap::new();
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
        let count = tables
            .entry(envelope.source_table.clone())
            .or_insert_with(|| RetainedSideTableCount {
                source_table: envelope.source_table.clone(),
                ..Default::default()
            });
        if let Some(group) = permit.and_then(|_| archived_side_group(&envelope.source_table)) {
            groups
                .entry(group)
                .or_default()
                .push((typed, row.value, envelope));
        } else {
            retain_envelope_in_txn(vault, wtxn, &typed, &row.value, &envelope, count)?;
        }
        after = Some(key);
    }
    if let Some(permit) = permit {
        // The enum declaration order is the fixed owning-group dependency order.
        for (group, staged) in groups {
            let (identities, rows): (Vec<_>, Vec<_>) = staged
                .into_iter()
                .map(|(key, value, row)| ((key, value), row))
                .unzip();
            let outcomes =
                land_archived_side_group_in_txn(group, vault, wtxn, permit, &rows, refresh)?;
            if outcomes.len() != rows.len() {
                return Err(Error::InvariantViolation(
                    "an archive landing group must return one outcome per envelope",
                ));
            }
            for (((key, value), envelope), outcome) in identities.iter().zip(&rows).zip(outcomes) {
                let count =
                    tables
                        .get_mut(&envelope.source_table)
                        .ok_or(Error::InvariantViolation(
                            "a staged archive envelope must have its table count",
                        ))?;
                match outcome {
                    ArchivedSideRowOutcome::Installed => {
                        RETAINED_SIDE_ROWS.delete(vault, wtxn, key)?;
                        count.installed_rows += 1;
                    }
                    ArchivedSideRowOutcome::Unchanged => {
                        RETAINED_SIDE_ROWS.delete(vault, wtxn, key)?;
                        count.unchanged_live_rows += 1;
                    }
                    ArchivedSideRowOutcome::KeptLive => {
                        retain_envelope_in_txn(vault, wtxn, key, value, envelope, count)?;
                        count.kept_live_rows += 1;
                    }
                    ArchivedSideRowOutcome::HeldBack(reason) => {
                        retain_envelope_in_txn(vault, wtxn, key, value, envelope, count)?;
                        add_held_back_count(&mut count.held_back, reason, 1);
                    }
                }
            }
        }
    }
    let mut summary = RetainedSideImportSummary {
        tables: tables.into_values().collect(),
        omissions: archive.manifest.side_table_omissions.clone(),
        ..Default::default()
    };
    for count in &summary.tables {
        summary.inserted_rows += count.inserted_rows;
        summary.unchanged_rows += count.unchanged_rows;
        summary.installed_rows += count.installed_rows;
        summary.unchanged_live_rows += count.unchanged_live_rows;
        summary.kept_live_rows += count.kept_live_rows;
        for held in &count.held_back {
            add_held_back_count(&mut summary.held_back, held.reason, held.rows);
        }
    }
    Ok(summary)
}

/// Keeps one envelope with SIDE-1's physical collision rules and inert-copy counters.
fn retain_envelope_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    key: &[u8; 32],
    value: &[u8],
    envelope: &ArchiveRetainedSideRow,
    count: &mut RetainedSideTableCount,
) -> Result<()> {
    match RETAINED_SIDE_ROWS.get_bytes(vault, wtxn, key)? {
        Some(stored) if stored == value => count.unchanged_rows += 1,
        Some(_) => {
            return Err(invalid(
                "retained side row collides with a different stored row",
            ));
        }
        None => {
            RETAINED_SIDE_ROWS.put(vault, wtxn, key, envelope)?;
            count.inserted_rows += 1;
        }
    }
    Ok(())
}

/// Adds a reason count while preserving enum order without a second stored total.
fn add_held_back_count(
    counts: &mut Vec<super::RetainedSideHeldBackCount>,
    reason: super::RetainedSideHeldBackReason,
    rows: usize,
) {
    match counts.binary_search_by_key(&reason, |count| count.reason) {
        Ok(index) => counts[index].rows += rows,
        Err(index) => counts.insert(index, super::RetainedSideHeldBackCount { reason, rows }),
    }
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
