//! Retained side-table envelopes carry source table names, original key suffixes and value
//! bytes, with identity hashes and collection, credential, import and erase passes. The owner
//! door installs tables with a landing group and retains the rest; other doors retain only.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek};

use heed::{RoTxn, RwTxn};
use oneiron_contracts::fingerprint::{ContentHash, LegacyDigest, purposes};
use oneiron_records::batch::export::archive_side_tables::byte_values;
use serde::{Deserialize, Serialize};

use super::archive_index::{IndexedArchive, Loc, Tag};
use super::archive_retained_room_ledgers::{
    note_ledger_envelope, retained_row_room, withhold_room_ledger,
};
use super::archive_retained_subjects::{RetainedSubjectRule, retained_subject_rule};
use super::archive_retained_subjects::{hard_deleted, judged_records};
use super::archive_side_dispositions::{omitted_decls, retained_decl, retained_decls};
use super::{
    ArchiveSideFamily, ArchiveSideRow, ImportOmissionReason, RetainedSideImportSummary,
    RetainedSideTableCount, SideRowBytes,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SUMMARY;
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
    /// Whether the exporting vault held this tuple live in its source table, not as an inert
    /// copy. Only such a tuple installs on the owner's restore; an inert copy stays inert, so an
    /// obsolete copy never displaces the source's live value (REVIEW-7771). A stored copy is
    /// inert, so it never carries the flag, and the flag is no part of the row's identity.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub source_live: bool,
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

/// The physical key of one retained row: BLAKE3 over the domain
/// (`purposes::archive::RETAINED_SIDE_ROW_KEY`) and the length-framed logical identity (the
/// source table name bytes, the source key bytes, the 32-byte value hash), each part as a u64
/// little-endian length followed by its bytes. `source_live` is no part of it.
pub(crate) fn retained_side_row_key(row: &ArchiveRetainedSideRow) -> [u8; 32] {
    let value_hash = ContentHash::of(&row.source_value);
    let mut digest = LegacyDigest::new(purposes::archive::RETAINED_SIDE_ROW_KEY);
    for part in [
        row.source_table.as_bytes(),
        row.source_key.as_slice(),
        value_hash.as_bytes().as_slice(),
    ] {
        digest.len_u64_le(part.len()).raw(part);
    }
    digest.finish()
}

/// The inert retained rows, keyed by [`retained_side_row_key`].
pub(super) const RETAINED_SIDE_ROWS: SideTable<[u8; 32], ArchiveRetainedSideRow, Named> =
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

/// Whether the whole-vault export keeps record `id` out, as its record pass does: the egress door
/// keeps it out (off the record, use-limited by a customer hold that refused its privacy erase,
/// or held back here, or its words came from such a row), or it is an epoch summary one of whose
/// transitive sources the door keeps out, or whose epoch does not resolve (FIX 1496 S5).
fn export_keeps_record_out(vault: &crate::Vault, rtxn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    if super::export_egress::whole_vault_export_excludes_entity_in_txn(vault, rtxn, id)? {
        return Ok(true);
    }
    let store = &vault.store;
    let summary_kept_out =
        crate::ports::EntityStoreRead::port_entity_with_raw(store, rtxn, id, |raw| {
            if EntityMetadataHeader::parse(raw)
                .is_none_or(|header| header.entity_type != ENTITY_TYPE_SUMMARY)
            {
                return Ok(false);
            }
            let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
            let admitted = crate::compaction::epoch_sources_admitted_in(
                store,
                rtxn,
                id,
                body,
                |source, _| {
                    Ok(
                        !super::export_egress::whole_vault_export_excludes_entity_in_txn(
                            vault, rtxn, source,
                        )?,
                    )
                },
            )?;
            Ok(admitted == Some(false))
        })?;
    Ok(summary_kept_out == Some(true))
}

/// Whether the whole-vault export withholds a retained row, live or inert. It does when a
/// record the row is about ([`RetainedSubjectRule::records`]) is one the export keeps out
/// ([`export_keeps_record_out`]), so no receipt, setting, grant or history row of a withheld
/// record goes either (REVIEW-9446 P1-1; FIX WHOLE-VAULT-EXPORT-RETAINED-ROWS-OF-WITHHELD-RECORDS),
/// and when its table states no rule or its rule cannot read the row. A ledger row, revision or
/// role grant of a room deleted here, which the archive does not carry as a record
/// ([`super::snapshot_body::row_exported_in_txn`]), stays home with it (round 2 P1-1; Engine
/// ANSWER RETAINED-ROOM-ROWS-WITHHELD Q1 = A). A GPU line period whose cohort seed is still
/// sealed on the store clock stays home until the period ends, as the get view keeps the seed
/// back until then ([`crate::gpu_line::period_row_seals_seed`]; Engine ANSWER
/// LE-ARCHIVE-PERIOD-SEED = A).
fn retained_row_withheld(
    vault: &crate::Vault,
    rtxn: &RoTxn<'_>,
    rule: Option<RetainedSubjectRule>,
    envelope: &ArchiveRetainedSideRow,
    inert: bool,
) -> Result<bool> {
    if envelope.source_table == crate::side_table::GPU_LINE_PERIOD.name
        && crate::gpu_line::period_row_seals_seed(
            &envelope.source_value,
            vault.store.clock.now_recorded_ms(),
        )
    {
        return Ok(true);
    }
    let Some(records) =
        rule.and_then(|rule| rule.records(&envelope.source_key, &envelope.source_value))
    else {
        return Ok(true);
    };
    // An inert copy about a record hard-deleted here stays out, stored before the delete or
    // imported after it; a live row keeps its policy
    // (FIX HARD-DELETE-RETAINED-ARCHIVE-ROW-OUTLIVES-RECORD).
    for id in judged_records(&envelope.source_table, inert, &records) {
        if (inert && hard_deleted(vault, rtxn, id)?) || export_keeps_record_out(vault, rtxn, id)? {
            return Ok(true);
        }
    }
    let Some(room) = retained_row_room(&envelope.source_table, &envelope.source_key) else {
        return Ok(false);
    };
    let exported = super::snapshot_body::row_exported_in_txn(&vault.store, rtxn, &room)?;
    Ok(!exported)
}

/// The source key and value of each retained tuple from `table` this vault's whole-vault export
/// carries, in physical key order: the export's own collection
/// ([`collect_retained_side_rows_in_txn`]), for integration tests.
///
/// # Errors
///
/// The collection's; a carried row that does not read as its envelope.
#[cfg(oneiron_test_support)]
pub(crate) fn exported_retained_tuples(
    vault: &crate::Vault,
    table: &str,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut tuples = Vec::new();
    for row in collect_retained_side_rows_in_txn(vault, &rtxn)? {
        let envelope = RETAINED_SIDE_ROWS.decode_value(&row.value)?;
        if envelope.source_table == table {
            tuples.push((envelope.source_key, envelope.source_value));
        }
    }
    Ok(tuples)
}

/// Every retained row this export carries, in physical key order: the live rows of the
/// retained source tables read raw and marked `source_live`, unioned with the inert envelopes
/// already stored, deduplicated by [`retained_side_row_key`] with the live row kept. A row about
/// a record the export keeps out is withheld ([`retained_row_withheld`]), and so is every live
/// and inert row of a room ledger one of whose live rows is withheld ([`withhold_room_ledger`])
/// or names an entity it keeps out ([`note_ledger_envelope`]); a withheld inert copy goes alone.
/// Collected into memory like the 41-family writer.
pub(crate) fn collect_retained_side_rows_in_txn(
    vault: &crate::Vault,
    rtxn: &RoTxn<'_>,
) -> Result<Vec<SideRowBytes>> {
    let store = &vault.store;
    let mut rows: BTreeMap<[u8; 32], SideRowBytes> = BTreeMap::new();
    let mut ledger_rooms: BTreeMap<[u8; 32], EntityId> = BTreeMap::new();
    let mut withheld_ledgers: BTreeSet<EntityId> = BTreeSet::new();
    for decl in retained_decls() {
        let rule = retained_subject_rule(decl.name);
        for row in decl.iter_raw(store, rtxn)? {
            let (source_key, source_value) = row?;
            let envelope = ArchiveRetainedSideRow {
                source_table: decl.name.to_owned(),
                source_key,
                source_value,
                source_live: true,
            };
            if retained_row_withheld(vault, rtxn, rule, &envelope, false)? {
                withhold_room_ledger(&envelope, &mut withheld_ledgers);
                continue;
            }
            let key = retained_side_row_key(&envelope);
            if !note_ledger_envelope(
                vault,
                rtxn,
                &envelope,
                key,
                &mut ledger_rooms,
                &mut withheld_ledgers,
            )? {
                continue;
            }
            let value = RETAINED_SIDE_ROWS.encode_value(&envelope)?;
            rows.entry(key).or_insert(SideRowBytes {
                family: ArchiveSideFamily::RetainedSideRow,
                key: key.to_vec(),
                value,
                owner: None,
                carriers: Vec::new(),
                names: Vec::new(),
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
        let rule = retained_subject_rule(&envelope.source_table);
        if retained_row_withheld(vault, rtxn, rule, &envelope, true)? {
            withhold_room_ledger(&envelope, &mut withheld_ledgers);
            continue;
        }
        let identity = retained_side_row_key(&envelope);
        if !note_ledger_envelope(
            vault,
            rtxn,
            &envelope,
            identity,
            &mut ledger_rooms,
            &mut withheld_ledgers,
        )? {
            continue;
        }
        rows.entry(identity).or_insert(SideRowBytes {
            family: ArchiveSideFamily::RetainedSideRow,
            key,
            value,
            owner: None,
            carriers: Vec::new(),
            names: Vec::new(),
        });
    }
    rows.retain(|identity, _| {
        ledger_rooms
            .get(identity)
            .is_none_or(|room| !withheld_ledgers.contains(room))
    });
    Ok(rows.into_values().collect())
}

/// The records the collected retained row `row` is about, as its table's rule names them
/// ([`RetainedSubjectRule::records`]); `None` when the row does not read as its envelope or its
/// rule cannot name them. An Owner's copy judges each by the members' mailbox rule (fix list
/// row 15416), as [`retained_row_withheld`] judges each by the egress door.
pub(crate) fn retained_side_row_records(row: &SideRowBytes) -> Option<Vec<EntityId>> {
    let envelope = RETAINED_SIDE_ROWS.decode_value(&row.value).ok()?;
    retained_subject_rule(&envelope.source_table)?
        .records(&envelope.source_key, &envelope.source_value)
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
        Mp::Array(items) => match byte_values(items) {
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

/// Visits retained envelopes in archive order, checking their codec and identity once per pass.
pub(crate) fn visit_retained_side_rows<R: Read + Seek>(
    archive: &IndexedArchive<'_, R>,
    mut visit: impl FnMut([u8; 32], ArchiveRetainedSideRow) -> Result<()>,
) -> Result<()> {
    let mut files = |file: &ExportBodyFile| file.read(&archive.files);
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
        visit(typed, envelope)?;
        after = Some(key);
    }
    Ok(())
}

/// Lands, on the owner's restore, each archived standing grant the source held live, before the
/// import puts in any row or link (Engine ANSWER CLAIM-NOTE-SAME-AS-RESTORE-PROOF = A): a
/// `same_as` between two CLAIMs comes back only under a live nightly-link grant, read before its
/// status claim and its link go in (`document_import::claim_pair_same_as`). The consent group's
/// own checks run (`consent::archive_restore`), so only a row whose stamp actor is already a live
/// PERSON here lands now; every other row waits for [`install_or_retain_side_rows_in_txn`],
/// after the imported persons, as before. Returns the keys of the rows installed here, which that
/// later pass counts as installed without landing them again. Other doors land nothing here.
pub(crate) fn land_standing_grants_first_in_txn<R: Read + Seek>(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    archive: &IndexedArchive<'_, R>,
    permit: Option<&super::OwnerArchiveRestorePermit>,
    projects: Option<&super::ProjectRootMap>,
    refresh: &mut super::archive_side_install::ArchivedSideRowRefresh,
) -> Result<BTreeSet<[u8; 32]>> {
    use super::archive_side_install::{
        ArchivedSideGroup, ArchivedSideRowOutcome, land_archived_side_group_in_txn,
    };

    let mut landed = BTreeSet::new();
    let Some(permit) = permit else {
        return Ok(landed);
    };
    let mut staged = Vec::new();
    visit_retained_side_rows(archive, |typed, envelope| {
        if envelope.source_live
            && envelope.source_table == crate::side_table::CONSENT_STANDING_GRANT.name
        {
            staged.push((typed, envelope));
        }
        Ok(())
    })?;
    if staged.is_empty() {
        return Ok(landed);
    }
    let (keys, rows): (Vec<_>, Vec<_>) = staged.into_iter().unzip();
    let outcomes = land_archived_side_group_in_txn(
        ArchivedSideGroup::Consent,
        vault,
        wtxn,
        permit,
        projects,
        &rows,
        refresh,
    )?;
    if outcomes.len() != rows.len() {
        return Err(Error::InvariantViolation(
            "an archive landing group must return one outcome per envelope",
        ));
    }
    for (key, outcome) in keys.into_iter().zip(outcomes) {
        if matches!(outcome, ArchivedSideRowOutcome::Installed) {
            RETAINED_SIDE_ROWS.delete(vault, wtxn, &key)?;
            landed.insert(key);
        }
    }
    Ok(landed)
}

/// Installs the owner's supported source tables and otherwise keeps envelopes inert in the
/// import transaction; actor and actorless doors retain only, with the original inert counts.
/// A row [`land_standing_grants_first_in_txn`] installed, named in `landed_first`, counts as
/// installed and lands no second time. `projects` is the import's map of the source root onto
/// this vault's root, which a landing group reads a row's place through.
/// On the owner door, each source-live HOOKS_GRANT tuple kept as a retained row is recorded
/// under `restore_receipt_hex` (32 hex) for the restore group's accept to install.
pub(crate) fn install_or_retain_side_rows_in_txn<R: Read + Seek>(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    archive: &IndexedArchive<'_, R>,
    permit: Option<&super::OwnerArchiveRestorePermit>,
    projects: Option<&super::ProjectRootMap>,
    restore_receipt_hex: Option<&str>,
    landed_first: &BTreeSet<[u8; 32]>,
    refresh: &mut super::archive_side_install::ArchivedSideRowRefresh,
) -> Result<RetainedSideImportSummary> {
    use super::archive_side_install::{
        ArchivedSideGroup, ArchivedSideRowOutcome, archived_side_group,
        land_archived_side_group_in_txn,
    };

    let mut tables: BTreeMap<String, RetainedSideTableCount> = BTreeMap::new();
    let mut groups: BTreeMap<ArchivedSideGroup, Vec<([u8; 32], ArchiveRetainedSideRow)>> =
        BTreeMap::new();
    visit_retained_side_rows(archive, |typed, envelope| {
        let count = tables
            .entry(envelope.source_table.clone())
            .or_insert_with(|| RetainedSideTableCount {
                source_table: envelope.source_table.clone(),
                ..Default::default()
            });
        if landed_first.contains(&typed) {
            count.installed_rows += 1;
            return Ok(());
        }
        // Only a tuple the source held live installs; an inert copy stays inert (REVIEW-7771).
        let group = permit
            .filter(|_| envelope.source_live)
            .and_then(|_| archived_side_group(&envelope.source_table));
        if let Some(group) = group {
            groups.entry(group).or_default().push((typed, envelope));
        } else {
            retain_envelope_in_txn(vault, wtxn, &typed, &envelope, count)?;
            // The owner's accept of this restore's inbox group lands the archived owner
            // grant the tuple carries (OPUS-MAP-5B2): record its retained key now. Only
            // this table, only a stored tuple, only on the owner door.
            if envelope.source_live
                && envelope.source_table == crate::side_table::HOOKS_GRANT.name
                && permit.is_some()
                && let Some(receipt_hex) = restore_receipt_hex
            {
                super::record_deferred_hook_grant_in_txn(vault, wtxn, receipt_hex, typed)?;
            }
        }
        Ok(())
    })?;
    if let Some(permit) = permit {
        // The enum declaration order is the fixed owning-group dependency order.
        for (group, staged) in groups {
            let (keys, rows): (Vec<_>, Vec<_>) = staged.into_iter().unzip();
            let outcomes = land_archived_side_group_in_txn(
                group, vault, wtxn, permit, projects, &rows, refresh,
            )?;
            if outcomes.len() != rows.len() {
                return Err(Error::InvariantViolation(
                    "an archive landing group must return one outcome per envelope",
                ));
            }
            for ((key, envelope), outcome) in keys.iter().zip(&rows).zip(outcomes) {
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
                        retain_envelope_in_txn(vault, wtxn, key, envelope, count)?;
                        count.kept_live_rows += 1;
                    }
                    ArchivedSideRowOutcome::HeldBack(reason) => {
                        retain_envelope_in_txn(vault, wtxn, key, envelope, count)?;
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

/// One stored retained row by its 32-byte physical key, for the deferred hook-grant landing
/// the restore group's accept runs.
pub(crate) fn retained_side_row_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 32],
) -> Result<Option<ArchiveRetainedSideRow>> {
    RETAINED_SIDE_ROWS.get(vault, txn, key)
}

/// Deletes one stored retained row by its 32-byte physical key: the deferred hook-grant
/// landing drops the retained copy of a row it installs, as the import does.
pub(crate) fn delete_retained_side_row_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
) -> Result<()> {
    RETAINED_SIDE_ROWS.delete(vault, txn, key)?;
    Ok(())
}

/// Keeps one envelope as an inert copy (no `source_live`) with SIDE-1's physical collision rules
/// and inert-copy counters.
fn retain_envelope_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    key: &[u8; 32],
    envelope: &ArchiveRetainedSideRow,
    count: &mut RetainedSideTableCount,
) -> Result<()> {
    let inert = ArchiveRetainedSideRow {
        source_live: false,
        ..envelope.clone()
    };
    let value = RETAINED_SIDE_ROWS.encode_value(&inert)?;
    match RETAINED_SIDE_ROWS.get_bytes(vault, wtxn, key)? {
        Some(stored) if stored == value => count.unchanged_rows += 1,
        Some(_) => {
            return Err(invalid(
                "retained side row collides with a different stored row",
            ));
        }
        None => {
            RETAINED_SIDE_ROWS.put(vault, wtxn, key, &inert)?;
            count.inserted_rows += 1;
        }
    }
    Ok(())
}

/// Keeps an inert copy of a `source_table` row with key `source_key` and value `source_value`
/// under its envelope identity, as an import keeps an archived copy, unchecked against the
/// table: a test plants a malformed copy an archive could carry (REVIEW-9739 P1-2). Not API.
#[cfg(oneiron_test_support)]
pub(crate) fn retain_inert_copy_for_test(
    vault: &crate::Vault,
    source_table: &str,
    source_key: Vec<u8>,
    source_value: Vec<u8>,
) -> Result<()> {
    let envelope = ArchiveRetainedSideRow {
        source_table: source_table.to_owned(),
        source_key,
        source_value,
        source_live: false,
    };
    let key = retained_side_row_key(&envelope);
    let mut txn = vault.store.env.write_txn()?;
    RETAINED_SIDE_ROWS.put(vault, &mut txn, &key, &envelope)?;
    txn.commit()?;
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
/// or its lowercase hex text, and each Gate decision copy that names the actor when read as the
/// ledger reads its rows, sealed ones included (REVIEW-7706). Rows of source tables without an
/// actor scrub stay, as does a sealed Gate decision copy no one here can read (its key retired or
/// never held).
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
        }) || (envelope.source_table
            == crate::side_table::GATE_DECISION_LEDGER.name
            && vault.store.gate_decision_copy_names_actor(
                &envelope.source_key,
                &envelope.source_value,
                actor,
            ) == Some(true));
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
