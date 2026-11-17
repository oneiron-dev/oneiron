//! The checkpoint-pins door's printed lines: [`pins`] captures, frames and
//! restores each getter and prints one line per owner, section row, restore
//! and target row.

use super::*;

/// One getter's capture as lines: one per owner, then its structure,
/// dispatched and unclassified rows. Answers each owner's framed rows,
/// opened with its actor parts.
pub(super) fn capture_pins(
    name: &'static str,
    captured: &Captured,
    frame: impl Fn(&OwnerRows) -> Result<Vec<u8>>,
    lines: &mut Vec<String>,
) -> Result<Vec<OpenedOwnerRows>> {
    let mut opened = Vec::new();
    for rows in captured.owners() {
        let framed = frame(rows)?;
        lines.push(format!(
            "OWNER {name} subtype={subtype:?} owner={owner} parts={parts:?} \
             deps={deps:?} actors={actors:?} sha256={framed}",
            subtype = rows.subtype,
            owner = bytes_to_hex_lower(&rows.owner32),
            parts = rows.rows,
            deps = rows.dependencies,
            actors = rows.actor_parts,
            framed = sha256_hex(&framed),
        ));
        opened.push(OpenedOwnerRows::open(
            &framed,
            rows.actor_parts.clone(),
            BTreeSet::new(),
        )?);
    }
    for row in &captured.structure {
        lines.push(format!("STRUCTURE {name} {row:?}"));
    }
    for row in &captured.dispatched {
        lines.push(format!("DISPATCHED {name} {row:?}"));
    }
    for row in &captured.unclassified {
        lines.push(format!("UNCLASSIFIED {name} {row:?}"));
    }
    Ok(opened)
}

/// One getter's restore into `target`, one write transaction, as lines: one
/// per owner with what it wrote and what it left out.
pub(super) fn restore_pins(
    name: &'static str,
    target: &Vault,
    opened: Vec<OpenedOwnerRows>,
    restore: impl Fn(&Store, &mut RwTxn<'_>, OpenedOwnerRows) -> Result<Restored>,
    lines: &mut Vec<String>,
) -> Result<()> {
    let mut txn = target.store.env.write_txn()?;
    for owner_rows in opened {
        let owner = bytes_to_hex_lower(&owner_rows.owner32);
        let restored = restore(&target.store, &mut txn, owner_rows)?;
        lines.push(format!(
            "RESTORED {name} owner={owner} written={written} dropped={dropped:?}",
            written = restored.written,
            dropped = restored.dropped,
        ));
    }
    txn.commit()?;
    Ok(())
}

/// One of the six getters' restore into `bare` with no actor parts, one
/// write transaction, as lines: one per owner with what it wrote and what it
/// left out. Blob versions take the production path, which defers the rows
/// whose actor did not open instead of dropping them.
pub(super) fn restore_bare_pins(
    name: &'static str,
    getter: Getter,
    captured: &Captured,
    bare: &Vault,
    lines: &mut Vec<String>,
) -> Result<()> {
    let mut txn = bare.store.env.write_txn()?;
    for rows in captured.owners() {
        let framed = getter_bytes_for_owner(getter, rows)?;
        let opened = OpenedOwnerRows::open(&framed, Vec::new(), BTreeSet::new())?;
        let owner = bytes_to_hex_lower(&opened.owner32);
        if getter == Getter::BlobArtifact {
            let total = opened.rows.len();
            let deferred = crate::blob_artifact::checkpoint::restore_or_defer_in_txn(
                &bare.store,
                &mut txn,
                opened,
            )?;
            match &deferred {
                None => {
                    lines.push(format!(
                        "RESTORED-BARE {name} owner={owner} written={total} dropped=[]"
                    ));
                    lines.push(format!("DEFERRED-BARE {name} owner={owner} rows=none"));
                }
                Some(deferred) => {
                    let dropped: Vec<_> =
                        deferred.rows.iter().map(|part| part.at().clone()).collect();
                    lines.push(format!(
                        "RESTORED-BARE {name} owner={owner} \
                         written={written} dropped={dropped:?}",
                        written = total - deferred.rows.len(),
                    ));
                    let parts: Vec<String> = deferred
                        .rows
                        .iter()
                        .map(|part| format!("{part:?}"))
                        .collect();
                    lines.push(format!("DEFERRED-BARE {name} owner={owner} rows={parts:?}"));
                }
            }
        } else {
            let restored = getter_restore_in_txn(getter, &bare.store, &mut txn, opened)?;
            lines.push(format!(
                "RESTORED-BARE {name} owner={owner} written={written} dropped={dropped:?}",
                written = restored.written,
                dropped = restored.dropped,
            ));
        }
    }
    txn.commit()?;
    Ok(())
}

/// One of the four getters' restore into `target`, one write transaction
/// per owner, as lines: one per owner with what it wrote and what it left
/// out, or its refusal. A restore that refuses is a result to pin, not a
/// test error: its transaction aborts and the next owner restores.
pub(super) fn restore_four_pins(
    name: &'static str,
    getter: Getter,
    target: &Vault,
    opened: Vec<OpenedOwnerRows>,
    lines: &mut Vec<String>,
) -> Result<()> {
    for owner_rows in opened {
        let owner = bytes_to_hex_lower(&owner_rows.owner32);
        let mut txn = target.store.env.write_txn()?;
        match getter_restore_in_txn(getter, &target.store, &mut txn, owner_rows) {
            Ok(restored) => {
                lines.push(format!(
                    "RESTORED {name} owner={owner} written={written} dropped={dropped:?}",
                    written = restored.written,
                    dropped = restored.dropped,
                ));
                txn.commit()?;
            }
            Err(error) => {
                lines.push(format!("REFUSED {name} owner={owner} error={error}"));
            }
        }
    }
    Ok(())
}

/// One of the four getters' restore into `bare` with no actor parts, one
/// write transaction per owner, as lines: one per owner with what it wrote
/// and what it left out, or its refusal.
pub(super) fn restore_four_bare_pins(
    name: &'static str,
    getter: Getter,
    captured: &Captured,
    bare: &Vault,
    lines: &mut Vec<String>,
) -> Result<()> {
    for rows in captured.owners() {
        let framed = getter_bytes_for_owner(getter, rows)?;
        let opened = OpenedOwnerRows::open(&framed, Vec::new(), BTreeSet::new())?;
        let owner = bytes_to_hex_lower(&opened.owner32);
        let mut txn = bare.store.env.write_txn()?;
        match getter_restore_in_txn(getter, &bare.store, &mut txn, opened) {
            Ok(restored) => {
                lines.push(format!(
                    "RESTORED-BARE {name} owner={owner} written={written} dropped={dropped:?}",
                    written = restored.written,
                    dropped = restored.dropped,
                ));
                txn.commit()?;
            }
            Err(error) => {
                lines.push(format!("REFUSED-BARE {name} owner={owner} error={error}"));
            }
        }
    }
    Ok(())
}

/// Every raw row of `table` in `vault` into `into`, by full stored key.
fn raw_rows_into<K: SideKey, V, C: SideCodec<V>>(
    vault: &Vault,
    getter: &'static str,
    table: SideTable<K, V, C>,
    into: &mut BTreeMap<Vec<u8>, (&'static str, Vec<u8>)>,
) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    for row in table.iter_raw_from(&vault.store, &txn, &[])? {
        let (key, value) = row?;
        let mut full = table.decl().prefix.to_vec();
        full.extend_from_slice(&key);
        into.insert(full, (getter, value));
    }
    Ok(())
}

/// Every raw row of every getter's tables in `target`, in key order.
pub(super) fn raw_pins(target: &Vault, lines: &mut Vec<String>) -> Result<()> {
    let mut rows: BTreeMap<Vec<u8>, (&'static str, Vec<u8>)> = BTreeMap::new();
    raw_rows_into(target, "bm25", TEXT_SOURCE, &mut rows)?;
    raw_rows_into(target, "batch", PHONETIC_SOURCE, &mut rows)?;
    raw_rows_into(target, "provenance_body", BODY, &mut rows)?;
    raw_rows_into(target, "provenance_body", BODY_DIGEST, &mut rows)?;
    raw_rows_into(target, "codebase", SNAPSHOTS, &mut rows)?;
    raw_rows_into(target, "codebase", REPO_INDEX, &mut rows)?;
    raw_rows_into(target, "codebase", PROJECT_INDEX, &mut rows)?;
    raw_rows_into(target, "codebase", FORK_INDEX, &mut rows)?;
    raw_rows_into(target, "codebase", SCOPE_INDEX, &mut rows)?;
    raw_rows_into(target, "codebase", CUSTODY_REPORTS, &mut rows)?;
    raw_rows_into(target, "outbound_ledger", LEDGER, &mut rows)?;
    raw_rows_into(target, "outbound_ledger", ATTEMPT_INDEX, &mut rows)?;
    raw_rows_into(target, "outbound_ledger", UNAVAILABLE, &mut rows)?;
    raw_rows_into(target, "outbound_ledger", CALL_ACCOUNTING, &mut rows)?;
    raw_rows_into(target, "blocked_reports", WITNESSES, &mut rows)?;
    raw_rows_into(target, "embed", MEDIA_VECTOR, &mut rows)?;
    raw_rows_into(target, "embed", MEDIA_DEVICE, &mut rows)?;
    raw_rows_into(target, "embed", MEDIA_REFUSED, &mut rows)?;
    raw_rows_into(target, "workflow_tool", TOOL_WAIT, &mut rows)?;
    raw_rows_into(target, "workflow_tool", BODY_SOURCE, &mut rows)?;
    raw_rows_into(target, "source_audience", RECORDS, &mut rows)?;
    raw_rows_into(target, "source_audience", HELD, &mut rows)?;
    for (key, (getter, value)) in rows {
        lines.push(format!(
            "RAW {getter} {key} {value}",
            key = bytes_to_hex_lower(&key),
            value = bytes_to_hex_lower(&value),
        ));
    }
    Ok(())
}

/// The nine getters, in pin order, each with the name its lines carry.
pub(super) const PINNED: [(&str, Getter); 9] = [
    ("bm25", Getter::TextSource),
    ("batch", Getter::PhoneticSource),
    ("provenance_body", Getter::ProvenanceBody),
    ("codebase", Getter::Codebase),
    ("outbound_ledger", Getter::OutboundCall),
    ("blocked_reports", Getter::BlockedSourceOwner),
    ("embed", Getter::EmbedMedia),
    ("workflow_tool", Getter::WorkflowTool),
    ("source_audience", Getter::SourceAudience),
];

/// The six getters, in pin order, each with the name its lines carry.
pub(super) const PINNED_SIX: [(&str, Getter); 6] = [
    ("typed_body", Getter::TypedBody),
    ("provenance_birth", Getter::ProvenanceBirth),
    ("code_document", Getter::CodeDocument),
    ("code_revision", Getter::CodeRevision),
    ("office_body", Getter::OfficeBody),
    ("blob_artifact", Getter::BlobArtifact),
];

/// Every raw row of the six getters' tables in `vault` into `into`, by full
/// stored key.
fn six_rows_into(
    vault: &Vault,
    into: &mut BTreeMap<Vec<u8>, (&'static str, Vec<u8>)>,
) -> Result<()> {
    raw_rows_into(vault, "typed_body", TB_HEADS, into)?;
    raw_rows_into(vault, "typed_body", TB_DOCS, into)?;
    raw_rows_into(vault, "typed_body", TB_FORKS, into)?;
    raw_rows_into(vault, "typed_body", TB_FORK_DOCS, into)?;
    raw_rows_into(vault, "typed_body", TB_RECEIPTS, into)?;
    raw_rows_into(vault, "provenance_birth", ROW_BIRTHS, into)?;
    raw_rows_into(vault, "provenance_birth", BIRTH_BY_TRIGGER, into)?;
    raw_rows_into(vault, "code_document", DOC_HEAD, into)?;
    raw_rows_into(vault, "code_document", DOC_FRONTIER, into)?;
    raw_rows_into(vault, "code_document", DOC_INGRESS, into)?;
    raw_rows_into(vault, "code_document", DOC_PATH, into)?;
    raw_rows_into(vault, "code_revision", REV_RECORDS, into)?;
    raw_rows_into(vault, "code_revision", REV_INTEGRITY, into)?;
    raw_rows_into(vault, "code_revision", REV_FRONTIER, into)?;
    raw_rows_into(vault, "code_revision", REV_FORKS, into)?;
    raw_rows_into(vault, "code_revision", REV_SESSION_INDEX, into)?;
    raw_rows_into(vault, "code_revision", REV_PARENT_INDEX, into)?;
    raw_rows_into(vault, "code_revision", REV_FORK_PARENT_INDEX, into)?;
    raw_rows_into(vault, "code_revision", REV_PROPOSALS, into)?;
    raw_rows_into(vault, "code_revision", REV_PROMOTIONS, into)?;
    raw_rows_into(vault, "office_body", OFF_SOURCES, into)?;
    raw_rows_into(vault, "office_body", OFF_FORKS, into)?;
    raw_rows_into(vault, "office_body", OFF_EXPORTS, into)?;
    raw_rows_into(vault, "office_body", OFF_EXPORT_AUTHORS, into)?;
    raw_rows_into(vault, "office_body", OFF_PROPOSALS, into)?;
    raw_rows_into(vault, "office_body", OFF_MEMBERSHIP, into)?;
    raw_rows_into(vault, "office_body", OFF_ORACLE, into)?;
    raw_rows_into(vault, "office_body", OFF_LIVE_EDIT, into)?;
    raw_rows_into(vault, "office_body", OFF_TOKEN_INDEX, into)?;
    raw_rows_into(vault, "blob_artifact", BLOB_HEAD, into)?;
    raw_rows_into(vault, "blob_artifact", BLOB_VERSIONS, into)?;
    raw_rows_into(vault, "blob_artifact", BLOB_POINTERS, into)?;
    raw_rows_into(vault, "blob_artifact", BLOB_ADMISSIONS, into)?;
    raw_rows_into(vault, "blob_artifact", BLOB_SERVING, into)?;
    Ok(())
}

/// Every raw row of the six getters' tables in `target`, then in `bare`, in
/// key order.
pub(super) fn raw_pins_six(target: &Vault, bare: &Vault, lines: &mut Vec<String>) -> Result<()> {
    let mut rows: BTreeMap<Vec<u8>, (&'static str, Vec<u8>)> = BTreeMap::new();
    six_rows_into(target, &mut rows)?;
    for (key, (getter, value)) in rows {
        lines.push(format!(
            "RAW {getter} {key} {value}",
            key = bytes_to_hex_lower(&key),
            value = bytes_to_hex_lower(&value),
        ));
    }
    let mut bare_rows: BTreeMap<Vec<u8>, (&'static str, Vec<u8>)> = BTreeMap::new();
    six_rows_into(bare, &mut bare_rows)?;
    for (key, (getter, value)) in bare_rows {
        lines.push(format!(
            "RAW-BARE {getter} {key} {value}",
            key = bytes_to_hex_lower(&key),
            value = bytes_to_hex_lower(&value),
        ));
    }
    Ok(())
}

/// The four getters, in pin order, each with the name its lines carry.
pub(super) const PINNED_FOUR: [(&str, Getter); 4] = [
    ("entities", Getter::Entities),
    ("note", Getter::Note),
    ("entity_doc", Getter::EntityDoc),
    ("entity_revision", Getter::EntityRevision),
];

/// Every raw row of the four getters' tables in `vault` into `into`, by full
/// stored key.
fn four_rows_into(
    vault: &Vault,
    into: &mut BTreeMap<Vec<u8>, (&'static str, Vec<u8>)>,
) -> Result<()> {
    raw_rows_into(vault, "note", N_HEAD, into)?;
    raw_rows_into(vault, "note", N_HEAD_DOC, into)?;
    raw_rows_into(vault, "note", N_OVERRIDE, into)?;
    raw_rows_into(vault, "note", N_SEAL, into)?;
    raw_rows_into(vault, "note", N_FORK, into)?;
    raw_rows_into(vault, "note", N_PROPOSAL_DOC, into)?;
    raw_rows_into(vault, "note", N_RECEIPT, into)?;
    raw_rows_into(vault, "note", N_BUNDLE, into)?;
    raw_rows_into(vault, "note", N_SYNC, into)?;
    raw_rows_into(vault, "note", N_FORK_AUTHORITY, into)?;
    raw_rows_into(vault, "note", N_RECEIPT_BY_REQUEST, into)?;
    raw_rows_into(vault, "note", N_PIN_SOURCE, into)?;
    raw_rows_into(vault, "note", N_PIN_CLAIM, into)?;
    raw_rows_into(vault, "note", N_PIN_CITING, into)?;
    raw_rows_into(vault, "note", N_PIN_REQUEST_CITING, into)?;
    raw_rows_into(vault, "note", N_PIN_REQUEST_CLAIM, into)?;
    raw_rows_into(vault, "note", N_PIN_REQUEST_SOURCE, into)?;
    raw_rows_into(vault, "note", N_TITLE_RESERVATION, into)?;
    raw_rows_into(vault, "note", N_TITLE_BY_NOTE, into)?;
    raw_rows_into(vault, "entity_doc", ED_HEAD, into)?;
    raw_rows_into(vault, "entity_doc", ED_FLOOR, into)?;
    raw_rows_into(vault, "entity_doc", ED_FORK, into)?;
    raw_rows_into(vault, "entity_doc", ED_FORK_SNAPSHOT, into)?;
    raw_rows_into(vault, "entity_doc", ED_PIN, into)?;
    raw_rows_into(vault, "entity_doc", ED_PURGE, into)?;
    raw_rows_into(vault, "entity_doc", ED_RECEIPT, into)?;
    raw_rows_into(vault, "entity_doc", ED_BUNDLE, into)?;
    raw_rows_into(vault, "entity_doc", ED_SNAPSHOT, into)?;
    raw_rows_into(vault, "entity_doc", ED_UPDATE, into)?;
    raw_rows_into(vault, "entity_revision", ER_STATE, into)?;
    raw_rows_into(vault, "entity_revision", ER_DOC, into)?;
    raw_rows_into(vault, "entity_revision", ER_FRONTIER, into)?;
    raw_rows_into(vault, "entity_revision", ER_IDENTITY, into)?;
    raw_rows_into(vault, "entity_revision", ER_TIMELINE, into)?;
    raw_rows_into(vault, "entity_revision", ER_REFILL, into)?;
    raw_rows_into(vault, "entity_revision", ER_PENDING_INDEX, into)?;
    raw_rows_into(vault, "entity_revision", ER_PENDING_PHONETIC, into)?;
    Ok(())
}

/// Every raw row of one raw database in `vault` into `into`, by key.
fn raw_db_into(
    vault: &Vault,
    db: &crate::overlay_db::OverlayDb,
    into: &mut BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    for row in db.iter(&txn)? {
        let (key, value) = row?;
        into.insert(key.into_owned(), value.into_owned());
    }
    Ok(())
}

/// Every row of the raw entity and edge databases in `vault`, each in key
/// order, tagged `tag`: `entities` first, then the database name.
fn raw_db_pins(vault: &Vault, tag: &'static str, lines: &mut Vec<String>) -> Result<()> {
    for (db_name, db) in [
        ("entities", &vault.store.entities),
        ("edges_out", &vault.store.edges_out),
        ("edges_in", &vault.store.edges_in),
    ] {
        let mut rows: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        raw_db_into(vault, db, &mut rows)?;
        for (key, value) in rows {
            lines.push(format!(
                "{tag} entities {db} {key} {value}",
                db = db_name,
                key = bytes_to_hex_lower(&key),
                value = bytes_to_hex_lower(&value),
            ));
        }
    }
    Ok(())
}

/// Every raw row of the four getters' tables in `target`, then in `bare`,
/// in key order, each followed by the raw entity and edge rows of that
/// vault.
pub(super) fn raw_pins_four(target: &Vault, bare: &Vault, lines: &mut Vec<String>) -> Result<()> {
    let mut rows: BTreeMap<Vec<u8>, (&'static str, Vec<u8>)> = BTreeMap::new();
    four_rows_into(target, &mut rows)?;
    for (key, (getter, value)) in rows {
        lines.push(format!(
            "RAW {getter} {key} {value}",
            key = bytes_to_hex_lower(&key),
            value = bytes_to_hex_lower(&value),
        ));
    }
    raw_db_pins(target, "RAW", lines)?;
    let mut bare_rows: BTreeMap<Vec<u8>, (&'static str, Vec<u8>)> = BTreeMap::new();
    four_rows_into(bare, &mut bare_rows)?;
    for (key, (getter, value)) in bare_rows {
        lines.push(format!(
            "RAW-BARE {getter} {key} {value}",
            key = bytes_to_hex_lower(&key),
            value = bytes_to_hex_lower(&value),
        ));
    }
    raw_db_pins(bare, "RAW-BARE", lines)?;
    Ok(())
}

/// Captures, frames and restores each of the nineteen getters through the
/// checkpoint registry, as a capture and a restore dispatch them: one line
/// per owner, section row, restore and target row, in getter order. The six
/// also restore into `bare` with no actor parts, and the four restore into
/// both vaults one owner per transaction, pinning refusals as results.
///
/// # Errors
///
/// The vaults', or a row the getters' codecs refuse.
pub fn pins(source: &Vault, target: &Vault, bare: &Vault) -> Result<Vec<String>> {
    clear_four(target)?;
    clear_four(bare)?;
    let mut lines = Vec::new();
    let txn = source.store.env.read_txn()?;
    for (name, getter) in PINNED {
        let captured = getter_capture(getter, &source.store, &txn)?;
        let opened = capture_pins(
            name,
            &captured,
            |rows| getter_bytes_for_owner(getter, rows),
            &mut lines,
        )?;
        restore_pins(
            name,
            target,
            opened,
            |store, wtxn, opened| getter_restore_in_txn(getter, store, wtxn, opened),
            &mut lines,
        )?;
    }
    for (name, getter) in PINNED_SIX {
        let captured = getter_capture(getter, &source.store, &txn)?;
        let opened = capture_pins(
            name,
            &captured,
            |rows| getter_bytes_for_owner(getter, rows),
            &mut lines,
        )?;
        restore_pins(
            name,
            target,
            opened,
            |store, wtxn, opened| getter_restore_in_txn(getter, store, wtxn, opened),
            &mut lines,
        )?;
        restore_bare_pins(name, getter, &captured, bare, &mut lines)?;
    }
    for (name, getter) in PINNED_FOUR {
        let captured = getter_capture(getter, &source.store, &txn)?;
        let opened = capture_pins(
            name,
            &captured,
            |rows| getter_bytes_for_owner(getter, rows),
            &mut lines,
        )?;
        restore_four_pins(name, getter, target, opened, &mut lines)?;
        restore_four_bare_pins(name, getter, &captured, bare, &mut lines)?;
    }
    raw_pins(target, &mut lines)?;
    raw_pins_six(target, bare, &mut lines)?;
    raw_pins_four(target, bare, &mut lines)?;
    Ok(lines)
}
