//! Window shallow-snapshot compaction and erased-id scrub.

use std::collections::BTreeSet;

use super::run::{HardEraseSweepRun, WindowSweepState};
#[cfg(all(feature = "sync", test))]
use super::run::{INJECT_RACE_BEFORE_COMPACT_WRITE, RACE_BENIGN_MARKER, RaceInjection};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
#[cfg(feature = "sync")]
use crate::error::{Error, SyncEngineContext, SyncProtocolPruneScope, SyncProtocolValidation};

/// Per-window outcome of [`compact_window`].
#[cfg(feature = "sync")]
enum CompactOutcome {
    /// Persisted state existed and was rebuilt through a shallow snapshot.
    Compacted,
    /// No persisted state for this window — nothing to do.
    Empty,
    /// The window changed between the read phase and the compaction write
    /// txn (a `u:w:` row was added/removed, or the `d:w:` snapshot was
    /// replaced) — the shallow snapshot built from the stale read no longer
    /// reflects durable state. The write txn is ABORTED (nothing committed,
    /// no carrier overwritten) and the window deferred; a clean re-run
    /// re-reads the quiesced window and compacts.
    RacedDefer,
}

/// Distinct window labels currently carrying persisted CRDT state —
/// `d:w:{key}` snapshots and `u:w:{key}:{seq:08x}` update rows.
fn persisted_window_labels(vault: &Vault) -> Result<(BTreeSet<String>, bool)> {
    let mut labels = BTreeSet::new();
    let mut malformed = false;
    let rtxn = vault.store.env.read_txn()?;
    for row in vault.store.sync_state.prefix_iter(&rtxn, "d:w:")? {
        let (key, _) = row?;
        labels.insert(key["d:w:".len()..].to_owned());
    }
    for row in vault.store.sync_state.prefix_iter(&rtxn, "u:w:")? {
        let (key, _) = row?;
        let rest = &key["u:w:".len()..];
        match rest.rsplit_once(':') {
            Some((label, _seq)) => {
                labels.insert(label.to_owned());
            }
            None => {
                // A u:w: row that does not address a window cannot be
                // proven payload-free — fail closed, block completion.
                tracing::error!(key = %key, "sweep: malformed u:w: row key");
                malformed = true;
            }
        }
    }
    Ok((labels, malformed))
}

#[cfg(feature = "sync")]
pub(super) fn compact_all_windows(
    vault: &Vault,
    erased: &BTreeSet<EntityId>,
    run: &mut HardEraseSweepRun,
    _now: u64,
) -> Result<WindowSweepState> {
    use crate::sync::types::{WindowKey, parse_window_key_str};

    let (labels, malformed) = persisted_window_labels(vault)?;
    let mut state = if malformed {
        WindowSweepState::Failed(format!("{:?}", crate::error::ErrorKind::InvalidKey))
    } else {
        WindowSweepState::AllCompacted
    };

    for label in &labels {
        if parse_window_key_str(label).is_none() {
            // Engine-written labels always validate; a foreign/corrupt row
            // cannot be loaded or proven payload-free — fail closed.
            tracing::error!(window = %label, "sweep: invalid persisted window label");
            if matches!(state, WindowSweepState::AllCompacted) {
                state =
                    WindowSweepState::Failed(format!("{:?}", crate::error::ErrorKind::InvalidKey));
            }
            continue;
        }
        let key = WindowKey::new(label);

        // OPEN or retained-handle windows are deferred (pinned): the live doc
        // keeps the full history in memory and its next full-snapshot persist
        // would resurrect the carrier over the shallow row, even after forced
        // deregistration removed the manager registry entry.
        if vault_window_is_live(vault, &key) {
            tracing::warn!(window = %label, "sweep: window live or retained — deferred");
            run.windows_deferred_live += 1;
            if matches!(state, WindowSweepState::AllCompacted) {
                state = WindowSweepState::Deferred;
            }
            continue;
        }

        match compact_window(vault, &key, erased) {
            Ok(CompactOutcome::Compacted) => run.windows_compacted += 1,
            Ok(CompactOutcome::Empty) => {}
            Ok(CompactOutcome::RacedDefer) => {
                tracing::warn!(
                    window = %label,
                    "sweep: window raced between read and compaction write — deferred"
                );
                run.windows_deferred_raced += 1;
                // Outcome precedence (pinned): Failed > Deferred(raced) >
                // Deferred(live) > AllCompacted. A raced window downgrades
                // ONLY from AllCompacted — it must never overwrite a Failed
                // (which routes to retry and consumes retry_state) nor an
                // existing Deferred.
                if matches!(state, WindowSweepState::AllCompacted) {
                    state = WindowSweepState::Deferred;
                }
            }
            Err(err) => {
                tracing::error!(
                    window = %label,
                    error = %err,
                    "sweep: window compaction FAILED — obligation kept for retry"
                );
                if !matches!(state, WindowSweepState::Failed(_)) {
                    state = WindowSweepState::Failed(format!("{:?}", err.kind()));
                }
            }
        }
    }
    Ok(state)
}

/// Non-sync builds cannot parse Loro window docs: if ANY CRDT carrier rows
/// exist, every job defers loudly (fail closed). A vault that never ran
/// sync has no historical CRDT carriers — its obligations can finalize
/// (the active carriers were erased in the delete transaction itself).
#[cfg(not(feature = "sync"))]
pub(super) fn compact_all_windows(
    vault: &Vault,
    _erased: &BTreeSet<EntityId>,
    _run: &mut HardEraseSweepRun,
    _now: u64,
) -> Result<WindowSweepState> {
    let (labels, malformed) = persisted_window_labels(vault)?;
    let queue_rows_exist = {
        let rtxn = vault.store.env.read_txn()?;
        let mut iter = vault.store.sync_queue.prefix_iter(&rtxn, b"q:")?;
        iter.next().transpose()?.is_some()
    };
    if !labels.is_empty() || malformed || queue_rows_exist {
        tracing::error!(
            windows = labels.len(),
            "sweep: CRDT carrier rows present but the engine was built without \
             the `sync` feature — historical-carrier compaction deferred (fail closed)"
        );
        return Ok(WindowSweepState::Deferred);
    }
    Ok(WindowSweepState::AllCompacted)
}

#[cfg(feature = "sync")]
fn vault_window_is_live(vault: &Vault, key: &crate::sync::types::WindowKey) -> bool {
    vault.live_window_for_sweep(key)
}

/// Compacts one CLOSED window: load `d:w:` + pending `u:w:` rows, scrub
/// live-map residue for erased ids, export a shallow snapshot at the
/// latest frontiers, and atomically replace the persistence triple, prune
/// the subsumed `u:w:` rows, and re-assert `fr:w:`. Returns whether any
/// persisted state existed.
#[cfg(feature = "sync")]
fn compact_window(
    vault: &Vault,
    key: &crate::sync::types::WindowKey,
    erased: &BTreeSet<EntityId>,
) -> Result<CompactOutcome> {
    use crate::sync::loro_support::{doc_from_snapshot, doc_version_vector, import_doc};
    use crate::sync::schema::create_window_doc;
    use loro::ExportMode;

    // Read phase (one read txn, dropped before any Loro work).
    let (snapshot_bytes, update_rows) = {
        let rtxn = vault.store.env.read_txn()?;
        let snapshot = vault
            .store
            .sync_state
            .get(&rtxn, &format!("d:w:{key}"))?
            .map(|value| value.to_vec());
        let mut rows: Vec<(String, Vec<u8>)> = Vec::new();
        let prefix = format!("u:w:{key}:");
        for entry in vault.store.sync_state.prefix_iter(&rtxn, &prefix)? {
            let (k, v) = entry?;
            rows.push((k.to_string(), v.to_vec()));
        }
        (snapshot, rows)
    };
    if snapshot_bytes.is_none() && update_rows.is_empty() {
        return Ok(CompactOutcome::Empty);
    }

    // Rebuild the doc UNOBSERVED — the sweep never touches LMDB through
    // Observer side effects; it only rewrites the persisted CRDT carriers.
    let doc = match &snapshot_bytes {
        Some(bytes) => doc_from_snapshot(bytes)?,
        None => create_window_doc("local", key),
    };
    for (_, bytes) in &update_rows {
        import_doc(&doc, bytes)?;
    }

    // §8c.2 live-map residue scrub: a concurrent re-put that won LWW over
    // the tombstone commit's key-delete leaves erased payload LIVE in the
    // map. Remove every entities/edges key referencing an erased id —
    // across hex-casing aliases (fail closed). Tombstones map untouched
    // (permanent); receipt entities are receipt-ids, never erased ids.
    scrub_erased_ids_from_doc(&doc, erased)?;

    // Shallow snapshot at the latest frontiers: live state byte-exact, op
    // history (the payload carrier) dropped, doc identity + VV preserved.
    doc.commit();
    let frontiers = doc.oplog_frontiers();
    let shallow = doc
        .export(ExportMode::shallow_snapshot(&frontiers))
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportShallowSnapshot, e))?;
    let vv = doc_version_vector(&doc);

    let merged_keys: BTreeSet<String> = update_rows.iter().map(|(k, _)| k.clone()).collect();
    let prefix = format!("u:w:{key}:");
    for k in &merged_keys {
        if !k.starts_with(&prefix) {
            // Surgical scope (fail closed): never touch another family.
            return Err(Error::sync_protocol(SyncProtocolValidation::ScopedPrune {
                scope: SyncProtocolPruneScope::SweepUpdateRows,
                prefix,
                key: k.clone(),
            }));
        }
    }

    // Test-only race injection point: lands a concurrent write AFTER the
    // read phase, BEFORE the compaction write txn, so the in-txn re-read
    // guards below have something to catch (one-shot).
    #[cfg(test)]
    inject_race_before_compact_write(vault, key, &snapshot_bytes)?;

    let dw_key = format!("d:w:{key}");
    // ABORT-ONLY raced-defer signal: the write closure returns `Err` (so
    // `with_write_txn` rolls the txn back, committing NOTHING) and sets this
    // flag, which the caller maps to `RacedDefer`. There is deliberately NO
    // `Ok` arm that commits nothing — the `d:w:`/`sv:` puts live AFTER the
    // re-read+compare, so an early return can never clobber a newer carrier.
    let raced = std::cell::Cell::new(false);
    let result = vault.with_write_txn(|wtxn| {
        // Finding 4 (anti-clobber): re-read `d:w:` and compare byte-for-byte
        // against the snapshot captured in the read phase — `Option<Vec<u8>>`
        // equality, so absent-vs-present (None↔Some) AND any byte difference
        // both count as a race. A concurrent persist replaced the snapshot;
        // overwriting it with our stale-based shallow would clobber newer
        // state, so defer.
        let current_snapshot = vault
            .store
            .sync_state
            .get(&*wtxn, &dw_key)?
            .map(|value| value.to_vec());
        if current_snapshot != snapshot_bytes {
            raced.set(true);
            return Err(Error::sync_protocol(
                SyncProtocolValidation::SweepSnapshotRace,
            ));
        }

        // Finding 1 (carrier completeness): re-read the `u:w:` row set and
        // require FULL SET-EQUALITY with what the read phase merged. A key
        // ADDED or REMOVED means a concurrent persist/prune raced in, so the
        // shallow snapshot no longer covers the window's durable ops — defer
        // rather than drop a carrier or finalize a window we cannot prove
        // payload-free. (Carrier completeness stays local here, not reliant
        // on any sibling d:w: co-write.)
        let mut current_keys: BTreeSet<String> = BTreeSet::new();
        for entry in vault.store.sync_state.prefix_iter(&*wtxn, &prefix)? {
            let (k, _) = entry?;
            current_keys.insert(k.to_string());
        }
        if current_keys != merged_keys {
            raced.set(true);
            return Err(Error::sync_protocol(
                SyncProtocolValidation::SweepUpdateRowsRace,
            ));
        }

        // Race-free: the shallow snapshot reflects the durable window.
        // Replace the persistence triple, prune the now-subsumed `u:w:`
        // rows, and re-assert `fr:w:`. Every merged key is deleted and the
        // set matched exactly, so zero `u:w:` rows remain on top of the
        // snapshot — the freshness flag is honestly fresh.
        vault.store.sync_state.put(wtxn, &dw_key, &shallow)?;
        vault
            .store
            .sync_state
            .put(wtxn, &format!("sv:w:{key}"), &vv)?;
        for k in &merged_keys {
            vault.store.sync_state.delete(wtxn, k)?;
        }
        vault
            .store
            .sync_state
            .put(wtxn, &format!("svf:w:{key}"), &[1u8])?;

        // Wire/SLA pin: the swept window cannot serve pre-shallow deltas —
        // peers behind the shallow start must take a full window resync.
        vault
            .store
            .sync_state
            .put(wtxn, &format!("fr:w:{key}"), &[1u8])?;
        Ok(())
    });
    match result {
        Ok(()) => Ok(CompactOutcome::Compacted),
        // The race guards aborted the txn — nothing committed, no carrier
        // clobbered. Surface a deferral, not a failure (no retry_state
        // consumed); the obligation stays for the quiesced re-run.
        Err(_) if raced.get() => Ok(CompactOutcome::RacedDefer),
        Err(err) => Err(err),
    }
}

/// Test-only race injection — see [`INJECT_RACE_BEFORE_COMPACT_WRITE`].
/// Performs a concurrent write in its OWN committed txn so the subsequent
/// compaction write txn's re-read guards observe it.
#[cfg(all(feature = "sync", test))]
fn inject_race_before_compact_write(
    vault: &Vault,
    key: &crate::sync::types::WindowKey,
    snapshot_bytes: &Option<Vec<u8>>,
) -> Result<()> {
    use crate::sync::loro_support::{doc_from_snapshot, export_snapshot, export_updates_from};
    use crate::sync::schema::create_window_doc;

    match INJECT_RACE_BEFORE_COMPACT_WRITE.with(std::cell::Cell::take) {
        RaceInjection::None => {}
        RaceInjection::AppendUpdateRow => {
            // Build a VALID concurrent update from the SAME window lineage
            // (deps = the window's frontiers) so a clean re-run imports it
            // without missing dependencies. Benign, sentinel-free payload.
            let racer = match snapshot_bytes {
                Some(bytes) => doc_from_snapshot(bytes)?,
                None => create_window_doc("racer", key),
            };
            let base_vv = racer.oplog_vv();
            racer
                .get_map("entities")
                .insert(EntityId::now().to_hex().as_str(), RACE_BENIGN_MARKER)
                .map_err(|e| Error::sync_engine(SyncEngineContext::LoroMapInsert, e))?;
            racer.commit();
            let delta = export_updates_from(&racer, &base_vv)?;
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .sync_state
                .put(&mut wtxn, &format!("u:w:{key}:ffffffff"), &delta)?;
            wtxn.commit()?;
        }
        RaceInjection::ReplaceSnapshot => {
            // Overwrite d:w: with a DIFFERENT valid snapshot carrying only
            // the benign marker — the re-read guard must refuse to clobber.
            let benign = create_window_doc("racer", key);
            benign
                .get_map("entities")
                .insert(EntityId::now().to_hex().as_str(), RACE_BENIGN_MARKER)
                .map_err(|e| Error::sync_engine(SyncEngineContext::LoroMapInsert, e))?;
            benign.commit();
            let snap = export_snapshot(&benign)?;
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .sync_state
                .put(&mut wtxn, &format!("d:w:{key}"), &snap)?;
            wtxn.commit()?;
        }
    }
    Ok(())
}

/// Removes every entities/edges map key referencing an erased id (any
/// hex-casing alias), committing once if anything changed. The tombstones
/// map is PERMANENT and untouched.
#[cfg(feature = "sync")]
fn scrub_erased_ids_from_doc(doc: &loro::LoroDoc, erased: &BTreeSet<EntityId>) -> Result<()> {
    use crate::sync::loro_support::map_delete;

    if erased.is_empty() {
        return Ok(());
    }

    let entities = doc.get_map("entities");
    let mut doomed_entities: Vec<String> = Vec::new();
    entities.for_each(|key, _| {
        // ANY value shape under an erased id's key is residue (fail
        // closed) — including non-binary values a crafted update planted.
        if EntityId::from_hex(key).is_ok_and(|id| erased.contains(&id)) {
            doomed_entities.push(key.to_owned());
        }
    });

    let edges = doc.get_map("edges");
    let mut doomed_edges: Vec<String> = Vec::new();
    edges.for_each(|key, _| {
        if let Some((src, _, tgt)) = crate::sync::bridge::parse_edge_key(key)
            && (erased.contains(&src) || erased.contains(&tgt))
        {
            doomed_edges.push(key.to_owned());
        }
    });

    if doomed_entities.is_empty() && doomed_edges.is_empty() {
        return Ok(());
    }
    for key in &doomed_entities {
        map_delete(&entities, key)?;
    }
    for key in &doomed_edges {
        map_delete(&edges, key)?;
    }
    doc.commit();
    Ok(())
}
