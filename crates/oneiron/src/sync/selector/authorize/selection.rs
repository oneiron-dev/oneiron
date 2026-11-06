//! Native row selection on the caller's read snapshot, without rebuilding a window.

use super::*;

pub(super) struct WindowSelection {
    pub(super) kept: BTreeSet<EntityId>,
    pub(super) shipped: BTreeSet<EntityId>,
    pub(super) withheld: BTreeSet<EntityId>,
    pub(super) claims_withheld: BTreeSet<EntityId>,
    pub(super) notes: NoteSelection,
    pub(super) revision_rows: Vec<(EntityId, Vec<u8>)>,
    pub(super) coreference: super::super::scope::CoreferenceExportContext,
}

pub(super) fn select_window_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: &LoroDoc,
    selector: &SyncSelector,
    position: &Position,
    grant_scope: crate::FederationGrantScope,
    authority_scope: &crate::federation::Scope,
    flagged: &BTreeSet<EntityId>,
    credential_scope: Option<&crate::federation::Scope>,
) -> Result<WindowSelection> {
    let scope_position = position.as_scope();
    let (_, mut claims_withheld) = withheld_claim_carriers(
        vault,
        txn,
        &source.get_map("entities"),
        &source.get_map("edges"),
    )?;
    // A withheld world's rows stay here even when packed while portable.
    claims_withheld.extend(crate::sync::window::device_only_ids(
        vault,
        txn,
        Withhold::Worlds(flagged),
        &source.get_map("entities"),
        &source.get_map("edges"),
    )?);
    let mut scope_error = None;
    let source_entities = source.get_map("entities");
    let source_edges = source.get_map("edges");
    let source_tombstones = source.get_map("tombstones");

    let mut tombstoned = BTreeSet::<EntityId>::new();
    map_for_each_tombstone_value(&source_tombstones, |raw_key, _| {
        let Ok(id) = EntityId::from_hex(raw_key) else {
            return;
        };
        tombstoned.insert(id);
    });
    for id in &tombstoned {
        if crate::settings::device_only_withholds(&vault.store, txn, flagged, id)? {
            claims_withheld.insert(*id);
        }
    }

    let facets = facet_filter(scope_position);
    let facet_scope =
        facet_scope_by_source(vault, txn, &source_entities, &source_edges, scope_position)?;
    let coreference = coreference_export_context(vault, txn, source, selector)?;
    // Credentials never leave through a selector, whatever the carrier says, and neither does
    // this vault's embedding setup (OF-370): a peer or a guest keeps its own.
    let mut custody_withheld = BTreeSet::new();
    map_for_each_value_bytes(&source_entities, |key, blob| {
        if blob.and_then(EntityMetadataHeader::parse).is_some_and(|h| {
            matches!(
                h.entity_type,
                crate::registry::ENTITY_TYPE_SECRET_CUSTODY
                    | crate::registry::ENTITY_TYPE_EMBEDDING_SETUP
            )
        }) && let Ok(id) = EntityId::from_hex(key)
        {
            custody_withheld.insert(id);
        }
    });
    // A delete a peer withdrew stays withheld, as at window egress.
    custody_withheld.extend(
        crate::sync::window::withdrawn_delete_carriers(vault, txn, source)?
            .into_iter()
            .map(|(_, id)| id),
    );
    let mut candidates = BTreeSet::<EntityId>::new();
    let mut kept = BTreeSet::<EntityId>::new();
    let mut seeds = BTreeSet::<EntityId>::new();

    map_for_each_value_bytes(&source_entities, |raw_key, maybe_blob| {
        let Some(blob) = maybe_blob else {
            return;
        };
        let Ok(id) = EntityId::from_hex(raw_key) else {
            return;
        };
        if id.to_hex() != raw_key {
            return;
        }
        if custody_withheld.contains(&id) || claims_withheld.contains(&id) {
            return;
        }
        // Tombstoned rows still evaluate scope: their live bytes must not
        // replicate (excluded from `out_entities` below), but an in-scope
        // tombstone must be retained to propagate the delete, while an
        // out-of-scope one is dropped to avoid leaking counts. Skipping
        // scope here would retain nothing under any filtered selector.
        let is_tombstoned = tombstoned.contains(&id);
        if scope_error.is_some() {
            return;
        }
        match crate::authority::row_causal_admitted(vault, txn, &id, blob) {
            Ok(true) => {}
            Ok(false) => return,
            // An undecodable CLAIM is a withheld row, not a failed export:
            // the window carries peer-controlled bytes (quarantine records a
            // rejected row but does not remove it from the CRDT), so one bad
            // row must not fail the whole filter closed. Every other decode
            // site on this path (`scope_for_blob`, `coreference_claim_passes`,
            // `world_passes`) already withholds; the causal check is the only
            // one that propagates, and it propagates only for CLAIM bodies.
            Err(crate::error::Error::InvalidClaimBody(_)) => return,
            Err(error) => {
                scope_error = Some(error);
                return;
            }
        }
        // A NOTE sits at one world it is in that the grant and the selector
        // both hold (FIX-LIST 9433).
        let selected = note_world::selector_world_axis(selector.world);
        let held = [&authority_scope.worlds, &selected];
        let scope = match note_world::blob_scope_held_at(&vault.store, txn, id, blob, &held) {
            Ok(Some(scope)) => scope,
            Ok(None) => return,
            Err(error) => {
                scope_error = Some(error);
                return;
            }
        };
        if !authority_scope.admits("read", &scope, &crate::federation::Scope::top()) {
            return;
        }
        match super::super::scope::settled_position_selected(&id, blob, &scope, scope_position) {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                scope_error = Some(error);
                return;
            }
        }
        let Some(decision) = entity_selector_decision(
            vault,
            (&id, blob),
            &scope,
            selector,
            &facet_scope,
            scope_position,
            &coreference,
        ) else {
            return;
        };
        // Facet rule C: a text is never a candidate, so never kept, seeded
        // or shipped, unless every source it was written from is a live row
        // this export reads, judged on its stored row. A tombstone carries
        // no text, so it still propagates its delete.
        if !is_tombstoned {
            match text_backed(vault, txn, &id, Some(blob), |source, raw| {
                if crate::settings::device_only_withholds_raw(
                    &vault.store,
                    txn,
                    flagged,
                    source,
                    Some(raw),
                )? {
                    return Ok(false);
                }
                Ok(source_selected(
                    vault,
                    txn,
                    (source, raw),
                    authority_scope,
                    selector,
                    scope_position,
                    &facet_scope,
                )? && crate::store::legal_hold::use_limit_in_txn(&vault.store, txn, source)?
                    .is_none())
            }) {
                Ok(true) => {}
                Ok(false) => return,
                Err(error) => {
                    scope_error = Some(error);
                    return;
                }
            }
            match crate::store::legal_hold::use_limit_in_txn(&vault.store, txn, &id) {
                Ok(Some(_)) => return,
                Ok(None) => {}
                Err(error) => {
                    scope_error = Some(error);
                    return;
                }
            }
        }
        candidates.insert(id);
        if facets.is_some() {
            if decision.facet_visible {
                kept.insert(id);
            }
            if decision.facet_seed {
                // A deleted seed's own tombstone is retained (it is kept),
                // but it does not pull neighbors: deletion ends closure.
                if is_tombstoned {
                    kept.insert(id);
                } else {
                    seeds.insert(id);
                }
            }
        } else {
            kept.insert(id);
        }
    });

    if let Some(error) = scope_error {
        return Err(error);
    }
    if facets.is_some() {
        kept.extend(seeds.iter().copied());
        map_for_each_value_bytes(&source_edges, |raw_key, maybe_value| {
            if maybe_value.is_none() {
                return;
            }
            let Some((src, kind, tgt)) = parse_edge_key(raw_key) else {
                return;
            };
            // A withheld `same_as` link is not a closure channel either: if the
            // peer may not see the link, it must not pull entities across it.
            if kind == EdgeKind::SameAs && !coreference.allows(src, tgt) {
                return;
            }
            if seeds.contains(&src) || seeds.contains(&tgt) {
                if candidates.contains(&src) {
                    kept.insert(src);
                }
                if candidates.contains(&tgt) {
                    kept.insert(tgt);
                }
            }
        });
    }

    // Project revisions (decision 9) never travel on their own scope: each
    // goes exactly when its PROJECT row does, every one of them whatever
    // month it was learned in, and none for a withheld project.
    let revision_kind = crate::workspace_roster::project_revision_type(&vault.store);
    if let Some(revision_kind) = revision_kind {
        let mut carriers = BTreeSet::new();
        map_for_each_value_bytes(&source_entities, |key, blob| {
            if blob
                .and_then(EntityMetadataHeader::parse)
                .is_some_and(|header| header.entity_type == revision_kind)
                && let Ok(id) = EntityId::from_hex(key)
            {
                carriers.insert(id);
            }
        });
        kept.retain(|id| !carriers.contains(id));
    }
    // A fresh peer may hold a valid selected target but only part of its
    // scoped birth/event/handoff closure in the source CRDT. Never emit the
    // target alone: the receiving replica would mistake missing history for
    // permission. The selector must carry the whole authenticated closure.
    let mut incomplete = BTreeSet::new();
    for id in kept.iter().copied() {
        let Some(blob) = crate::sync::loro_support::map_get_bytes(&source_entities, &id.to_hex())
        else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&blob) else {
            continue;
        };
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            continue;
        }
        let Ok(body) = crate::claim::decode_claim_body(&blob[ENTITY_METADATA_HEADER_LEN..], true)
        else {
            continue;
        };
        if !crate::authority::machine_claim_needs_history(&vault.store, txn, &body)? {
            continue;
        }
        let Some(required) = machine_history_controls(vault, txn, id)? else {
            incomplete.insert(id);
            continue;
        };
        if required.iter().any(|control| {
            !kept.contains(control)
                || !crate::sync::loro_support::map_contains_binary(
                    &source_entities,
                    &control.to_hex(),
                )
        }) {
            incomplete.insert(id);
        }
    }
    // A NOTE this export drops is judged in its snapshot too (Sol round 17
    // on #1384), so nothing is withheld after the epoch pass. A device-only
    // flag is policy, not authority: promotion authority keeps a NOTE the
    // flag holds here, as it keeps every other row (this corrects #1402's
    // authority-mode NOTE drop).
    let grant_selector = Some((grant_scope, selector));
    let notes = NoteSelection::judged_in_with_scope(
        vault,
        txn,
        flagged,
        source,
        &kept,
        grant_selector,
        credential_scope,
    )?;
    // An epoch summary leaves only beside every record it was written from:
    // the pass reads what this export ships, in its snapshot, so it runs
    // after every other withholding and before anything is written.
    let shipped = kept
        .iter()
        .filter(|id| !tombstoned.contains(id) && !incomplete.contains(id) && !notes.drops(id))
        .copied()
        .collect::<BTreeSet<_>>();
    let withheld = unbacked_epochs(vault, txn, source, &shipped)?;
    let mut revision_rows = Vec::new();
    if revision_kind.is_some() {
        for project in shipped.iter().filter(|id| !withheld.contains(id)) {
            for companion in
                crate::workspace_roster::exportable_revisions_in_txn(&vault.store, txn, *project)?
            {
                if let Some(raw) = vault.get_raw_in(txn, &companion)? {
                    revision_rows.push((companion, raw));
                }
            }
        }
    }
    Ok(WindowSelection {
        kept,
        shipped,
        withheld,
        claims_withheld,
        notes,
        revision_rows,
        coreference,
    })
}
