use super::*;

/// `withhold` names the worlds kept off the machine the export serves. Every
/// export door withholds; promotion authority asks only what the grant
/// covers. `reach` says where the shipped rows' births may go.
/// Live rows and their text sources honor current use limits; tombstones still propagate.
pub(in crate::sync::selector) fn filter_window_doc(
    vault: &Vault,
    source: &LoroDoc,
    key: &WindowKey,
    selector: &SyncSelector,
    position: &Position,
    withhold: Withhold<'_>,
    reach: BirthReach<'_>,
) -> Result<LoroDoc> {
    filter_window_doc_in_scope(
        vault, source, key, selector, position, withhold, reach, None,
    )
}

pub(in crate::sync::selector) fn filter_window_doc_in_scope(
    vault: &Vault,
    source: &LoroDoc,
    key: &WindowKey,
    selector: &SyncSelector,
    position: &Position,
    withhold: Withhold<'_>,
    reach: BirthReach<'_>,
    credential_scope: Option<&crate::federation::Scope>,
) -> Result<LoroDoc> {
    let scope_position = position.as_scope();
    // A selector must not trigger Observer A with unselected NOTE sidecars.
    // Refresh a detached window, then copy only owners that pass this filter.
    let source_bytes = crate::sync::loro_support::export_snapshot(source)?;
    let refreshed = crate::sync::loro_support::doc_from_snapshot(&source_bytes)?;
    crate::sync::note::refresh_for(vault, &refreshed, key, withhold)?;
    // The canonical window packs nothing an unknown destination may not
    // read but a world window's own world, which the filter below withholds
    // by key. A proved machine's export packs, into this detached copy, the
    // other private rows that machine may read.
    if matches!(withhold, Withhold::Worlds(_) | Withhold::Peer(_)) {
        reverse_rematerialize_with(vault, &refreshed, key, withhold)?;
    }
    let source = &refreshed;
    let grant_raw = live_federation_grant(vault, &selector.grant_id)?;
    if withhold.withholds_window(vault, key)? {
        let out = create_window_doc("selector", key);
        out.commit();
        return Ok(out);
    }
    let grant = decode_federation_grant_body(&grant_raw[ENTITY_METADATA_HEADER_LEN..])?;
    let authority_scope = match credential_scope {
        Some(bound) => grant.authority_scope.meet(bound),
        None => grant.authority_scope.clone(),
    };
    // One read snapshot for the whole export: withheld claims, facet scope, coreference
    // consent, causal admission, and record stamps all read through this
    // `rtxn`. Opening nested read txns on this thread would fail with
    // `Storage(Mdb(BadRslot))` under LMDB's single-slot rule, so the scope
    // doors take the txn instead of opening their own.
    let rtxn = vault.store.env.read_txn()?;
    let flagged = withhold.worlds_in(vault, &rtxn)?;
    if key.world().is_some_and(|world| flagged.contains(&world)) {
        let out = create_window_doc("selector", key);
        out.commit();
        return Ok(out);
    }
    let selection::WindowSelection {
        mut kept,
        mut shipped,
        withheld,
        claims_withheld,
        notes,
        revision_rows,
        coreference,
    } = selection::select_window_rows_in_txn(
        vault,
        &rtxn,
        source,
        selector,
        position,
        grant.scope,
        &authority_scope,
        &flagged,
        credential_scope,
    )?;
    let facets = facet_filter(scope_position);
    let out = create_window_doc("selector", key);
    let source_entities = source.get_map("entities");
    let source_edges = source.get_map("edges");
    let source_tombstones = source.get_map("tombstones");
    drop(rtxn);
    #[cfg(any(test, feature = "test-hooks"))]
    crate::sync::window::test_hooks::run_device_only_flag_race(vault)?;
    kept.retain(|id| !withheld.contains(id));
    shipped.retain(|id| !withheld.contains(id));

    projection::copy_entities(&source_entities, &out, &shipped, &revision_rows)?;

    let authorized_base = if key.world().is_some() {
        authorized_base_edge_endpoints(
            vault,
            &source_edges,
            &kept,
            selector,
            position,
            withhold,
            credential_scope,
        )?
    } else {
        BTreeSet::new()
    };
    projection::copy_edges(&source_edges, &out, &kept, &authorized_base, &coreference);

    let out_tombstones = out.get_map("tombstones");
    let open = facets.is_none() && band_filter(scope_position).is_none();
    let all = matches!(selector.world, SyncSelectorWorld::All);
    let export = super::super::tombstones::TombstoneExport::new(&authority_scope, open && all);
    let ttxn = vault.store.env.read_txn()?;
    projection::copy_tombstones(
        vault,
        &ttxn,
        &source_tombstones,
        &out_tombstones,
        &claims_withheld,
        &kept,
        &export,
    );

    projection::copy_companions(source, &out, reach, withhold, &shipped, &notes)?;
    out.commit();
    Ok(out)
}
