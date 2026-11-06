//! Grant-scoped checking of the new bootstrap supplier's original projections.

use super::*;
use crate::authority::VerifiedSlip;

/// All source windows must already be staged on this same writer before
/// this check runs. The final proof and selector belong to the original
/// accepted member and selected vault. A per-window staging loop cannot
/// replace that batch boundary: native world edges read real base windows.
/// Signed authority history is checked separately on its actual staged rows
/// and original bodies, under the same final grant. This does not supply HTTPS
/// provenance, a target lifecycle or publication.
pub(in crate::sync) fn check_bootstrap_sources(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    verified: &VerifiedSlip,
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
    history: &[(EntityId, Vec<u8>)],
    sources: &[(&WindowKey, &[u8], &LoroDoc)],
) -> Result<()> {
    let claims = verified.claims();
    let grant_ref = claims.grant_ref.as_deref().ok_or_else(invalid)?;
    if EntityId::from_hex(grant_ref)? != selector.grant_id
        || EntityId::from_hex(&claims.holder_ref)? != selector.member_ref
    {
        return Err(invalid());
    }
    let position = authorize_selector_export_in_txn(
        vault,
        txn,
        grant_scope,
        selector,
        vault.now_recorded_at(),
    )?;
    let grant_raw = live_federation_grant_in(vault, txn, &selector.grant_id)?;
    let grant = decode_federation_grant_body(&grant_raw[ENTITY_METADATA_HEADER_LEN..])?;
    let authority_scope = grant.authority_scope.meet(verified.scope());
    check_authority_history(vault, txn, history, &authority_scope, selector, &position)?;
    let mut source_by_key = HashMap::new();
    for (key, _, source) in sources {
        if source_by_key.insert(key.as_str(), *source).is_some() {
            return Err(invalid());
        }
    }
    let destination_key = WithheldKey::fresh();
    let flagged = BTreeSet::new();
    for (key, update, source) in sources {
        let selected = project_source(
            vault,
            txn,
            source,
            key,
            selector,
            &position,
            grant.scope,
            &authority_scope,
            verified.scope(),
            &destination_key,
            &source_by_key,
            &flagged,
            Withhold::Nothing,
        )?;
        super::projection_history::check_projection_history(update, &selected)?;
    }
    Ok(())
}

/// History is not a window projection. Read each original signed body from
/// the final writer through the native source-row selector and stored scope.
pub(in crate::sync) fn check_authority_history(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    history: &[(EntityId, Vec<u8>)],
    authority_scope: &crate::federation::Scope,
    selector: &SyncSelector,
    position: &Position,
) -> Result<()> {
    let facet_scope = HashMap::new();
    for (id, original_body) in history {
        let raw = vault.get_raw_in(txn, id)?.ok_or_else(invalid)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
        let body = raw.get(ENTITY_METADATA_HEADER_LEN..).ok_or_else(invalid)?;
        if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG || body != original_body.as_slice() {
            return Err(invalid());
        }
        let entry = crate::authority::decode_authority_log_entry_body(body)?;
        if crate::authority::authority_log_entity_id(&entry)? != *id {
            return Err(invalid());
        }
        if !source_selected(
            vault,
            txn,
            (id, &raw),
            authority_scope,
            selector,
            position.as_scope(),
            &facet_scope,
        )? {
            return Err(invalid());
        }
        // The native log stamp is id-derived; a world-side operation also
        // names its world in its signed body, independently of that stamp.
        let world = crate::federation::record_scope::record_world_in(
            &vault.store,
            txn,
            *id,
            header.entity_type,
            body,
        )?
        .ok_or_else(invalid)?;
        if let Some(world) = world {
            let world = ScopeId(world);
            if !authority_scope.worlds.contains(&world)
                || !position.as_scope().worlds.contains(&world)
            {
                return Err(invalid());
            }
        }
        if crate::store::legal_hold::use_limit_in_txn(&vault.store, txn, id)?.is_some() {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(in crate::sync) fn project_source(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: &LoroDoc,
    key: &WindowKey,
    selector: &SyncSelector,
    position: &Position,
    grant_scope: FederationGrantScope,
    authority_scope: &crate::federation::Scope,
    credential_scope: &crate::federation::Scope,
    destination_key: &WithheldKey,
    sources: &HashMap<&str, &LoroDoc>,
    flagged: &BTreeSet<EntityId>,
    withhold: Withhold<'_>,
) -> Result<LoroDoc> {
    // This is the native authority judgment: what the grant reads. The
    // actual home exporter still applies its destination/device policy.
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
        txn,
        source,
        selector,
        position,
        grant_scope,
        authority_scope,
        flagged,
        Some(credential_scope),
    )?;
    kept.retain(|id| !withheld.contains(id));
    shipped.retain(|id| !withheld.contains(id));
    let out = create_window_doc("selector", key);
    projection::copy_entities(&source.get_map("entities"), &out, &shipped, &revision_rows)?;
    let authorized_base = if key.world().is_some() {
        base_endpoints(
            vault,
            txn,
            &source.get_map("edges"),
            &kept,
            selector,
            position,
            grant_scope,
            authority_scope,
            credential_scope,
            sources,
            flagged,
            withhold,
        )?
    } else {
        BTreeSet::new()
    };
    projection::copy_edges(
        &source.get_map("edges"),
        &out,
        &kept,
        &authorized_base,
        &coreference,
    );
    let scope_position = position.as_scope();
    let open = facet_filter(scope_position).is_none() && band_filter(scope_position).is_none();
    let all = matches!(selector.world, SyncSelectorWorld::All);
    let export = super::super::tombstones::TombstoneExport::new(authority_scope, open && all);
    projection::copy_tombstones(
        vault,
        txn,
        &source.get_map("tombstones"),
        &out.get_map("tombstones"),
        &claims_withheld,
        &kept,
        &export,
    );
    projection::copy_companions(
        source,
        &out,
        BirthReach::OtherVault(destination_key),
        withhold,
        &shipped,
        &notes,
    )?;
    out.commit();
    Ok(out)
}

/// Native cross-month endpoint selection over the exact source batch, not
/// over a local row alone. Recursion terminates at the learned-at base key:
/// base-window projections never resolve additional world-edge endpoints.
fn base_endpoints(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    edges: &loro::LoroMap,
    kept: &BTreeSet<EntityId>,
    selector: &SyncSelector,
    position: &Position,
    grant_scope: FederationGrantScope,
    authority_scope: &crate::federation::Scope,
    credential_scope: &crate::federation::Scope,
    sources: &HashMap<&str, &LoroDoc>,
    flagged: &BTreeSet<EntityId>,
    withhold: Withhold<'_>,
) -> Result<BTreeSet<EntityId>> {
    let mut wanted = BTreeSet::new();
    map_for_each_value_bytes(edges, |raw, value| {
        if value.is_none() {
            return;
        }
        if let Some((src, _, tgt)) = parse_edge_key(raw) {
            if kept.contains(&src) && !kept.contains(&tgt) {
                wanted.insert(tgt);
            }
            if kept.contains(&tgt) && !kept.contains(&src) {
                wanted.insert(src);
            }
        }
    });
    let mut selected_by_month = HashMap::<String, LoroDoc>::new();
    let mut allowed = BTreeSet::new();
    for id in wanted {
        let Some(raw) = vault.get_raw_in(txn, &id)? else {
            continue;
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity metadata"))?;
        if crate::sync::types::entity_world(&raw)?.is_some() {
            continue;
        }
        let base_key = WindowKey::from_timestamp(header.learned_at);
        if !selected_by_month.contains_key(base_key.as_str()) {
            let source = sources.get(base_key.as_str()).ok_or_else(invalid)?;
            let selected = project_source(
                vault,
                txn,
                source,
                &base_key,
                selector,
                position,
                grant_scope,
                authority_scope,
                credential_scope,
                &WithheldKey::fresh(),
                sources,
                flagged,
                withhold,
            )?;
            selected_by_month.insert(base_key.to_string(), selected);
        }
        if selected_by_month[base_key.as_str()]
            .get_map("entities")
            .get(&id.to_hex())
            .is_some()
        {
            allowed.insert(id);
        }
    }
    Ok(allowed)
}

fn invalid() -> Error {
    Error::InvalidConfig(
        "shared replica source does not match its accepted member and batch".into(),
    )
}
