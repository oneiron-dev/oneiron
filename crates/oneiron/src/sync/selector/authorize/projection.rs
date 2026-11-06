//! Native selected-window copying, shared by exports and staged read checks.

use super::*;
use loro::LoroMap;

pub(super) fn copy_entities(
    source_entities: &LoroMap,
    out: &LoroDoc,
    shipped: &BTreeSet<EntityId>,
    revision_rows: &[(EntityId, Vec<u8>)],
) -> Result<()> {
    let out_entities = out.get_map("entities");
    for (id, raw) in revision_rows {
        map_insert_bytes(&out_entities, &id.to_hex(), raw)?;
    }
    map_for_each_value_bytes(source_entities, |raw_key, maybe_blob| {
        let Some(blob) = maybe_blob else { return };
        let Ok(id) = EntityId::from_hex(raw_key) else {
            return;
        };
        if id.to_hex() != raw_key || !shipped.contains(&id) {
            return;
        }
        let _ = map_insert_bytes(&out_entities, raw_key, blob);
    });

    Ok(())
}

pub(super) fn copy_edges(
    source_edges: &LoroMap,
    out: &LoroDoc,
    kept: &BTreeSet<EntityId>,
    authorized_base: &BTreeSet<EntityId>,
    coreference: &super::super::scope::CoreferenceExportContext,
) {
    let out_edges = out.get_map("edges");
    map_for_each_value_bytes(source_edges, |raw_key, maybe_value| {
        let Some(value) = maybe_value else {
            return;
        };
        let Some((src, kind, tgt)) = parse_edge_key(raw_key) else {
            return;
        };
        // ONE-1414: the link itself is coreference material. It crosses only
        // on this pact's own Approved consent — never as a side effect of both
        // endpoints happening to be exportable.
        if kind == EdgeKind::SameAs && !coreference.allows(src, tgt) {
            return;
        }
        if (kept.contains(&src) && kept.contains(&tgt))
            || (kept.contains(&src) && authorized_base.contains(&tgt))
            || (kept.contains(&tgt) && authorized_base.contains(&src))
        {
            let _ = map_insert_bytes(&out_edges, raw_key, value);
        }
    });
}

pub(super) fn copy_tombstones(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source_tombstones: &LoroMap,
    out_tombstones: &LoroMap,
    claims_withheld: &BTreeSet<EntityId>,
    kept: &BTreeSet<EntityId>,
    export: &super::super::tombstones::TombstoneExport<'_>,
) {
    map_for_each_tombstone_value(source_tombstones, |raw_key, value| {
        let Ok(id) = EntityId::from_hex(raw_key) else {
            return;
        };
        if claims_withheld.contains(&id) {
            return;
        }
        if kept.contains(&id) || export.admits(vault, txn, &id, value) {
            let _ = map_insert_bytes(out_tombstones, raw_key, value);
        }
    });
}

pub(super) fn copy_companions(
    source: &LoroDoc,
    out: &LoroDoc,
    reach: BirthReach<'_>,
    withhold: Withhold<'_>,
    shipped: &BTreeSet<EntityId>,
    notes: &NoteSelection,
) -> Result<()> {
    // Rule A: a birth crosses only beside an owner this filter shipped, and
    // only as far as `reach` lets it.
    copy_births_within(source, out, reach)?;
    // FIX 6870: a repo's manifest crosses only beside a CODE row this
    // filter shipped, which already passed the grant's selector.
    crate::sync::repo_manifests::copy_repo_manifest_heads(source, out, |code| {
        shipped.contains(code)
    })?;
    crate::sync::asset_body::references::copy_refs_within(source, out)?;
    // FIX 2902: a proved machine of this vault's takes, beside each shipped
    // row, the origin this vault's import judged its bytes by, and beside each
    // shipped MESSAGE its writer's proof (FIX 12113).
    if matches!(reach, BirthReach::OwnMachines)
        && matches!(withhold, Withhold::Worlds(_) | Withhold::Peer(_))
    {
        crate::sync::ingest::copy_peer_origins(source, out)?;
        crate::sync::ingest::copy_writer_proofs(source, out)?;
        crate::sync::origin_positions::copy_for_own_machines(source, out)?;
    }
    crate::sync::note::copy_selected(source, out, notes)?;
    Ok(())
}
