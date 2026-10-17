//! Grant and pact authorization resolving the requested position under the grant ceiling, guest-share stripping, and the closed-subgraph filter pass.

use std::collections::{BTreeSet, HashMap};

use loro::LoroDoc;

use crate::Vault;
use crate::authority::{AuthorityFold, FederationGrantActivation, federation_grant_activation};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError, SyncSelectorValidation as SelectorError};
use crate::federation::{
    Ceiling, FederationDirectionScope, FederationGrantScope, Position, ScopeAxis, ScopeId,
    base_world_axis, decode_federation_grant_body,
};
use crate::registry::{ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_FEDERATION_GRANT};
use crate::sync::bridge::parse_edge_key;
use crate::sync::local_claims::withheld_claim_carriers;
use crate::sync::loro_support::{
    map_for_each_tombstone_value, map_for_each_value_bytes, map_insert_bytes,
};
use crate::sync::row_birth::{BirthReach, copy_births_within};
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;
use crate::sync::window::{
    Withhold, apply_pending_window_updates, load_window_from_state, reverse_rematerialize_with,
};

use super::codec::{SyncSelector, SyncSelectorWorld, selector_err};
use super::epoch_egress::unbacked_epochs;
use super::machine_history::machine_history_controls;
use super::scope::{
    band_filter, coreference_export_context, entity_selector_decision, facet_filter,
    facet_scope_by_source,
};
use super::text_egress::{source_selected, text_backed};

/// Validates that a selector is backed by a matching federation grant, stays
/// under the effective scope ceiling of every pact bound to that grant, and —
/// for a delegate — has not expired.
pub fn authorize_sync_selector(
    vault: &Vault,
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
) -> Result<()> {
    authorize_sync_selector_at(
        vault,
        grant_scope,
        selector,
        vault.store.clock.now_recorded_at(),
    )
}

/// [`authorize_sync_selector`] against an explicit clock.
///
/// Delegate expiry is a wall-clock edge, so the tests that pin the exact
/// second it flips must not race the real clock to reach it.
pub(super) fn authorize_sync_selector_at(
    vault: &Vault,
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
    now_secs: u64,
) -> Result<()> {
    authorize_selector_export(vault, grant_scope, selector, now_secs).map(|_| ())
}

/// The stored FederationGrant row `id` names, read with its liveness in one
/// transaction. A deleted grant is no grant, even while an unapplied delete
/// leaves its body stored. The transaction closes before the caller folds
/// authority on its own.
fn live_federation_grant(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
    let txn = vault.store.env.read_txn()?;
    live_federation_grant_in(vault, &txn, id)
}

/// [`live_federation_grant`], read in `txn`.
pub(super) fn live_federation_grant_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<u8>> {
    let raw = vault
        .get_raw_in(txn, id)?
        .ok_or_else(|| selector_err(SelectorError::GrantNotFound))?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or_else(|| selector_err(SelectorError::GrantHeader))?;
    if header.entity_type != ENTITY_TYPE_FEDERATION_GRANT {
        return Err(selector_err(SelectorError::GrantWrongType));
    }
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, id)?.is_live() {
        return Err(selector_err(SelectorError::GrantNotFound));
    }
    Ok(raw)
}

/// [`authorize_sync_selector`], plus the resolved position the export path
/// must then filter under.
pub(super) fn authorize_selector_export(
    vault: &Vault,
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
    now_secs: u64,
) -> Result<Position> {
    let raw = live_federation_grant(vault, &selector.grant_id)?;

    let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    if grant.role.is_guest() || !matches!(grant.scope, FederationGrantScope::Vault { .. }) {
        return Err(selector_err(SelectorError::GrantScopeMismatch));
    }
    if grant.scope != grant_scope {
        return Err(selector_err(SelectorError::GrantScopeMismatch));
    }
    if grant.member_ref != selector.member_ref {
        return Err(selector_err(SelectorError::MemberNotGranted));
    }
    // Pact activation gate (ONE-1408): grants without lifecycle entries stay
    // authorized (Unpacted legacy-allow — shipped guest grants must not
    // brick); pact-bound grants confer access only while Active. The fold is
    // recomputed on every call by design (no caching in this chain).
    let fold = vault.authority_fold()?;
    match federation_grant_activation(&fold, &selector.grant_id) {
        FederationGrantActivation::Unpacted | FederationGrantActivation::Active => {}
        FederationGrantActivation::Inactive(_) => {
            return Err(selector_err(SelectorError::GrantInactive));
        }
    }
    // Pact scope ceiling (ONE-1591): an operative pact-bound grant carries no
    // more than the meet of every bound pact's effective scope. The flat
    // `grant.scope` equality above answers a different question and is not a
    // substitute for it.
    let position =
        resolve_selector_position(selector, &ceiling_for_grant(&fold, &selector.grant_id))?;
    // Delegate expiry (ONE-1409): the LAST arm of the door, so a delegate that
    // is also inactive or over its ceiling still denies for those reasons
    // first. Expiry is checked here rather than at mint time because a stored
    // grant outlives the process that wrote it; the expiry second itself
    // denies, and a non-delegate grant carries no expiry and confers at any
    // age. Unpacted delegates are gated too — legacy-allow covers the missing
    // PACT, never a lapsed delegation.
    if !grant.confers_at(now_secs) {
        return Err(selector_err(SelectorError::GrantExpired));
    }
    Ok(position)
}

/// The position `selector` requests under `ceiling`: an unnarrowed axis takes
/// the ceiling's, a named one keeps its set. A named axis outside the ceiling
/// is refused, never clamped.
pub(super) fn resolve_selector_position(
    selector: &SyncSelector,
    ceiling: &Ceiling,
) -> Result<Position> {
    let worlds = match selector.world {
        SyncSelectorWorld::All => ScopeAxis::All,
        SyncSelectorWorld::Base => base_world_axis(),
        SyncSelectorWorld::World(id) => ScopeAxis::Some(BTreeSet::from([ScopeId(id.entity_id())])),
    };
    if !worlds.is_narrowing_of(&ceiling.as_scope().worlds)
        || !selector.facets.within(&ceiling.as_scope().facets)
        || !selector.bands.within(&ceiling.as_scope().bands)
    {
        return Err(selector_err(SelectorError::GrantScopeMismatch));
    }
    let position = Position::new(FederationDirectionScope {
        worlds,
        facets: selector.facets.resolve(&ceiling.as_scope().facets),
        bands: selector.bands.resolve(&ceiling.as_scope().bands),
    });
    if !position.is_narrowing_of(ceiling) {
        return Err(selector_err(SelectorError::GrantScopeMismatch));
    }
    Ok(position)
}

/// The facet and band ceiling of `grant_id`: the meet of its bound pacts, or
/// every axis open when it is unpacted. The grant's `authority_scope` still
/// bounds each exported record.
pub(super) fn ceiling_for_grant(fold: &AuthorityFold, grant_id: &EntityId) -> Ceiling {
    effective_scope_for_grant(fold, grant_id).unwrap_or(Ceiling::new(FederationDirectionScope {
        worlds: ScopeAxis::All,
        facets: ScopeAxis::All,
        bands: ScopeAxis::All,
    }))
}

/// Axis-wise meet of the effective scope of every pact bound to `grant_id`, or
/// `None` when the grant is unpacted.
///
/// Concurrent Connects on divergent branches can bind one grant under several
/// pact ids; intersecting them all avoids picking one arbitrary binding. The
/// filter is `grant_ref` alone rather than `grant_ref` plus `Active`: this runs
/// only after the activation gate returned `Unpacted` or `Active`, so every
/// pact naming the grant is already Active and operative, and dropping a pact
/// could only WIDEN the ceiling.
pub(super) fn effective_scope_for_grant(
    fold: &AuthorityFold,
    grant_id: &EntityId,
) -> Option<Ceiling> {
    fold.federation_pacts
        .values()
        .filter(|pact| pact.grant_ref == *grant_id)
        .map(|pact| pact.effective_scope.clone())
        .reduce(|left, right| left.intersect(&right))
        .map(Ceiling::new)
}

pub(super) fn strip_guest_share_metadata(source: &LoroDoc, key: &WindowKey) -> Result<LoroDoc> {
    let out = create_window_doc("guest-share", key);
    let source_entities = source.get_map("entities");
    let source_edges = source.get_map("edges");

    let mut stripped = BTreeSet::<EntityId>::new();
    let out_entities = out.get_map("entities");
    let mut result = Ok(());
    map_for_each_value_bytes(&source_entities, |raw_key, maybe_blob| {
        if result.is_err() {
            return;
        }
        let Some(blob) = maybe_blob else {
            return;
        };
        let Ok(id) = EntityId::from_hex(raw_key) else {
            return;
        };
        if id.to_hex() != raw_key {
            return;
        }
        if guest_share_metadata_blob(blob) {
            stripped.insert(id);
            return;
        }
        result = map_insert_bytes(&out_entities, raw_key, blob);
    });
    result?;

    let out_edges = out.get_map("edges");
    let mut result = Ok(());
    map_for_each_value_bytes(&source_edges, |raw_key, maybe_value| {
        if result.is_err() {
            return;
        }
        let Some(value) = maybe_value else {
            return;
        };
        let Some((src, _, tgt)) = parse_edge_key(raw_key) else {
            return;
        };
        if stripped.contains(&src) || stripped.contains(&tgt) {
            return;
        }
        result = map_insert_bytes(&out_edges, raw_key, value);
    });
    result?;

    // Tombstone rows are entity ids without type metadata. A guest-share
    // snapshot omits them to avoid leaking deleted membership/topology counts.
    // Its NOTEs already passed the selection that made `source`. A guest is
    // another vault, as far as its rows' births go.
    copy_births_within(source, &out, BirthReach::OtherVault)?;
    crate::sync::note::copy_selected(source, &out, &BTreeSet::new())?;
    out.commit();
    Ok(out)
}

fn guest_share_metadata_blob(blob: &[u8]) -> bool {
    // A world key pad is half of a world's key: a guest never holds one.
    EntityMetadataHeader::parse(blob).is_some_and(|header| {
        matches!(
            header.entity_type,
            ENTITY_TYPE_FEDERATION_GRANT
                | ENTITY_TYPE_AUTHORITY_LOG
                | crate::registry::ENTITY_TYPE_WORLD_KEY_PAD
        )
    })
}

/// A world edge may name an entity carried by a different base-month Doc.
/// Authorize that endpoint through the SAME selector over its real base Doc;
/// a local row alone is not evidence that the grant may export it.
fn authorized_base_edge_endpoints(
    vault: &Vault,
    edges: &loro::LoroMap,
    kept: &BTreeSet<EntityId>,
    selector: &SyncSelector,
    position: &Position,
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
        let Some(raw) = vault.get_raw(&id)? else {
            continue;
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity metadata"))?;
        if crate::sync::types::entity_world(&raw)?.is_some() {
            continue;
        }
        let base_key = WindowKey::from_timestamp(header.learned_at);
        if !selected_by_month.contains_key(base_key.as_str()) {
            let base = match load_window_from_state(vault, "selector-base", &base_key) {
                Ok(doc) => doc,
                Err(Error::Sync(SyncError::WindowNotFound { .. })) => {
                    let doc = create_window_doc("selector-base", &base_key);
                    apply_pending_window_updates(vault, &doc, &base_key)?;
                    doc
                }
                Err(error) => return Err(error),
            };
            reverse_rematerialize_with(vault, &base, &base_key, withhold)?;
            // Read only for what it selects: no birth is copied.
            let selected = filter_window_doc(
                vault,
                &base,
                &base_key,
                selector,
                position,
                withhold,
                BirthReach::OtherVault,
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

/// `withhold` names the worlds kept off the machine the export serves. Every
/// export door withholds; promotion authority asks only what the grant
/// covers. `reach` says where the shipped rows' births may go.
pub(super) fn filter_window_doc(
    vault: &Vault,
    source: &LoroDoc,
    key: &WindowKey,
    selector: &SyncSelector,
    position: &Position,
    withhold: Withhold<'_>,
    reach: BirthReach,
) -> Result<LoroDoc> {
    let scope_position = position.as_scope();
    // A selector must not trigger Observer A with unselected NOTE sidecars.
    // Refresh a detached window, then copy only owners that pass this filter.
    let source_bytes = crate::sync::loro_support::export_snapshot(source)?;
    let refreshed = crate::sync::loro_support::doc_from_snapshot(&source_bytes)?;
    crate::sync::note::refresh(vault, &refreshed, key)?;
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
    let (_, mut claims_withheld) = withheld_claim_carriers(
        vault,
        &rtxn,
        &source.get_map("entities"),
        &source.get_map("edges"),
    )?;
    // A withheld world's rows stay here even when packed while portable.
    claims_withheld.extend(crate::sync::window::device_only_ids(
        vault,
        &rtxn,
        Withhold::Worlds(&flagged),
        &source.get_map("entities"),
        &source.get_map("edges"),
    )?);
    let mut scope_error = None;
    let out = create_window_doc("selector", key);
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
        if crate::settings::device_only_withholds(&vault.store, &rtxn, &flagged, id)? {
            claims_withheld.insert(*id);
        }
    }

    let facets = facet_filter(scope_position);
    let facet_scope = facet_scope_by_source(
        vault,
        &rtxn,
        &source_entities,
        &source_edges,
        scope_position,
    )?;
    let coreference = coreference_export_context(vault, &rtxn, source, selector)?;
    // Credentials never leave through a selector, whatever the carrier says.
    let mut custody_withheld = BTreeSet::new();
    map_for_each_value_bytes(&source_entities, |key, blob| {
        if blob
            .and_then(EntityMetadataHeader::parse)
            .is_some_and(|h| h.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY)
            && let Ok(id) = EntityId::from_hex(key)
        {
            custody_withheld.insert(id);
        }
    });
    // A delete a peer withdrew stays withheld, as at window egress.
    custody_withheld.extend(
        crate::sync::window::withdrawn_delete_carriers(vault, &rtxn, source)?
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
        match crate::authority::row_causal_admitted(vault, &rtxn, &id, blob) {
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
        let scope =
            match crate::federation::record_scope::scope_for_blob(&vault.store, &rtxn, id, blob) {
                Ok(Some(scope)) => scope,
                Ok(None) => return,
                Err(error) => {
                    scope_error = Some(error);
                    return;
                }
            };
        if !grant
            .authority_scope
            .admits("read", &scope, &crate::federation::Scope::top())
        {
            return;
        }
        match super::scope::settled_position_selected(&id, blob, &scope, scope_position) {
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
            match text_backed(vault, &rtxn, &id, Some(blob), |source, raw| {
                if crate::settings::device_only_withholds_raw(
                    &vault.store,
                    &rtxn,
                    &flagged,
                    source,
                    Some(raw),
                )? {
                    return Ok(false);
                }
                source_selected(
                    vault,
                    &rtxn,
                    (source, raw),
                    &grant.authority_scope,
                    selector,
                    scope_position,
                    &facet_scope,
                )
            }) {
                Ok(true) => {}
                Ok(false) => return,
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
        if !crate::authority::machine_claim_needs_history(&vault.store, &rtxn, &body)? {
            continue;
        }
        let Some(required) = machine_history_controls(vault, &rtxn, id)? else {
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
    let notes_dropped = crate::sync::note::dropped_in(vault, &rtxn, &flagged, source, &kept)?;
    // An epoch summary leaves only beside every record it was written from:
    // the pass reads what this export ships, in its snapshot, so it runs
    // after every other withholding and before anything is written.
    let mut shipped = kept
        .iter()
        .filter(|id| {
            !tombstoned.contains(id) && !incomplete.contains(id) && !notes_dropped.contains(id)
        })
        .copied()
        .collect::<BTreeSet<_>>();
    let withheld = unbacked_epochs(vault, &rtxn, source, &shipped)?;
    let mut revision_rows = Vec::new();
    if revision_kind.is_some() {
        for project in shipped.iter().filter(|id| !withheld.contains(id)) {
            for companion in
                crate::workspace_roster::exportable_revisions_in_txn(&vault.store, &rtxn, *project)?
            {
                if let Some(raw) = vault.get_raw_in(&rtxn, &companion)? {
                    revision_rows.push((companion, raw));
                }
            }
        }
    }
    drop(rtxn);
    #[cfg(any(test, feature = "test-hooks"))]
    crate::sync::window::test_hooks::run_device_only_flag_race(vault)?;
    kept.retain(|id| !withheld.contains(id));
    shipped.retain(|id| !withheld.contains(id));

    let out_entities = out.get_map("entities");
    for (id, raw) in &revision_rows {
        map_insert_bytes(&out_entities, &id.to_hex(), raw)?;
    }
    map_for_each_value_bytes(&source_entities, |raw_key, maybe_blob| {
        let Some(blob) = maybe_blob else { return };
        let Ok(id) = EntityId::from_hex(raw_key) else {
            return;
        };
        if id.to_hex() != raw_key || !shipped.contains(&id) {
            return;
        }
        let _ = map_insert_bytes(&out_entities, raw_key, blob);
    });

    let authorized_base = if key.world().is_some() {
        authorized_base_edge_endpoints(vault, &source_edges, &kept, selector, position, withhold)?
    } else {
        BTreeSet::new()
    };
    let out_edges = out.get_map("edges");
    map_for_each_value_bytes(&source_edges, |raw_key, maybe_value| {
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

    let out_tombstones = out.get_map("tombstones");
    map_for_each_tombstone_value(&source_tombstones, |raw_key, value| {
        let Ok(id) = EntityId::from_hex(raw_key) else {
            return;
        };
        if claims_withheld.contains(&id) {
            return;
        }
        if kept.contains(&id)
            || (facets.is_none()
                && band_filter(scope_position).is_none()
                && matches!(selector.world, SyncSelectorWorld::All))
        {
            let _ = map_insert_bytes(&out_tombstones, raw_key, value);
        }
    });

    // Rule A: a birth crosses only beside an owner this filter shipped, and
    // only as far as `reach` lets it.
    copy_births_within(source, &out, reach)?;
    crate::sync::note::copy_selected(source, &out, &notes_dropped)?;
    out.commit();
    Ok(out)
}
