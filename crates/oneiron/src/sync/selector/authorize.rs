//! Grant and pact authorization resolving the requested position under the grant ceiling, guest-share stripping, and the closed-subgraph filter pass.

use std::collections::BTreeSet;

use loro::LoroDoc;

use crate::Vault;
use crate::authority::{AuthorityFold, FederationGrantActivation, federation_grant_activation};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Result, SyncSelectorValidation as SelectorError};
use crate::federation::{
    FederationDirectionScope, FederationGrantScope, ScopeAxis, ScopeId, base_world_axis,
    decode_federation_grant_body,
};
use crate::registry::{ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_FEDERATION_GRANT};
use crate::sync::bridge::parse_edge_key;
use crate::sync::local_claims::withheld_claim_carriers;
use crate::sync::loro_support::{
    map_for_each_tombstone_value, map_for_each_value_bytes, map_insert_bytes,
};
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;

use super::codec::{SyncSelector, SyncSelectorWorld, selector_err};
use super::scope::{
    band_filter, coreference_export_context, entity_selector_decision, facet_filter,
    facet_scope_by_source,
};

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

/// [`authorize_sync_selector`], plus the resolved position the export path
/// must then filter under.
pub(super) fn authorize_selector_export(
    vault: &Vault,
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
    now_secs: u64,
) -> Result<FederationDirectionScope> {
    let raw = vault
        .get_raw(&selector.grant_id)?
        .ok_or_else(|| selector_err(SelectorError::GrantNotFound))?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or_else(|| selector_err(SelectorError::GrantHeader))?;
    if header.entity_type != ENTITY_TYPE_FEDERATION_GRANT {
        return Err(selector_err(SelectorError::GrantWrongType));
    }

    let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
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
    ceiling: &FederationDirectionScope,
) -> Result<FederationDirectionScope> {
    let worlds = match selector.world {
        SyncSelectorWorld::All => ScopeAxis::All,
        SyncSelectorWorld::Base => base_world_axis(),
        SyncSelectorWorld::World(id) => ScopeAxis::Some(BTreeSet::from([ScopeId(id.entity_id())])),
    };
    if !worlds.is_narrowing_of(&ceiling.worlds)
        || !selector.facets.within(&ceiling.facets)
        || !selector.bands.within(&ceiling.bands)
    {
        return Err(selector_err(SelectorError::GrantScopeMismatch));
    }
    Ok(FederationDirectionScope {
        worlds,
        facets: selector.facets.resolve(&ceiling.facets),
        bands: selector.bands.resolve(&ceiling.bands),
    })
}

/// The facet and band ceiling of `grant_id`: the meet of its bound pacts, or
/// every axis open when it is unpacted. The grant's `authority_scope` still
/// bounds each exported record.
pub(super) fn ceiling_for_grant(
    fold: &AuthorityFold,
    grant_id: &EntityId,
) -> FederationDirectionScope {
    effective_scope_for_grant(fold, grant_id).unwrap_or(FederationDirectionScope {
        worlds: ScopeAxis::All,
        facets: ScopeAxis::All,
        bands: ScopeAxis::All,
    })
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
) -> Option<FederationDirectionScope> {
    fold.federation_pacts
        .values()
        .filter(|pact| pact.grant_ref == *grant_id)
        .map(|pact| pact.effective_scope.clone())
        .reduce(|left, right| left.intersect(&right))
}

pub(super) fn strip_guest_share_metadata(
    vault: &Vault,
    source: &LoroDoc,
    key: &WindowKey,
) -> Result<LoroDoc> {
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
    crate::sync::note::copy_selected(vault, source, &out)?;
    out.commit();
    Ok(out)
}

fn guest_share_metadata_blob(blob: &[u8]) -> bool {
    EntityMetadataHeader::parse(blob).is_some_and(|header| {
        matches!(
            header.entity_type,
            ENTITY_TYPE_FEDERATION_GRANT | ENTITY_TYPE_AUTHORITY_LOG
        )
    })
}

pub(super) fn filter_window_doc(
    vault: &Vault,
    source: &LoroDoc,
    key: &WindowKey,
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
    position: &FederationDirectionScope,
) -> Result<LoroDoc> {
    // A selector must not trigger Observer A with unselected NOTE sidecars.
    // Refresh a detached window, then copy only owners that pass this filter.
    let source_bytes = crate::sync::loro_support::export_snapshot(source)?;
    let refreshed = crate::sync::loro_support::doc_from_snapshot(&source_bytes)?;
    crate::sync::note::refresh(vault, &refreshed, key)?;
    let source = &refreshed;
    let grant_raw = vault
        .get_raw(&selector.grant_id)?
        .ok_or_else(|| selector_err(SelectorError::GrantNotFound))?;
    let grant_header = EntityMetadataHeader::parse(&grant_raw)
        .ok_or_else(|| selector_err(SelectorError::GrantHeader))?;
    if grant_header.entity_type != ENTITY_TYPE_FEDERATION_GRANT {
        return Err(selector_err(SelectorError::GrantWrongType));
    }
    let grant = decode_federation_grant_body(&grant_raw[ENTITY_METADATA_HEADER_LEN..])?;
    // Opens its own read txn, so it runs before the export snapshot below.
    let (_, claims_withheld) =
        withheld_claim_carriers(vault, &source.get_map("entities"), &source.get_map("edges"))?;
    // One read snapshot for the whole export: facet scope, coreference
    // consent, causal admission, and record stamps all read through this
    // `rtxn`. Opening nested read txns on this thread would fail with
    // `Storage(Mdb(BadRslot))` under LMDB's single-slot rule, so the scope
    // doors take the txn instead of opening their own.
    let rtxn = vault.store.env.read_txn()?;
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

    let facets = facet_filter(position);
    let facet_scope =
        facet_scope_by_source(vault, &rtxn, &source_entities, &source_edges, position)?;
    let coreference = coreference_export_context(vault, &rtxn, source, selector)?;
    let mut custody_ids = BTreeSet::new();
    map_for_each_value_bytes(&source_entities, |key, blob| {
        if blob
            .and_then(EntityMetadataHeader::parse)
            .is_some_and(|h| h.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY)
            && let Ok(id) = EntityId::from_hex(key)
        {
            custody_ids.insert(id);
        }
    });
    let mut custody_withheld = BTreeSet::new();
    for id in custody_ids {
        if vault.get_raw_in(&rtxn, &id)?.is_some_and(|raw| {
            EntityMetadataHeader::parse(&raw).is_some_and(|h| {
                h.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY
                    && !crate::secret_custody::custody_sync_allowed(
                        &raw[ENTITY_METADATA_HEADER_LEN..],
                    )
            })
        }) {
            custody_withheld.insert(id);
        }
    }
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
        match crate::authority::row_causal_admitted(vault, &rtxn, blob) {
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
        let Some(decision) = entity_selector_decision(
            vault,
            (&id, blob),
            grant_scope,
            selector,
            &facet_scope,
            position,
            &coreference,
        ) else {
            return;
        };
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
    drop(rtxn);
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

    let out_entities = out.get_map("entities");
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
        if kept.contains(&id) && !tombstoned.contains(&id) {
            let _ = map_insert_bytes(&out_entities, raw_key, blob);
        }
    });

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
        if kept.contains(&src) && kept.contains(&tgt) {
            let _ = map_insert_bytes(&out_edges, raw_key, value);
        }
    });

    let out_tombstones = out.get_map("tombstones");
    map_for_each_tombstone_value(&source_tombstones, |raw_key, value| {
        let Ok(id) = EntityId::from_hex(raw_key) else {
            return;
        };
        if kept.contains(&id)
            || (facets.is_none()
                && band_filter(position).is_none()
                && matches!(selector.world, SyncSelectorWorld::All))
        {
            let _ = map_insert_bytes(&out_tombstones, raw_key, value);
        }
    });

    crate::sync::note::copy_selected(vault, source, &out)?;
    out.commit();
    Ok(out)
}
