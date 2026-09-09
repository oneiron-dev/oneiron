//! Grant and pact authorization with EmptyAxis coupling, guest-share stripping, and the closed-subgraph filter pass.

use std::collections::BTreeSet;

use loro::LoroDoc;

use crate::Vault;
use crate::authority::{AuthorityFold, FederationGrantActivation, federation_grant_activation};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Result, SyncSelectorValidation as SelectorError};
use crate::federation::{
    FederationDirectionScope, FederationGrantScope, FederationScopeBands, FederationScopeFacets,
    FederationScopeWorlds, decode_federation_grant_body,
};
use crate::registry::{ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_FEDERATION_GRANT};
use crate::sync::bridge::parse_edge_key;
use crate::sync::loro_support::{
    map_for_each_tombstone_value, map_for_each_value_bytes, map_insert_bytes,
};
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;

use super::codec::{EmptyAxis, SyncSelector, SyncSelectorWorld, selector_err};
use super::scope::{coreference_export_context, entity_selector_decision, facet_scope_by_source};

/// Validates that a selector is backed by a matching federation grant, stays
/// under the effective scope ceiling of every pact bound to that grant, and —
/// for a delegate — has not expired.
pub fn authorize_sync_selector(
    vault: &Vault,
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
) -> Result<()> {
    authorize_sync_selector_at(vault, grant_scope, selector, crate::unix_seconds_now())
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

/// [`authorize_sync_selector`], plus the [`EmptyAxis`] reading the export path
/// must then filter under.
///
/// Both answers come from ONE pass because both come from ONE fact — whether a
/// pact binds this grant. Splitting them would let the filter read an axis the
/// ceiling check credited differently, which is the whole OF-453 L3 defect.
pub(super) fn authorize_selector_export(
    vault: &Vault,
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
    now_secs: u64,
) -> Result<EmptyAxis> {
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
    // substitute for it. Unpacted grants have no pact and keep legacy-allow —
    // on the export path too, which is what `EmptyAxis` carries out of here.
    let empty = match effective_scope_for_grant(&fold, &selector.grant_id) {
        None => EmptyAxis::Unfiltered,
        Some(ceiling) => {
            if !selector_direction_scope(selector).is_narrowing_of(&ceiling) {
                return Err(selector_err(SelectorError::GrantScopeMismatch));
            }
            EmptyAxis::Bottom
        }
    };
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
    Ok(empty)
}

/// Reads a selector's wire semantics as a federation direction scope.
///
/// OF-453 L3 (owner ruling R-20260807 §6): an empty facet or band vector NEVER
/// decodes as "everything". Both axes are kind-tagged, so silence maps to the
/// lattice ⊥ — a narrowing of every ceiling that requests nothing — and `All`
/// on either axis is reachable only from a pact, never from a selector.
pub(super) fn selector_direction_scope(selector: &SyncSelector) -> FederationDirectionScope {
    FederationDirectionScope {
        worlds: match selector.world {
            SyncSelectorWorld::All => FederationScopeWorlds::All,
            SyncSelectorWorld::Base => FederationScopeWorlds::Base,
            SyncSelectorWorld::World(id) => FederationScopeWorlds::Worlds(vec![id.entity_id()]),
        },
        facets: if selector.facets.is_empty() {
            FederationScopeFacets::Bottom
        } else {
            FederationScopeFacets::Some(selector.facets.clone())
        },
        bands: if selector.bands.is_empty() {
            FederationScopeBands::Bottom
        } else {
            FederationScopeBands::Some(selector.bands.clone())
        },
    }
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
    empty: EmptyAxis,
) -> Result<LoroDoc> {
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

    let facet_scope = facet_scope_by_source(vault, &source_entities, &source_edges, selector)?;
    let coreference = coreference_export_context(vault, source, selector)?;
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
        if tombstoned.contains(&id) {
            return;
        }
        let Some(decision) = entity_selector_decision(
            &id,
            blob,
            grant_scope,
            selector,
            &facet_scope,
            empty,
            &coreference,
        ) else {
            return;
        };
        candidates.insert(id);
        if selector.facet_filter_active(empty) {
            if decision.facet_visible {
                kept.insert(id);
            }
            if decision.facet_seed {
                seeds.insert(id);
            }
        } else {
            kept.insert(id);
        }
    });

    if selector.facet_filter_active(empty) {
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
        if kept.contains(&id) || !selector.any_filter_active(empty) {
            let _ = map_insert_bytes(&out_tombstones, raw_key, value);
        }
    });

    out.commit();
    Ok(out)
}
