//! Grant and pact authorization resolving the requested position under the grant ceiling, guest-share stripping, and the closed-subgraph filter pass.

use std::collections::{BTreeSet, HashMap};

use loro::LoroDoc;

use crate::Vault;
use crate::authority::AuthorityFold;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError, SyncSelectorValidation as SelectorError};
use crate::federation::record_scope::note_world;
use crate::federation::{
    Ceiling, FederationDirectionScope, FederationGrantScope, Position, ScopeAxis, ScopeId,
    base_world_axis, decode_federation_grant_body,
};
use crate::provenance::birth::WithheldKey;
use crate::registry::{ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_FEDERATION_GRANT};
use crate::sync::bridge::parse_edge_key;
use crate::sync::local_claims::withheld_claim_carriers;
use crate::sync::loro_support::{
    map_for_each_tombstone_value, map_for_each_value_bytes, map_insert_bytes,
};
use crate::sync::note::NoteSelection;
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

// [`live_federation_grant`], read in `txn`: the shared federation helper the
// grant travel door reads too (FIX 2998).
pub(super) use crate::federation::live_federation_grant_in;

/// [`authorize_sync_selector`], plus the resolved position the export path
/// must then filter under.
pub(super) fn authorize_selector_export(
    vault: &Vault,
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
    now_secs: u64,
) -> Result<Position> {
    let txn = vault.store.env.read_txn()?;
    authorize_selector_export_in_txn(vault, &txn, grant_scope, selector, now_secs)
}

/// The same grant, pact, ceiling and expiry checks in the caller's snapshot.
pub(in crate::sync) fn authorize_sync_selector_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
) -> Result<()> {
    authorize_selector_export_in_txn(vault, txn, grant_scope, selector, vault.now_recorded_at())
        .map(|_| ())
}

fn authorize_selector_export_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
    now_secs: u64,
) -> Result<Position> {
    let raw = live_federation_grant_in(vault, txn, &selector.grant_id)?;

    let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    // A shared-vault member grant or a Connect guest grant (FIX 3016); an Ask
    // guest grant never backs a selector.
    if !crate::federation::grant_serves_selector(&grant) {
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
    // brick); pact-bound grants confer access only while Active. A Connect
    // grant is inert until one Active pact with its peer binds it (FIX 3016).
    // The fold is recomputed on every call by design (no caching in this
    // chain).
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    if !crate::federation::pact_admits_grant(&fold, &selector.grant_id, &grant) {
        return Err(selector_err(SelectorError::GrantInactive));
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
    crate::authority::current_grant_scope(fold, grant_id).map(Ceiling::new)
}

pub(super) fn strip_guest_share_metadata(
    source: &LoroDoc,
    key: &WindowKey,
    withheld: &WithheldKey,
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
    // Its NOTEs already passed the selection that made `source`. A guest is
    // another vault, as far as its rows' births go.
    copy_births_within(source, &out, BirthReach::OtherVault(withheld))?;
    // A body reference rides beside the owner it binds (FIX 5489).
    crate::sync::asset_body::references::copy_refs_within(source, &out)?;
    crate::sync::note::copy_selected(source, &out, &NoteSelection::carried())?;
    out.commit();
    Ok(out)
}

fn guest_share_metadata_blob(blob: &[u8]) -> bool {
    // A world key pad is half of a world's key: a guest never holds one. Nor does a guest
    // hold the vault's embedding setup (OF-370).
    EntityMetadataHeader::parse(blob).is_some_and(|header| {
        matches!(
            header.entity_type,
            ENTITY_TYPE_FEDERATION_GRANT
                | ENTITY_TYPE_AUTHORITY_LOG
                | crate::registry::ENTITY_TYPE_WORLD_KEY_PAD
                | crate::registry::ENTITY_TYPE_EMBEDDING_SETUP
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
                BirthReach::OtherVault(&WithheldKey::fresh()),
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

mod filter;
pub(super) use filter::filter_window_doc;
