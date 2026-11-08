//! Origin positions covered by the existing peer-host Connect signature.

use std::collections::{BTreeMap, BTreeSet};

use loro::{ExportMode, LoroDoc};
use serde::{Deserialize, Serialize};

use super::{
    ORIGIN_FACET, SCOPE_RECORD, Stamp, birth_facet, bump_scope_revision, singleton, stored_scope,
};
use crate::authority::FederationPactStatus;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::error::{Error, Result, SyncEngineContext};
use crate::federation::{FederationGrant, Scope, ScopeAxis, ScopeId};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::provenance::birth::{RowBirth, row_birth_in_txn};
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_NOTE,
};
use crate::store::asset_file_in_txn;
use crate::store::loro_document::{map_for_each_value_bytes, map_get_bytes, map_insert_bytes};
use crate::sync::SyncSelector;
use crate::sync::client::VerifiedConnectOrigin;
use crate::{EntityId, Vault};

const ORIGIN_POSITIONS: &str = "origin_positions";

/// The kinds a Connect origin position places: a NOTE, an ASSET and a
/// caption. Each is born under one facet and sits in its live worlds, and the
/// guest export carries none of their birth facets (FIX 22223).
fn placed_kind(kind: u8) -> bool {
    matches!(
        kind,
        ENTITY_TYPE_NOTE | ENTITY_TYPE_ASSET | ENTITY_TYPE_ASSET_TEXT
    )
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileFacts {
    blake3: [u8; 32],
    len: u64,
    xxh32: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginPosition {
    kind: u8,
    carrier: [u8; 32],
    incarnation: [u8; 32],
    facet: EntityId,
    scope: Scope,
    sources: BTreeSet<EntityId>,
    file: Option<FileFacts>,
}

fn incarnation(birth: &RowBirth) -> Result<[u8; 32]> {
    // Copy masking changes refs, not who made the row, when, or its input hash.
    let bytes = rmp_serde::to_vec_named(&(
        &birth.made_by.process,
        birth.made_by.at,
        &birth.content_hash,
    ))
    .map_err(|_| Error::InvalidConfig("Connect birth does not encode".into()))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn related_in_doc(doc: &LoroDoc, id: EntityId, kind: EdgeKind) -> BTreeSet<EntityId> {
    let mut targets = BTreeSet::new();
    map_for_each_value_bytes(&doc.get_map("edges"), |key, value| {
        if value.is_some()
            && let Some((source, edge_kind, target)) = crate::sync::bridge::parse_edge_key(key)
            && source == id
            && edge_kind == kind
        {
            targets.insert(target);
        }
    });
    targets
}

fn related_in_store(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: EdgeKind,
) -> Result<BTreeSet<EntityId>> {
    vault
        .store
        .port_edges(txn, &id, EdgeDirection::Out, Some(kind), None)?
        .map(|edge| edge.map(|edge| edge.target))
        .collect()
}

fn file_facts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    doc: &LoroDoc,
    id: EntityId,
    raw: &[u8],
) -> Result<Option<Option<FileFacts>>> {
    if raw.first() != Some(&ENTITY_TYPE_ASSET) {
        return Ok(Some(None));
    }
    let Some(manifest) =
        asset_file_in_txn(&vault.store, txn, &id, &raw[ENTITY_METADATA_HEADER_LEN..])?
    else {
        return Ok(Some(None));
    };
    if crate::sync::asset_body::references::bound_in(doc, &id, raw).is_none() {
        return Ok(None);
    }
    match vault.with_admitted_asset_file_in_txn(txn, &manifest, |_| Ok(())) {
        Ok(()) => Ok(Some(Some(FileFacts {
            blake3: manifest.facts.blake3,
            len: manifest.facts.len,
            xxh32: manifest.facts.xxh32,
        }))),
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// The carried row of the ASSET or caption `id` and its birth incarnation,
/// when the carrier `doc` holds the stored bytes, they read here, and its
/// carried birth is the stored one.
fn current_row(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    doc: &LoroDoc,
    id: EntityId,
) -> Result<Option<(Vec<u8>, [u8; 32])>> {
    let key = id.to_hex();
    let Some(raw) = map_get_bytes(&doc.get_map("entities"), &key) else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if !placed_kind(header.entity_type)
        || vault.store.port_entity_raw(txn, &id)?.as_deref() != Some(raw.as_slice())
        || !crate::ports::raw_readable_in_txn(&vault.store, txn, &id, &raw)?
    {
        return Ok(None);
    }
    let Some(birth) = row_birth_in_txn(&vault.store, txn, &id)? else {
        return Ok(None);
    };
    let Some(carried) = map_get_bytes(&doc.get_map("row_births"), &key) else {
        return Ok(None);
    };
    let Ok(carried) = rmp_serde::from_slice::<RowBirth>(&carried) else {
        return Ok(None);
    };
    let born = incarnation(&birth)?;
    if incarnation(&carried)? != born {
        return Ok(None);
    }
    Ok(Some((raw, born)))
}

/// The facet the source's row `id` was born under: its one stored `FacetOf`
/// target. A guest export never carries that edge, because the FACET row
/// sits in base reality, which the window does not read. So the position
/// names the facet, and the window signature covers it (FIX 22223).
fn source_facet(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<Option<EntityId>> {
    let Some(facet) = birth_facet(&vault.store, txn, id)? else {
        return Ok(None);
    };
    Ok(
        (related_in_store(vault, txn, id, EdgeKind::FacetOf)? == BTreeSet::from([facet]))
            .then_some(facet),
    )
}

fn source_position(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    doc: &LoroDoc,
    id: EntityId,
    grant: &FederationGrant,
    ceilings: &[&ScopeAxis<ScopeId>],
) -> Result<Option<OriginPosition>> {
    let Some((raw, born)) = current_row(vault, txn, doc, id)? else {
        return Ok(None);
    };
    let Some(facet) = source_facet(vault, txn, id)? else {
        return Ok(None);
    };
    let kind = raw[0];
    let Some(scope) = stored_scope(&vault.store, txn, id, kind)? else {
        return Ok(None);
    };
    // An ASSET or a caption sits where its live worlds place it (FIX 22223):
    // held at the grant's and this window's worlds, it carries its one world
    // there. Base reality, which no Connect grant names, carries nothing.
    let scope = super::note_world::held_at(&vault.store, txn, id, kind, &scope, ceilings);
    let one_world = matches!(&scope.worlds, ScopeAxis::Some(worlds) if worlds.len() == 1);
    if !one_world
        || scope.worlds == crate::federation::base_world_axis()
        || scope.facets != singleton(ScopeId(facet))
        || scope.bands != singleton(kind)
        || scope.verbs != ScopeAxis::Bottom
    {
        return Ok(None);
    }
    let mut read = scope.clone();
    read.verbs = singleton("read".to_owned());
    if !read.is_narrowing_of(&grant.authority_scope) {
        return Ok(None);
    }
    let sources = if kind == ENTITY_TYPE_ASSET_TEXT {
        let sources = related_in_store(vault, txn, id, EdgeKind::DerivedFrom)?;
        if sources.is_empty()
            || sources != related_in_doc(doc, id, EdgeKind::DerivedFrom)
            || super::asset_text::sources_birth_facet(
                &vault.store,
                txn,
                &sources.iter().copied().collect::<Vec<_>>(),
            )? != facet
        {
            return Ok(None);
        }
        sources
    } else {
        BTreeSet::new()
    };
    let Some(file) = file_facts(vault, txn, doc, id, &raw)? else {
        return Ok(None);
    };
    Ok(Some(OriginPosition {
        kind,
        carrier: *blake3::hash(&raw).as_bytes(),
        incarnation: born,
        facet,
        scope,
        sources,
        file,
    }))
}

/// Attests only current rows the real guest export already selected.
pub(crate) fn witness_connect_positions(
    vault: &Vault,
    update: &[u8],
    grant: &FederationGrant,
    selector: &SyncSelector,
) -> Result<Option<Vec<u8>>> {
    let doc = LoroDoc::new();
    doc.import(&update)
        .map_err(|_| Error::InvalidConfig("Connect window does not decode".into()))?;
    let txn = vault.store.env.read_txn()?;
    let crate::vault::LiveEntityRow::Live { entity_type, body } =
        crate::vault::live_entity_row_in_txn(&vault.store, &txn, &selector.grant_id)?
    else {
        return Ok(None);
    };
    if entity_type != ENTITY_TYPE_FEDERATION_GRANT
        || crate::federation::decode_federation_grant_body(&body)? != *grant
    {
        return Ok(None);
    }
    let mut rows = Vec::new();
    map_for_each_value_bytes(&doc.get_map("entities"), |key, raw| {
        if raw.is_some_and(|raw| raw.first().is_some_and(|kind| placed_kind(*kind)))
            && let Ok(id) = EntityId::from_hex(key)
            && id.to_hex() == key
        {
            rows.push(id);
        }
    });
    // The worlds this window may carry a position in: the grant's, met with
    // the window's own (FIX 22223).
    let window = super::note_world::selector_world_axis(selector.world);
    let ceilings = [&grant.authority_scope.worlds, &window];
    let mut positions = BTreeMap::new();
    for id in rows {
        if let Some(position) = source_position(vault, &txn, &doc, id, grant, &ceilings)? {
            positions.insert(id, position);
        }
    }
    // A caption carries its position only beside every source's, each an
    // ASSET born under the caption's facet.
    let unbacked: BTreeSet<EntityId> = positions
        .iter()
        .filter(|(_, position)| {
            position.kind == ENTITY_TYPE_ASSET_TEXT
                && !position.sources.iter().all(|source| {
                    positions.get(source).is_some_and(|backing| {
                        backing.kind == ENTITY_TYPE_ASSET && backing.facet == position.facet
                    })
                })
        })
        .map(|(id, _)| *id)
        .collect();
    positions.retain(|id, _| !unbacked.contains(id));
    if positions.is_empty() {
        return Ok(None);
    }
    let map = doc.get_map(ORIGIN_POSITIONS);
    for (id, position) in positions {
        let bytes = rmp_serde::to_vec_named(&position)
            .map_err(|_| Error::InvalidConfig("Connect position does not encode".into()))?;
        map_insert_bytes(&map, &id.to_hex(), &bytes)?;
    }
    doc.commit();
    let update = doc
        .export(ExportMode::all_updates())
        .map_err(|error| Error::sync_engine(SyncEngineContext::LoroExportAllUpdates, error))?;
    // Optional proof bytes must not make a previously admitted raw update too large.
    Ok((update.len() <= crate::sync::transport::MAX_DECODED_PAYLOAD_BYTES).then_some(update))
}

fn recipient_position(
    position: &OriginPosition,
    source: &[u8; 32],
    inbound: &crate::federation::FederationDirectionScope,
    body: &crate::authority::ConnectWindow,
) -> Result<Option<Scope>> {
    let facets = if body.facets.is_empty() {
        inbound.facets.clone()
    } else {
        body.facets.iter().copied().map(ScopeId).collect()
    };
    let bands = if body.bands.is_empty() {
        inbound.bands.clone()
    } else {
        body.bands.iter().copied().collect()
    };
    let scope = &position.scope;
    // The position names the one sender world this signed window carries
    // (FIX 22223); it lands in this vault's copy of that world.
    if scope.worlds != singleton(ScopeId(body.world_ref))
        || scope.facets != singleton(ScopeId(position.facet))
        || scope.bands != singleton(position.kind)
        || scope.verbs != ScopeAxis::Bottom
        || !scope.facets.is_narrowing_of(&facets)
        || !crate::federation::selector_range_of(position.kind)
            .is_some_and(|band| bands.contains(&band))
    {
        return Ok(None);
    }
    let foreign = crate::federation::foreign_world_for(source, body.world_ref)?;
    Ok(Some(Scope {
        worlds: singleton(ScopeId(foreign.entity_id())),
        ..scope.clone()
    }))
}

/// Consumes a token only the already verified Connect caller can construct.
pub(crate) fn import_connect_positions(
    vault: &Vault,
    verified: &VerifiedConnectOrigin<'_>,
) -> Result<()> {
    let body = verified.body();
    let doc = LoroDoc::new();
    doc.import(&body.update)
        .map_err(|_| Error::InvalidConfig("Connect window does not decode".into()))?;
    let mut positions = BTreeMap::new();
    map_for_each_value_bytes(&doc.get_map(ORIGIN_POSITIONS), |key, bytes| {
        if let (Ok(id), Some(bytes)) = (EntityId::from_hex(key), bytes)
            && id.to_hex() == key
            && let Ok(position) = rmp_serde::from_slice::<OriginPosition>(bytes)
            && rmp_serde::to_vec_named(&position).ok().as_deref() == Some(bytes)
            && placed_kind(position.kind)
        {
            positions.insert(id, position);
        }
    });
    if positions.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|txn| {
        let fold = vault.authority_fold_readonly_in_txn(txn)?;
        let Some(state) = fold.federation_pacts.get(&verified.pact()) else {
            return Ok(());
        };
        let crate::vault::LiveEntityRow::Live {
            entity_type,
            body: grant_body,
        } = crate::vault::live_entity_row_in_txn(&vault.store, txn, &state.grant_ref)?
        else {
            return Ok(());
        };
        if entity_type != ENTITY_TYPE_FEDERATION_GRANT
            || crate::federation::decode_federation_grant_body(&grant_body)? != *verified.grant()
        {
            return Ok(());
        }
        let signed = verified.state();
        if fold.vault_id != Some(verified.local())
            || state.status != FederationPactStatus::Active
            || state.peer_vault_id != signed.peer_vault_id
            || state.peer_owner_key != signed.peer_owner_key
            || state.pact_epoch != signed.pact_epoch
            || state.grant_ref != signed.grant_ref
            || state.pact_scope != signed.pact_scope
        {
            return Ok(());
        }
        let Ok(delivery) = fold.active_pact_delivery(&state.grant_ref) else {
            return Ok(());
        };
        if delivery.pact != verified.pact()
            || delivery.epoch != body.epoch
            || delivery.source_vault != state.peer_vault_id
        {
            return Ok(());
        }
        let inbound = if verified.local() <= state.peer_vault_id {
            &state.pact_scope.hi_to_lo
        } else {
            &state.pact_scope.lo_to_hi
        };
        let mut admitted_sources = BTreeSet::new();
        let mut changed = false;
        // Sources land before the captions they back.
        for kind in [ENTITY_TYPE_NOTE, ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT] {
            for (id, position) in positions
                .iter()
                .filter(|(_, position)| position.kind == kind)
            {
                let Some(scope) =
                    recipient_position(position, &delivery.source_vault, inbound, body)?
                else {
                    continue;
                };
                let Some((raw, born)) = current_row(vault, txn, &doc, *id)? else {
                    continue;
                };
                // The carrier holds no `FacetOf` edge (see `source_facet`);
                // a stored one must name the signed facet.
                let facet = position.facet;
                if raw[0] != kind
                    || related_in_store(vault, txn, *id, EdgeKind::FacetOf)?
                        .iter()
                        .any(|stored| *stored != facet)
                    || born != position.incarnation
                    || *blake3::hash(&raw).as_bytes() != position.carrier
                    || file_facts(vault, txn, &doc, *id, &raw)? != Some(position.file.clone())
                {
                    continue;
                }
                if kind == ENTITY_TYPE_ASSET_TEXT
                    && (position.sources.is_empty()
                        || related_in_doc(&doc, *id, EdgeKind::DerivedFrom) != position.sources
                        || related_in_store(vault, txn, *id, EdgeKind::DerivedFrom)?
                            != position.sources
                        || !position.sources.is_subset(&admitted_sources))
                {
                    continue;
                }
                // The row must already sit in the signed foreign world here:
                // its `InWorld` edge (a caption's, its sources') landed on this
                // vault's copy of the world. A row whose edge is still
                // deferred, because no WORLD row for that copy exists here yet,
                // reads as base reality, and a stamp beside it would place a
                // guest's row in base under the sender's facet (FIX 22223).
                // Its position waits for a later Connect, once the edge lands.
                if super::note_world::live_worlds_in(&vault.store, txn, *id, kind).axis()
                    != scope.worlds
                {
                    continue;
                }
                if let Some(prior) = SCOPE_RECORD.get(&vault.store, txn, id)? {
                    if prior.version != 2
                        || prior.kind != kind
                        || prior.birth_facet != *facet.as_bytes()
                        || prior.scope != scope
                    {
                        continue;
                    }
                } else {
                    SCOPE_RECORD.put(
                        &vault.store,
                        txn,
                        id,
                        &Stamp {
                            version: 2,
                            kind,
                            birth_facet: *facet.as_bytes(),
                            scope,
                        },
                    )?;
                    // With no edge to the sender's FACET here, the stamp's
                    // facet is kept beside it, where `birth_facet` reads it.
                    if related_in_store(vault, txn, *id, EdgeKind::FacetOf)?.is_empty() {
                        ORIGIN_FACET.put(&vault.store, txn, id, &facet)?;
                    }
                    changed = true;
                }
                if kind == ENTITY_TYPE_ASSET {
                    admitted_sources.insert(*id);
                }
            }
        }
        if changed {
            bump_scope_revision(&vault.store, txn)?;
        }
        Ok(())
    })
}
