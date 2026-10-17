//! Which models a node offers the owner's other nodes, and the row a node
//! writes for each one it hears of (FIX 1295). A node offers only its own
//! models, on that device or on the owner's own server; relaying a third
//! party's model across the mesh waits on canon Q3.

use std::collections::BTreeMap;

use oneiron::llm::LlmCatalogCost;
use oneiron::llm::registry::{ModelRegistryRow, ModelWireFormat};
use oneiron::{LlmCatalogEntry, ModelId, ModelLocality, Vault};
use oneiron_mesh_transport::MachineId;
use serde_json::Value as JsonValue;

/// Row metadata naming the node a mesh model row came from. A row that
/// carries it is discovery's own, and the next refresh may rewrite it.
pub const MESH_PEER: &str = "mesh_peer";
/// Row metadata saying the serving node declared no price: owned compute,
/// priced at zero.
pub const COST_DECLARED: &str = "cost_declared";

/// Whether a node offers a model that runs at `locality` to the owner's
/// other nodes: its own models only.
#[must_use]
pub fn advertises(locality: ModelLocality) -> bool {
    matches!(locality, ModelLocality::OnDevice | ModelLocality::OwnServer)
}

/// What one catalog refresh did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CatalogRefresh {
    /// Models the owner's other nodes serve, now routed to them.
    pub written: Vec<ModelId>,
    /// Models the vault already routes another way (a pack or local row).
    /// That row wins; no mesh row is written.
    pub conflicts: Vec<ModelId>,
    /// Why a node was not asked, or did not answer. Its rows stay.
    pub unreached: Vec<String>,
}

/// The row for a model `peer` offers: an own-server route at the price the
/// peer declared, or at zero when it declared none. `None` for a model the
/// peer may not offer, or one no row can hold.
pub(super) fn mesh_row(peer: MachineId, mut entry: LlmCatalogEntry) -> Option<ModelRegistryRow> {
    if !advertises(entry.locality) {
        return None;
    }
    // From this node, the call goes to the owner's own server.
    entry.locality = ModelLocality::OwnServer;
    if entry.cost.is_none() {
        entry.cost = Some(LlmCatalogCost {
            input_per_million: "0".to_owned(),
            output_per_million: "0".to_owned(),
            cache_read_per_million: None,
            cache_write_per_million: None,
        });
        entry
            .metadata
            .insert(COST_DECLARED.to_owned(), JsonValue::from("none"));
    }
    entry
        .metadata
        .insert(MESH_PEER.to_owned(), JsonValue::from(peer.to_hex()));
    let row = ModelRegistryRow {
        version: 1,
        wire: ModelWireFormat::OwnServer,
        catalog: entry,
        scores: BTreeMap::new(),
        fetched_at: BTreeMap::new(),
    };
    row.validate().ok().map(|()| row)
}

/// Writes `row` unless the vault routes its model another way. A row
/// discovery wrote before is refreshed, its scores kept. `Ok(false)` is a
/// conflict: the existing row wins.
pub(super) fn merge(vault: &Vault, mut row: ModelRegistryRow) -> oneiron::Result<bool> {
    match vault.model_registry_row(&row.catalog.model)? {
        None => {}
        Some(existing)
            if existing.wire == ModelWireFormat::OwnServer
                && existing.catalog.metadata.contains_key(MESH_PEER) =>
        {
            if existing.catalog == row.catalog {
                return Ok(true);
            }
            row.scores = existing.scores;
            row.fetched_at = existing.fetched_at;
        }
        Some(_) => return Ok(false),
    }
    vault.put_model_registry_row(&row)?;
    Ok(true)
}
