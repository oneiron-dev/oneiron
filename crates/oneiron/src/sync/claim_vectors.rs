//! FIX 7791: a CLAIM's cloud-filled vector on the window plane.
//!
//! ARCH-0035: vector rows are derived, but a vector a cloud rung computed
//! is the same row on every one of the owner's machines, so it rides beside
//! its claim body instead of being re-embedded per device. The on-device
//! route never rides: a locally filled vector is re-embedded locally, as
//! today. Only the owner's machines take the map: the selector copies no
//! side map to a federated or guest window.
//!
//! - The stored EMB-3 row travels verbatim, never re-encoded, under its
//!   claim, and only beside that claim's body in the same window.
//! - The carrier names the body it was embedded from (`body_digest`): a
//!   superseded or transformed body drops the vector and takes the ordinary
//!   pending-embedding path.
//! - `route` is the sender's rung id (`model@place`) reconstructed from its
//!   stored provenance through the one producer (`offer_id`/`offer_place`).
//!   Reconstruction is a fail-closed heuristic: a row filled behind
//!   `embedder serve` spells no place and never rides; a GPU pod's
//!   per-lease base spells a place no order can name, so its row rides
//!   and never matches.
//!   The receiver never parses the route; its world order admits it by
//!   whole-string equality or the row re-embeds.
//! - Admission refuses every insert that is not a whole, well-formed
//!   carrier filed under a claim id, in the latest state, at a snapshot's
//!   root and in every retained operation. World windows take the map:
//!   claims live there too, and route policy is judged per row at take time.
//! - Every export, and the erase sweep, drop the vector of a claim this
//!   vault erased or the window does not carry.

pub(super) mod checkpoint;

use loro::{CommitOptions, LoroDoc, LoroMap, LoroValue, ValueOrContainer};
use serde::{Deserialize, Serialize};

use super::bridge::BRIDGE_ORIGIN;
use super::loro_support::{map_contains_binary, map_delete, map_get_bytes, map_insert_bytes};
use super::types::WindowKey;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::embed::{EmbedderLocality, EmbeddingProvenance};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::run_admission::{offer_id, offer_place};
use crate::ports::{IndexMetaKey, RetrievalIndexInventory};
use crate::{ModelId, ModelLocality, Vault};

/// The window root map that carries CLAIM vectors beside their bodies.
pub(crate) const CLAIM_VECTORS_MAP: &str = "claim_vectors";

/// The locality byte of a vector filled on the owner's own server.
pub(crate) const LOCALITY_OWNER_SERVER: u8 = 1;
/// The locality byte of a vector filled by a third party.
pub(crate) const LOCALITY_THIRD_PARTY: u8 = 2;

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("claim vector refused: {reason}"))
}

/// One claim's cloud-filled vector as a window carries it, filed under the
/// claim id it embeds. The row is the stored EMB-3 bytes verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CarriedVector {
    /// The sender vault's embedding space id, `org/name@revision`.
    pub model_id: String,
    /// The row's dimension count: `(row.len() - 1) / 2`.
    pub dims: u64,
    /// The sender rung's `model@place` route id, reconstructed at export.
    pub route: String,
    /// The sender's embedding transform pin, where it pins one.
    pub transform: Option<String>,
    /// Where the vector was filled: 1 owner server, 2 third party.
    pub locality: u8,
    /// blake3 of the claim BODY bytes (no entity header) it embeds.
    pub body_digest: [u8; 32],
    /// The sender row's device provenance, carried for the receiver's mark.
    pub provenance: EmbeddingProvenance,
    /// The stored EMB-3 v1 row, byte for byte.
    pub row: Vec<u8>,
}

/// The digest that binds a carried vector to its claim body bytes.
pub(crate) fn claim_body_digest(body: &[u8]) -> [u8; 32] {
    *blake3::hash(body).as_bytes()
}

fn encode(carried: &CarriedVector) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(carried).map_err(|_| refused("does not encode"))
}

/// Decodes a carried vector. A carrier has one spelling.
fn decode(bytes: &[u8]) -> Result<CarriedVector> {
    let carried: CarriedVector =
        rmp_serde::from_slice(bytes).map_err(|_| refused("not a claim vector"))?;
    if encode(&carried)? != bytes {
        return Err(refused("not in its one spelling"));
    }
    Ok(carried)
}

/// The most dimensions a carried row may name: past every served
/// embedder, short of a decode a window writer could weaponize.
const MAX_CARRIED_DIMS: usize = 16_384;

/// The vault-agnostic shape of a whole carrier: a real space id, a route
/// an order could name, a cloud locality, and a structurally sound EMB-3
/// row of finite values whose length its `dims` names.
fn well_formed(carried: &CarriedVector) -> bool {
    if crate::store::validate_embedding_model_id(&carried.model_id).is_err()
        || !matches!(
            carried.locality,
            LOCALITY_OWNER_SERVER | LOCALITY_THIRD_PARTY
        )
        || carried.route.is_empty()
        || carried.route.len() > 128
        || carried.route.chars().any(char::is_control)
        || carried.row.len() < 3
        || (carried.row.len() - 1) % 2 != 0
        || (carried.row.len() - 1) / 2 > MAX_CARRIED_DIMS
        || carried
            .transform
            .as_ref()
            .is_some_and(|pin| pin.len() > 512)
        || carried.provenance.runtime.len() > 2048
    {
        return false;
    }
    let dims = (carried.row.len() - 1) / 2;
    u64::try_from(dims) == Ok(carried.dims)
        && crate::store::decode_vector_row(&carried.row, dims)
            .is_ok_and(|values| values.iter().all(|value| value.is_finite()))
}

/// Admits one insert into a window's `claim_vectors` map: a whole carrier
/// filed under its claim. The map holds whole rows only, never parts.
pub(crate) fn admit_claim_vector_carrier(
    _key: Option<&WindowKey>,
    map_key: &str,
    value: &LoroValue,
) -> Result<()> {
    if !EntityId::from_hex(map_key).is_ok_and(|id| id.to_hex() == map_key) {
        return Err(refused("filed under a non-claim key"));
    }
    let LoroValue::Binary(bytes) = value else {
        return Err(refused("not bytes"));
    };
    let carried = decode(bytes)?;
    if !well_formed(&carried) {
        return Err(refused("not a whole carrier"));
    }
    Ok(())
}

/// [`admit_claim_vector_carrier`] over every row `map` holds.
pub(crate) fn admit_claim_vector_map(key: Option<&WindowKey>, map: &LoroMap) -> Result<()> {
    let mut rows = Vec::new();
    let mut nested = false;
    map.for_each(|map_key, value| match value {
        ValueOrContainer::Value(value) => rows.push((map_key.to_owned(), value)),
        ValueOrContainer::Container(_) => nested = true,
    });
    if nested {
        return Err(refused("nested container"));
    }
    for (map_key, value) in &rows {
        admit_claim_vector_carrier(key, map_key, value)?;
    }
    Ok(())
}

/// The sender rung's route id, reconstructed from a stored row's
/// provenance: the space id is this vault's own, and the place is the
/// endpoint its fill answer named, spelled through the one producer the
/// ladder and the rung build share. `None` wherever the answer named no
/// endpoint URL (an `embedder serve` candle mark) -- the row then never
/// rides, and the receiver re-embeds. A per-lease pod URL does
/// reconstruct, to a place no receiver order names: the row rides and
/// never matches. The endpoint's explicit default port is
/// kept byte-for-byte, where the rung's own mint normalized it away: such
/// a route simply matches no order entry. Fail closed throughout.
fn reconstruct_route(model_id: &str, runtime: &str, locality: ModelLocality) -> Option<String> {
    let model = ModelId::new(model_id).ok()?;
    for (at, _) in runtime.match_indices('@') {
        let base = &runtime[at + 1..];
        if !base.contains("://") {
            continue;
        }
        let place = offer_place(locality, base);
        if !place.is_empty() && place != locality.as_str() {
            return Some(offer_id(&model, &place));
        }
    }
    None
}

fn read_meta_text(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    key: IndexMetaKey,
) -> Result<Option<String>> {
    vault.store.port_index_meta_with_raw(rtxn, key, |bytes| {
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| Error::CorruptedIndex("embedding space record"))
    })
}

/// Writes into `doc` the vector CLAIM `id` holds here, when it was filled
/// off this device and the window's copy is not already this exact row for
/// this exact body. Every skip is a row the receiver locally re-embeds:
/// no body beside it in the window, no settled vector, an on-device fill,
/// no declared space, or no route its provenance can spell. Body, row and
/// marks read in one transaction, so the carrier binds one instant's body
/// digest to that same instant's row. Commits on its own; returns whether
/// it wrote.
pub(crate) fn mirror_claim_vector(vault: &Vault, doc: &LoroDoc, id: &EntityId) -> Result<bool> {
    let hex = id.to_hex();
    if !map_contains_binary(&doc.get_map("entities"), &hex) {
        return Ok(false);
    }
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .get_raw_in(&rtxn, id)?
        .and_then(|raw| crate::world_keys::live_route_row(&vault.store, raw))
    else {
        return Ok(false);
    };
    if !EntityMetadataHeader::parse(&raw)
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
    {
        return Ok(false);
    }
    let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
        return Ok(false);
    };
    let (locality_byte, model_locality) = match vault.embedding_locality_in_txn(&rtxn, id)? {
        Some(EmbedderLocality::OwnerServer) => (LOCALITY_OWNER_SERVER, ModelLocality::OwnServer),
        Some(EmbedderLocality::ThirdParty) => (LOCALITY_THIRD_PARTY, ModelLocality::ThirdParty),
        _ => return Ok(false),
    };
    let Some(row) = vault
        .store
        .port_vector_with_raw(&rtxn, id, |bytes| Ok(bytes.to_vec()))?
    else {
        return Ok(false);
    };
    let Some(model_id) = read_meta_text(vault, &rtxn, IndexMetaKey::ModelId)? else {
        return Ok(false);
    };
    let Some(provenance) = vault.embedding_provenance_in_txn(&rtxn, id)? else {
        return Ok(false);
    };
    let Some(route) = reconstruct_route(&model_id, &provenance.runtime, model_locality) else {
        tracing::debug!(claim = %hex, "claim vector spells no route; stays on this machine");
        return Ok(false);
    };
    if row.len() < 3 || (row.len() - 1) % 2 != 0 {
        return Ok(false);
    }
    let Ok(dims) = u64::try_from((row.len() - 1) / 2) else {
        return Ok(false);
    };
    let transform = match read_meta_text(vault, &rtxn, IndexMetaKey::EmbeddingTransform)? {
        Some(pin) => Some(pin),
        None => vault.config.embedding_transform.clone(),
    };
    let carried = CarriedVector {
        model_id,
        dims,
        route,
        transform,
        locality: locality_byte,
        body_digest: claim_body_digest(body),
        provenance,
        row,
    };
    // Never write a carrier this machine's own admission would refuse.
    if !well_formed(&carried) {
        return Ok(false);
    }
    let map = doc.get_map(CLAIM_VECTORS_MAP);
    if map_get_bytes(&map, &hex)
        .and_then(|bytes| decode(&bytes).ok())
        .is_some_and(|held| held.body_digest == carried.body_digest && held.row == carried.row)
    {
        return Ok(false);
    }
    map_insert_bytes(&map, &hex, &encode(&carried)?)?;
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    Ok(true)
}

/// The well-formed carrier `doc` holds for claim `id`, where it holds one:
/// the receive side's read, taken inside the body's own put.
pub(crate) fn take_claim_vector(doc: &LoroDoc, id: &EntityId) -> Option<CarriedVector> {
    if !holds_claim_vector_map(doc) {
        return None;
    }
    let map = doc.get_map(CLAIM_VECTORS_MAP);
    let carried = decode(&map_get_bytes(&map, &id.to_hex())?).ok()?;
    well_formed(&carried).then_some(carried)
}

/// Whether `doc` holds a claim vector map. Looking a root up by name
/// creates it: look first.
fn holds_claim_vector_map(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(CLAIM_VECTORS_MAP))
}

/// Drops from `doc` the vector of each claim this vault erased or the
/// window no longer carries: erase wins over a vector, and a vector never
/// rides where its body does not. `history_free` names the window pinned
/// history-free before any row goes; the sweep passes `None`. Returns
/// whether a row went, committed.
pub(crate) fn scrub_claim_vectors(
    vault: &Vault,
    doc: &LoroDoc,
    history_free: Option<&WindowKey>,
) -> Result<bool> {
    if !holds_claim_vector_map(doc) {
        return Ok(false);
    }
    let map = doc.get_map(CLAIM_VECTORS_MAP);
    let entities = doc.get_map("entities");
    let mut filed = Vec::new();
    map.for_each(|map_key, value| {
        if let ValueOrContainer::Value(LoroValue::Binary(_)) = value {
            filed.push(map_key.to_owned());
        }
    });
    let mut gone = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for map_key in filed {
            let erased = match EntityId::from_hex(&map_key) {
                Ok(claim) => crate::ports::removed_in_txn(&vault.store, &rtxn, &claim)?,
                Err(_) => false,
            };
            if !map_contains_binary(&entities, &map_key) || erased {
                gone.push(map_key);
            }
        }
    }
    if gone.is_empty() {
        return Ok(false);
    }
    if let Some(key) = history_free {
        super::window::require_history_free_window(vault, key)?;
    }
    for map_key in &gone {
        map_delete(&map, map_key)?;
    }
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    Ok(true)
}
