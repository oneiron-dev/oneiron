//! The member's native replica manifest and window reads, admitted before disclosure.

use std::collections::{BTreeSet, HashMap};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use loro::{ExportMode, LoroDoc};
use serde::{Deserialize, Serialize};

use crate::authority::{
    AuthorityEntryHash, PeerMachine, authority_entry_hash, authority_log_entity_id,
    decode_authority_log_entry_body,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result, SyncEngineContext, SyncError};
use crate::federation::record_scope::record_world_in;
use crate::federation::{
    FIRST_PARTY_MEMBER_ROLES, FederationGrantScope, Position, Scope, ScopeId,
    decode_federation_grant_body, live_federation_grant_in,
};
use crate::provenance::birth::WithheldKey;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::sync::selector::{
    SyncSelector, SyncSelectorWorld, authorize_selector_export_in_txn, check_authority_history,
    check_projection_history, decode_sync_selector, encode_sync_selector, project_source,
};
use crate::sync::window::{Withhold, apply_pending_window_updates, load_window_from_state};
use crate::sync::{WindowKey, discover_local_window_keys, filtered_window_doc_for_peer_in_scope};
use crate::{EntityId, Vault};

/// `vault.members.replica_manifest` input: the selected logical vault and the
/// member's grant, hex. The door already matched it semantically to the slip.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedReplicaManifestRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    pub grant: String,
}

/// `vault.members.replica_manifest` answer: canonical grant echo, strict
/// selector bytes, original signed bodies parent-first, advisory window keys.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedReplicaManifest {
    pub grant: String,
    pub selector: String,
    pub entries: Vec<String>,
    pub windows: Vec<String>,
}

/// `vault.members.replica_window` input: logical vault, grant, window key and
/// the manifest selector echo. Nothing here is trusted until the final gate.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedReplicaWindowRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    pub grant: String,
    pub window: String,
    pub selector: String,
}

/// `vault.members.replica_window` answer: the requested key and its filtered
/// snapshot bytes. Base docs read for world-edge checks never ride along.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedReplicaWindow {
    pub window: String,
    pub update: String,
}

/// The final gate's authoritative read under one caller snapshot.
struct FinalGate {
    expected: SyncSelector,
    position: Position,
    authority_scope: Scope,
    flagged: BTreeSet<EntityId>,
}

/// Live person, creation, live grant, native position, met scope, Unknown
/// destination flags. Revalidation only: the transport already spent this
/// request's nonce, and nothing here admits again.
fn final_gate(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reader: &AuthenticatedOwner,
    served: &Scope,
    vault_id: u64,
    grant_id: EntityId,
) -> Result<FinalGate> {
    if vault_id == 0 {
        return Err(invalid());
    }
    let person = reader.revalidate_person_in_txn(vault, txn)?;
    let creation = vault
        .shared_vault_creation_in_txn(txn)?
        .ok_or_else(invalid)?;
    if creation.vault_id == 0 || creation.vault_id != vault_id {
        return Err(invalid());
    }
    let grant_raw = live_federation_grant_in(vault, txn, &grant_id)?;
    let grant = decode_federation_grant_body(&grant_raw[ENTITY_METADATA_HEADER_LEN..])?;
    if grant.scope != FederationGrantScope::vault(vault_id)
        || grant.member_ref != person
        || !FIRST_PARTY_MEMBER_ROLES.contains(&grant.role)
    {
        return Err(invalid());
    }
    let expected = SyncSelector::new(
        grant_id,
        person,
        SyncSelectorWorld::All,
        Vec::new(),
        Vec::new(),
    );
    let position = authorize_selector_export_in_txn(
        vault,
        txn,
        FederationGrantScope::vault(vault_id),
        &expected,
        vault.now_recorded_at(),
    )?;
    let authority_scope = grant.authority_scope.meet(served);
    let flagged = Withhold::Peer(PeerMachine::Unknown).worlds_in(vault, txn)?;
    Ok(FinalGate {
        expected,
        position,
        authority_scope,
        flagged,
    })
}

/// Whether `key` names a world window this member may not hold: flagged for
/// the Unknown destination or outside the grant and position worlds.
fn withheld_window(gate: &FinalGate, key: &WindowKey) -> bool {
    key.world().is_some_and(|world| {
        gate.flagged.contains(&world)
            || !gate.authority_scope.worlds.contains(&ScopeId(world))
            || !gate.position.as_scope().worlds.contains(&ScopeId(world))
    })
}

/// The history bodies this member may hold, with their content ids, in the
/// original parent-first order. Side-world rows outside the grant and position
/// worlds or flagged for the Unknown destination are omitted; main ancestry
/// stays complete, and the remainder keeps every parent it names. Every other
/// failure refuses (the reused checker verifies stored rows, selection, world
/// and use limits). Store and corruption errors propagate, never omit.
fn admitted_history(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    gate: &FinalGate,
    bodies: &[Vec<u8>],
) -> Result<Vec<(EntityId, Vec<u8>)>> {
    struct Row {
        hash: AuthorityEntryHash,
        id: EntityId,
        body: Vec<u8>,
        parents: Vec<AuthorityEntryHash>,
        world: Option<EntityId>,
    }
    let mut rows = Vec::with_capacity(bodies.len());
    for body in bodies {
        let entry = decode_authority_log_entry_body(body)?;
        let hash = authority_entry_hash(&entry)?;
        let id = authority_log_entity_id(&entry)?;
        let world = record_world_in(
            &vault.store,
            txn,
            id,
            ENTITY_TYPE_AUTHORITY_LOG,
            body.as_slice(),
        )?
        .ok_or_else(invalid)?;
        rows.push(Row {
            hash,
            id,
            body: body.clone(),
            parents: entry.parent_hashes.clone(),
            world,
        });
    }
    let mut omitted = BTreeSet::new();
    for row in &rows {
        if let Some(world) = row.world {
            let scoped = ScopeId(world);
            if !gate.authority_scope.worlds.contains(&scoped)
                || !gate.position.as_scope().worlds.contains(&scoped)
                || gate.flagged.contains(&world)
            {
                omitted.insert(row.hash);
            }
        }
    }
    let kept: BTreeSet<AuthorityEntryHash> = rows
        .iter()
        .filter(|row| !omitted.contains(&row.hash))
        .map(|row| row.hash)
        .collect();
    for row in &rows {
        if omitted.contains(&row.hash) {
            continue;
        }
        for parent in &row.parents {
            if !kept.contains(parent) {
                return Err(invalid());
            }
        }
    }
    let remainder: Vec<(EntityId, Vec<u8>)> = rows
        .iter()
        .filter(|row| !omitted.contains(&row.hash))
        .map(|row| (row.id, row.body.clone()))
        .collect();
    check_authority_history(
        vault,
        txn,
        &remainder,
        &gate.authority_scope,
        &gate.expected,
        &gate.position,
    )?;
    Ok(remainder)
}

/// The manifest and the transmitted history ids beside it. Native preparation
/// discovers advisory keys first; the original signed history and its read
/// authority come from the same final snapshot, with Unknown flags applied.
pub(crate) fn manifest_listing(
    vault: &Vault,
    reader: &AuthenticatedOwner,
    served: &Scope,
    input: SharedReplicaManifestRequest,
) -> Result<(SharedReplicaManifest, Vec<EntityId>)> {
    let grant_id = EntityId::from_hex(&input.grant).map_err(|_| invalid())?;
    let prepared_keys = discover_local_window_keys(vault)?;
    let txn = vault.store.env.read_txn()?;
    let gate = final_gate(vault, &txn, reader, served, input.vault_id, grant_id)?;
    let history_final = vault.export_signed_authority_history_in_txn(&txn)?;
    let remainder = admitted_history(vault, &txn, &gate, &history_final)?;
    let windows: Vec<String> = prepared_keys
        .iter()
        .filter(|key| !withheld_window(&gate, key))
        .map(|key| key.as_str().to_owned())
        .collect();
    let selector_bytes = encode_sync_selector(&gate.expected)?;
    let ids: Vec<EntityId> = remainder.iter().map(|(id, _)| *id).collect();
    drop(txn);
    let manifest = SharedReplicaManifest {
        grant: grant_id.to_hex(),
        selector: STANDARD.encode(selector_bytes),
        entries: remainder
            .iter()
            .map(|(_, body)| STANDARD.encode(body))
            .collect(),
        windows,
    };
    Ok((manifest, ids))
}

/// One filtered window and its outgoing entity ids beside it. Preparation runs
/// the native Unknown-destination peer export (refresh, reverse remat, filter,
/// eligible companions, born-with carry) under an authentic preliminary
/// selector; the final gate re-derives the expected selector, requires the
/// echo to equal it, re-verifies replica entitlement over raw history, and
/// requires the prepared snapshot to sit inside the final native projection.
pub(crate) fn window_listing(
    vault: &Vault,
    reader: &AuthenticatedOwner,
    served: &Scope,
    input: SharedReplicaWindowRequest,
) -> Result<(SharedReplicaWindow, Vec<EntityId>)> {
    let grant_id = EntityId::from_hex(&input.grant).map_err(|_| invalid())?;
    let key = WindowKey::try_new(input.window.clone()).ok_or_else(invalid)?;
    let echo_bytes = STANDARD.decode(&input.selector).map_err(|_| invalid())?;
    let echo = decode_sync_selector(&echo_bytes)?;
    let prelim = {
        let txn = vault.store.env.read_txn()?;
        let person = reader.revalidate_person_in_txn(vault, &txn)?;
        let grant_raw = live_federation_grant_in(vault, &txn, &grant_id)?;
        let grant = decode_federation_grant_body(&grant_raw[ENTITY_METADATA_HEADER_LEN..])?;
        if grant.member_ref != person {
            return Err(invalid());
        }
        SyncSelector::new(
            grant_id,
            person,
            SyncSelectorWorld::All,
            Vec::new(),
            Vec::new(),
        )
    };
    let source_doc = native_window(vault, &key)?;
    let filtered = filtered_window_doc_for_peer_in_scope(
        vault,
        &source_doc,
        &key,
        FederationGrantScope::vault(input.vault_id),
        &prelim,
        PeerMachine::Unknown,
        Some(served),
    )?;
    let base_docs = native_bases(vault, &key, &filtered, &prelim, served, input.vault_id)?;
    let update = filtered
        .export(ExportMode::Snapshot)
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportSnapshot, e))?;
    let mut outgoing: Vec<EntityId> = Vec::new();
    crate::sync::loro_support::map_for_each_value_bytes(
        &filtered.get_map("entities"),
        |name, value| {
            if value.is_some()
                && let Ok(id) = EntityId::from_hex(name)
                && id.to_hex() == name
            {
                outgoing.push(id);
            }
        },
    );
    let txn = vault.store.env.read_txn()?;
    let gate = final_gate(vault, &txn, reader, served, input.vault_id, grant_id)?;
    if echo != gate.expected {
        return Err(invalid());
    }
    if withheld_window(&gate, &key) {
        return Err(invalid());
    }
    let history_final = vault.export_signed_authority_history_in_txn(&txn)?;
    admitted_history(vault, &txn, &gate, &history_final)?;
    let sources: HashMap<&str, &LoroDoc> = base_docs
        .iter()
        .map(|(name, doc)| (name.as_str(), doc))
        .collect();
    let destination_key = WithheldKey::fresh();
    let projected = project_source(
        vault,
        &txn,
        &filtered,
        &key,
        &gate.expected,
        &gate.position,
        FederationGrantScope::vault(input.vault_id),
        &gate.authority_scope,
        served,
        &destination_key,
        &sources,
        &gate.flagged,
        Withhold::Worlds(&gate.flagged),
    )?;
    drop(txn);
    check_projection_history(update.as_slice(), &projected)?;
    let reply = SharedReplicaWindow {
        window: key.as_str().to_owned(),
        update: STANDARD.encode(&update),
    };
    Ok((reply, outgoing))
}

/// The existing selector loader also recovers a not-yet-snapshotted window
/// from its native pending updates before the ordinary peer export remats it.
fn native_window(vault: &Vault, key: &WindowKey) -> Result<LoroDoc> {
    match load_window_from_state(vault, "shared-replica", key) {
        Ok(doc) => Ok(doc),
        Err(Error::Sync(SyncError::WindowNotFound { .. })) => {
            let doc = crate::sync::schema::create_window_doc("shared-replica", key);
            apply_pending_window_updates(vault, &doc, key)?;
            Ok(doc)
        }
        Err(error) => Err(error),
    }
}

/// Only the real base months named by this world window's edge endpoints.
/// These native projections authorize endpoints; none of their bytes leave.
fn native_bases(
    vault: &Vault,
    key: &WindowKey,
    source: &LoroDoc,
    selector: &SyncSelector,
    served: &Scope,
    vault_id: u64,
) -> Result<HashMap<String, LoroDoc>> {
    let mut docs = HashMap::new();
    if key.world().is_none() {
        return Ok(docs);
    }
    let mut endpoints = BTreeSet::new();
    crate::sync::loro_support::map_for_each_value_bytes(&source.get_map("edges"), |name, value| {
        if value.is_some()
            && let Some((from, _, to)) = crate::sync::bridge::parse_edge_key(name)
        {
            endpoints.insert(from);
            endpoints.insert(to);
        }
    });
    let mut keys = std::collections::BTreeMap::new();
    {
        let txn = vault.store.env.read_txn()?;
        for id in endpoints {
            let Some(raw) = vault.get_raw_in(&txn, &id)? else {
                continue;
            };
            if crate::sync::types::entity_world(&raw)?.is_some() {
                continue;
            }
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("entity metadata"))?;
            let base = WindowKey::from_timestamp(header.learned_at);
            keys.insert(base.as_str().to_owned(), base);
        }
    }
    for (name, base) in keys {
        let raw = native_window(vault, &base)?;
        let selected = filtered_window_doc_for_peer_in_scope(
            vault,
            &raw,
            &base,
            FederationGrantScope::vault(vault_id),
            selector,
            PeerMachine::Unknown,
            Some(served),
        )?;
        docs.insert(name, selected);
    }
    Ok(docs)
}

fn invalid() -> Error {
    Error::InvalidConfig(
        "shared replica source does not match its accepted member and batch".into(),
    )
}
