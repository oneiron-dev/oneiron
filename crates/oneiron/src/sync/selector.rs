//! Grant-backed closed-subgraph sync selectors.
//!
//! Existing full-window sync exports opaque Loro deltas from the canonical
//! window doc. Those bytes cannot be redacted safely after export, so selector
//! sync builds a synthetic window doc containing only the authorized closed
//! subgraph and exports from that doc instead.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Cursor;

use loro::{CommitOptions, ExportMode, LoroDoc};
use rmpv::Value;
#[cfg(feature = "sync")]
use xxhash_rust::xxh3::xxh3_64;

use crate::Vault;
use crate::authority::{
    AuthorityOp, decode_authority_log_entry_body, genesis_vault_id,
    validate_authority_log_entry_body_bytes,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimLifecycleStatus, restamp_federated_claim_source, validate_claim_body_and_decode,
};
use crate::error::{Error, Result};
use crate::federation::{FederationGrantScope, decode_federation_grant_body};
use crate::types::{
    CompanionExportClassification, CompanionScope, ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_COMPANION_REGISTER, ENTITY_TYPE_FACET, ENTITY_TYPE_FEDERATION_GRANT,
    ENTITY_TYPE_WORLD, EdgeKind, EntityId, TypeByteBand, band_of, decode_companion_record_body,
};

use super::bridge::parse_edge_key;
use super::loro_support::{
    map_for_each_tombstone_value, map_for_each_value_bytes, map_insert_bytes,
};
use super::schema::create_window_doc;
use super::types::WindowKey;

/// Current selector payload schema version.
pub const SYNC_SELECTOR_SCHEMA_VERSION: u64 = 1;

const SELECTOR_KEYS: [&str; 6] = [
    "schema_version",
    "grant_id",
    "member_ref",
    "world",
    "facets",
    "bands",
];
const KEY_SCHEMA_VERSION: &str = SELECTOR_KEYS[0];
const KEY_GRANT_ID: &str = SELECTOR_KEYS[1];
const KEY_MEMBER_REF: &str = SELECTOR_KEYS[2];
const KEY_WORLD: &str = SELECTOR_KEYS[3];
const KEY_FACETS: &str = SELECTOR_KEYS[4];
const KEY_BANDS: &str = SELECTOR_KEYS[5];

const WORLD_KEYS: [&str; 2] = ["kind", "id"];
const WORLD_KIND_ALL: &str = "all";
const WORLD_KIND_BASE: &str = "base";
const WORLD_KIND_WORLD: &str = "world";

const SELECTOR_VV_PREFIX_LEN: usize = 4;
pub(crate) const FEDERATED_TOMBSTONE_ADMISSION_ERROR: &str =
    "federated tombstone updates require delete admission";

/// World component of a closed-subgraph selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncSelectorWorld {
    /// Include base and all world-scoped claims.
    All,
    /// Include only base-reality claims.
    Base,
    /// Include base-reality claims and claims scoped to this world.
    World(EntityId),
}

/// Per-window closed-subgraph selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncSelector {
    /// Stored `FEDERATION_GRANT` entity that authorizes using the selector.
    pub grant_id: EntityId,
    /// Principal named by the selector. Must match the grant's `member_ref`.
    pub member_ref: EntityId,
    /// World filter applied to CLAIM bodies.
    pub world: SyncSelectorWorld,
    /// Allowed `FacetOf` targets. Empty means no facet filter.
    pub facets: Vec<EntityId>,
    /// Allowed entity type-byte bands. Empty means all bands.
    pub bands: Vec<TypeByteBand>,
}

impl SyncSelector {
    /// Constructs a selector with stable, deduplicated facet/band sets.
    #[must_use]
    pub fn new(
        grant_id: EntityId,
        member_ref: EntityId,
        world: SyncSelectorWorld,
        facets: Vec<EntityId>,
        bands: Vec<TypeByteBand>,
    ) -> Self {
        let facets = facets
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut normalized_bands = Vec::new();
        for band in [
            TypeByteBand::Semantic,
            TypeByteBand::Core,
            TypeByteBand::Companion,
            TypeByteBand::Productivity,
            TypeByteBand::Crm,
            TypeByteBand::InducedDynamicMaintenance,
        ] {
            if bands.contains(&band) {
                normalized_bands.push(band);
            }
        }
        Self {
            grant_id,
            member_ref,
            world,
            facets,
            bands: normalized_bands,
        }
    }

    fn facet_filter_active(&self) -> bool {
        !self.facets.is_empty()
    }

    fn band_filter_active(&self) -> bool {
        !self.bands.is_empty()
    }

    fn any_filter_active(&self) -> bool {
        self.facet_filter_active()
            || self.band_filter_active()
            || !matches!(self.world, SyncSelectorWorld::All)
    }
}

/// Decoded selector request payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorVvRequest {
    pub selector: SyncSelector,
    pub remote_vv: Vec<u8>,
}

/// Encodes `[selector_len:4BE][selector_msgpack][remote_vv]`.
pub fn encode_selector_vv_request(selector: &SyncSelector, remote_vv: &[u8]) -> Result<Vec<u8>> {
    let selector_bytes = encode_sync_selector(selector)?;
    let selector_len =
        u32::try_from(selector_bytes.len()).map_err(|_| selector_err("sync selector too large"))?;
    let mut out =
        Vec::with_capacity(SELECTOR_VV_PREFIX_LEN + selector_bytes.len() + remote_vv.len());
    out.extend_from_slice(&selector_len.to_be_bytes());
    out.extend_from_slice(&selector_bytes);
    out.extend_from_slice(remote_vv);
    Ok(out)
}

/// Decodes `[selector_len:4BE][selector_msgpack][remote_vv]`.
pub fn decode_selector_vv_request(bytes: &[u8]) -> Result<SelectorVvRequest> {
    if bytes.len() < SELECTOR_VV_PREFIX_LEN {
        return Err(selector_err("sync selector request too short"));
    }
    let selector_len = u32::from_be_bytes(
        bytes[..SELECTOR_VV_PREFIX_LEN]
            .try_into()
            .map_err(|_| selector_err("sync selector length"))?,
    ) as usize;
    let selector_end = SELECTOR_VV_PREFIX_LEN
        .checked_add(selector_len)
        .ok_or_else(|| selector_err("sync selector length overflow"))?;
    if selector_len == 0 || bytes.len() < selector_end {
        return Err(selector_err("sync selector request truncated"));
    }
    let selector = decode_sync_selector(&bytes[SELECTOR_VV_PREFIX_LEN..selector_end])?;
    Ok(SelectorVvRequest {
        selector,
        remote_vv: bytes[selector_end..].to_vec(),
    })
}

/// Encodes a selector as strict MessagePack.
pub fn encode_sync_selector(selector: &SyncSelector) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(SYNC_SELECTOR_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_GRANT_ID),
            Value::from(selector.grant_id.to_hex()),
        ),
        (
            Value::from(KEY_MEMBER_REF),
            Value::from(selector.member_ref.to_hex()),
        ),
        (Value::from(KEY_WORLD), encode_world(selector.world)),
        (
            Value::from(KEY_FACETS),
            Value::Array(
                selector
                    .facets
                    .iter()
                    .map(|facet| Value::from(facet.to_hex()))
                    .collect(),
            ),
        ),
        (
            Value::from(KEY_BANDS),
            Value::Array(
                selector
                    .bands
                    .iter()
                    .map(|band| Value::from(band_to_wire(*band)))
                    .collect(),
            ),
        ),
    ]);

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| selector_err("sync selector MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes a strict MessagePack selector.
pub fn decode_sync_selector(bytes: &[u8]) -> Result<SyncSelector> {
    let mut cursor = Cursor::new(bytes);
    let value =
        rmpv::decode::read_value(&mut cursor).map_err(|_| selector_err("sync selector decode"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(selector_err("sync selector trailing bytes"));
    }
    decode_selector_value(&value)
}

/// Validates the selector's grant and builds a filtered window doc.
pub fn filtered_window_doc(
    vault: &Vault,
    source: &LoroDoc,
    key: &WindowKey,
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
) -> Result<LoroDoc> {
    authorize_sync_selector(vault, grant_scope, selector)?;
    Ok(filter_window_doc(source, key, grant_scope, selector))
}

/// Role carried by a member/guest federation import path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FederationAdmissionRole {
    Member,
    Guest,
}

impl FederationAdmissionRole {
    const fn origin(self) -> &'static str {
        match self {
            Self::Member => "federation_admission.member",
            Self::Guest => "federation_admission.guest",
        }
    }
}

/// Produces locally admitted window update bytes for a member/guest federation
/// import.
///
/// The incoming CRDT update is decoded into an unobserved scratch doc. Claim
/// entities are re-stamped to `src=imported` and evaluated against the local
/// source-trust floor before any bytes are copied into the returned update.
/// The returned doc is freshly authored with a federation admission origin,
/// so callers can import it through the ordinary replay/materialization path
/// without giving the original remote op ids trust-blind write authority.
#[cfg(feature = "sync")]
pub fn admit_federated_window_update(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
) -> Result<Vec<u8>> {
    let remote = create_window_doc("federation-remote", key);
    remote
        .import(update)
        .map_err(|source| Error::CrdtDecodeError {
            context: "import federated update",
            source,
        })?;

    let admitted = create_admission_doc(key, update, role)?;
    let policy =
        vault.with_write_txn(|wtxn| crate::gate::resolve_policy_manifest(&vault.store, wtxn))?;

    reject_federated_tombstones(&remote)?;
    copy_admitted_entities(vault, &policy, &remote, &admitted)?;
    copy_binary_map(&remote.get_map("edges"), &admitted.get_map("edges"))?;

    admitted.commit_with(CommitOptions::new().origin(role.origin()));
    admitted
        .export(ExportMode::all_updates())
        .map_err(|e| Error::SyncProtocolError(e.to_string()))
}

#[cfg(feature = "sync")]
fn create_admission_doc(
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
) -> Result<LoroDoc> {
    let doc = LoroDoc::new();
    doc.set_peer_id(federated_admission_peer_id(key, update, role))
        .map_err(|e| Error::SyncProtocolError(e.to_string()))?;
    let _entities = doc.get_map("entities");
    let _edges = doc.get_map("edges");
    let _tombstones = doc.get_map("tombstones");
    doc.commit();
    Ok(doc)
}

#[cfg(feature = "sync")]
fn federated_admission_peer_id(
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
) -> u64 {
    let mut material = Vec::with_capacity(
        b"oneiron.federation.admission.peer.v0".len()
            + role.origin().len()
            + key.as_str().len()
            + std::mem::size_of::<u64>()
            + update.len(),
    );
    material.extend_from_slice(b"oneiron.federation.admission.peer.v0");
    material.extend_from_slice(&(role.origin().len() as u64).to_le_bytes());
    material.extend_from_slice(role.origin().as_bytes());
    material.extend_from_slice(&(key.as_str().len() as u64).to_le_bytes());
    material.extend_from_slice(key.as_str().as_bytes());
    material.extend_from_slice(&(update.len() as u64).to_le_bytes());
    material.extend_from_slice(update);

    match xxh3_64(&material) {
        0 => 1,
        u64::MAX => u64::MAX - 1,
        peer_id => peer_id,
    }
}

/// Test-only helper for downstream crates that need to seed a grant-backed
/// selector without opening the public maintenance-band write gate.
#[cfg(feature = "test-hooks")]
pub fn put_selector_test_federation_grant(
    vault: &Vault,
    grant_id: &EntityId,
    grant: &crate::federation::FederationGrant,
    learned_at: u64,
) -> Result<()> {
    let body = crate::federation::encode_federation_grant_body(grant)?;
    vault
        .batch()
        .put_replicated(
            grant_id,
            ENTITY_TYPE_FEDERATION_GRANT,
            crate::types::TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        )
        .commit()
}

fn decode_selector_value(value: &Value) -> Result<SyncSelector> {
    let Value::Map(entries) = value else {
        return Err(selector_err("sync selector must be a map"));
    };
    validate_selector_keys(entries)?;
    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64() != Some(SYNC_SELECTOR_SCHEMA_VERSION) {
        return Err(selector_err("sync selector unsupported schema version"));
    }

    let grant_id = decode_entity_hex(required_value(entries, KEY_GRANT_ID)?)?;
    let member_ref = decode_entity_hex(required_value(entries, KEY_MEMBER_REF)?)?;
    let world = decode_world(required_value(entries, KEY_WORLD)?)?;
    let facets = decode_entity_array(required_value(entries, KEY_FACETS)?)?;
    let bands = decode_band_array(required_value(entries, KEY_BANDS)?)?;

    Ok(SyncSelector::new(
        grant_id, member_ref, world, facets, bands,
    ))
}

#[cfg(feature = "sync")]
fn copy_admitted_entities(
    vault: &Vault,
    policy: &crate::gate::PolicyManifestResolution,
    source: &LoroDoc,
    target: &LoroDoc,
) -> Result<()> {
    let source_entities = source.get_map("entities");
    let target_entities = target.get_map("entities");
    let mut result = Ok(());
    map_for_each_value_bytes(&source_entities, |key, value| {
        if result.is_err() {
            return;
        }
        result = admit_federated_entity_blob(vault, policy, key, value)
            .and_then(|blob| map_insert_bytes(&target_entities, key, &blob));
    });
    result
}

#[cfg(feature = "sync")]
fn admit_federated_entity_blob(
    vault: &Vault,
    policy: &crate::gate::PolicyManifestResolution,
    key: &str,
    value: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let blob = value.ok_or(Error::InvalidKey)?;
    let id = EntityId::from_hex(key).map_err(|_| Error::InvalidKey)?;
    if key != id.to_hex() {
        return Err(Error::InvalidKey);
    }

    let header =
        EntityMetadataHeader::parse(blob).ok_or(Error::CorruptedIndex("entity metadata"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM {
        if header.entity_type == ENTITY_TYPE_AUTHORITY_LOG {
            admit_federated_authority_log(vault, &blob[ENTITY_METADATA_HEADER_LEN..])?;
            return Ok(blob.to_vec());
        }
        if band_of(header.entity_type) == TypeByteBand::InducedDynamicMaintenance {
            return Err(Error::MaintenanceKindNotWritable(header.entity_type));
        }
        return Ok(blob.to_vec());
    }

    let body = validate_claim_body_and_decode(&blob[ENTITY_METADATA_HEADER_LEN..], true)?;
    let body = restamp_federated_claim_source(body);
    crate::gate::check_federated_claim_admission(&body, policy)?;
    let encoded = crate::claim::encode_claim_body(&body)?;

    let mut admitted = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + encoded.len());
    admitted.extend_from_slice(&blob[..ENTITY_METADATA_HEADER_LEN]);
    admitted.extend_from_slice(&encoded);
    Ok(admitted)
}

#[cfg(feature = "sync")]
fn admit_federated_authority_log(vault: &Vault, body: &[u8]) -> Result<()> {
    validate_authority_log_entry_body_bytes(body)?;
    let entry = decode_authority_log_entry_body(body)?;
    let entry_vault_id = match &entry.op {
        AuthorityOp::Genesis { .. } => genesis_vault_id(&entry)?,
        _ => entry
            .vault_id
            .ok_or(Error::InvalidAuthorityLogBody("missing authority vault id"))?,
    };
    let local_vault_id = vault
        .authority_fold()?
        .vault_id
        .ok_or(Error::InvalidAuthorityLogBody(
            "missing local authority root",
        ))?;
    if entry_vault_id != local_vault_id {
        return Err(Error::InvalidAuthorityLogBody(
            "foreign authority log vault id",
        ));
    }
    Ok(())
}

#[cfg(feature = "sync")]
fn copy_binary_map(source: &loro::LoroMap, target: &loro::LoroMap) -> Result<()> {
    let mut result = Ok(());
    map_for_each_value_bytes(source, |key, value| {
        if result.is_err() {
            return;
        }
        result = value
            .ok_or(Error::InvalidKey)
            .and_then(|bytes| map_insert_bytes(target, key, bytes));
    });
    result
}

#[cfg(feature = "sync")]
fn reject_federated_tombstones(source: &LoroDoc) -> Result<()> {
    let mut has_tombstone = false;
    map_for_each_tombstone_value(&source.get_map("tombstones"), |_, _| {
        has_tombstone = true;
    });
    if has_tombstone {
        return Err(Error::SyncProtocolError(
            FEDERATED_TOMBSTONE_ADMISSION_ERROR.to_string(),
        ));
    }
    Ok(())
}

/// Validates that a selector is backed by a matching federation grant.
pub fn authorize_sync_selector(
    vault: &Vault,
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
) -> Result<()> {
    let raw = vault
        .get_raw(&selector.grant_id)?
        .ok_or_else(|| selector_err("sync selector grant not found"))?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or_else(|| selector_err("sync selector grant header"))?;
    if header.entity_type != ENTITY_TYPE_FEDERATION_GRANT {
        return Err(selector_err("sync selector grant wrong type"));
    }

    let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    if grant.scope != grant_scope {
        return Err(selector_err("sync selector grant scope mismatch"));
    }
    if grant.member_ref != selector.member_ref {
        return Err(selector_err("sync selector member not granted"));
    }
    Ok(())
}

fn filter_window_doc(
    source: &LoroDoc,
    key: &WindowKey,
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
) -> LoroDoc {
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

    let facet_scope = facet_scope_by_source(&source_edges, selector);
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
        let Some(decision) =
            entity_selector_decision(&id, blob, grant_scope, selector, &facet_scope)
        else {
            return;
        };
        candidates.insert(id);
        if selector.facet_filter_active() {
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

    if selector.facet_filter_active() {
        kept.extend(seeds.iter().copied());
        map_for_each_value_bytes(&source_edges, |raw_key, maybe_value| {
            if maybe_value.is_none() {
                return;
            }
            let Some((src, _, tgt)) = parse_edge_key(raw_key) else {
                return;
            };
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
        let Some((src, _, tgt)) = parse_edge_key(raw_key) else {
            return;
        };
        if kept.contains(&src) && kept.contains(&tgt) {
            let _ = map_insert_bytes(&out_edges, raw_key, value);
        }
    });

    let out_tombstones = out.get_map("tombstones");
    map_for_each_tombstone_value(&source_tombstones, |raw_key, value| {
        let Ok(id) = EntityId::from_hex(raw_key) else {
            return;
        };
        if kept.contains(&id) || !selector.any_filter_active() {
            let _ = map_insert_bytes(&out_tombstones, raw_key, value);
        }
    });

    out.commit();
    out
}

#[derive(Debug, Default)]
struct FacetScope {
    any: bool,
    selected: bool,
    unselected: bool,
    malformed: bool,
}

#[derive(Debug)]
struct EntitySelectorDecision {
    facet_visible: bool,
    facet_seed: bool,
}

fn facet_scope_by_source(
    edges: &loro::LoroMap,
    selector: &SyncSelector,
) -> HashMap<EntityId, FacetScope> {
    let selected: HashSet<EntityId> = selector.facets.iter().copied().collect();
    let mut scopes = HashMap::<EntityId, FacetScope>::new();
    if selected.is_empty() {
        return scopes;
    }

    map_for_each_value_bytes(edges, |raw_key, maybe_value| {
        let Some((src, kind, tgt)) = parse_edge_key(raw_key) else {
            return;
        };
        if kind != EdgeKind::FacetOf {
            return;
        }
        let entry = scopes.entry(src).or_default();
        entry.any = true;
        if maybe_value.is_none() {
            entry.malformed = true;
            return;
        }
        if selected.contains(&tgt) {
            entry.selected = true;
        } else {
            entry.unselected = true;
        }
    });
    scopes
}

fn entity_selector_decision(
    id: &EntityId,
    blob: &[u8],
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
    facet_scope: &HashMap<EntityId, FacetScope>,
) -> Option<EntitySelectorDecision> {
    let header = EntityMetadataHeader::parse(blob)?;
    if header.entity_type == ENTITY_TYPE_COMPANION_REGISTER
        && !companion_register_passes_selector(blob, grant_scope)
    {
        return None;
    }
    if selector.band_filter_active() && !selector.bands.contains(&band_of(header.entity_type)) {
        return None;
    }
    if selector.facet_filter_active()
        && header.entity_type == ENTITY_TYPE_FACET
        && !selector.facets.contains(id)
    {
        return None;
    }
    if selector.facet_filter_active()
        && facet_scope.get(id).is_some_and(|scope| {
            scope.malformed || scope.unselected || (scope.any && !scope.selected)
        })
    {
        return None;
    }
    if header.entity_type == ENTITY_TYPE_WORLD {
        match selector.world {
            SyncSelectorWorld::All => {}
            SyncSelectorWorld::Base => return None,
            SyncSelectorWorld::World(world) if *id != world => return None,
            SyncSelectorWorld::World(_) => {}
        }
    }
    if !world_passes(
        header.entity_type,
        &blob[ENTITY_METADATA_HEADER_LEN..],
        selector.world,
    ) {
        return None;
    }
    let facet_visible = selector.facet_filter_active()
        && header.entity_type == ENTITY_TYPE_FACET
        && selector.facets.contains(id);
    let facet_seed =
        selector.facet_filter_active() && facet_scope.get(id).is_some_and(|scope| scope.selected);
    Some(EntitySelectorDecision {
        facet_visible,
        facet_seed,
    })
}

fn companion_register_passes_selector(blob: &[u8], grant_scope: FederationGrantScope) -> bool {
    let Ok(record) = decode_companion_record_body(&blob[ENTITY_METADATA_HEADER_LEN..]) else {
        return false;
    };
    if !matches!(
        record.lifecycle,
        ClaimLifecycleStatus::Active | ClaimLifecycleStatus::Retracted
    ) {
        return false;
    }
    match record.export_classification {
        CompanionExportClassification::LocalOnly => false,
        CompanionExportClassification::Portable => {
            !matches!(record.scope, CompanionScope::SharedVault { .. })
        }
        CompanionExportClassification::SharedVault => {
            let FederationGrantScope::Vault {
                vault_id: grant_vault_id,
            } = grant_scope;
            matches!(
                record.scope,
                CompanionScope::SharedVault { vault_id } if vault_id == grant_vault_id
            )
        }
    }
}

fn world_passes(entity_type: u8, body: &[u8], world: SyncSelectorWorld) -> bool {
    let target = match world {
        SyncSelectorWorld::All => return true,
        SyncSelectorWorld::Base => None,
        SyncSelectorWorld::World(id) => Some(id),
    };
    if entity_type != ENTITY_TYPE_CLAIM {
        return true;
    }
    let Ok(body) = crate::claim::decode_claim_body(body, true) else {
        return false;
    };
    match body.world {
        None => true,
        Some(claim_world) => target == Some(claim_world),
    }
}

fn encode_world(world: SyncSelectorWorld) -> Value {
    match world {
        SyncSelectorWorld::All => Value::Map(vec![(
            Value::from(WORLD_KEYS[0]),
            Value::from(WORLD_KIND_ALL),
        )]),
        SyncSelectorWorld::Base => Value::Map(vec![(
            Value::from(WORLD_KEYS[0]),
            Value::from(WORLD_KIND_BASE),
        )]),
        SyncSelectorWorld::World(id) => Value::Map(vec![
            (Value::from(WORLD_KEYS[0]), Value::from(WORLD_KIND_WORLD)),
            (Value::from(WORLD_KEYS[1]), Value::from(id.to_hex())),
        ]),
    }
}

fn decode_world(value: &Value) -> Result<SyncSelectorWorld> {
    let Value::Map(entries) = value else {
        return Err(selector_err("sync selector world must be a map"));
    };
    let kind = required_value(entries, WORLD_KEYS[0])?
        .as_str()
        .ok_or_else(|| selector_err("sync selector world kind"))?;
    match kind {
        WORLD_KIND_ALL => {
            if entries.len() != 1 {
                return Err(selector_err("sync selector all world has extra fields"));
            }
            Ok(SyncSelectorWorld::All)
        }
        WORLD_KIND_BASE => {
            if entries.len() != 1 {
                return Err(selector_err("sync selector base world has extra fields"));
            }
            Ok(SyncSelectorWorld::Base)
        }
        WORLD_KIND_WORLD => {
            validate_world_keys(entries)?;
            Ok(SyncSelectorWorld::World(decode_entity_hex(
                required_value(entries, WORLD_KEYS[1])?,
            )?))
        }
        _ => Err(selector_err("sync selector unknown world kind")),
    }
}

fn validate_selector_keys(entries: &[(Value, Value)]) -> Result<()> {
    let mut seen = [false; SELECTOR_KEYS.len()];
    for (key, _) in entries {
        let key = key
            .as_str()
            .ok_or_else(|| selector_err("sync selector key must be string"))?;
        let Some(index) = SELECTOR_KEYS.iter().position(|expected| *expected == key) else {
            return Err(selector_err("sync selector unknown key"));
        };
        if seen[index] {
            return Err(selector_err("sync selector duplicate key"));
        }
        seen[index] = true;
    }
    if seen.iter().all(|present| *present) {
        Ok(())
    } else {
        Err(selector_err("sync selector missing key"))
    }
}

fn validate_world_keys(entries: &[(Value, Value)]) -> Result<()> {
    let mut seen = [false; WORLD_KEYS.len()];
    for (key, _) in entries {
        let key = key
            .as_str()
            .ok_or_else(|| selector_err("sync selector world key"))?;
        let Some(index) = WORLD_KEYS.iter().position(|expected| *expected == key) else {
            return Err(selector_err("sync selector world unknown key"));
        };
        if seen[index] {
            return Err(selector_err("sync selector world duplicate key"));
        }
        seen[index] = true;
    }
    if seen.iter().all(|present| *present) {
        Ok(())
    } else {
        Err(selector_err("sync selector world missing key"))
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(entry_key, value)| (entry_key.as_str() == Some(key)).then_some(value))
        .ok_or_else(|| selector_err("sync selector missing required value"))
}

fn decode_entity_hex(value: &Value) -> Result<EntityId> {
    let hex = value
        .as_str()
        .ok_or_else(|| selector_err("sync selector entity id must be hex"))?;
    EntityId::from_hex(hex).map_err(|_| selector_err("sync selector invalid entity id"))
}

fn decode_entity_array(value: &Value) -> Result<Vec<EntityId>> {
    let Value::Array(values) = value else {
        return Err(selector_err("sync selector entity list must be array"));
    };
    values.iter().map(decode_entity_hex).collect()
}

fn decode_band_array(value: &Value) -> Result<Vec<TypeByteBand>> {
    let Value::Array(values) = value else {
        return Err(selector_err("sync selector bands must be array"));
    };
    values.iter().map(decode_band).collect()
}

fn decode_band(value: &Value) -> Result<TypeByteBand> {
    let band = value
        .as_str()
        .ok_or_else(|| selector_err("sync selector band must be string"))?;
    match band {
        "semantic" => Ok(TypeByteBand::Semantic),
        "core" => Ok(TypeByteBand::Core),
        "companion" => Ok(TypeByteBand::Companion),
        "productivity" => Ok(TypeByteBand::Productivity),
        "crm" => Ok(TypeByteBand::Crm),
        "maintenance" => Ok(TypeByteBand::InducedDynamicMaintenance),
        _ => Err(selector_err("sync selector unknown band")),
    }
}

fn band_to_wire(band: TypeByteBand) -> &'static str {
    match band {
        TypeByteBand::Semantic => "semantic",
        TypeByteBand::Core => "core",
        TypeByteBand::Companion => "companion",
        TypeByteBand::Productivity => "productivity",
        TypeByteBand::Crm => "crm",
        TypeByteBand::InducedDynamicMaintenance => "maintenance",
    }
}

fn selector_err(msg: &'static str) -> Error {
    Error::SyncProtocolError(msg.to_owned())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use loro::{ExportMode, LoroDoc};

    use super::*;
    use crate::authority::{
        AUTHORITY_LOG_SCHEMA_VERSION, AuthorityAttestation, AuthorityKey, AuthorityLogEntry,
        AuthoritySignature, AuthoritySignatureSuite, AuthorityTier, DeviceAuthority, ROLE_ADMIN,
        ROLE_OWNER, authority_transcript, encode_authority_log_entry_body,
    };
    use crate::batch::ENTITY_METADATA_HEADER_LEN;
    use crate::claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
        decode_claim_body, encode_claim_body,
    };
    use crate::federation::{
        FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
        encode_federation_grant_body,
    };
    use crate::provenance::{
        EdgeProvenanceClaimBody, SupersessionStatus, encode_actor_class_evidence,
        encode_edge_provenance_value,
    };
    use crate::store::Store;
    use crate::sync::bridge::encode_edge_value_for_crdt;
    use crate::sync::loro_support::map_get_bytes;
    use crate::types::{
        CompanionProvenance, CompanionRecord, CompanionScope, ENTITY_TYPE_COMPANION_REGISTER,
        ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_WORLD,
        EdgeActorClass, TimeRange, Vad, encode_companion_record_body,
    };

    fn entity_id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 16]).unwrap()
    }

    fn entity_blob(entity_type: u8, body: &[u8]) -> Vec<u8> {
        let mut blob = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
        blob.push(entity_type);
        blob.extend_from_slice(&1_u64.to_be_bytes());
        blob.extend_from_slice(&1_u64.to_be_bytes());
        blob.extend_from_slice(&1_u64.to_be_bytes());
        blob.extend_from_slice(body);
        blob
    }

    fn authority_genesis_entry(seed: u8) -> AuthorityLogEntry {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
        let op = AuthorityOp::Genesis {
            device: DeviceAuthority {
                key: key.clone(),
                transport_key_binding: [7; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER | ROLE_ADMIN,
            },
            genesis_nonce: [seed.wrapping_add(1); 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: 86_400,
        };
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: None,
            seq: 0,
            parent_hashes: Vec::new(),
            op,
            signer: AuthoritySignature {
                suite: AuthoritySignatureSuite::Ed25519,
                public_key: key,
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: u64::from(seed),
        };
        let transcript = authority_transcript(&entry).unwrap();
        entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
        entry
    }

    fn claim_blob(world: Option<EntityId>) -> Vec<u8> {
        let mut claim = ClaimBody::new(
            "selector.test",
            ClaimSubject::Entity(entity_id(0x90)),
            Value::from("value"),
            0.8,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
        );
        claim.world = world;
        entity_blob(ENTITY_TYPE_CLAIM, &encode_claim_body(&claim).unwrap())
    }

    fn edge_provenance_claim_blob() -> Vec<u8> {
        let confidence = 0.75_f32;
        let record = EdgeProvenanceClaimBody::new(
            entity_id(0xA4),
            confidence,
            SupersessionStatus::Confirmed,
        );
        let mut claim = ClaimBody::new(
            crate::provenance::PREDICATE_EDGE_PROVENANCE,
            ClaimSubject::Edge {
                source: entity_id(0xA5),
                kind: EdgeKind::Mentions,
                target: entity_id(0xA6),
            },
            encode_edge_provenance_value(&record),
            confidence,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        claim.evidence = Some(encode_actor_class_evidence(EdgeActorClass::Human));
        claim.source = Some(ClaimSource::ToolOutput);
        entity_blob(ENTITY_TYPE_CLAIM, &encode_claim_body(&claim).unwrap())
    }

    fn companion_record_body(
        persona_ref: EntityId,
        export_classification: CompanionExportClassification,
    ) -> Vec<u8> {
        companion_record_body_in_scope(
            persona_ref,
            CompanionScope::neutral(),
            export_classification,
        )
    }

    fn companion_record_body_in_scope(
        persona_ref: EntityId,
        scope: CompanionScope,
        export_classification: CompanionExportClassification,
    ) -> Vec<u8> {
        companion_record_body_in_scope_with_lifecycle(
            persona_ref,
            scope,
            export_classification,
            ClaimLifecycleStatus::Active,
        )
    }

    fn companion_record_body_in_scope_with_lifecycle(
        persona_ref: EntityId,
        scope: CompanionScope,
        export_classification: CompanionExportClassification,
        lifecycle: ClaimLifecycleStatus,
    ) -> Vec<u8> {
        let mut record = CompanionRecord::persona(
            scope,
            persona_ref,
            Value::from("private companion tuning"),
            CompanionProvenance::new(
                entity_id(0xB8),
                EdgeActorClass::Agent,
                ClaimSource::UserStated,
                ClaimApprovalStatus::Approved,
                Value::from("private provenance"),
            ),
            export_classification,
        );
        record.lifecycle = lifecycle;
        match lifecycle {
            ClaimLifecycleStatus::Active => {
                record = record.created_at(1_772_400_000).unwrap();
            }
            ClaimLifecycleStatus::Superseded => record
                .lifecycle_events
                .push(crate::types::companion::CompanionLifecycleEvent::superseded(1_772_400_000)),
            ClaimLifecycleStatus::Retracted => record.lifecycle_events.push(
                crate::types::companion::CompanionLifecycleEvent::retired(1_772_400_000),
            ),
        }
        encode_companion_record_body(&record).unwrap()
    }

    fn encode_policy_manifest(extra_entries: Vec<(Value, Value)>) -> Vec<u8> {
        let mut entries = vec![
            (Value::from("schema_version"), Value::from("1.1")),
            (Value::from("pack_id"), Value::from("selector-test")),
            (Value::from("pack_version"), Value::from("v1")),
            (
                Value::from("min_engine_version"),
                Value::from(env!("CARGO_PKG_VERSION")),
            ),
            (
                Value::from("defaults"),
                Value::Map(vec![
                    (Value::from("criticality"), Value::from("normal")),
                    (Value::from("sensitivity"), Value::from("normal")),
                ]),
            ),
            (Value::from("rules"), Value::Array(vec![])),
            (
                Value::from("actor_ceilings"),
                Value::Array(vec![Value::Map(vec![
                    (Value::from("actor_class"), Value::from("first_party")),
                    (Value::from("ceiling"), Value::from("auto")),
                ])]),
            ),
        ];
        entries.extend(extra_entries);
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &Value::Map(entries)).unwrap();
        out
    }

    fn source_trust_entry(source: ClaimSource, max_auto_sensitivity: u8) -> (Value, Value) {
        let row = Value::Map(vec![
            (
                Value::from("max_auto_sensitivity"),
                Value::from(u64::from(max_auto_sensitivity)),
            ),
            (Value::from("receipted"), Value::Boolean(true)),
            (Value::from("warned"), Value::Boolean(true)),
        ]);
        (
            Value::from("source_trust"),
            Value::Map(vec![(Value::from(source.as_str()), row)]),
        )
    }

    fn put_imported_source_trust(vault: &Vault) {
        let body = encode_policy_manifest(vec![source_trust_entry(ClaimSource::Imported, 0)]);
        let id = entity_id(0xA7);
        let payload = entity_blob(ENTITY_TYPE_POLICY_MANIFEST, &body);
        vault
            .with_write_txn(|wtxn| {
                vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
                let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
                vault.store.type_index.put(wtxn, &type_key, &[])?;
                Ok(())
            })
            .unwrap();
    }

    fn insert_entity(doc: &LoroDoc, id: EntityId, entity_type: u8, body: &[u8]) {
        map_insert_bytes(
            &doc.get_map("entities"),
            &id.to_hex(),
            &entity_blob(entity_type, body),
        )
        .unwrap();
    }

    fn insert_blob(doc: &LoroDoc, id: EntityId, blob: &[u8]) {
        map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), blob).unwrap();
    }

    fn insert_edge(doc: &LoroDoc, src: EntityId, kind: EdgeKind, tgt: EntityId) {
        let key = format!("{}:{:02}:{}", src.to_hex(), kind as u8, tgt.to_hex());
        let value = encode_edge_value_for_crdt(kind, 0.7, 1, Some(Vad::NEUTRAL), None).unwrap();
        map_insert_bytes(&doc.get_map("edges"), &key, &value).unwrap();
    }

    fn insert_malformed_edge(doc: &LoroDoc, src: EntityId, kind: EdgeKind, tgt: EntityId) {
        let key = format!("{}:{:02}:{}", src.to_hex(), kind as u8, tgt.to_hex());
        doc.get_map("edges")
            .insert(key.as_str(), "not-binary")
            .unwrap();
    }

    fn insert_tombstone(doc: &LoroDoc, id: EntityId) {
        map_insert_bytes(&doc.get_map("tombstones"), &id.to_hex(), b"deleted").unwrap();
    }

    fn insert_uppercase_tombstone_alias(doc: &LoroDoc, id: EntityId) {
        map_insert_bytes(
            &doc.get_map("tombstones"),
            &id.to_hex().to_ascii_uppercase(),
            b"deleted",
        )
        .unwrap();
    }

    fn import_ids(update: &[u8]) -> Vec<EntityId> {
        let doc = create_window_doc("receiver", &WindowKey::new("2026-03"));
        doc.import(update).unwrap();
        let mut ids = Vec::new();
        map_for_each_value_bytes(&doc.get_map("entities"), |key, value| {
            if value.is_some() {
                ids.push(EntityId::from_hex(key).unwrap());
            }
        });
        ids.sort_unstable();
        ids
    }

    fn test_selector_scope() -> FederationGrantScope {
        FederationGrantScope::vault(7)
    }

    fn test_vault_with_grant_scope(
        member_ref: EntityId,
        scope: FederationGrantScope,
    ) -> (tempfile::TempDir, Vault, EntityId) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
        let grant_id = EntityId::now();
        let grant = FederationGrant::new(
            scope,
            member_ref,
            FederationGrantRole::Viewer,
            FederationGrantPreset::ReadOnly,
        );
        let body = encode_federation_grant_body(&grant).unwrap();
        vault
            .batch()
            .put_replicated(
                &grant_id,
                ENTITY_TYPE_FEDERATION_GRANT,
                TimeRange { start: 1, end: 1 },
                1,
                &body,
            )
            .commit()
            .unwrap();
        (dir, vault, grant_id)
    }

    fn test_vault_with_grant(member_ref: EntityId) -> (tempfile::TempDir, Vault, EntityId) {
        test_vault_with_grant_scope(member_ref, test_selector_scope())
    }

    #[test]
    fn selector_codec_round_trips_strict_payload() {
        let selector = SyncSelector::new(
            entity_id(0xA1),
            entity_id(0xB1),
            SyncSelectorWorld::World(entity_id(0xC1)),
            vec![entity_id(0xD1), entity_id(0xD1)],
            vec![
                TypeByteBand::Core,
                TypeByteBand::Semantic,
                TypeByteBand::Core,
            ],
        );
        let payload = encode_selector_vv_request(&selector, b"vv").unwrap();
        let decoded = decode_selector_vv_request(&payload).unwrap();
        assert_eq!(decoded.selector, selector);
        assert_eq!(decoded.remote_vv, b"vv");

        let mut trailing = encode_sync_selector(&selector).unwrap();
        trailing.push(0);
        assert!(decode_sync_selector(&trailing).is_err());

        let unsupported_version = Value::Map(vec![
            (Value::from(KEY_SCHEMA_VERSION), Value::from(2_u64)),
            (
                Value::from(KEY_GRANT_ID),
                Value::from(selector.grant_id.to_hex()),
            ),
            (
                Value::from(KEY_MEMBER_REF),
                Value::from(selector.member_ref.to_hex()),
            ),
            (Value::from(KEY_WORLD), encode_world(selector.world)),
            (
                Value::from(KEY_FACETS),
                Value::Array(
                    selector
                        .facets
                        .iter()
                        .map(|facet| Value::from(facet.to_hex()))
                        .collect(),
                ),
            ),
            (
                Value::from(KEY_BANDS),
                Value::Array(
                    selector
                        .bands
                        .iter()
                        .map(|band| Value::from(band_to_wire(*band)))
                        .collect(),
                ),
            ),
        ]);
        let mut unsupported = Vec::new();
        rmpv::encode::write_value(&mut unsupported, &unsupported_version).unwrap();
        assert!(decode_sync_selector(&unsupported).is_err());
    }

    #[test]
    fn federated_admission_rejects_maintenance_band_non_claim_entities() {
        let (_dir, vault, _grant_id) = test_vault_with_grant(entity_id(0xA2));
        let window_key = WindowKey::new("2026-03");
        let doc = create_window_doc("remote", &window_key);
        insert_entity(
            &doc,
            entity_id(0xA3),
            ENTITY_TYPE_POLICY_MANIFEST,
            b"remote-policy",
        );
        doc.commit();
        let update = doc.export(ExportMode::all_updates()).unwrap();

        let err = admit_federated_window_update(
            &vault,
            &window_key,
            &update,
            FederationAdmissionRole::Member,
        )
        .expect_err("federated maintenance-band non-claims must fail closed");
        assert!(matches!(
            err,
            Error::MaintenanceKindNotWritable(ENTITY_TYPE_POLICY_MANIFEST)
        ));
    }

    #[test]
    fn federated_admission_rejects_foreign_authority_log() {
        let (_dir, vault, _grant_id) = test_vault_with_grant(entity_id(0xB2));
        let local = authority_genesis_entry(0x51);
        vault
            .put_authority_log_entry(&entity_id(0x51), &local, TimeRange { start: 1, end: 1 }, 1)
            .unwrap();

        let foreign = authority_genesis_entry(0x52);
        let foreign_body = encode_authority_log_entry_body(&foreign).unwrap();
        let window_key = WindowKey::new("2026-03");
        let doc = create_window_doc("remote", &window_key);
        insert_entity(
            &doc,
            entity_id(0x52),
            ENTITY_TYPE_AUTHORITY_LOG,
            &foreign_body,
        );
        doc.commit();
        let update = doc.export(ExportMode::all_updates()).unwrap();

        let err = admit_federated_window_update(
            &vault,
            &window_key,
            &update,
            FederationAdmissionRole::Member,
        )
        .expect_err("foreign authority roots must not enter admitted federation updates");
        assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
    }

    #[test]
    fn federated_admission_allows_reserved_edge_provenance_claim_with_imported_trust() {
        let (_dir, vault, _grant_id) = test_vault_with_grant(entity_id(0xA8));
        put_imported_source_trust(&vault);
        let window_key = WindowKey::new("2026-03");
        let claim_id = entity_id(0xA9);
        let doc = create_window_doc("remote", &window_key);
        insert_blob(&doc, claim_id, &edge_provenance_claim_blob());
        doc.commit();
        let update = doc.export(ExportMode::all_updates()).unwrap();

        let admitted = admit_federated_window_update(
            &vault,
            &window_key,
            &update,
            FederationAdmissionRole::Member,
        )
        .expect("valid reserved provenance claim should admit under imported trust");

        let receiver = create_window_doc("receiver", &window_key);
        receiver.import(&admitted).unwrap();
        let blob = map_get_bytes(&receiver.get_map("entities"), &claim_id.to_hex())
            .expect("admitted provenance claim");
        let body = decode_claim_body(&blob[ENTITY_METADATA_HEADER_LEN..], true).unwrap();
        assert_eq!(body.predicate, crate::provenance::PREDICATE_EDGE_PROVENANCE);
        assert_eq!(body.source, Some(ClaimSource::Imported));
    }

    #[test]
    fn federated_admission_duplicate_frame_is_byte_identical() {
        let (_dir, vault, _grant_id) = test_vault_with_grant(entity_id(0xAA));
        put_imported_source_trust(&vault);
        let window_key = WindowKey::new("2026-03");
        let claim_id = entity_id(0xAB);
        let doc = create_window_doc("remote", &window_key);
        insert_blob(&doc, claim_id, &edge_provenance_claim_blob());
        doc.commit();
        let update = doc.export(ExportMode::all_updates()).unwrap();

        let first = admit_federated_window_update(
            &vault,
            &window_key,
            &update,
            FederationAdmissionRole::Guest,
        )
        .expect("first admission");
        let second = admit_federated_window_update(
            &vault,
            &window_key,
            &update,
            FederationAdmissionRole::Guest,
        )
        .expect("duplicate admission");
        assert_eq!(
            second, first,
            "same role/window/update must produce byte-identical admitted updates"
        );
    }

    #[test]
    fn selected_window_omits_other_facets_and_keeps_closed_edges() {
        let member = entity_id(0x31);
        let (_dir, vault, grant_id) = test_vault_with_grant(member);
        let window_key = WindowKey::new("2026-03");
        let doc = create_window_doc("source", &window_key);

        let facet_allowed = entity_id(0xA1);
        let facet_denied = entity_id(0xB1);
        let claim_allowed = entity_id(0x11);
        let claim_denied = entity_id(0x12);
        let person = entity_id(0x21);
        let denied_only_person = entity_id(0x22);
        insert_entity(&doc, facet_allowed, ENTITY_TYPE_FACET, b"facet-a");
        insert_entity(&doc, facet_denied, ENTITY_TYPE_FACET, b"facet-b");
        insert_blob(&doc, claim_allowed, &claim_blob(None));
        insert_blob(&doc, claim_denied, &claim_blob(None));
        insert_entity(&doc, person, ENTITY_TYPE_PERSON, b"person");
        insert_entity(
            &doc,
            denied_only_person,
            ENTITY_TYPE_PERSON,
            b"denied-only-person",
        );
        insert_edge(&doc, claim_allowed, EdgeKind::FacetOf, facet_allowed);
        insert_edge(&doc, claim_denied, EdgeKind::FacetOf, facet_denied);
        insert_edge(&doc, claim_allowed, EdgeKind::Supports, person);
        insert_edge(&doc, claim_denied, EdgeKind::Supports, person);
        insert_edge(&doc, claim_denied, EdgeKind::Supports, denied_only_person);
        doc.commit();

        let selector = SyncSelector::new(
            grant_id,
            member,
            SyncSelectorWorld::All,
            vec![facet_allowed],
            vec![],
        );
        let filtered =
            filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
                .unwrap();
        let update = filtered.export(ExportMode::all_updates()).unwrap();
        let ids = import_ids(&update);

        assert!(ids.contains(&claim_allowed));
        assert!(ids.contains(&facet_allowed));
        assert!(ids.contains(&person));
        assert!(
            !ids.contains(&claim_denied),
            "unauthorized facet claim leaked"
        );
        assert!(
            !ids.contains(&facet_denied),
            "unreferenced denied facet entity leaked"
        );
        assert!(
            !ids.contains(&denied_only_person),
            "non-faceted neighbor reachable only from a denied facet leaked"
        );

        let receiver = create_window_doc("receiver", &window_key);
        receiver.import(&update).unwrap();
        let mut edge_count = 0;
        map_for_each_value_bytes(&receiver.get_map("edges"), |_, value| {
            if value.is_some() {
                edge_count += 1;
            }
        });
        assert_eq!(
            edge_count, 2,
            "only edges whose endpoints survived the selector should replicate"
        );
    }

    #[test]
    fn companion_register_api_selector_suppresses_local_only_records() {
        let member = entity_id(0x39);
        let (_dir, vault, grant_id) = test_vault_with_grant(member);
        let window_key = WindowKey::new("2026-03");
        let doc = create_window_doc("source", &window_key);

        let local_id = entity_id(0x3A);
        let portable_id = entity_id(0x3B);
        let shared_id = entity_id(0x3C);
        let other_shared_id = entity_id(0x3D);
        let retired_portable_id = entity_id(0x3E);
        insert_entity(
            &doc,
            local_id,
            ENTITY_TYPE_COMPANION_REGISTER,
            &companion_record_body(local_id, CompanionExportClassification::LocalOnly),
        );
        insert_entity(
            &doc,
            portable_id,
            ENTITY_TYPE_COMPANION_REGISTER,
            &companion_record_body(portable_id, CompanionExportClassification::Portable),
        );
        insert_entity(
            &doc,
            shared_id,
            ENTITY_TYPE_COMPANION_REGISTER,
            &companion_record_body_in_scope(
                shared_id,
                CompanionScope::shared_vault(7),
                CompanionExportClassification::SharedVault,
            ),
        );
        insert_entity(
            &doc,
            other_shared_id,
            ENTITY_TYPE_COMPANION_REGISTER,
            &companion_record_body_in_scope(
                other_shared_id,
                CompanionScope::shared_vault(8),
                CompanionExportClassification::SharedVault,
            ),
        );
        insert_entity(
            &doc,
            retired_portable_id,
            ENTITY_TYPE_COMPANION_REGISTER,
            &companion_record_body_in_scope_with_lifecycle(
                retired_portable_id,
                CompanionScope::neutral(),
                CompanionExportClassification::Portable,
                ClaimLifecycleStatus::Retracted,
            ),
        );
        doc.commit();

        let selector = SyncSelector::new(
            grant_id,
            member,
            SyncSelectorWorld::All,
            vec![],
            vec![TypeByteBand::Companion],
        );
        let filtered =
            filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
                .unwrap();
        let entities = filtered.get_map("entities");
        assert!(
            map_get_bytes(&entities, &local_id.to_hex()).is_none(),
            "selector export must not include local-only companion register records"
        );
        assert!(
            map_get_bytes(&entities, &portable_id.to_hex()).is_some(),
            "selector export should keep syncable companion register records"
        );
        assert!(
            map_get_bytes(&entities, &shared_id.to_hex()).is_some(),
            "selector export should keep companion records for the authorized shared vault"
        );
        assert!(
            map_get_bytes(&entities, &other_shared_id.to_hex()).is_none(),
            "selector export must not include another shared vault's companion register records"
        );
        assert!(
            map_get_bytes(&entities, &retired_portable_id.to_hex()).is_some(),
            "selector export should propagate portable companion retirement records"
        );
    }

    #[test]
    fn selector_denies_entity_with_any_unselected_facet_of() {
        let member = entity_id(0x39);
        let (_dir, vault, grant_id) = test_vault_with_grant(member);
        let window_key = WindowKey::new("2026-09");
        let doc = create_window_doc("source", &window_key);

        let facet_allowed = entity_id(0xA9);
        let facet_denied = entity_id(0xB9);
        let dual_facet_claim = entity_id(0x19);
        let person = entity_id(0x29);

        insert_entity(&doc, facet_allowed, ENTITY_TYPE_FACET, b"facet-a");
        insert_entity(&doc, facet_denied, ENTITY_TYPE_FACET, b"facet-b");
        insert_blob(&doc, dual_facet_claim, &claim_blob(None));
        insert_entity(&doc, person, ENTITY_TYPE_PERSON, b"person");
        insert_edge(&doc, dual_facet_claim, EdgeKind::FacetOf, facet_allowed);
        insert_edge(&doc, dual_facet_claim, EdgeKind::FacetOf, facet_denied);
        insert_edge(&doc, dual_facet_claim, EdgeKind::Supports, person);
        doc.commit();

        let selector = SyncSelector::new(
            grant_id,
            member,
            SyncSelectorWorld::All,
            vec![facet_allowed],
            vec![],
        );
        let update =
            filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
                .unwrap()
                .export(ExportMode::all_updates())
                .unwrap();
        let ids = import_ids(&update);

        assert!(ids.contains(&facet_allowed));
        assert!(
            !ids.contains(&dual_facet_claim),
            "an entity with any unselected FacetOf must fail closed"
        );
        assert!(
            !ids.contains(&facet_denied),
            "unselected facet entity leaked"
        );
        assert!(
            !ids.contains(&person),
            "neighbors of a denied dual-facet entity leaked"
        );
    }

    #[test]
    fn selector_facet_closure_does_not_expand_from_facet_entities() {
        let member = entity_id(0x3A);
        let (_dir, vault, grant_id) = test_vault_with_grant(member);
        let window_key = WindowKey::new("2026-10");
        let doc = create_window_doc("source", &window_key);

        let facet_allowed = entity_id(0xAA);
        let claim_allowed = entity_id(0x1A);
        let selected_person = entity_id(0x2A);
        let facet_neighbor = entity_id(0x3B);

        insert_entity(&doc, facet_allowed, ENTITY_TYPE_FACET, b"facet-a");
        insert_blob(&doc, claim_allowed, &claim_blob(None));
        insert_entity(
            &doc,
            selected_person,
            ENTITY_TYPE_PERSON,
            b"selected-person",
        );
        insert_entity(&doc, facet_neighbor, ENTITY_TYPE_PERSON, b"facet-neighbor");
        insert_edge(&doc, claim_allowed, EdgeKind::FacetOf, facet_allowed);
        insert_edge(&doc, claim_allowed, EdgeKind::Supports, selected_person);
        insert_edge(&doc, facet_allowed, EdgeKind::Supports, facet_neighbor);
        doc.commit();

        let selector = SyncSelector::new(
            grant_id,
            member,
            SyncSelectorWorld::All,
            vec![facet_allowed],
            vec![],
        );
        let update =
            filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
                .unwrap()
                .export(ExportMode::all_updates())
                .unwrap();
        let ids = import_ids(&update);

        assert!(ids.contains(&facet_allowed));
        assert!(ids.contains(&claim_allowed));
        assert!(ids.contains(&selected_person));
        assert!(
            !ids.contains(&facet_neighbor),
            "selected facet entities must not seed arbitrary closure edges"
        );
    }

    #[test]
    fn selector_applies_world_and_band_filters() {
        let member = entity_id(0x32);
        let (_dir, vault, grant_id) = test_vault_with_grant(member);
        let window_key = WindowKey::new("2026-04");
        let doc = create_window_doc("source", &window_key);
        let world = entity_id(0xE1);
        let other_world = entity_id(0xE2);
        let claim_world = entity_id(0x41);
        let claim_base = entity_id(0x42);
        let claim_other_world = entity_id(0x43);
        let world_entity = world;
        let task_like = entity_id(0x45);

        insert_blob(&doc, claim_world, &claim_blob(Some(world)));
        insert_blob(&doc, claim_base, &claim_blob(None));
        insert_blob(&doc, claim_other_world, &claim_blob(Some(other_world)));
        insert_entity(&doc, world_entity, ENTITY_TYPE_WORLD, b"world");
        insert_entity(&doc, task_like, 80, b"task-list");
        doc.commit();

        let selector = SyncSelector::new(
            grant_id,
            member,
            SyncSelectorWorld::World(world),
            vec![],
            vec![TypeByteBand::Semantic, TypeByteBand::Core],
        );
        let update =
            filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
                .unwrap()
                .export(ExportMode::all_updates())
                .unwrap();
        let ids = import_ids(&update);

        assert!(ids.contains(&claim_world));
        assert!(
            ids.contains(&claim_base),
            "base claims belong to every world selector"
        );
        assert!(ids.contains(&world_entity));
        assert!(!ids.contains(&claim_other_world));
        assert!(!ids.contains(&task_like), "productivity band leaked");
    }

    #[test]
    fn selector_requires_matching_federation_grant_member() {
        let member = entity_id(0x33);
        let (_dir, vault, grant_id) = test_vault_with_grant(member);
        let window_key = WindowKey::new("2026-05");
        let doc = create_window_doc("source", &window_key);
        insert_entity(&doc, entity_id(0x55), ENTITY_TYPE_PERSON, b"person");
        doc.commit();

        let selector = SyncSelector::new(
            grant_id,
            entity_id(0x34),
            SyncSelectorWorld::All,
            vec![],
            vec![],
        );
        assert!(
            filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
                .is_err()
        );
    }

    #[test]
    fn selector_requires_matching_federation_grant_scope() {
        let member = entity_id(0x35);
        let (_dir, vault, grant_id) =
            test_vault_with_grant_scope(member, FederationGrantScope::vault(8));
        let window_key = WindowKey::new("2026-05");
        let doc = create_window_doc("source", &window_key);
        insert_entity(&doc, entity_id(0x56), ENTITY_TYPE_PERSON, b"person");
        doc.commit();

        let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
        assert!(
            filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
                .is_err()
        );
    }

    #[test]
    fn selector_suppresses_tombstoned_live_map_residue() {
        let member = entity_id(0x36);
        let (_dir, vault, grant_id) = test_vault_with_grant(member);
        let window_key = WindowKey::new("2026-06");
        let doc = create_window_doc("source", &window_key);
        let residue = entity_id(0x57);
        insert_entity(&doc, residue, ENTITY_TYPE_PERSON, b"stale-live-blob");
        insert_tombstone(&doc, residue);
        doc.commit();

        let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
        let filtered =
            filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
                .unwrap();
        let receiver = create_window_doc("receiver", &window_key);
        receiver
            .import(&filtered.export(ExportMode::all_updates()).unwrap())
            .unwrap();

        assert!(
            receiver
                .get_map("entities")
                .get(residue.to_hex().as_str())
                .is_none(),
            "tombstoned live-map residue must not replicate"
        );
        assert!(
            receiver
                .get_map("tombstones")
                .get(residue.to_hex().as_str())
                .is_some(),
            "unfiltered selector snapshots should retain tombstones"
        );
    }

    #[test]
    fn selector_suppresses_tombstone_alias_live_map_residue() {
        let member = entity_id(0x38);
        let (_dir, vault, grant_id) = test_vault_with_grant(member);
        let window_key = WindowKey::new("2026-08");
        let doc = create_window_doc("source", &window_key);
        let residue = entity_id(0x58);
        insert_entity(&doc, residue, ENTITY_TYPE_PERSON, b"stale-live-blob");
        insert_uppercase_tombstone_alias(&doc, residue);
        doc.commit();

        let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
        let filtered =
            filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
                .unwrap();
        let receiver = create_window_doc("receiver", &window_key);
        receiver
            .import(&filtered.export(ExportMode::all_updates()).unwrap())
            .unwrap();

        assert!(
            receiver
                .get_map("entities")
                .get(residue.to_hex().as_str())
                .is_none(),
            "any parseable tombstone alias must suppress live-map residue"
        );
        assert!(
            receiver
                .get_map("tombstones")
                .get(residue.to_hex().to_ascii_uppercase().as_str())
                .is_some(),
            "selector snapshots should retain the alias tombstone"
        );
    }

    #[test]
    fn selector_treats_malformed_facet_of_value_as_denied_scope() {
        let member = entity_id(0x37);
        let (_dir, vault, grant_id) = test_vault_with_grant(member);
        let window_key = WindowKey::new("2026-07");
        let doc = create_window_doc("source", &window_key);
        let facet_allowed = entity_id(0xA7);
        let facet_denied = entity_id(0xB7);
        let malformed_claim = entity_id(0x17);

        insert_entity(&doc, facet_allowed, ENTITY_TYPE_FACET, b"facet-a");
        insert_entity(&doc, facet_denied, ENTITY_TYPE_FACET, b"facet-b");
        insert_blob(&doc, malformed_claim, &claim_blob(None));
        insert_malformed_edge(&doc, malformed_claim, EdgeKind::FacetOf, facet_denied);
        insert_edge(&doc, facet_allowed, EdgeKind::Supports, malformed_claim);
        doc.commit();

        let selector = SyncSelector::new(
            grant_id,
            member,
            SyncSelectorWorld::All,
            vec![facet_allowed],
            vec![],
        );
        let update =
            filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
                .unwrap()
                .export(ExportMode::all_updates())
                .unwrap();
        let ids = import_ids(&update);

        assert!(ids.contains(&facet_allowed));
        assert!(
            !ids.contains(&malformed_claim),
            "malformed FacetOf value must fail closed, not behave as absent"
        );
    }
}
