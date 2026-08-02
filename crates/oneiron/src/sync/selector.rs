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
    AuthorityOp, FederationGrantActivation, authority_log_entity_id,
    decode_authority_log_entry_body, federation_grant_activation, genesis_vault_id,
    validate_authority_log_entry_body_bytes,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimLifecycleStatus, restamp_federated_claim_source, validate_claim_body_and_decode,
};
use crate::companion::{
    CompanionExportClassification, CompanionScope, ENTITY_TYPE_COMPANION_REGISTER,
    decode_companion_record_body,
};
use crate::edge::EdgeKind;
use crate::entity_id::{EntityId, LocalWorldId};
use crate::error::{
    Error, Result, SyncEngineContext, SyncProtocolValidation,
    SyncSelectorValidation as SelectorError,
};
use crate::federation::{
    FederationGrantScope, GuestShareEnvelope, GuestShareEnvelopeBody, decode_federation_grant_body,
    sign_guest_share_envelope,
};
use crate::registry::{
    ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_FEDERATION_GRANT,
    ENTITY_TYPE_WORLD, TypeByteBand, band_of,
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

/// World component of a closed-subgraph selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncSelectorWorld {
    /// Include base and all world-scoped claims.
    All,
    /// Include only base-reality claims.
    Base,
    /// Include base-reality claims and claims scoped to this world.
    World(LocalWorldId),
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
        u32::try_from(selector_bytes.len()).map_err(|_| selector_err(SelectorError::TooLarge))?;
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
        return Err(selector_err(SelectorError::RequestTooShort));
    }
    let selector_len = u32::from_be_bytes(
        bytes[..SELECTOR_VV_PREFIX_LEN]
            .try_into()
            .map_err(|_| selector_err(SelectorError::Length))?,
    ) as usize;
    let selector_end = SELECTOR_VV_PREFIX_LEN
        .checked_add(selector_len)
        .ok_or_else(|| selector_err(SelectorError::LengthOverflow))?;
    if selector_len == 0 || bytes.len() < selector_end {
        return Err(selector_err(SelectorError::RequestTruncated));
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
        .map_err(|_| selector_err(SelectorError::MessagePackEncode))?;
    Ok(out)
}

/// Decodes a strict MessagePack selector.
pub fn decode_sync_selector(bytes: &[u8]) -> Result<SyncSelector> {
    let mut cursor = Cursor::new(bytes);
    let value =
        rmpv::decode::read_value(&mut cursor).map_err(|_| selector_err(SelectorError::Decode))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(selector_err(SelectorError::TrailingBytes));
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

/// Builds and signs a guest-share envelope from selector-filtered window bytes.
///
/// The signature is computed only after the selected window has been stripped
/// of federation grant records, authority-log roster/topology records, and
/// tombstone metadata.
pub fn guest_share_envelope<S>(
    vault: &Vault,
    source: &LoroDoc,
    key: &WindowKey,
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
    signer: S,
) -> Result<GuestShareEnvelope>
where
    S: FnOnce(&[u8]) -> Result<Vec<u8>>,
{
    let body = guest_share_envelope_body(vault, source, key, grant_scope, selector)?;
    sign_guest_share_envelope(body, signer)
}

/// Builds the stripped, unsigned guest-share envelope body for a selector.
pub fn guest_share_envelope_body(
    vault: &Vault,
    source: &LoroDoc,
    key: &WindowKey,
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
) -> Result<GuestShareEnvelopeBody> {
    authorize_sync_selector(vault, grant_scope, selector)?;
    let filtered = filter_window_doc(source, key, grant_scope, selector);
    let stripped = strip_guest_share_metadata(&filtered, key)?;
    let update = stripped
        .export(ExportMode::all_updates())
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportAllUpdates, e))?;
    let selector_bytes = encode_sync_selector(selector)?;
    Ok(GuestShareEnvelopeBody::new(
        grant_scope,
        selector.member_ref,
        selector_bytes,
        key.as_str(),
        update,
    ))
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
    copy_admitted_edges(&remote.get_map("edges"), &admitted.get_map("edges"))?;

    admitted.commit_with(CommitOptions::new().origin(role.origin()));
    admitted
        .export(ExportMode::all_updates())
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportAllUpdates, e))
}

#[cfg(feature = "sync")]
fn create_admission_doc(
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
) -> Result<LoroDoc> {
    let doc = LoroDoc::new();
    doc.set_peer_id(federated_admission_peer_id(key, update, role))
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroSetPeerId, e))?;
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
            crate::temporal::TimeRange {
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
        return Err(selector_err(SelectorError::MustBeMap));
    };
    validate_selector_keys(entries)?;
    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64() != Some(SYNC_SELECTOR_SCHEMA_VERSION) {
        return Err(selector_err(SelectorError::UnsupportedSchemaVersion));
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
            admit_federated_authority_log(vault, &id, &blob[ENTITY_METADATA_HEADER_LEN..])?;
            return Ok(blob.to_vec());
        }
        // Engine-authored kinds are CLASSIFICATION-routed, not band-routed:
        // IDENTITY_TOPOLOGY_EVENT (76) is Maintenance-classified inside the
        // Companion band (owner-ruled byte-space v3), so a band-only check
        // would hand a member/guest single-writer ledger authority. The
        // band check stays for the reserved-unregistered maintenance bytes
        // (125/126/127/130), which carry no registry entry.
        if band_of(header.entity_type) == TypeByteBand::InducedDynamicMaintenance
            || crate::registry::entity_type_registry_entry(header.entity_type).is_some_and(
                |entry| entry.classification == crate::registry::EntityClassification::Maintenance,
            )
        {
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

/// Federation admission door for a type-122 carrier.
///
/// ONE-1604-D1 (fix-leg 4): the CRDT row's KEY is bound to the id derived
/// from the decoded body, exactly as `check_authority_log_store_key` binds it
/// at the write door. Without the bind, admission validated the body and the
/// vault root but never checked that the body belonged at `id` — so a
/// wrong-key authority row entered the ADMITTED doc and only failed later at
/// materialize. That is strictly worse than rejecting here: the admitted doc
/// is what the ordinary replay path imports, so the mismatch surfaced after
/// the row had already been copied into locally authored bytes, and anything
/// this door scopes off the same key operated on a row that could never be
/// admitted under it.
///
/// The bind is a REMOTE rejection, not a local failure:
/// `AuthorityLogStoreKeyMismatch` is already classified in
/// `quarantine::remote_rejection_reason`, so the replay sites quarantine the
/// row and continue rather than aborting the window (H2). Deriving the id
/// costs one hash over bytes this function has already decoded.
#[cfg(feature = "sync")]
fn admit_federated_authority_log(vault: &Vault, id: &EntityId, body: &[u8]) -> Result<()> {
    validate_authority_log_entry_body_bytes(body)?;
    let entry = decode_authority_log_entry_body(body)?;
    if authority_log_entity_id(&entry)? != *id {
        return Err(Error::AuthorityLogStoreKeyMismatch { id: *id });
    }
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

/// Copies the federated edges map, rejecting reserved-kind edge keys:
/// `merged_into` / `split_into` writes are the identity-topology door's
/// side-effects and never member/guest input (ARCH-0055) — copying the raw
/// bytes would hand a federated peer redirect-shell write authority over
/// the host's entities. Keys that do not parse as edge keys copy through
/// unchanged: the ordinary materialization path quarantines them with
/// evidence (the same division Observer B uses).
#[cfg(feature = "sync")]
fn copy_admitted_edges(source: &loro::LoroMap, target: &loro::LoroMap) -> Result<()> {
    let mut result = Ok(());
    map_for_each_value_bytes(source, |key, value| {
        if result.is_err() {
            return;
        }
        if let Some((_, kind, _)) = super::bridge::parse_edge_key(key)
            && let Err(reserved) = crate::edge::validate_public_edge_kind(kind)
        {
            result = Err(reserved);
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
        return Err(Error::sync_protocol(
            SyncProtocolValidation::FederatedTombstoneAdmission,
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
        FederationGrantActivation::Unpacted | FederationGrantActivation::Active => Ok(()),
        FederationGrantActivation::Inactive(_) => Err(selector_err(SelectorError::GrantInactive)),
    }
}

fn strip_guest_share_metadata(source: &LoroDoc, key: &WindowKey) -> Result<LoroDoc> {
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
            SyncSelectorWorld::World(world) if *id != world.entity_id() => return None,
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
        SyncSelectorWorld::World(id) => Some(id.entity_id()),
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
            (
                Value::from(WORLD_KEYS[1]),
                Value::from(id.entity_id().to_hex()),
            ),
        ]),
    }
}

fn decode_world(value: &Value) -> Result<SyncSelectorWorld> {
    let Value::Map(entries) = value else {
        return Err(selector_err(SelectorError::WorldMustBeMap));
    };
    let kind = required_value(entries, WORLD_KEYS[0])?
        .as_str()
        .ok_or_else(|| selector_err(SelectorError::WorldKind))?;
    match kind {
        WORLD_KIND_ALL => {
            if entries.len() != 1 {
                return Err(selector_err(SelectorError::AllWorldHasExtraFields));
            }
            Ok(SyncSelectorWorld::All)
        }
        WORLD_KIND_BASE => {
            if entries.len() != 1 {
                return Err(selector_err(SelectorError::BaseWorldHasExtraFields));
            }
            Ok(SyncSelectorWorld::Base)
        }
        WORLD_KIND_WORLD => {
            validate_world_keys(entries)?;
            let world = decode_entity_hex(required_value(entries, WORLD_KEYS[1])?)?;
            let local_world = LocalWorldId::try_from(world)
                .map_err(|_| selector_err(SelectorError::ForeignWorldId))?;
            Ok(SyncSelectorWorld::World(local_world))
        }
        _ => Err(selector_err(SelectorError::UnknownWorldKind)),
    }
}

fn validate_selector_keys(entries: &[(Value, Value)]) -> Result<()> {
    let mut seen = [false; SELECTOR_KEYS.len()];
    for (key, _) in entries {
        let key = key
            .as_str()
            .ok_or_else(|| selector_err(SelectorError::KeyMustBeString))?;
        let Some(index) = SELECTOR_KEYS.iter().position(|expected| *expected == key) else {
            return Err(selector_err(SelectorError::UnknownKey));
        };
        if seen[index] {
            return Err(selector_err(SelectorError::DuplicateKey));
        }
        seen[index] = true;
    }
    if seen.iter().all(|present| *present) {
        Ok(())
    } else {
        Err(selector_err(SelectorError::MissingKey))
    }
}

fn validate_world_keys(entries: &[(Value, Value)]) -> Result<()> {
    let mut seen = [false; WORLD_KEYS.len()];
    for (key, _) in entries {
        let key = key
            .as_str()
            .ok_or_else(|| selector_err(SelectorError::WorldKey))?;
        let Some(index) = WORLD_KEYS.iter().position(|expected| *expected == key) else {
            return Err(selector_err(SelectorError::WorldUnknownKey));
        };
        if seen[index] {
            return Err(selector_err(SelectorError::WorldDuplicateKey));
        }
        seen[index] = true;
    }
    if seen.iter().all(|present| *present) {
        Ok(())
    } else {
        Err(selector_err(SelectorError::WorldMissingKey))
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(entry_key, value)| (entry_key.as_str() == Some(key)).then_some(value))
        .ok_or_else(|| selector_err(SelectorError::MissingRequiredValue))
}

fn decode_entity_hex(value: &Value) -> Result<EntityId> {
    let hex = value
        .as_str()
        .ok_or_else(|| selector_err(SelectorError::EntityIdMustBeHex))?;
    EntityId::from_hex(hex).map_err(|_| selector_err(SelectorError::InvalidEntityId))
}

fn decode_entity_array(value: &Value) -> Result<Vec<EntityId>> {
    let Value::Array(values) = value else {
        return Err(selector_err(SelectorError::EntityListMustBeArray));
    };
    values.iter().map(decode_entity_hex).collect()
}

fn decode_band_array(value: &Value) -> Result<Vec<TypeByteBand>> {
    let Value::Array(values) = value else {
        return Err(selector_err(SelectorError::BandsMustBeArray));
    };
    values.iter().map(decode_band).collect()
}

fn decode_band(value: &Value) -> Result<TypeByteBand> {
    let band = value
        .as_str()
        .ok_or_else(|| selector_err(SelectorError::BandMustBeString))?;
    match band {
        "semantic" => Ok(TypeByteBand::Semantic),
        "core" => Ok(TypeByteBand::Core),
        "companion" => Ok(TypeByteBand::Companion),
        "productivity" => Ok(TypeByteBand::Productivity),
        "crm" => Ok(TypeByteBand::Crm),
        "maintenance" => Ok(TypeByteBand::InducedDynamicMaintenance),
        _ => Err(selector_err(SelectorError::UnknownBand)),
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

fn selector_err(reason: SelectorError) -> Error {
    Error::sync_protocol(SyncProtocolValidation::Selector { reason })
}

#[cfg(test)]
mod tests;
