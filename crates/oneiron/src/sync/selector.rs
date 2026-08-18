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
    AuthorityFold, AuthorityOp, FederationGrantActivation, FederationPactStatus,
    authority_log_entity_id, decode_authority_log_entry_body, federation_grant_activation,
    genesis_vault_id, validate_authority_log_entry_body_bytes,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    COREFERENCE_PACT_ID_LEN, ClaimLifecycleStatus, restamp_federated_claim_source,
    validate_claim_body_and_decode,
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
    FederationDirectionScope, FederationGrantScope, FederationScopeBands, FederationScopeFacets,
    FederationScopeWorlds, GuestShareEnvelope, GuestShareEnvelopeBody, SelectorRange,
    decode_federation_grant_body, selector_range_of, sign_guest_share_envelope,
};
use crate::registry::{
    ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_FEDERATION_GRANT,
    ENTITY_TYPE_WORLD, EntityClassification, TypeByteZone, entity_type_registry_entry, zone_of,
};

use super::bridge::parse_edge_key;
use super::loro_support::{
    map_for_each_tombstone_value, map_for_each_value_bytes, map_insert_bytes,
};
#[cfg(feature = "sync")]
use super::quarantine::{self, QuarantineContainer};
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
    /// Allowed `FacetOf` targets. Empty is read by `EmptyAxis`: the lattice ⊥
    /// under a pact-bound grant, "no facet filter" under an unpacted one.
    pub facets: Vec<EntityId>,
    /// Allowed entity type-byte bands. Empty is read by `EmptyAxis`: the
    /// lattice ⊥ under a pact-bound grant, "all bands" under an unpacted one.
    pub bands: Vec<SelectorRange>,
}

impl SyncSelector {
    /// Constructs a selector with stable, deduplicated facet/band sets.
    #[must_use]
    pub fn new(
        grant_id: EntityId,
        member_ref: EntityId,
        world: SyncSelectorWorld,
        facets: Vec<EntityId>,
        bands: Vec<SelectorRange>,
    ) -> Self {
        let facets = facets
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut normalized_bands = Vec::new();
        for band in [
            SelectorRange::Semantic,
            SelectorRange::Core,
            SelectorRange::Companion,
            SelectorRange::Productivity,
            SelectorRange::Crm,
            SelectorRange::InducedDynamicMaintenance,
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

    fn facet_filter_active(&self, empty: EmptyAxis) -> bool {
        !self.facets.is_empty() || empty == EmptyAxis::Bottom
    }

    fn band_filter_active(&self, empty: EmptyAxis) -> bool {
        !self.bands.is_empty() || empty == EmptyAxis::Bottom
    }

    fn any_filter_active(&self, empty: EmptyAxis) -> bool {
        self.facet_filter_active(empty)
            || self.band_filter_active(empty)
            || !matches!(self.world, SyncSelectorWorld::All)
    }
}

/// How the EXPORT path reads an empty facet or band vector.
///
/// One wire field, two readers: [`selector_direction_scope`] answers the
/// CEILING question and this answers the EXPORT question. OF-453 L3 is exactly
/// the demand that the two agree. Reading silence as ⊥ for the ceiling and as
/// "no filter" for the export is not a harmless mismatch — it IS the inversion
/// the R-20260807 §6 re-pin exists to kill: the peer sends the DEFAULT wire
/// shape, authorizes as "requests nothing" beneath any ceiling however narrow,
/// and is then handed the whole window.
///
/// The split is by BINDING, not by axis:
///
/// * a PACT-BOUND grant has a ceiling to escape, so silence exports as the ⊥
///   the ceiling check just credited the selector with;
/// * an UNPACTED grant has no ceiling at all, so silence keeps its legacy wire
///   meaning and shipped guest grants do not brick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmptyAxis {
    /// The lattice ⊥: the axis filter is ACTIVE with nothing named, so it
    /// admits nothing. A selector that authorized as requesting nothing
    /// exports nothing.
    Bottom,
    /// The legacy wire reading: no filter on this axis.
    Unfiltered,
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
    let empty = authorize_selector_export(vault, grant_scope, selector, crate::unix_seconds_now())?;
    filter_window_doc(vault, source, key, grant_scope, selector, empty)
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
    let empty = authorize_selector_export(vault, grant_scope, selector, crate::unix_seconds_now())?;
    let filtered = filter_window_doc(vault, source, key, grant_scope, selector, empty)?;
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
    copy_admitted_edges(
        vault,
        key,
        &remote.get_map("entities"),
        &remote.get_map("edges"),
        &admitted.get_map("edges"),
    )?;

    admitted.commit_with(CommitOptions::new().origin(role.origin()));
    admitted
        .export(ExportMode::all_updates())
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportAllUpdates, e))
}

/// Re-runs federated claim admission over ALREADY-ADMITTED window bytes using
/// the policy resolved RIGHT NOW.
///
/// `admit_federated_window_update` evaluates claims against the policy that was
/// resolved at ADMISSION time. A staged vault import parks those bytes behind a
/// durable Pending receipt, and the human confirmation that releases them can
/// land arbitrarily later — so the policy the operator actually consented under
/// is the one in force at CONFIRM time, not the one that happened to be loaded
/// when the artifact was first staged. This door re-resolves the manifest with
/// the same resolver the stage leg uses and re-applies the same claim gate.
///
/// It deliberately re-checks the admitted bytes AS THEY ARE rather than
/// re-deriving a fresh admitted doc: the receipt pins their digest, so a
/// re-admission would produce different bytes and break the digest bind. The
/// claims inside are already restamped to `src=imported`, which is exactly the
/// source the gate must judge on the import path, so no restamp is repeated.
///
/// Non-claim rows were admitted by identity/kind rules that do not depend on
/// resolved policy, so they are left alone here.
#[cfg(feature = "sync")]
pub(crate) fn revalidate_admitted_federated_claims(
    vault: &Vault,
    key: &WindowKey,
    admitted_update: &[u8],
    role: FederationAdmissionRole,
) -> Result<()> {
    let admitted = create_window_doc(role.origin(), key);
    admitted
        .import(admitted_update)
        .map_err(|source| Error::CrdtDecodeError {
            context: "import admitted update",
            source,
        })?;

    let policy =
        vault.with_write_txn(|wtxn| crate::gate::resolve_policy_manifest(&vault.store, wtxn))?;

    let mut result = Ok(());
    map_for_each_value_bytes(&admitted.get_map("entities"), |_, value| {
        if result.is_err() {
            return;
        }
        result = recheck_admitted_claim_blob(&policy, value);
    });
    result
}

#[cfg(feature = "sync")]
fn recheck_admitted_claim_blob(
    policy: &crate::gate::PolicyManifestResolution,
    value: Option<&[u8]>,
) -> Result<()> {
    let blob = value.ok_or(Error::InvalidKey)?;
    let header =
        EntityMetadataHeader::parse(blob).ok_or(Error::CorruptedIndex("entity metadata"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(());
    }
    let body = validate_claim_body_and_decode(&blob[ENTITY_METADATA_HEADER_LEN..], true)?;
    crate::gate::check_federated_claim_admission(&body, policy)
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
        // Engine-authored kinds are CLASSIFICATION-routed, never byte-range
        // routed. Before byte-space v3 the second arm here was a "byte >= 120"
        // band test, which was only ever a PROXY for "engine-authored" — and
        // the v3 re-key moves every maintenance kind DOWN into 64–99, so
        // keeping that test would have silently begun admitting peer-written
        // maintenance records. The zone arm below now covers only bytes with
        // no static kind at all: the canon-reserved system bytes (69/72/74/75)
        // and the entire pack half, neither of which a peer may author.
        let engine_authored = entity_type_registry_entry(header.entity_type).map_or_else(
            || {
                !matches!(
                    zone_of(header.entity_type),
                    TypeByteZone::Semantic | TypeByteZone::Core | TypeByteZone::CompiledProduct
                )
            },
            |entry| entry.classification == EntityClassification::Maintenance,
        );
        if engine_authored {
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

/// Federation admission door for a AUTHORITY_LOG carrier.
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
///
/// ONE-1645 admission boundary for the `FacetOf` type table. The replay
/// chokepoint (`window::forward_rematerialize`) already quarantines an
/// off-table stamp before it reaches LMDB, but the FEDERATION SELECTOR reads
/// the RAW Loro map, not LMDB: a forged `PERSON -> <selected FACET>` row that
/// merely SITS in the admitted / live document could scope what this vault
/// exports to a facet-limited peer — quarantined-but-present is enough. The
/// complete fix is layered: this door keeps a PROVABLY off-table row out of
/// the doc, and [`facet_scope_by_source`] mirrors the same table on the READ
/// side so whatever residue survives the H2 defer is inert anyway.
///
/// The invariant here is deliberately asymmetric, and the asymmetry is the
/// whole design (see [`admitted_facet_of_verdict`]):
///
/// * PROVABLY off-table on the facts in hand — a KNOWN off-table source, or a
///   KNOWN non-FACET target, either one sufficient ALONE — is DROPPED with a
///   typed [`Error::InvalidFacetOfEdge`] quarantine record. The row is not
///   copied, so the selector can never read it.
/// * UNKNOWABLE deciding endpoint — the endpoint has not arrived yet — PASSES
///   THROUGH. The remat gate's defer-then-validate owns those: a hard verdict
///   here would burn a legitimate out-of-order delivery permanently (H2). The
///   read mirror is what makes that pass-through safe even after the missing
///   endpoint later lands off-table.
///
/// Dropping the edge while still admitting its source entity is harmless: the
/// entity arrives UNSTAMPED, which is strictly less disclosure than the peer
/// asked for.
///
/// THE DROP IS TERMINAL, and the quarantine shape follows from that. A dropped
/// row never enters the admitted doc, so no forward rematerialization can ever
/// replay it — the evidence written here is the WHOLE account of that row, and
/// it must not schedule retry work nobody can discharge. The rejections
/// therefore ride a [`quarantine::TerminalRejectionBatch`]: no `rm:w:` marker
/// (an unhealable marker would pend forever and permanently poison the erasure
/// SLA channel `rm:` exists to carry), and ONE write transaction for the whole
/// pass rather than one per rejected row (the peer chooses N, so a per-row
/// commit is an amplification primitive it controls). Evidence is bounded at
/// [`quarantine::MAX_QUARANTINE_ROWS_PER_PASS`] rows per pass; beyond that
/// rejections are accounted by count, never silently.
#[cfg(feature = "sync")]
fn copy_admitted_edges(
    vault: &Vault,
    window_key: &WindowKey,
    source_entities: &loro::LoroMap,
    source: &loro::LoroMap,
    target: &loro::LoroMap,
) -> Result<()> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rejections = quarantine::TerminalRejectionBatch::new(window_key.as_str());
    let mut result = Ok(());
    map_for_each_value_bytes(source, |key, value| {
        if result.is_err() {
            return;
        }
        if let Some((src, kind, tgt)) = super::bridge::parse_edge_key(key) {
            if let Err(reserved) = crate::edge::validate_public_edge_kind(kind) {
                result = Err(reserved);
                return;
            }
            match admitted_facet_of_verdict(vault, &rtxn, source_entities, src, kind, tgt) {
                Ok(AdmittedEdgeVerdict::Copy) => {}
                Ok(AdmittedEdgeVerdict::DropOffTable(off_table)) => {
                    // Quarantine-and-continue: the peer's forged row gets
                    // typed durable evidence, the window's other N-1 rows
                    // still admit. `payload` is the raw value when present.
                    rejections.push(
                        QuarantineContainer::Edges,
                        key,
                        &off_table,
                        value.unwrap_or(&[]),
                    );
                    return;
                }
                // A LOCAL fault reading endpoint types (corrupted stored
                // header, heed read error) is never the peer's rejection:
                // fail closed on the whole admission rather than record a
                // quarantine row that misattributes our defect to them.
                Err(local) => {
                    result = Err(local);
                    return;
                }
            }
        }
        result = value
            .ok_or(Error::InvalidKey)
            .and_then(|bytes| map_insert_bytes(target, key, bytes));
    });
    result?;
    // Evidence commits only once the copy pass itself succeeded: a pass that
    // fails closed admits nothing, so recording peer rejections from a frame
    // this vault refused whole would be an account of a thing that never
    // happened.
    drop(rtxn);
    rejections.commit(vault)
}

/// What the admission boundary does with one parsed edge row.
#[cfg(feature = "sync")]
enum AdmittedEdgeVerdict {
    /// On-table, not a `FacetOf` row at all, or a row whose DECIDING endpoint
    /// type is not knowable yet — copy it and let the replay gate own it.
    Copy,
    /// PROVABLY off-table on the facts in hand: a known off-table source, or a
    /// known non-FACET target, is each sufficient alone. Drop with this typed
    /// rejection.
    DropOffTable(Error),
}

/// Resolves the ONE-1645 `FacetOf` table for ONE admitted row.
///
/// Endpoint types resolve from two sources, in this order:
///
/// 1. the LOCAL vault row (`batch::stored_entity_type`) — entity type is
///    immutable per id ([`Error::EntityTypeImmutable`]), so a stored type is
///    permanent truth about that id;
/// 2. the ADMITTED UPDATE's own entities map — the endpoint arriving in the
///    SAME frame as its stamp is the common legitimate case, and reading it
///    here is what keeps a well-formed peer from being forced through the
///    defer path on every first delivery.
///
/// The verdict is ONE-SIDED-sufficient
/// ([`crate::batch::facet_of_endpoints_provably_off_table`]): the table is a
/// conjunction of two independent per-endpoint predicates, so a KNOWN off-table
/// source alone proves the row bad no matter what its target turns out to be,
/// and a KNOWN non-FACET target alone proves it bad no matter what its source
/// turns out to be. Demanding BOTH endpoints before rejecting would let a
/// forger buy a pass by simply withholding the endpoint that is not the
/// incriminating one.
///
/// Only a row whose DECIDING endpoint stays unknowable passes through: the
/// endpoint has not arrived, and the remat gate's defer-then-validate owns it.
/// This is the H2 line — an unknowable type is not evidence of a forgery, and
/// treating it as one would wedge out-of-order delivery permanently. That
/// residue is inert on the export path regardless, because
/// [`facet_scope_by_source`] now honors a scope only from a row whose BOTH
/// endpoints resolve onto this same table.
///
/// The table itself is [`crate::batch::facet_of_endpoint_types_on_table`] and
/// its halves, the single copy the write/replay door also runs.
#[cfg(feature = "sync")]
fn admitted_facet_of_verdict(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    source_entities: &loro::LoroMap,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
) -> Result<AdmittedEdgeVerdict> {
    if kind != EdgeKind::FacetOf {
        return Ok(AdmittedEdgeVerdict::Copy);
    }
    let src_type = admitted_endpoint_type(vault, rtxn, source_entities, &src)?;
    let tgt_type = admitted_endpoint_type(vault, rtxn, source_entities, &tgt)?;
    if !crate::batch::facet_of_endpoints_provably_off_table(src_type, tgt_type) {
        return Ok(AdmittedEdgeVerdict::Copy);
    }
    Ok(AdmittedEdgeVerdict::DropOffTable(
        Error::InvalidFacetOfEdge {
            src,
            src_type,
            tgt,
            tgt_type,
        },
    ))
}

/// One endpoint's type byte at admission time: the stored row first (permanent
/// truth — entity type is immutable per id), then the admitted update's own
/// entities map. `None` = not knowable yet.
///
/// A remote blob too short to carry a header is NOT a local defect and must
/// not fail the admission closed — it is unparsable REMOTE input, which the
/// entity pass and the replay door already reject on their own terms. It reads
/// as unknowable here, so a forged stamp cannot dodge the table by shipping a
/// truncated endpoint blob: the endpoint never materializes, so the stamp's
/// source never becomes exportable either.
#[cfg(feature = "sync")]
fn admitted_endpoint_type(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    source_entities: &loro::LoroMap,
    id: &EntityId,
) -> Result<Option<u8>> {
    if let Some(stored) = crate::batch::stored_entity_type(&vault.store, rtxn, id)? {
        return Ok(Some(stored));
    }
    Ok(
        super::loro_support::map_get_bytes(source_entities, &id.to_hex())
            .as_deref()
            .and_then(EntityMetadataHeader::parse)
            .map(|header| header.entity_type),
    )
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
pub(crate) fn authorize_sync_selector_at(
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
fn authorize_selector_export(
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
fn selector_direction_scope(selector: &SyncSelector) -> FederationDirectionScope {
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
fn effective_scope_for_grant(
    fold: &AuthorityFold,
    grant_id: &EntityId,
) -> Option<FederationDirectionScope> {
    fold.federation_pacts
        .values()
        .filter(|pact| pact.grant_ref == *grant_id)
        .map(|pact| pact.effective_scope.clone())
        .reduce(|left, right| left.intersect(&right))
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

/// Which coreference material this ONE export request may carry (ONE-1414).
///
/// Cross-vault coreference is LOCAL BY DEFAULT: a `same_as` link and every
/// `core.coreference.*` claim stay home unless the owner consented to share
/// THIS link into THIS pact. The context is the whole answer for one request —
/// built once, read on every row — so the edge pass and the claim pass cannot
/// reach different conclusions about the same link.
///
/// `pact_id` absent means the grant is UNPACTED, and an unpacted grant carries
/// no coreference material at all: with no pact there is nothing a consent
/// claim could name, so a consent-SHAPED claim in the window is not consent to
/// anything. That case is not special-cased anywhere — it falls out of
/// `allowed_links` being empty.
#[derive(Debug, Default)]
struct CoreferenceExportContext {
    /// The pact this export runs under, when the grant is pact-bound.
    pact_id: Option<[u8; COREFERENCE_PACT_ID_LEN]>,
    /// Links the owner consented to share into exactly `pact_id`, with
    /// endpoint order normalized — consent is a property of the LINK, not of
    /// which endpoint happens to be stored as the source.
    allowed_links: BTreeSet<(EntityId, EntityId)>,
}

impl CoreferenceExportContext {
    fn allows(&self, source: EntityId, target: EntityId) -> bool {
        self.allowed_links
            .contains(&normalized_coreference_pair(source, target))
    }

    /// Whether one decoded CLAIM body may travel.
    ///
    /// Claims outside the `core.coreference.*` namespace are none of this
    /// context's business and pass untouched. Inside it:
    ///
    /// * the claim must hang off a `same_as` EdgeRef whose link is allowed —
    ///   a coreference-namespace claim on any other subject describes no link
    ///   this context can vouch for, so it is withheld;
    /// * a STATUS claim then travels with its link, because the status is what
    ///   makes the shared link mean anything;
    /// * a SHARE-CONSENT claim travels only when it names THIS export's pact.
    ///   Pact Q's consent is not a weaker statement about pact P, it is a
    ///   statement about a relationship P's peer is not party to — shipping it
    ///   would disclose the existence of another federation.
    fn claim_travels(&self, body: &crate::claim::ClaimBody) -> bool {
        if !body
            .predicate
            .starts_with(crate::claim::PREDICATE_COREFERENCE_PREFIX)
        {
            return true;
        }
        let crate::claim::ClaimSubject::Edge {
            source,
            kind: EdgeKind::SameAs,
            target,
        } = body.subject
        else {
            return false;
        };
        if !self.allows(source, target) {
            return false;
        }
        if body.predicate != crate::claim::PREDICATE_COREFERENCE_SHARE_CONSENT {
            return true;
        }
        matches!(
            (
                self.pact_id,
                crate::claim::coreference_share_consent_pact_id(body),
            ),
            (Some(pact), Ok(claimed)) if claimed == pact
        )
    }
}

/// Endpoint pair in a stable order, so one link has one identity regardless of
/// which orientation it was stored in.
fn normalized_coreference_pair(source: EntityId, target: EntityId) -> (EntityId, EntityId) {
    if source <= target {
        (source, target)
    } else {
        (target, source)
    }
}

/// Resolves what coreference material this request may carry.
///
/// The `same_as` pairs come from the SOURCE DOC — that is what could be
/// exported — while CONSENT is read from the VAULT. That split is the same
/// stored-first discipline [`mirrored_endpoint_type`] applies to endpoint
/// types, and for the same reason: LMDB holds the owner's actual decision,
/// whereas a document row is whatever last won the map. Reading consent from
/// the doc would let a row decide its own disclosure.
///
/// The doc scan runs FIRST and returns early when the window carries no
/// `same_as` edge at all, which is the overwhelming majority of exports: the
/// authority fold is not recomputed for a window that has no link to share.
/// The early return is not a bypass — the default context allows nothing, so a
/// stray coreference claim whose link is absent from the window is still
/// withheld.
fn coreference_export_context(
    vault: &Vault,
    source: &LoroDoc,
    selector: &SyncSelector,
) -> Result<CoreferenceExportContext> {
    let mut pairs = BTreeSet::<(EntityId, EntityId)>::new();
    map_for_each_value_bytes(&source.get_map("edges"), |raw_key, maybe_value| {
        if maybe_value.is_none() {
            return;
        }
        if let Some((src, EdgeKind::SameAs, tgt)) = parse_edge_key(raw_key) {
            pairs.insert(normalized_coreference_pair(src, tgt));
        }
    });
    if pairs.is_empty() {
        return Ok(CoreferenceExportContext::default());
    }

    let fold = vault.authority_fold()?;
    let Some(pact_id) = active_export_pact(&fold, &selector.grant_id) else {
        return Ok(CoreferenceExportContext::default());
    };

    let mut allowed_links = BTreeSet::new();
    for (a, b) in pairs {
        if crate::federation::coreference_shared_for_pact(vault, a, b, &pact_id)? {
            allowed_links.insert((a, b));
        }
    }
    Ok(CoreferenceExportContext {
        pact_id: Some(pact_id),
        allowed_links,
    })
}

/// The id of the ACTIVE pact governing `grant_id`, or `None` when the grant is
/// unpacted or its governing pact is not Active.
///
/// Which pact governs is [`AuthorityFold::pact_for_grant`]'s decision and stays
/// there; this only recovers the id, which the fold keys the map by rather than
/// storing in the state. The identity comparison is by reference into that same
/// map, so it can never match a different pact that merely compares equal.
fn active_export_pact(
    fold: &AuthorityFold,
    grant_id: &EntityId,
) -> Option<[u8; COREFERENCE_PACT_ID_LEN]> {
    let pact = fold.pact_for_grant(grant_id)?;
    if pact.status != FederationPactStatus::Active {
        return None;
    }
    fold.federation_pacts
        .iter()
        .find_map(|(id, candidate)| std::ptr::eq(candidate, pact).then_some(*id))
}

/// One source entity's `FacetOf` scope, as read by [`facet_scope_by_source`].
///
/// A source with NO entry is Unfaceted — either it carries no `FacetOf` rows
/// at all, or every row it carries was SCOPE-INERT (the source is not typed
/// into the admitted set, or the row's target does not resolve to a FACET).
/// The two are deliberately the same state: an inert stamp is not a withhold,
/// it is a non-statement.
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

/// Builds the per-source facet scope a facet-limited peer's export is filtered
/// against, honoring a `FacetOf` row's scope ONLY when BOTH endpoints resolve
/// onto the ONE-1645 table: the source into the admitted set
/// (`CLAIM | TURN | EVENT`) and the target to a FACET.
///
/// READ MIRROR OF THE WRITE TABLE — the why. This door reads the RAW Loro map,
/// never LMDB, so it sees rows no write door would have accepted: the local
/// batch door aborts an off-table stamp, the remat chokepoint quarantines one,
/// and [`copy_admitted_edges`] drops a PROVABLY off-table one at the
/// federation trust boundary — but the H2 defer deliberately lets a row whose
/// deciding endpoint is not knowable YET pass through, and that row is still
/// sitting in the document after its endpoint later arrives typed off-table.
/// Honoring it would let a forged `PERSON -> <selected FACET>` stamp pull the
/// PERSON and its one-hop neighbors across the disclosure boundary, which is
/// an authorization bypass, not a schema violation.
///
/// So the read side runs the SAME table the write side runs, on BOTH endpoints
/// ([`crate::batch::facet_of_endpoint_types_on_table`]): a stamp is honored
/// here exactly when it is a stamp the engine would have let be WRITTEN. A row
/// failing either half is SCOPE-INERT — never a seed, never a withhold — so
/// its source is simply Unfaceted, judged on the selector's other filters like
/// any unstamped entity.
///
/// BOTH HALVES ARE LOAD-BEARING, and the target half is the subtler one. A
/// selector's `facets` list is a set of ids the peer NAMED; membership in it
/// is not evidence the id exists, still less that it is a FACET. A forged
/// `<on-table src> -> <selected id>` row aimed at an ABSENT id would, under a
/// source-only mirror, seed closure from an id the document never typed — and
/// a later frame delivering that id as a PERSON would keep the seed live,
/// because nothing re-examines a resident row. Requiring the target to RESOLVE
/// TO A FACET makes the row inert until such a blob actually exists, at which
/// point the row HEALS into ordinary scoping.
///
/// ENDPOINT TYPES RESOLVE STORED-FIRST, the same two-source order
/// [`admitted_endpoint_type`] uses at the admission boundary:
///
/// 1. the LOCAL vault row — entity type is immutable per id
///    ([`Error::EntityTypeImmutable`]), so a stored type is PERMANENT truth
///    about that id, and the quarantine door that enforces it leaves LMDB
///    holding the first-writer type;
/// 2. else the document blob.
///
/// Reading the document blob FIRST would be LWW-gameable: a peer stores an
/// endpoint as PERSON (the type-conflict quarantine correctly leaves LMDB at
/// PERSON) while a higher-Lamport EVENT blob wins the Loro map, and a
/// blob-first mirror reads the fake.
///
/// WHERE THE TWO DISAGREE the STORED type wins, in BOTH endpoint roles: the
/// conflicting blob is a write the immutability gate rejected, and a rejected
/// write is never consulted for anything. [`mirrored_endpoint_type`] carries
/// the rule and its full argument.
///
/// The asymmetry — inert rather than fail-closed — is deliberate. Making the
/// mirror "helpfully" withhold on an unwritable row would hand a hostile peer
/// a SUPPRESSION primitive: spray `<host's PERSON> -> <any facet>` rows into
/// the window and the host's own entities vanish from a legitimate grant.
/// Refusing to READ an unwritable row is the fix; letting it DENY is the same
/// bug with the sign flipped.
///
/// SCOPE OF THIS MIRROR: it is the read-side twin of THIS lane's write table,
/// nothing wider. The broader exposure-gate design — which disclosure surfaces
/// should consult facet scope at all, and how facet exposure state is
/// consented — is S-DISC2's, and ONE-1646's gate table is derived from door
/// behavior that this function's admitted set now defines on both sides.
/// EVENT is admitted, so EVENT-sourced stamps stay disclosure-effective here
/// (pinned by `tests::selector_denies_event_scoped_to_unselected_facet`).
fn facet_scope_by_source(
    vault: &Vault,
    entities: &loro::LoroMap,
    edges: &loro::LoroMap,
    selector: &SyncSelector,
) -> Result<HashMap<EntityId, FacetScope>> {
    let selected: HashSet<EntityId> = selector.facets.iter().copied().collect();
    let mut scopes = HashMap::<EntityId, FacetScope>::new();
    if selected.is_empty() {
        return Ok(scopes);
    }

    let rtxn = vault.store.env.read_txn()?;
    // Endpoint types are read once per id, not once per row: a source may
    // carry many stamps and a facet may be named by many sources. One rule
    // serves both roles, so an id appearing in both still costs one read.
    let mut types = HashMap::<EntityId, Option<u8>>::new();
    let mut result = Ok(());
    map_for_each_value_bytes(edges, |raw_key, maybe_value| {
        if result.is_err() {
            return;
        }
        let Some((src, kind, tgt)) = parse_edge_key(raw_key) else {
            return;
        };
        if kind != EdgeKind::FacetOf {
            return;
        }
        // BOTH endpoints must resolve onto the table. A LOCAL fault reading
        // stored types (corrupted header, heed read error) is our defect, not
        // the peer's: fail the export closed rather than silently drop a scope
        // and over-disclose.
        let (src_type, tgt_type) = match (
            mirrored_endpoint_type(vault, &rtxn, entities, &mut types, &src),
            mirrored_endpoint_type(vault, &rtxn, entities, &mut types, &tgt),
        ) {
            (Ok(src_type), Ok(tgt_type)) => (src_type, tgt_type),
            (Err(local), _) | (_, Err(local)) => {
                result = Err(local);
                return;
            }
        };
        // A row that fails either half is SCOPE-INERT: not a seed, and not a
        // withhold either. The target half is the one a source-only mirror
        // misses — a selector's `facets` list is ids the peer NAMED, which is
        // no evidence any of them exists or is a FACET.
        let on_table = matches!((src_type, tgt_type), (Some(src_type), Some(tgt_type))
            if crate::batch::facet_of_endpoint_types_on_table(src_type, tgt_type));
        if !on_table {
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
    result.map(|()| scopes)
}

/// One `FacetOf` endpoint's effective type byte for the read mirror, memoized
/// per id. ONE rule, both roles — an endpoint carries the same type whichever
/// end of the row it sits on, so a single memo entry serves both.
///
/// Resolution is [`admitted_endpoint_type`]'s STORED-FIRST order, with the
/// stored row winning OUTRIGHT when the two facts disagree:
///
/// 1. the LOCAL vault row — entity type is immutable per id
///    ([`Error::EntityTypeImmutable`]), so a stored type is PERMANENT truth
///    and the quarantine door that enforces it leaves LMDB holding the
///    first-writer type. When it exists, nothing else is consulted;
/// 2. else the document blob — the not-yet-materialized endpoint of an honest
///    out-of-order delivery (the H2 line), which the ONE-1645 table then
///    judges on its own merits;
/// 3. neither ⇒ `None`: unknowable, hence scope-inert until the endpoint
///    really lands, at which point the row HEALS into ordinary scoping.
///
/// STORED-WINS IS THE WHOLE CONFLICT RULE, and it is one rule rather than a
/// per-role pair because a CONFLICTING blob is a write the immutability gate
/// REJECTED — a rejected write is not evidence about anything, so it is never
/// consulted, in either role, for any purpose. Both attacks die on the same
/// clause:
///
/// * a conflicting blob never CREATES a seed. A stored PERSON with a forged
///   admitted-type blob still reads PERSON, so the stamp stays off the table
///   and seeds nothing — the peer cannot BUY scope with a type the engine
///   refused to write. Symmetrically on the target: a forged FACET blob over
///   a stored PERSON cannot manufacture a facet.
/// * a conflicting blob never ERASES a withhold. A stored EVENT source and a
///   stored FACET target keep scoping through any retype aimed at either end,
///   so an entity withheld from a facet-limited peer stays withheld. Reading a
///   conflict as `None` on EITHER end would make the row inert and delete
///   containment a valid stored row had already established.
///
/// SUPPRESSION STILL CANNOT BE MANUFACTURED, which is the property the
/// inert-not-fail-closed rule protects: the withholds that survive are exactly
/// the ones the STORED types already justified. A forged unselected stamp
/// aimed at a stored-PERSON source is off the table and stays inert, so no new
/// suppression primitive appears — a peer cannot make the host's own rows
/// vanish from a legitimate grant by spraying rejected blobs.
///
/// FAIL DIRECTION: stored truth never loses to a rejected write, in either
/// role. A peer-controlled conflict can therefore never move a row from
/// withheld to exported, nor from contained to seeded.
///
/// Absent, non-binary, and header-unparsable document blobs all read as no
/// document fact. A LOCAL fault reading the stored row (unparsable header) is
/// our defect, not the peer's, and propagates.
fn mirrored_endpoint_type(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    entities: &loro::LoroMap,
    cache: &mut HashMap<EntityId, Option<u8>>,
    id: &EntityId,
) -> Result<Option<u8>> {
    if let Some(cached) = cache.get(id) {
        return Ok(*cached);
    }
    let resolved = match crate::batch::stored_entity_type(&vault.store, rtxn, id)? {
        Some(stored) => Some(stored),
        None => super::loro_support::map_get_bytes(entities, &id.to_hex())
            .as_deref()
            .and_then(EntityMetadataHeader::parse)
            .map(|header| header.entity_type),
    };
    cache.insert(*id, resolved);
    Ok(resolved)
}

fn entity_selector_decision(
    id: &EntityId,
    blob: &[u8],
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
    facet_scope: &HashMap<EntityId, FacetScope>,
    empty: EmptyAxis,
    coreference: &CoreferenceExportContext,
) -> Option<EntitySelectorDecision> {
    let header = EntityMetadataHeader::parse(blob)?;
    if !coreference_claim_passes(header.entity_type, blob, coreference) {
        return None;
    }
    // Interim ONE-1865 guard (SECRET-01, ONE-1919): no SECRET_CUSTODY record
    // replicates at all until ONE-1865's per-credential portable dial replaces
    // this blanket exclusion with `portable ∧ !device_only` respect. Without
    // this the class contract ("device-bound never leaves the device",
    // "cross-vault never replicated") would be false from merge until 1865.
    if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
        return None;
    }
    if header.entity_type == ENTITY_TYPE_COMPANION_REGISTER
        && !companion_register_passes_selector(blob, grant_scope)
    {
        return None;
    }
    if selector.band_filter_active(empty)
        && !selector
            .bands
            .contains(&selector_range_of(header.entity_type))
    {
        return None;
    }
    if selector.facet_filter_active(empty)
        && header.entity_type == ENTITY_TYPE_FACET
        && !selector.facets.contains(id)
    {
        return None;
    }
    if selector.facet_filter_active(empty)
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
    let facet_visible = selector.facet_filter_active(empty)
        && header.entity_type == ENTITY_TYPE_FACET
        && selector.facets.contains(id);
    let facet_seed = selector.facet_filter_active(empty)
        && facet_scope.get(id).is_some_and(|scope| scope.selected);
    Some(EntitySelectorDecision {
        facet_visible,
        facet_seed,
    })
}

/// ONE-1414 coreference exclusion, applied to ONE candidate entity blob.
///
/// Non-CLAIM blobs are none of this arm's business and pass untouched. A CLAIM
/// blob that does not DECODE is WITHHELD, the same fail-closed reading
/// [`world_passes`] already applies to the same bytes.
///
/// The fail direction is not stylistic. `filtered_window_doc` filters a
/// caller-supplied doc, and in production that doc is the live window carrying
/// peer-pushed rows the bridge itself calls peer-controlled input — quarantine
/// RECORDS a rejected row but does not remove it from the CRDT. Passing an
/// undecodable CLAIM through would therefore hand a peer a bypass with no
/// forgery required: plant a row carrying `core.coreference.share_consent`, a
/// byte-20 EdgeRef, and pact Q, then break one required field so full decode
/// fails. [`CoreferenceExportContext::claim_travels`] is the ONLY place the
/// allowed link and the exact export pact are checked, so skipping it exports
/// the raw claim verbatim — across a pact boundary, or out of an unpacted grant
/// that may carry no coreference material at all. The identical path would also
/// let a structurally impossible status (`confirmed` at `Auto`) travel.
///
/// Nothing legitimate is lost: an undecodable CLAIM is a row no reader can
/// interpret, and withholding it discloses strictly less than shipping it.
fn coreference_claim_passes(
    entity_type: u8,
    blob: &[u8],
    coreference: &CoreferenceExportContext,
) -> bool {
    if entity_type != ENTITY_TYPE_CLAIM {
        return true;
    }
    crate::claim::decode_claim_body(&blob[ENTITY_METADATA_HEADER_LEN..], true)
        .is_ok_and(|body| coreference.claim_travels(&body))
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

fn decode_band_array(value: &Value) -> Result<Vec<SelectorRange>> {
    let Value::Array(values) = value else {
        return Err(selector_err(SelectorError::BandsMustBeArray));
    };
    values.iter().map(decode_band).collect()
}

fn decode_band(value: &Value) -> Result<SelectorRange> {
    let band = value
        .as_str()
        .ok_or_else(|| selector_err(SelectorError::BandMustBeString))?;
    match band {
        "semantic" => Ok(SelectorRange::Semantic),
        "core" => Ok(SelectorRange::Core),
        "companion" => Ok(SelectorRange::Companion),
        "productivity" => Ok(SelectorRange::Productivity),
        "crm" => Ok(SelectorRange::Crm),
        "maintenance" => Ok(SelectorRange::InducedDynamicMaintenance),
        _ => Err(selector_err(SelectorError::UnknownBand)),
    }
}

fn band_to_wire(band: SelectorRange) -> &'static str {
    match band {
        SelectorRange::Semantic => "semantic",
        SelectorRange::Core => "core",
        SelectorRange::Companion => "companion",
        SelectorRange::Productivity => "productivity",
        SelectorRange::Crm => "crm",
        SelectorRange::InducedDynamicMaintenance => "maintenance",
    }
}

fn selector_err(reason: SelectorError) -> Error {
    Error::sync_protocol(SyncProtocolValidation::Selector { reason })
}

#[cfg(test)]
mod tests;
