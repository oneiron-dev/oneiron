//! Selector wire types, strict MessagePack encode/decode with key validators, and the filtered-doc/envelope entry points.

use std::collections::BTreeSet;
use std::io::Cursor;

use loro::{ExportMode, LoroDoc};
use rmpv::Value;

use crate::Vault;
use crate::entity_id::{EntityId, LocalWorldId};
use crate::error::{
    Error, Result, SyncEngineContext, SyncProtocolValidation,
    SyncSelectorValidation as SelectorError,
};
use crate::federation::{
    FederationGrantScope, GuestShareEnvelope, GuestShareEnvelopeBody, SelectorRange,
    sign_guest_share_envelope,
};
use crate::sync::types::WindowKey;

use super::authorize::{authorize_selector_export, filter_window_doc, strip_guest_share_metadata};

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

pub(super) const KEY_SCHEMA_VERSION: &str = SELECTOR_KEYS[0];

pub(super) const KEY_GRANT_ID: &str = SELECTOR_KEYS[1];

pub(super) const KEY_MEMBER_REF: &str = SELECTOR_KEYS[2];

pub(super) const KEY_WORLD: &str = SELECTOR_KEYS[3];

pub(super) const KEY_FACETS: &str = SELECTOR_KEYS[4];

pub(super) const KEY_BANDS: &str = SELECTOR_KEYS[5];

pub(super) const WORLD_KEYS: [&str; 2] = ["kind", "id"];

const WORLD_KIND_ALL: &str = "all";

const WORLD_KIND_BASE: &str = "base";

pub(super) const WORLD_KIND_WORLD: &str = "world";

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

    pub(super) fn facet_filter_active(&self, empty: EmptyAxis) -> bool {
        !self.facets.is_empty() || empty == EmptyAxis::Bottom
    }

    pub(super) fn band_filter_active(&self, empty: EmptyAxis) -> bool {
        !self.bands.is_empty() || empty == EmptyAxis::Bottom
    }

    pub(super) fn any_filter_active(&self, empty: EmptyAxis) -> bool {
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
pub(super) enum EmptyAxis {
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

pub(super) fn encode_world(world: SyncSelectorWorld) -> Value {
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

pub(super) fn band_to_wire(band: SelectorRange) -> &'static str {
    match band {
        SelectorRange::Semantic => "semantic",
        SelectorRange::Core => "core",
        SelectorRange::Companion => "companion",
        SelectorRange::Productivity => "productivity",
        SelectorRange::Crm => "crm",
        SelectorRange::InducedDynamicMaintenance => "maintenance",
    }
}

pub(super) fn selector_err(reason: SelectorError) -> Error {
    Error::sync_protocol(SyncProtocolValidation::Selector { reason })
}
