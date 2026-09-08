//! Vault floor resolution plus the shared strict POLICY_MANIFEST walk.

use rmpv::Value;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::store::Store;

use super::codec::invalid_body;
use super::floor_keys;
use super::types::{CustodyClass, CustodyTier, SecretCustodyFloor, TierBand};

/// MessagePack key-map helpers local to this module (the per-module idiom;
/// gate.rs's own copies are private to it).
pub(super) enum MapValue<'a> {
    Missing,
    Duplicate,
    Present(&'a Value),
}

pub(super) fn single_map_value<'a>(entries: &'a [(Value, Value)], needle: &str) -> MapValue<'a> {
    let mut found = None;
    for (key, value) in entries {
        if key.as_str() == Some(needle) {
            if found.is_some() {
                return MapValue::Duplicate;
            }
            found = Some(value);
        }
    }
    found.map_or(MapValue::Missing, MapValue::Present)
}

pub(super) fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    match single_map_value(entries, key) {
        MapValue::Present(value) => Some(value),
        MapValue::Missing | MapValue::Duplicate => None,
    }
}

pub(super) fn as_u64(value: &Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        Some(n)
    } else if let Some(n) = value.as_i64() {
        u64::try_from(n).ok()
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// The ONE strict walk over the vault's indexed POLICY_MANIFEST bodies
// ---------------------------------------------------------------------------

/// Why a strict POLICY_MANIFEST walk refused: the ONE classification every
/// security consumer of that plane maps into its own error surface.
///
/// Each payload is a SAFE CONSTANT. No entity id, no type-index key byte, no
/// body byte and no secret value ever reaches one of these reasons — a refusal
/// travels back to whoever asked, and it must be safe to print.
#[derive(Debug)]
pub(crate) enum PolicyManifestWalkError {
    /// The store itself could not be read. Not a statement about any manifest:
    /// the landed storage refusal, passed through unchanged.
    Storage(Error),
    /// The INDEXED MANIFEST PLANE disagrees with itself — an unusable
    /// type-index key, an entry whose entity row is gone, an entity whose
    /// metadata header will not parse, or an entry naming a row of some other
    /// type.
    IndexPlane(&'static str),
    /// A manifest body is PRESENT but does not canonically decode.
    UnreadableBody(&'static str),
}

/// The custody-side mapping of a strict-walk refusal, applied EXPLICITLY at
/// the one call site rather than through a `From` impl: a security
/// classification should never happen by accident under a `?`.
///
/// A storage failure passes through unchanged. [`Error::CorruptedIndex`] is the
/// landed idiom this module already answers with when an entity row's header or
/// type disagrees with the index that named it (see
/// [`read_secret_custody_in_txn`]), and a manifest body whose bytes will not
/// decode is the same class of damage one plane further in. Both carry only the
/// walk's safe constant reason.
fn floor_walk_refusal(err: PolicyManifestWalkError) -> Error {
    match err {
        PolicyManifestWalkError::Storage(err) => err,
        PolicyManifestWalkError::IndexPlane(reason)
        | PolicyManifestWalkError::UnreadableBody(reason) => Error::CorruptedIndex(reason),
    }
}

/// Extracts the trailing [`EntityId`] from a type-index key. Returns `None`
/// when the key does not carry a well-formed id for `entity_type` — the shape
/// check the strict walk turns into a refusal. ([`crate::gate`] keeps its own
/// copy for the diagnostics-collecting resolver it owns; that helper is
/// private to its module.)
fn type_index_entity_id(key: &[u8], entity_type: u8) -> Option<EntityId> {
    if key.len() != ENTITY_ID_LEN + 1 || key[0] != entity_type {
        return None;
    }
    EntityId::from_bytes(key[1..].try_into().ok()?).ok()
}

/// Reads ONE policy-manifest body as the CANONICAL single MessagePack value
/// the manifest contract defines — exactly one value, covering exactly the
/// whole body, the same shape [`crate::gate`]'s canonical decoder requires of
/// the bodies it owns.
///
/// The two answers are separated by READABILITY, not by shape:
///
/// * A body that canonically decodes to a value which is NOT a map is a plane
///   this walk's consumers do not read: `Ok(None)`. The manifest body SCHEMA
///   belongs to the gate, and readable content that simply is not a security
///   consumer's key set is not that consumer's to reject.
/// * A body that does not canonically decode AT ALL — empty, truncated,
///   corrupt, or carrying bytes left over past its value — is UNREADABLE. What
///   such a body declared cannot be seen, and it is exactly a RESTRICTIVE
///   declaration that corruption erases, so defaulting it would silently
///   restore the permissive posture the declaration existed to narrow. That
///   fails closed, like every other present-but-unreadable declaration here.
pub(crate) fn policy_manifest_body_map(
    body: &[u8],
) -> std::result::Result<Option<Vec<(Value, Value)>>, PolicyManifestWalkError> {
    use std::io::Cursor;

    let mut cursor = Cursor::new(body);
    let Ok(value) = rmpv::decode::read_value(&mut cursor) else {
        return Err(PolicyManifestWalkError::UnreadableBody(
            "policy-manifest body does not decode",
        ));
    };
    if cursor.position() != body.len() as u64 {
        return Err(PolicyManifestWalkError::UnreadableBody(
            "policy-manifest body has bytes past its value",
        ));
    }
    let Value::Map(entries) = value else {
        return Ok(None);
    };
    Ok(Some(entries))
}

/// Every indexed POLICY_MANIFEST body in the vault, canonically decoded, under
/// ONE strict walk shared by every security consumer of that plane.
///
/// STRICT is the whole point, and it is why this is not the diagnostics
/// resolver [`crate::gate`] owns: a manifest a consumer cannot read is
/// indistinguishable, from here, from a manifest that narrowed the consumer's
/// posture to nothing. An unusable type-index key, an entry whose entity row is
/// gone, an entity whose metadata header will not parse, an entry that names a
/// row of some other type, and a body that will not canonically decode are all
/// "a declaration was indexed and this consumer cannot see it". SKIPPING any of
/// them hands back the permissive default, so deleting one entity row would be
/// enough to re-open what a declaration had shut. Every one of them fails
/// closed instead, naming only a safe constant reason.
///
/// Readable bodies that carry no map are the one thing that is NOT an error:
/// they are dropped from the returned set, because the body schema belongs to
/// the gate and an unrelated readable plane is nobody else's to refuse.
pub(crate) fn policy_manifest_bodies_strict(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> std::result::Result<Vec<Vec<(Value, Value)>>, PolicyManifestWalkError> {
    let mut bodies = Vec::new();
    for index_entry in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_POLICY_MANIFEST])
        .map_err(PolicyManifestWalkError::Storage)?
    {
        let (key, _) = index_entry.map_err(PolicyManifestWalkError::Storage)?;
        let Some(id) = type_index_entity_id(&key, ENTITY_TYPE_POLICY_MANIFEST) else {
            return Err(PolicyManifestWalkError::IndexPlane(
                "policy-manifest type-index key is unusable",
            ));
        };
        let Some(raw) = store
            .entities
            .get(txn, id.as_bytes())
            .map_err(PolicyManifestWalkError::Storage)?
        else {
            return Err(PolicyManifestWalkError::IndexPlane(
                "policy-manifest index entry has no entity row",
            ));
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Err(PolicyManifestWalkError::IndexPlane(
                "policy-manifest entity metadata header is invalid",
            ));
        };
        if header.entity_type != ENTITY_TYPE_POLICY_MANIFEST {
            return Err(PolicyManifestWalkError::IndexPlane(
                "policy-manifest entry names another entity type",
            ));
        }
        if let Some(entries) = policy_manifest_body_map(&raw[ENTITY_METADATA_HEADER_LEN..])? {
            bodies.push(entries);
        }
    }
    Ok(bodies)
}

impl SecretCustodyFloor {
    /// The tier band for one custody class.
    #[must_use]
    pub fn band_for(&self, class: CustodyClass) -> TierBand {
        match class {
            CustodyClass::CustodyPortable => self.portable,
            CustodyClass::CustodyDeviceBound => self.device_bound,
            CustodyClass::CrossVault => self.cross_vault,
        }
    }

    /// Narrows `self` against `other`, most-restrictive per field.
    pub(super) fn merge(&mut self, other: SecretCustodyFloor) {
        self.portable = self.portable.narrow(other.portable);
        self.device_bound = self.device_bound.narrow(other.device_bound);
        self.cross_vault = self.cross_vault.narrow(other.cross_vault);
        self.rotation_max_age_secs = match (self.rotation_max_age_secs, other.rotation_max_age_secs)
        {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        for (k, v) in other.env_bindings {
            self.env_bindings
                .entry(k)
                .and_modify(|existing| {
                    // Conflicting environment bindings fail closed to the
                    // narrower (lexicographically smaller, deterministic)
                    // restriction note.
                    if v.as_str() < existing.as_str() {
                        *existing = v.clone();
                    }
                })
                .or_insert(v);
        }
    }

    /// Resolves the floor from every POLICY_MANIFEST body in the vault.
    /// Most-restrictive wins per field. An ABSENT floor row takes the default
    /// — that is what "no floor declared" means. A row that is PRESENT but
    /// unreadable is an ERROR: see `decode_floor_keys`.
    ///
    /// The same reasoning governs the INDEX PLANE those bodies are reached
    /// through, and this resolver no longer owns a walk of its own: it consumes
    /// the shared strict one (`policy_manifest_bodies_strict`), so a broken
    /// indexed declaration fails closed here exactly as it does at the
    /// credential door. An unusable type-index key, a dangling entity row, an
    /// unparseable metadata header, an entry naming another entity type, and a
    /// body that will not canonically decode all refuse. Skipping one would
    /// hand back the permissive `T0..T2` default band — the one direction a
    /// floor must never fail.
    pub fn resolve(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Self> {
        let mut floor = SecretCustodyFloor::default();
        for entries in policy_manifest_bodies_strict(store, txn).map_err(floor_walk_refusal)? {
            floor.merge(decode_floor_keys(&entries)?);
        }
        Ok(floor)
    }
}

/// Decodes the `secret.custody.*` rows out of one canonically-decoded
/// POLICY_MANIFEST body into a partial floor. Two packs with conflicting rows
/// resolve most-restrictive per field via [`SecretCustodyFloor::merge`].
///
/// ABSENT rows leave the defaults — that is what "this pack declares no floor
/// for that field" means. A row that is PRESENT but unreadable (wrong
/// MessagePack type, tier grade outside `0..=2`, or DUPLICATED so the intended
/// value is ambiguous) is an ERROR, not a default. Defaulting it would widen
/// the vault's posture back to the permissive `T0..T2` band — a floor may only
/// ever narrow, so silently reverting a declared narrowing is the one failure
/// direction this type exists to prevent.
///
/// A body that is not a MessagePack map never reaches here at all: the shared
/// walk drops readable non-map bodies (the POLICY_MANIFEST body schema belongs
/// to [`crate::gate`]) and fails closed on bodies that do not canonically
/// decode ([`policy_manifest_body_map`]).
fn decode_floor_keys(entries: &[(Value, Value)]) -> Result<SecretCustodyFloor> {
    let tier_at = |key: &'static str| -> Result<Option<CustodyTier>> {
        match single_map_value(entries, key) {
            MapValue::Missing => Ok(None),
            MapValue::Present(v) => as_u64(v)
                .and_then(|n| CustodyTier::from_u8(u8::try_from(n).ok()?))
                .map(Some)
                .ok_or_else(|| invalid_body(key)),
            MapValue::Duplicate => Err(invalid_body(key)),
        }
    };

    let mut floor = SecretCustodyFloor::default();
    if let Some(t) = tier_at(floor_keys::PORTABLE_MIN)? {
        floor.portable.min = t;
    }
    if let Some(t) = tier_at(floor_keys::PORTABLE_MAX)? {
        floor.portable.max = t;
    }
    if let Some(t) = tier_at(floor_keys::DEVICE_BOUND_MIN)? {
        floor.device_bound.min = t;
    }
    if let Some(t) = tier_at(floor_keys::DEVICE_BOUND_MAX)? {
        floor.device_bound.max = t;
    }
    if let Some(t) = tier_at(floor_keys::CROSS_VAULT_MIN)? {
        floor.cross_vault.min = t;
    }
    if let Some(t) = tier_at(floor_keys::CROSS_VAULT_MAX)? {
        floor.cross_vault.max = t;
    }
    match single_map_value(entries, floor_keys::ROTATION_MAX_AGE_SECS) {
        MapValue::Missing => {}
        MapValue::Present(v) => {
            floor.rotation_max_age_secs =
                Some(as_u64(v).ok_or(invalid_body(floor_keys::ROTATION_MAX_AGE_SECS))?);
        }
        MapValue::Duplicate => return Err(invalid_body(floor_keys::ROTATION_MAX_AGE_SECS)),
    }
    match single_map_value(entries, floor_keys::ENV_BINDINGS) {
        MapValue::Missing => {}
        MapValue::Present(Value::Map(rows)) => {
            for (k, v) in rows {
                let (Some(k), Some(v)) = (k.as_str(), v.as_str()) else {
                    return Err(invalid_body(floor_keys::ENV_BINDINGS));
                };
                floor.env_bindings.insert(k.to_owned(), v.to_owned());
            }
        }
        MapValue::Present(_) | MapValue::Duplicate => {
            return Err(invalid_body(floor_keys::ENV_BINDINGS));
        }
    }
    Ok(floor)
}
