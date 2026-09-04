//! ARCH-0069 secret custody — SECRET-01 (ONE-1919): custody classes, the
//! custody record that is the secret value's home, repo-side manifest
//! declaration, and vault-resident custody floors.
//!
//! # Custody classes (S1/S2)
//!
//! * `custody-portable` — the value may replicate beyond this device (the
//!   default reach; the ONE-1865 per-credential dial narrows it).
//! * `custody-device-bound` — the value is pinned to this device.
//! * `cross-vault` — door-only: the value never replicates at all.
//!
//! The classes grade **exposure of the secret VALUE** (ARCH-0069 S1
//! carve-out (a)): they are custody postures over where the value may live,
//! never a device tier and never a claim on the credential. Under the
//! host-root authority model (OF-452 D1/D7/D10) there is no hardware-anchored
//! custody principal and no device-lease key plane; the authority principal
//! for any cross-boundary use is the **host-minted capability slip**
//! (verbs+facets+lifetime, minted from the vault's authority log). Enrolment
//! is pairing (D7). In-process callers name their `effector` string honestly
//! or not at all; the receipt trail exists so misuse is never silent. This
//! module does not pretend the in-process effector string is a cryptographic
//! binding — it is the declared scope the slip's cross-boundary authority is
//! narrowed against, and the typed deny (`SecretBindingDenied`) is the
//! fail-closed door when no binding covers `(secret_ref, effector)`.
//!
//! # The value never leaves the body (S1 plane discipline)
//!
//! `SecretCustodyRecord.value_bytes` is **plaintext bytes at rest under the
//! vault DEK plane** — the same at-rest protection every entity body gets.
//! The custody discipline is about planes, not a second encryption layer:
//! the value NEVER leaves this body into claims (secrets are never claims),
//! never into the CRDT plane (the interim ONE-1865 guard seals the type byte
//! from the sync selector), never into export, receipts, or logs. `Debug`
//! for the record redacts the value; `SecretCustodyMetadata` has no value
//! field by construction.
//!
//! # Module map
//!
//! * wire/keystone types: [`CustodyClass`], [`CustodyTier`], [`TierBand`],
//!   [`SecretCustodyFloor`], [`SecretBinding`], [`SecretCustodyStatus`],
//!   [`SecretCustodyRecord`], [`SecretCustodyMetadata`];
//! * body codec: [`SECRET_CUSTODY_BODY_KEYS`], [`encode_secret_custody_body`],
//!   [`decode_secret_custody_body`];
//! * the ONE strict walk over the vault's indexed POLICY_MANIFEST bodies,
//!   shared by every security consumer of that plane:
//!   `policy_manifest_bodies_strict`;
//! * floor resolution over those bodies: [`SecretCustodyFloor::resolve`];
//! * the `Vault` doors: [`Vault::register_secret`],
//!   [`Vault::resolve_secret_ref`], [`Vault::get_secret_metadata`], and the
//!   SECRET-02 value-read door `Vault::get_secret_value_in_txn`.
//!
//! Companion [`crate::secret_manifest`] owns the repo-side TOML declaration
//! and the narrow-only validator (manifest ∧ vault floor, most-restrictive
//! wins).

use std::collections::BTreeMap;
use std::fmt;

use rmpv::{Value, ValueRef};
use serde::{Deserialize, Serialize};

use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_SECRET_CUSTODY};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::Vault;

// ---------------------------------------------------------------------------
// Custody classes & tiers
// ---------------------------------------------------------------------------

/// ARCH-0069 S1 custody classes. Wire strings are canon nouns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CustodyClass {
    /// The value may replicate beyond this device (the default reach).
    CustodyPortable,
    /// The value is pinned to this device (device-pin locality posture under
    /// slip authority — not a hardware/device custody tier).
    CustodyDeviceBound,
    /// Door-only: the value never replicates at all.
    CrossVault,
}

impl CustodyClass {
    /// The canon kebab-case wire noun.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CustodyPortable => "custody-portable",
            Self::CustodyDeviceBound => "custody-device-bound",
            Self::CrossVault => "cross-vault",
        }
    }

    /// Parses the canon kebab-case wire noun.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "custody-portable" => Some(Self::CustodyPortable),
            "custody-device-bound" => Some(Self::CustodyDeviceBound),
            "cross-vault" => Some(Self::CrossVault),
            _ => None,
        }
    }
}

/// SECRET-02 owns tier mechanics; the enum is declared here because
/// [`SecretBinding`]s and [`SecretCustodyFloor`] name it.
///
/// Ordering is exposure of the secret VALUE: `T0Doored < T1Leased <
/// T2LocalRegistered`. `T0` is always the least-exposed bound. Authority is
/// never tier-shaped: the custody principal is the host-minted capability
/// slip (OF-452 D1/D7), not a device tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CustodyTier {
    /// Least exposed: value only reachable at the door.
    T0Doored,
    /// Value reachable under a lease.
    T1Leased,
    /// Value reachable as a locally-registered reference.
    T2LocalRegistered,
}

impl CustodyTier {
    /// The integer wire grade (`T0`=0 … `T2`=2).
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::T0Doored => 0,
            Self::T1Leased => 1,
            Self::T2LocalRegistered => 2,
        }
    }

    /// Parses from the integer wire grade.
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::T0Doored),
            1 => Some(Self::T1Leased),
            2 => Some(Self::T2LocalRegistered),
            _ => None,
        }
    }
}

/// Per-class allowed tier band (inclusive). Floors narrow the `max` (the most
/// exposure a class may reach), never force exposure — `min` is informational
/// (and `T0Doored` by default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierBand {
    /// Least-exposed tier in the band (informational).
    pub min: CustodyTier,
    /// Most-exposed tier the class may reach under this band.
    pub max: CustodyTier,
}

impl TierBand {
    /// A band spanning a single tier.
    #[must_use]
    pub const fn only(tier: CustodyTier) -> Self {
        Self {
            min: tier,
            max: tier,
        }
    }

    /// True when `tier` sits inside this band (inclusive).
    #[must_use]
    pub fn admits(&self, tier: CustodyTier) -> bool {
        self.min <= tier && tier <= self.max
    }

    /// The narrower of two bands (most-restrictive merge).
    #[must_use]
    pub fn narrow(self, other: Self) -> Self {
        Self {
            min: self.min.max(other.min),
            max: self.max.min(other.max),
        }
    }
}

// ---------------------------------------------------------------------------
// Resolved vault custody floor
// ---------------------------------------------------------------------------

/// The vault's custody floor, resolved from the `secret.custody.*` keys in
/// POLICY_MANIFEST bodies (DEC-0005: floors live in the vault's policy
/// manifests; callers narrow, never widen). Most-restrictive wins per field
/// across packs.
///
/// The tiers grade exposure of the secret VALUE (never a device tier) —
/// under host-root there is no device tier to be "custodial" against; the
/// authority principal is the capability slip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretCustodyFloor {
    /// Allowed tier band for `custody-portable` (default `T0..T2`).
    pub portable: TierBand,
    /// Allowed tier band for `custody-device-bound` (default `T0..T2`).
    pub device_bound: TierBand,
    /// Allowed tier band for `cross-vault` (default `T0..T0`, door-only).
    pub cross_vault: TierBand,
    /// Maximum age before a value must be rotated (None = no floor).
    pub rotation_max_age_secs: Option<u64>,
    /// Environment bindings (e.g. `prod` → restriction note), narrowed on
    /// conflicting values.
    pub env_bindings: BTreeMap<String, String>,
}

impl Default for SecretCustodyFloor {
    fn default() -> Self {
        Self {
            portable: TierBand {
                min: CustodyTier::T0Doored,
                max: CustodyTier::T2LocalRegistered,
            },
            device_bound: TierBand {
                min: CustodyTier::T0Doored,
                max: CustodyTier::T2LocalRegistered,
            },
            cross_vault: TierBand::only(CustodyTier::T0Doored),
            rotation_max_age_secs: None,
            env_bindings: BTreeMap::new(),
        }
    }
}

/// MessagePack key-map helpers local to this module (the per-module idiom;
/// gate.rs's own copies are private to it).
enum MapValue<'a> {
    Missing,
    Duplicate,
    Present(&'a Value),
}

fn single_map_value<'a>(entries: &'a [(Value, Value)], needle: &str) -> MapValue<'a> {
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

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    match single_map_value(entries, key) {
        MapValue::Present(value) => Some(value),
        MapValue::Missing | MapValue::Duplicate => None,
    }
}

fn as_u64(value: &Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        Some(n)
    } else if let Some(n) = value.as_i64() {
        u64::try_from(n).ok()
    } else {
        None
    }
}

/// MessagePack keys the custody floor reads out of POLICY_MANIFEST bodies.
mod floor_keys {
    pub(crate) const PORTABLE_MIN: &str = "secret.custody.floor.portable.min";
    pub(crate) const PORTABLE_MAX: &str = "secret.custody.floor.portable.max";
    pub(crate) const DEVICE_BOUND_MIN: &str = "secret.custody.floor.device_bound.min";
    pub(crate) const DEVICE_BOUND_MAX: &str = "secret.custody.floor.device_bound.max";
    pub(crate) const CROSS_VAULT_MIN: &str = "secret.custody.floor.cross_vault.min";
    pub(crate) const CROSS_VAULT_MAX: &str = "secret.custody.floor.cross_vault.max";
    pub(crate) const ROTATION_MAX_AGE_SECS: &str = "secret.custody.rotation_max_age_secs";
    pub(crate) const ENV_BINDINGS: &str = "secret.custody.env_bindings";
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
    fn merge(&mut self, other: SecretCustodyFloor) {
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

// ---------------------------------------------------------------------------
// Bindings, status, record, metadata
// ---------------------------------------------------------------------------

/// The scope verb a binding must declare before the value door will hand over
/// plaintext. Scopes are otherwise free-form: they name what a binding is FOR,
/// and only this one is load-bearing at a door.
pub const SECRET_SCOPE_READ: &str = "read";

/// A binding scoping which effector may use a secret ref, at what tier
/// ceiling. The binding check scopes usage, drives tier admission, and
/// stamps receipts. No binding covering `(secret_ref, effector)` with the
/// required scope ⇒ [`Error::SecretBindingDenied`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretBinding {
    /// The effector, e.g. `"connector:gmail"`, `"door:receive-pack"`.
    pub effector: String,
    /// The most-exposed tier this binding may request.
    pub tier_ceiling: CustodyTier,
    /// Declared scopes the binding covers.
    pub scopes: Vec<String>,
}

impl SecretBinding {
    /// Whether this binding carries the [`SECRET_SCOPE_READ`] grant the value
    /// door requires.
    ///
    /// An EMPTY scope list is NOT a wildcard. Reading it as one is how a
    /// declared-but-unenforced field becomes a hole: every binding written
    /// before scopes meant anything would silently grant plaintext reads. A
    /// binding that declares no scope grants no read.
    #[must_use]
    pub fn grants_read(&self) -> bool {
        self.scopes.iter().any(|s| s == SECRET_SCOPE_READ)
    }
}

/// Lifecycle status of a custody record. Only `Active` records are usable;
/// a `Revoked` name frees for re-registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecretCustodyStatus {
    /// Live and usable within its bindings.
    Active,
    /// Temporarily unusable; name still held.
    Suspended,
    /// Terminal; the name frees for re-registration.
    Revoked,
}

impl SecretCustodyStatus {
    /// The wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
        }
    }

    /// Parses the wire string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// Entity body for `ENTITY_TYPE_SECRET_CUSTODY`: the secret value's home.
///
/// `value_bytes` is plaintext under the vault DEK plane and NEVER leaves this
/// body into claims / CRDT / export / receipts / logs. `Debug` redacts it.
/// `policy_floor_snapshot` records the floor at register time for audit;
/// `manifest_ref` + `declared_paths` are copied from the manifest entry so
/// downstream consumers (SECRET-03, snapshot exclusion) have a vault-side
/// data source.
/// No `Serialize`/`Deserialize`: a derived serializer would emit `value_bytes`
/// into whatever format a caller reached for (JSON log line, receipt, wire
/// payload) with no door in the way — the same leak `Debug` is hand-rolled to
/// prevent. The body codec below is the ONE serialization of this type, and it
/// exists to write the vault-resident body, nothing else.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretCustodyRecord {
    /// Body schema version (`SECRET_CUSTODY_SCHEMA_VERSION` at encode).
    pub schema_version: u16,
    /// Unique-per-vault secret name; see [`SECRET_NAME_INDEX_PREFIX`].
    pub name: String,
    /// The custody class — the value-exposure posture.
    pub class: CustodyClass,
    /// The OF-422 portable dial. Stored as data from day one so ONE-1865
    /// needs no migration; enforcement (replication locality) is ONE-1865's.
    /// On a `cross-vault` record this is stored-but-inert.
    pub device_only: bool,
    /// The secret value bytes (plaintext under the DEK plane; redacted in
    /// `Debug`; never serialized into logs/receipts/claims/CRDT).
    ///
    /// `pub(crate)`, not `pub`: a value read must go through the bound door
    /// [`Vault::get_secret_value_in_txn`] (which enforces the effector binding)
    /// rather than reaching the field directly on a decoded record. Within the
    /// crate the codec and doors move the bytes; out-of-crate there is no raw
    /// accessor at all — the value never crosses the crate boundary unbound.
    pub(crate) value_bytes: Vec<u8>,
    /// Lifecycle status.
    pub status: SecretCustodyStatus,
    /// Unix seconds at registration.
    pub registered_at: u64,
    /// Unix seconds of the last rotation (SECRET-04 stamps it).
    pub rotated_at: Option<u64>,
    /// Rotation generation counter.
    pub rotation_generation: u32,
    /// Effector bindings on this record.
    pub bindings: Vec<SecretBinding>,
    /// The manifest path this entry was registered from (empty when
    /// registered outside a manifest flow). Read via [`Self::manifest_ref`];
    /// `pub(crate)` keeps the struct's serde/codec construction inside the
    /// crate while exposing only a read-only reference outward.
    pub(crate) manifest_ref: String,
    /// Declared secret paths copied from the manifest entry (SECRET-03).
    pub declared_paths: Vec<String>,
    /// The resolved vault floor at register time (audit).
    pub policy_floor_snapshot: SecretCustodyFloor,
}

// Deliberately hand-rolled: never print `value_bytes` (S1). The grep-guard
// test asserts `value_bytes` does not appear in the Debug output.
impl fmt::Debug for SecretCustodyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretCustodyRecord")
            .field("schema_version", &self.schema_version)
            .field("name", &self.name)
            .field("class", &self.class)
            .field("device_only", &self.device_only)
            .field(
                "value_bytes",
                &format_args!("<redacted {} bytes>", self.value_bytes.len()),
            )
            .field("status", &self.status)
            .field("registered_at", &self.registered_at)
            .field("rotated_at", &self.rotated_at)
            .field("rotation_generation", &self.rotation_generation)
            .field("bindings", &self.bindings)
            .field("manifest_ref", &self.manifest_ref)
            .field("declared_paths", &self.declared_paths)
            .field("policy_floor_snapshot", &self.policy_floor_snapshot)
            .finish()
    }
}

/// The value-less projection — the ONLY read most callers get. Has no value
/// field by construction (type-level proof of S1's read-plane discipline).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretCustodyMetadata {
    /// The secret name.
    pub name: String,
    /// The custody class.
    pub class: CustodyClass,
    /// Lifecycle status.
    pub status: SecretCustodyStatus,
    /// Unix seconds at registration.
    pub registered_at: u64,
    /// Unix seconds of the last rotation.
    pub rotated_at: Option<u64>,
    /// Rotation generation counter.
    pub rotation_generation: u32,
    /// Effector bindings.
    pub bindings: Vec<SecretBinding>,
}

impl SecretCustodyRecord {
    /// Projects to the value-less metadata read.
    #[must_use]
    pub fn metadata(&self) -> SecretCustodyMetadata {
        SecretCustodyMetadata {
            name: self.name.clone(),
            class: self.class,
            status: self.status,
            registered_at: self.registered_at,
            rotated_at: self.rotated_at,
            rotation_generation: self.rotation_generation,
            bindings: self.bindings.clone(),
        }
    }

    /// Looks up the binding covering `effector`. Drives tier admission.
    #[must_use]
    pub fn binding_for(&self, effector: &str) -> Option<&SecretBinding> {
        self.bindings.iter().find(|b| b.effector == effector)
    }

    /// The manifest path this entry was registered from — the read-only,
    /// binding-door-safe view of `manifest_ref` for out-of-crate consumers
    /// (SECRET-03 snapshot exclusion reads it from the record's body decode).
    /// Empty when the record was registered outside a manifest flow.
    #[must_use]
    pub fn manifest_ref(&self) -> &str {
        &self.manifest_ref
    }
}

// ---------------------------------------------------------------------------
// Body codec — a MessagePack key map named by SECRET_CUSTODY_BODY_KEYS
// ---------------------------------------------------------------------------

/// The body's MessagePack keys, in field order. `13 keys = 13 fields`.
pub const SECRET_CUSTODY_BODY_KEYS: [&str; 13] = [
    "schema_version",
    "name",
    "class",
    "device_only",
    "value_bytes",
    "status",
    "registered_at",
    "rotated_at",
    "rotation_generation",
    "bindings",
    "manifest_ref",
    "declared_paths",
    "policy_floor_snapshot",
];

/// The body schema version stamped at encode time.
pub const SECRET_CUSTODY_SCHEMA_VERSION: u16 = 1;

/// The `vault_meta` name-index key prefix mapping a live secret name to its
/// `EntityId` (`"vault_meta: name -> EntityId"`).
pub const SECRET_NAME_INDEX_PREFIX: &str = "secret_custody:name:v1:";

fn invalid_body(reason: &'static str) -> Error {
    Error::InvalidSecretCustodyBody(reason)
}

/// ONE-1865 arms the replication and export posture for SECRET_CUSTODY; until
/// then the type byte is sealed from the raw and CRDT planes. This is the ONE
/// rejection constructor every REJECTING door names, so a grep for it audits
/// the whole seal:
///
/// * the replicated write wall (`batch::apply_ops`' Put arm) — the CRDT replay
///   door never materializes a peer-supplied custody body; the record writes
///   ONLY through [`Vault::register_secret`]. Public raw puts are already
///   refused one level up by the `Maintenance` classification
///   (`MaintenanceKindNotWritable(77)`);
/// * the generic read doors [`Vault::get`] and [`Vault::get_raw`], whose bytes
///   would otherwise carry `value_bytes` in the clear — the ONLY sanctioned
///   value read is [`Vault::get_secret_value_in_txn`];
/// * the export scrub's malformed-key arm ([`crate::sync::window`]), which
///   quarantines a custody carrier filed under a non-canonical peer key.
///
/// The two SILENT doors are deliberately not errors: the sync selector
/// ([`crate::sync::selector`]) drops the byte from the export set, and reverse
/// rematerialization skips-and-scrubs it. Neither has a caller to fail.
pub(crate) fn reject_secret_custody_byte() -> Error {
    invalid_body("secret custody records are sealed from the raw/CRDT planes until ONE-1865")
}

fn tier_band_to_value(band: &TierBand) -> Value {
    Value::Map(vec![
        (Value::from("min"), Value::from(u64::from(band.min.as_u8()))),
        (Value::from("max"), Value::from(u64::from(band.max.as_u8()))),
    ])
}

fn tier_band_from_value(value: &Value) -> Result<TierBand> {
    let Value::Map(entries) = value else {
        return Err(invalid_body("tier band must be a map"));
    };
    let min = required_value(entries, "min")
        .and_then(as_u64)
        .and_then(|n| CustodyTier::from_u8(u8::try_from(n).ok()?))
        .ok_or(invalid_body("tier band min"))?;
    let max = required_value(entries, "max")
        .and_then(as_u64)
        .and_then(|n| CustodyTier::from_u8(u8::try_from(n).ok()?))
        .ok_or(invalid_body("tier band max"))?;
    Ok(TierBand { min, max })
}

fn floor_to_value(floor: &SecretCustodyFloor) -> Value {
    let env = Value::Map(
        floor
            .env_bindings
            .iter()
            .map(|(k, v)| (Value::from(k.as_str()), Value::from(v.as_str())))
            .collect(),
    );
    Value::Map(vec![
        (Value::from("portable"), tier_band_to_value(&floor.portable)),
        (
            Value::from("device_bound"),
            tier_band_to_value(&floor.device_bound),
        ),
        (
            Value::from("cross_vault"),
            tier_band_to_value(&floor.cross_vault),
        ),
        (
            Value::from("rotation_max_age_secs"),
            match floor.rotation_max_age_secs {
                Some(n) => Value::from(n),
                None => Value::Nil,
            },
        ),
        (Value::from("env_bindings"), env),
    ])
}

fn floor_from_value(value: &Value) -> Result<SecretCustodyFloor> {
    let Value::Map(entries) = value else {
        return Err(invalid_body("policy_floor_snapshot must be a map"));
    };
    let portable = tier_band_from_value(
        required_value(entries, "portable").ok_or(invalid_body("floor portable"))?,
    )?;
    let device_bound = tier_band_from_value(
        required_value(entries, "device_bound").ok_or(invalid_body("floor device_bound"))?,
    )?;
    let cross_vault = tier_band_from_value(
        required_value(entries, "cross_vault").ok_or(invalid_body("floor cross_vault"))?,
    )?;
    let rotation_max_age_secs = match required_value(entries, "rotation_max_age_secs") {
        Some(Value::Nil) | None => None,
        Some(v) => Some(as_u64(v).ok_or(invalid_body("floor rotation_max_age_secs"))?),
    };
    let mut env_bindings = BTreeMap::new();
    if let Some(Value::Map(rows)) = required_value(entries, "env_bindings") {
        for (k, v) in rows {
            match (k.as_str(), v.as_str()) {
                (Some(k), Some(v)) => {
                    env_bindings.insert(k.to_owned(), v.to_owned());
                }
                _ => return Err(invalid_body("floor env_bindings entry")),
            }
        }
    }
    Ok(SecretCustodyFloor {
        portable,
        device_bound,
        cross_vault,
        rotation_max_age_secs,
        env_bindings,
    })
}

fn binding_to_value(binding: &SecretBinding) -> Value {
    Value::Map(vec![
        (
            Value::from("effector"),
            Value::from(binding.effector.as_str()),
        ),
        (
            Value::from("tier_ceiling"),
            Value::from(u64::from(binding.tier_ceiling.as_u8())),
        ),
        (
            Value::from("scopes"),
            Value::Array(
                binding
                    .scopes
                    .iter()
                    .map(|s| Value::from(s.as_str()))
                    .collect(),
            ),
        ),
    ])
}

fn binding_from_value(value: &Value) -> Result<SecretBinding> {
    let Value::Map(entries) = value else {
        return Err(invalid_body("binding must be a map"));
    };
    let effector = required_value(entries, "effector")
        .and_then(|v| v.as_str())
        .ok_or(invalid_body("binding effector"))?
        .to_owned();
    let tier_ceiling = required_value(entries, "tier_ceiling")
        .and_then(as_u64)
        .and_then(|n| CustodyTier::from_u8(u8::try_from(n).ok()?))
        .ok_or(invalid_body("binding tier_ceiling"))?;
    let scopes = match required_value(entries, "scopes") {
        Some(Value::Array(items)) => {
            let mut scopes = Vec::with_capacity(items.len());
            for item in items {
                scopes.push(
                    item.as_str()
                        .ok_or(invalid_body("binding scope"))?
                        .to_owned(),
                );
            }
            scopes
        }
        Some(_) => return Err(invalid_body("binding scopes must be an array")),
        None => Vec::new(),
    };
    Ok(SecretBinding {
        effector,
        tier_ceiling,
        scopes,
    })
}

/// Encodes a custody record into its MessagePack key-map body.
pub fn encode_secret_custody_body(rec: &SecretCustodyRecord) -> Result<Vec<u8>> {
    let map = Value::Map(vec![
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[0]),
            Value::from(u64::from(rec.schema_version)),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[1]),
            Value::from(rec.name.as_str()),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[2]),
            Value::from(rec.class.as_str()),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[3]),
            Value::from(rec.device_only),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[4]),
            Value::Binary(rec.value_bytes.clone()),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[5]),
            Value::from(rec.status.as_str()),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[6]),
            Value::from(rec.registered_at),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[7]),
            match rec.rotated_at {
                Some(n) => Value::from(n),
                None => Value::Nil,
            },
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[8]),
            Value::from(u64::from(rec.rotation_generation)),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[9]),
            Value::Array(rec.bindings.iter().map(binding_to_value).collect()),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[10]),
            Value::from(rec.manifest_ref.as_str()),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[11]),
            Value::Array(
                rec.declared_paths
                    .iter()
                    .map(|p| Value::from(p.as_str()))
                    .collect(),
            ),
        ),
        (
            Value::from(SECRET_CUSTODY_BODY_KEYS[12]),
            floor_to_value(&rec.policy_floor_snapshot),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &map)
        .map_err(|_| invalid_body("encode secret custody body"))?;
    Ok(out)
}

/// Decodes a custody record from its MessagePack key-map body. All 13 keys
/// are required except `rotated_at` (nil-or-int): `bindings`, `manifest_ref`,
/// and `declared_paths` may be EMPTY (an empty array or string is still a
/// present, well-formed key) but must not be MISSING — a record is complete
/// on write. A missing required key is a body-schema reject.
pub fn decode_secret_custody_body(bytes: &[u8]) -> Result<SecretCustodyRecord> {
    use std::io::Cursor;

    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid_body("decode secret custody body"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_body("trailing bytes after secret custody body"));
    }
    let Value::Map(entries) = value else {
        return Err(invalid_body("secret custody body must be a map"));
    };

    let schema_version = required_value(&entries, SECRET_CUSTODY_BODY_KEYS[0])
        .and_then(as_u64)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or(invalid_body("schema_version"))?;
    let name = required_value(&entries, SECRET_CUSTODY_BODY_KEYS[1])
        .and_then(|v| v.as_str())
        .ok_or(invalid_body("name"))?
        .to_owned();
    let class = required_value(&entries, SECRET_CUSTODY_BODY_KEYS[2])
        .and_then(|v| v.as_str())
        .and_then(CustodyClass::parse)
        .ok_or(invalid_body("class"))?;
    let device_only = required_value(&entries, SECRET_CUSTODY_BODY_KEYS[3])
        .and_then(Value::as_bool)
        .ok_or(invalid_body("device_only"))?;
    let value_bytes = match required_value(&entries, SECRET_CUSTODY_BODY_KEYS[4]) {
        Some(Value::Binary(b)) => b.clone(),
        Some(Value::String(s)) => s.as_str().unwrap_or_default().as_bytes().to_vec(),
        _ => return Err(invalid_body("value_bytes")),
    };
    let status = required_value(&entries, SECRET_CUSTODY_BODY_KEYS[5])
        .and_then(|v| v.as_str())
        .and_then(SecretCustodyStatus::parse)
        .ok_or(invalid_body("status"))?;
    let registered_at = required_value(&entries, SECRET_CUSTODY_BODY_KEYS[6])
        .and_then(as_u64)
        .ok_or(invalid_body("registered_at"))?;
    let rotated_at = match required_value(&entries, SECRET_CUSTODY_BODY_KEYS[7]) {
        Some(Value::Nil) | None => None,
        Some(v) => Some(as_u64(v).ok_or(invalid_body("rotated_at"))?),
    };
    let rotation_generation = required_value(&entries, SECRET_CUSTODY_BODY_KEYS[8])
        .and_then(as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(invalid_body("rotation_generation"))?;
    // bindings / manifest_ref / declared_paths are REQUIRED keys (FIX5): an
    // empty value is fine, but a MISSING key is a body-schema reject, not a
    // silent empty default.
    let bindings = match required_value(&entries, SECRET_CUSTODY_BODY_KEYS[9]) {
        Some(Value::Array(items)) => {
            let mut bindings = Vec::with_capacity(items.len());
            for item in items {
                bindings.push(binding_from_value(item)?);
            }
            bindings
        }
        Some(_) => return Err(invalid_body("bindings must be an array")),
        None => return Err(invalid_body("bindings")),
    };
    let manifest_ref = required_value(&entries, SECRET_CUSTODY_BODY_KEYS[10])
        .and_then(|v| v.as_str())
        .ok_or(invalid_body("manifest_ref"))?
        .to_owned();
    let declared_paths = match required_value(&entries, SECRET_CUSTODY_BODY_KEYS[11]) {
        Some(Value::Array(items)) => {
            let mut paths = Vec::with_capacity(items.len());
            for item in items {
                paths.push(
                    item.as_str()
                        .ok_or(invalid_body("declared_path"))?
                        .to_owned(),
                );
            }
            paths
        }
        Some(_) => return Err(invalid_body("declared_paths must be an array")),
        None => return Err(invalid_body("declared_paths")),
    };
    let policy_floor_snapshot = match required_value(&entries, SECRET_CUSTODY_BODY_KEYS[12]) {
        Some(v) => floor_from_value(v)?,
        None => return Err(invalid_body("policy_floor_snapshot")),
    };

    Ok(SecretCustodyRecord {
        schema_version,
        name,
        class,
        device_only,
        value_bytes,
        status,
        registered_at,
        rotated_at,
        rotation_generation,
        bindings,
        manifest_ref,
        declared_paths,
        policy_floor_snapshot,
    })
}

// ---------------------------------------------------------------------------
// Name index
// ---------------------------------------------------------------------------

/// Resolves a live secret name to its custody `EntityId` inside an
/// existing txn. `pub(crate)` for SECRET-02's lease doors (ONE-1920), which
/// hold their own write txn and must not open a nested read txn.
pub(crate) fn resolve_secret_ref_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    name: &str,
) -> Result<Option<EntityId>> {
    let Some(bytes) = store.vault_meta.get(txn, &name_index_key(name))? else {
        return Ok(None);
    };
    let id_bytes: [u8; 16] = bytes
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex("secret name index id"))?;
    let id = EntityId::from_bytes(id_bytes)
        .map_err(|_| Error::CorruptedIndex("secret name index id"))?;
    Ok(Some(id))
}

/// The `vault_meta` index key for a live secret name.
fn name_index_key(name: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(SECRET_NAME_INDEX_PREFIX.len() + name.len());
    key.extend_from_slice(SECRET_NAME_INDEX_PREFIX.as_bytes());
    key.extend_from_slice(name.as_bytes());
    key
}

/// Reads and decodes a custody record under either a read or write txn.
/// `pub(crate)` for SECRET-02's lease doors (ONE-1920): they resolve the
/// record inside their own write txn to drive admission and read
/// `declared_paths` — value reads still route ONLY through the bound door
/// [`Vault::get_secret_value_in_txn`].
pub(crate) fn read_secret_custody_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<SecretCustodyRecord>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("secret custody entity header"));
    };
    if header.entity_type != ENTITY_TYPE_SECRET_CUSTODY {
        return Err(Error::CorruptedIndex("secret custody entity type"));
    }
    decode_secret_custody_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

// ---------------------------------------------------------------------------
// Admission projection (SECRET-02, SOL-1920-04)
// ---------------------------------------------------------------------------

/// The admission projection of a custody record: every field SECRET-02's
/// lease doors need to ADMIT and to drive T2, and nothing else. Has no
/// value field by construction — admission never heap-copies plaintext;
/// the ONE value decode is the bound door [`Vault::get_secret_value_in_txn`]
/// itself (its caller wraps the bytes in `Zeroizing`). Raw-record access is
/// not broadened: the full decode stays behind
/// [`read_secret_custody_in_txn`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecretCustodyAdmission {
    /// The secret name.
    pub(crate) name: String,
    /// The custody class.
    pub(crate) class: CustodyClass,
    /// Lifecycle status.
    pub(crate) status: SecretCustodyStatus,
    /// Rotation generation counter (the S6 staleness signal leases stamp).
    pub(crate) rotation_generation: u32,
    /// Effector bindings.
    pub(crate) bindings: Vec<SecretBinding>,
    /// Manifest-declared local paths (the T2 target set).
    pub(crate) declared_paths: Vec<String>,
}

impl SecretCustodyAdmission {
    /// Looks up the binding covering `effector` — mirrors
    /// [`SecretCustodyRecord::binding_for`], drives tier admission.
    #[must_use]
    pub(crate) fn binding_for(&self, effector: &str) -> Option<&SecretBinding> {
        self.bindings.iter().find(|b| b.effector == effector)
    }
}

/// The borrowing half of [`required_value`]: a MISSING or DUPLICATED key
/// both yield `None`, over [`ValueRef`] entries.
fn required_value_ref<'a, 'b>(
    entries: &'b [(ValueRef<'a>, ValueRef<'a>)],
    key: &str,
) -> Option<&'b ValueRef<'a>> {
    let mut found = None;
    for (k, v) in entries {
        if let ValueRef::String(s) = k
            && s.as_str() == Some(key)
        {
            if found.is_some() {
                return None;
            }
            found = Some(v);
        }
    }
    found
}

/// A string field out of a borrowing value, tied to the body buffer.
fn str_ref<'a>(value: &ValueRef<'a>, reason: &'static str) -> Result<&'a str> {
    match value {
        ValueRef::String(s) => s.into_str().ok_or(invalid_body(reason)),
        _ => Err(invalid_body(reason)),
    }
}

/// An integer field out of a borrowing value (the owned codec's `as_u64`
/// discipline: u64 direct, else a non-negative i64).
fn u64_ref(value: &ValueRef<'_>, reason: &'static str) -> Result<u64> {
    match value {
        ValueRef::Integer(n) => n
            .as_u64()
            .or_else(|| n.as_i64().and_then(|v| u64::try_from(v).ok()))
            .ok_or(invalid_body(reason)),
        _ => Err(invalid_body(reason)),
    }
}

/// The borrowing half of [`binding_from_value`].
fn binding_from_value_ref(value: &ValueRef<'_>) -> Result<SecretBinding> {
    let ValueRef::Map(entries) = value else {
        return Err(invalid_body("binding must be a map"));
    };
    let effector = str_ref(
        required_value_ref(entries, "effector").ok_or(invalid_body("binding effector"))?,
        "binding effector",
    )?
    .to_owned();
    let tier_raw = u64_ref(
        required_value_ref(entries, "tier_ceiling").ok_or(invalid_body("binding tier_ceiling"))?,
        "binding tier_ceiling",
    )?;
    let tier_ceiling = CustodyTier::from_u8(
        u8::try_from(tier_raw).map_err(|_| invalid_body("binding tier_ceiling"))?,
    )
    .ok_or(invalid_body("binding tier_ceiling"))?;
    let scopes = match required_value_ref(entries, "scopes") {
        Some(ValueRef::Array(items)) => {
            let mut scopes = Vec::with_capacity(items.len());
            for item in items {
                scopes.push(str_ref(item, "binding scope")?.to_owned());
            }
            scopes
        }
        Some(_) => return Err(invalid_body("binding scopes must be an array")),
        None => Vec::new(),
    };
    Ok(SecretBinding {
        effector,
        tier_ceiling,
        scopes,
    })
}

/// Decodes the admission projection from a custody body WITHOUT
/// materializing the value: the borrowing MessagePack reader leaves
/// `value_bytes` a slice of the LMDB-resident page, so the admission path
/// holds no heap copy of the plaintext at all (SOL-1920-04). The keys the
/// doors consume plus the presence/shape of `value_bytes` validate with
/// the same missing-or-duplicated reject discipline as
/// [`decode_secret_custody_body`]; keys the doors never read stay the full
/// codec's affair (registration already ran it).
pub(crate) fn decode_secret_custody_admission_body(bytes: &[u8]) -> Result<SecretCustodyAdmission> {
    use std::io::Cursor;

    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value_ref(&mut cursor)
        .map_err(|_| invalid_body("decode secret custody body"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_body("trailing bytes after secret custody body"));
    }
    let ValueRef::Map(entries) = value else {
        return Err(invalid_body("secret custody body must be a map"));
    };
    // Present and byte-shaped, never copied: the value stays a borrow of
    // the store page and dies with the decoded tree.
    match required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[4]) {
        Some(ValueRef::Binary(_)) | Some(ValueRef::String(_)) => {}
        _ => return Err(invalid_body("value_bytes")),
    }
    let name = str_ref(
        required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[1]).ok_or(invalid_body("name"))?,
        "name",
    )?
    .to_owned();
    let class = CustodyClass::parse(str_ref(
        required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[2]).ok_or(invalid_body("class"))?,
        "class",
    )?)
    .ok_or(invalid_body("class"))?;
    let status = SecretCustodyStatus::parse(str_ref(
        required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[5]).ok_or(invalid_body("status"))?,
        "status",
    )?)
    .ok_or(invalid_body("status"))?;
    let rotation_generation = u32::try_from(u64_ref(
        required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[8])
            .ok_or(invalid_body("rotation_generation"))?,
        "rotation_generation",
    )?)
    .map_err(|_| invalid_body("rotation_generation"))?;
    let bindings = match required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[9]) {
        Some(ValueRef::Array(items)) => {
            let mut bindings = Vec::with_capacity(items.len());
            for item in items {
                bindings.push(binding_from_value_ref(item)?);
            }
            bindings
        }
        Some(_) => return Err(invalid_body("bindings must be an array")),
        None => return Err(invalid_body("bindings")),
    };
    let declared_paths = match required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[11]) {
        Some(ValueRef::Array(items)) => {
            let mut paths = Vec::with_capacity(items.len());
            for item in items {
                paths.push(str_ref(item, "declared_path")?.to_owned());
            }
            paths
        }
        Some(_) => return Err(invalid_body("declared_paths must be an array")),
        None => return Err(invalid_body("declared_paths")),
    };
    Ok(SecretCustodyAdmission {
        name,
        class,
        status,
        rotation_generation,
        bindings,
        declared_paths,
    })
}

/// Reads the admission projection under either txn kind — the doors of
/// SECRET-02 resolve this instead of the full record (SOL-1920-04).
pub(crate) fn read_secret_custody_admission_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<SecretCustodyAdmission>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("secret custody entity header"));
    };
    if header.entity_type != ENTITY_TYPE_SECRET_CUSTODY {
        return Err(Error::CorruptedIndex("secret custody entity type"));
    }
    decode_secret_custody_admission_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

// ---------------------------------------------------------------------------
// Vault doors
// ---------------------------------------------------------------------------

/// Enforces the narrow-only rule against the LIVE floor and hands back the
/// live band for `rec`'s class.
///
/// The floor is resolved from the vault INSIDE the caller's transaction,
/// never from the caller-supplied snapshot (which may be stale). Every
/// binding's tier ceiling must fit inside the live band for the record's
/// class: a CrossVault record read against the default snapshot (its band
/// T0..T0) but binding T2 is rejected here, not after commit.
///
/// `pub(crate)` for SECRET-04's `Vault::rotate_secret` (ONE-1922): a
/// rotation is a FRESH authorization of the record's exposure, not a
/// grandfather clause for the posture it registered under, so a floor
/// narrowed since registration must refuse to re-bless a wider binding
/// through exactly this body rather than a second, unmarked copy of it.
pub(crate) fn refuse_bindings_wider_than_live_floor(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    rec: &SecretCustodyRecord,
) -> Result<TierBand> {
    let live_band = SecretCustodyFloor::resolve(store, txn)?.band_for(rec.class);
    for b in &rec.bindings {
        if b.tier_ceiling > live_band.max {
            return Err(Error::ManifestWidensFloor {
                secret_ref: rec.name.clone(),
                class: rec.class,
                requested: b.tier_ceiling,
                floor_max: live_band.max,
            });
        }
    }
    Ok(live_band)
}

/// Writes one custody body through the ONE sealed put shape, stamping
/// `occurred_at` as both the occurrence range and the learned-at.
///
/// Type-77 bodies are sealed from the raw/CRDT planes until ONE-1865: the
/// `apply_put` seal admits byte 77 only through the engine-internal
/// non-replicated shape (`allow_maintenance && !allow_reserved_predicate`,
/// the shape the default policy-manifest seeder uses). Any public or
/// replicated CRDT carry of byte 77 rejects there until then.
///
/// `pub(crate)` for SECRET-04's `Vault::rotate_secret` and
/// `Vault::revoke_secret` (ONE-1922), which re-put an existing record inside
/// their own write transaction: registration mints the id and all three land
/// through this body, so the seal shape has exactly one definition.
pub(crate) fn put_secret_custody_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    rec: &SecretCustodyRecord,
    occurred_at: u64,
) -> Result<()> {
    let data = encode_secret_custody_body(rec)?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![BatchOp::Put {
            id: *id,
            entity_type: ENTITY_TYPE_SECRET_CUSTODY,
            occurred: TimeRange {
                start: occurred_at,
                end: occurred_at,
            },
            learned_at: occurred_at,
            data,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )
}

impl Vault {
    /// Registers a secret-custody record, minting the `EntityId` and writing
    /// the name index. Denies a duplicate LIVE name (a name held by an
    /// `Active`/`Suspended` record); a `Revoked` name frees for
    /// re-registration. The record must register `Active`, carry the resolved
    /// floor snapshot narrower-or-equal to the live floor, and name its
    /// manifest ref when it came from a declared entry.
    pub fn register_secret(&self, rec: SecretCustodyRecord) -> Result<EntityId> {
        if rec.status != SecretCustodyStatus::Active {
            return Err(invalid_body("registration requires status active"));
        }
        if rec.name.is_empty() {
            return Err(invalid_body("secret name must not be empty"));
        }
        if rec.schema_version != SECRET_CUSTODY_SCHEMA_VERSION {
            return Err(invalid_body("unsupported secret custody schema version"));
        }
        let id = EntityId::now();

        let mut wtxn = self.store.env.write_txn()?;
        let index_key = name_index_key(&rec.name);

        // Resolve the floor against the LIVE vault inside this write
        // transaction and enforce narrow-only against it (never against the
        // caller-supplied snapshot, which may be stale).
        let live_band = refuse_bindings_wider_than_live_floor(&self.store, &wtxn, &rec)?;
        // The audit snapshot attached to the record must be narrower-or-equal
        // to the live floor: a caller-attested WIDER floor would lie about
        // the register-time posture. Most-restrictive-wins merge means a
        // snapshot equal to or narrower than live is accepted as-is.
        let snap_band = rec.policy_floor_snapshot.band_for(rec.class);
        if snap_band.max > live_band.max {
            return Err(Error::ManifestWidensFloor {
                secret_ref: rec.name.clone(),
                class: rec.class,
                requested: snap_band.max,
                floor_max: live_band.max,
            });
        }

        if let Some(existing_bytes) = self.store.vault_meta.get(&wtxn, &index_key)? {
            let id_bytes: [u8; 16] = existing_bytes
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("secret name index id"))?;
            let existing_id = EntityId::from_bytes(id_bytes)
                .map_err(|_| Error::CorruptedIndex("secret name index id"))?;
            // A live name denies; a revoked or missing record frees the index.
            if read_secret_custody_in_txn(&self.store, &wtxn, &existing_id)?
                .is_some_and(|existing| existing.status != SecretCustodyStatus::Revoked)
            {
                return Err(Error::SecretNameInUse { name: rec.name });
            }
        }

        // SECRET-01 dedicated door: the sealed type-77 put shape lives in
        // `put_secret_custody_in_txn`, shared with SECRET-04's rotate/revoke.
        put_secret_custody_in_txn(self, &mut wtxn, &id, &rec, rec.registered_at)?;
        self.store
            .vault_meta
            .put(&mut wtxn, &index_key, id.as_bytes())?;
        wtxn.commit()?;
        Ok(id)
    }

    /// Resolves a live secret name to its custody `EntityId`. Returns `None`
    /// when the name has no live record.
    pub fn resolve_secret_ref(&self, name: &str) -> Result<Option<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        resolve_secret_ref_in_txn(&self.store, &rtxn, name)
    }

    /// Reads the value-less metadata projection. This is the ONLY read most
    /// callers get: it has no value field.
    pub fn get_secret_metadata(&self, id: &EntityId) -> Result<Option<SecretCustodyMetadata>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(read_secret_custody_in_txn(&self.store, &rtxn, id)?.map(|rec| rec.metadata()))
    }

    /// Door/lease paths only (SECRET-02). Reads the raw value bytes for a
    /// record within a write txn, requiring a binding that covers `effector`
    /// AND declares the [`SECRET_SCOPE_READ`] grant: anything else ⇒
    /// [`Error::SecretBindingDenied`]. Naming the effector is not by itself a
    /// read grant — the binding's declared scope is what admits plaintext, and
    /// an empty scope list is no grant at all.
    /// The value never escapes into claims/CRDT/export/receipts/logs; this
    /// door is the narrowest possible read and exists so SECRET-02's door /
    /// lease machinery is the single value-read call-site. Consumed by
    /// [`crate::secret_lease`] (ONE-1920).
    pub(crate) fn get_secret_value_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        id: &EntityId,
        effector: &str,
    ) -> Result<Option<Vec<u8>>> {
        let Some(rec) = read_secret_custody_in_txn(&self.store, txn, id)? else {
            return Ok(None);
        };
        if rec.status != SecretCustodyStatus::Active {
            return Err(Error::SecretCustodyNotActive { name: rec.name });
        }
        if !rec
            .binding_for(effector)
            .is_some_and(SecretBinding::grants_read)
        {
            return Err(Error::SecretBindingDenied {
                effector: effector.to_owned(),
                secret_ref: rec.name,
            });
        }
        Ok(Some(rec.value_bytes))
    }
}

#[cfg(test)]
mod tests;
