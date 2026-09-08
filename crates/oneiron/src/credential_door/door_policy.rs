//! Policy model: effectors, dials, floors, merge rules, and map helpers.

use std::collections::BTreeSet;

use rmpv::Value;

use super::door_credential::DoorCredential;
use super::door_types::{
    CredentialDoorError, DOOR_EFFECTORS, DOOR_MAX_LEASE_TTL_SECS, DoorResult, TtlCeiling,
    names_a_floor,
};
use crate::secret_custody::{
    PolicyManifestWalkError, policy_manifest_bodies_strict, policy_manifest_body_map,
};
use crate::secret_lease::VaultInstant;
use crate::store::Store;

/// MessagePack keys this door reads out of POLICY_MANIFEST bodies.
pub(super) mod door_policy_keys {
    /// Narrowed TTL ceiling, in seconds.
    pub(crate) const MAX_LEASE_TTL_SECS: &str = "secret.door.max_lease_ttl_secs";
    /// Narrowed effector set.
    pub(crate) const ALLOWED_EFFECTORS: &str = "secret.door.allowed_effectors";
    /// What an error names when the malformed field is the BODY that would
    /// carry the door rows rather than one row inside it.
    pub(crate) const NAMESPACE: &str = "secret.door.*";
    /// What an error names when the corruption is in the INDEXED MANIFEST
    /// PLANE itself — the type-index entry, the entity row it points at, or
    /// that row's metadata header — rather than in any body this door reads.
    /// A safe, constant label: no entity id, no key bytes, no body bytes.
    pub(crate) const MANIFEST_PLANE: &str = "policy_manifest.index";
}

/// MessagePack key-map helpers local to this module (the per-module idiom the
/// custody floor and the gate each keep their own copy of).
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

fn as_u64(value: &Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        Some(n)
    } else if let Some(n) = value.as_i64() {
        u64::try_from(n).ok()
    } else {
        None
    }
}

/// The refusal a strict POLICY_MANIFEST walk hands this door, mapped into the
/// door's own module-local surface.
///
/// A storage failure stays the landed custody refusal it already was. Every
/// other refusal names a SAFE CONSTANT label and a safe constant reason — the
/// index-plane label when the corruption is in the indexed manifest plane
/// itself, the door's namespace when a body is present but unreadable — and
/// never an id, a key byte, or a byte of any body.
fn manifest_refusal(err: PolicyManifestWalkError) -> CredentialDoorError {
    match err {
        PolicyManifestWalkError::Storage(err) => CredentialDoorError::Custody(err),
        PolicyManifestWalkError::IndexPlane(reason) => CredentialDoorError::InvalidDoorPolicy {
            key: door_policy_keys::MANIFEST_PLANE,
            reason,
        },
        PolicyManifestWalkError::UnreadableBody(reason) => CredentialDoorError::InvalidDoorPolicy {
            key: door_policy_keys::NAMESPACE,
            reason,
        },
    }
}

/// ONE door effector, PROVED a member of [`DOOR_EFFECTORS`].
///
/// The payload is a `&'static str` borrowed from [`DOOR_EFFECTORS`] itself and
/// the field is private, so a value of this type IS one of the door's own
/// effector constants — not a string that happened to compare equal to one at
/// some earlier moment, in some other transaction. That is the difference from
/// the bare `&str` this replaces at the authorization site: a name becomes
/// authority only by passing [`DoorEffector::parse`], and what comes out the
/// other side carries the CONSTANT rather than the caller's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DoorEffector(&'static str);

impl DoorEffector {
    /// Every effector this door knows, as proved values. The one place a
    /// `DoorEffector` is built without a membership test, because this IS the
    /// membership set.
    fn all() -> impl Iterator<Item = Self> {
        DOOR_EFFECTORS.iter().copied().map(Self)
    }

    /// The membership test that is the only OTHER way in. An empty name, a
    /// foreign connector, and a near-miss spelling all fail it, so "there is no
    /// unscoped door operation" becomes a fact about the type instead of a
    /// check every call site has to remember to repeat.
    pub(super) fn parse(name: &str) -> Option<Self> {
        Self::all().find(|effector| effector.0 == name)
    }

    /// The effector's constant name, for the rows, receipts and evaluator
    /// arguments that still spell it out.
    pub(crate) fn as_str(self) -> &'static str {
        self.0
    }
}

/// The dial's effector set: a SUBSET of [`DOOR_EFFECTORS`] by construction.
///
/// A `BTreeSet<DoorEffector>` cannot hold a name this door does not know,
/// because [`DoorEffector`] cannot hold one — so "a dial may only narrow the
/// door's effectors" is enforced by the ELEMENT TYPE rather than by a
/// membership check at each use. The `BTreeSet<String>` this replaces could
/// hold anything at all; the widen refusal lived in whoever remembered to test
/// membership before trusting the set, and a set that reached a mint untested
/// was indistinguishable from one that had been.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectorDial(BTreeSet<DoorEffector>);

impl Default for EffectorDial {
    /// The safe default IS the widest a dial may ever be: the door's whole
    /// effector set. A dial nobody narrowed narrows nothing, and there is no
    /// spelling here for "unbounded".
    fn default() -> Self {
        Self(DoorEffector::all().collect())
    }
}

impl EffectorDial {
    /// The lattice meet: the intersection, i.e. the more restrictive of two
    /// dials. Commutative, associative, idempotent, and incapable of widening,
    /// so packs compose to the same answer in any order.
    fn meet(&self, other: &Self) -> Self {
        Self(self.0.intersection(&other.0).copied().collect())
    }

    /// Whether this dial still admits a PROVED effector. There is no overload
    /// taking a `&str`: proving membership of [`DOOR_EFFECTORS`] happens once,
    /// at [`DoorEffector::parse`], and never again by accident here.
    pub(super) fn admits(&self, effector: DoorEffector) -> bool {
        self.0.contains(&effector)
    }

    /// How many effectors survive the dial — for the regressions that prove an
    /// emptied dial is a shut door.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }
}

/// The dial-narrowable catastrophe floors, RESOLVED — a snapshot, never a
/// second resolver.
///
/// Every floor a `secret.door.*` row may narrow lives here, and lives in its
/// LATTICE form ([`TtlCeiling`]) rather than as a number. That is why there is
/// no `max_lease_ttl_secs: u64` field any more: a raw `u64` can hold a ceiling
/// above [`DOOR_MAX_LEASE_TTL_SECS`], can be assigned from anywhere, and puts
/// the floor back in the hands of whoever remembers to `min` against it last.
///
/// [`DOOR_SCAN_ALWAYS_ON`] and [`DOOR_ONE_SHOT_MAX_LIFETIME_SECS`] are
/// deliberately NOT here. They are not dial space at all, and a field on a
/// resolved snapshot is exactly the shape that would suggest some row could
/// move them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PolicyFloors {
    pub(super) lease_ttl: TtlCeiling,
}

impl PolicyFloors {
    /// The floors a declaration of `secs` buys. Narrowing only by construction:
    /// [`TtlCeiling::at_most`] clamps at the hard floor on the way in.
    pub(super) fn at_most_lease_ttl(secs: u64) -> Self {
        Self {
            lease_ttl: TtlCeiling::at_most(secs),
        }
    }

    /// The lattice meet, per floor: the tighter of two snapshots.
    pub(super) fn meet(self, other: Self) -> Self {
        Self {
            lease_ttl: self.lease_ttl.meet(other.lease_ttl),
        }
    }

    /// The resolved lease-TTL ceiling.
    pub(crate) fn lease_ttl(self) -> TtlCeiling {
        self.lease_ttl
    }
}

/// The resolved door dial: the floors it narrows and the effectors it leaves
/// open. Narrow-only by construction — every field starts at its widest safe
/// value and merges toward the most restrictive declaration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DoorPolicy {
    pub(super) floors: PolicyFloors,
    pub(super) dial: EffectorDial,
}

impl DoorPolicy {
    /// Narrows `self` against `other`, most-restrictive per field. Only meets
    /// compose here, so no order of packs can raise anything.
    fn merge(&mut self, other: &DoorPolicy) {
        self.floors = self.floors.meet(other.floors);
        self.dial = self.dial.meet(&other.dial);
    }

    /// The effector set this dial resolved to.
    pub(crate) fn dial(&self) -> &EffectorDial {
        &self.dial
    }

    /// The resolved lease-TTL ceiling in seconds, for the refusals and
    /// assertions that have to report a number.
    pub(crate) fn lease_ttl_ceiling_secs(&self) -> u64 {
        self.floors.lease_ttl.secs()
    }

    /// Whether this dial still admits `effector` as a door scope. An empty
    /// effector is never admitted: there is no unscoped door operation, and
    /// [`DoorEffector::parse`] is the single place that is decided.
    pub(crate) fn admits_effector(&self, effector: &str) -> bool {
        DoorEffector::parse(effector).is_some_and(|proved| self.dial.admits(proved))
    }

    /// The same effective ceiling, in seconds.
    pub(crate) fn effective_lease_ttl_ceiling(
        &self,
        credential: &DoorCredential,
        now: VaultInstant,
    ) -> u64 {
        self.effective_ttl_ceiling(credential, now).secs()
    }

    /// Resolves the dial from every POLICY_MANIFEST body in the vault,
    /// most-restrictive wins.
    ///
    /// An ABSENT row means "this pack declares no door dial" and takes the
    /// safe default. A row that is PRESENT but unreadable, duplicated, or
    /// widening is an ERROR: defaulting it would silently restore the
    /// permissive posture the declaration existed to narrow.
    ///
    /// The same reasoning governs the INDEX PLANE the bodies are reached
    /// through, and it is why this door consumes the STRICT shared walk
    /// ([`policy_manifest_bodies_strict`]) instead of the diagnostics-collecting
    /// resolver [`crate::gate`] owns. A manifest the door cannot read is
    /// indistinguishable, from here, from a manifest that narrowed the dial to
    /// nothing: an unusable type-index key, an entry whose entity row is gone,
    /// an entity whose metadata header will not parse, an entry that names a
    /// row of some other type, and a body that will not canonically decode are
    /// all "a declaration was indexed and this door cannot see it". Skipping
    /// any of them hands back the FULL effector set and the FULL TTL ceiling,
    /// so deleting one entity row would be enough to re-open a door a dial had
    /// shut. Every one of them fails closed instead, through
    /// [`manifest_refusal`], naming only a constant label and a constant
    /// reason — never an id, a key, or a byte of any body.
    pub(crate) fn resolve(store: &Store, txn: &heed::RoTxn<'_>) -> DoorResult<Self> {
        let mut policy = DoorPolicy::default();
        for entries in policy_manifest_bodies_strict(store, txn).map_err(manifest_refusal)? {
            policy.merge(&decode_door_policy_rows(&entries)?);
        }
        Ok(policy)
    }
}

impl DoorPolicy {
    /// The effective lease ceiling: the hard floor, narrowed by the dial,
    /// narrowed again by the slip's own attenuation (itself already a minimum
    /// over every caveat applied), and narrowed last by what is LEFT of the
    /// slip's validity at `now`. Only minima compose here, so no combination
    /// of dial, slip, caveat order, and witnessed instant can ever raise it.
    ///
    /// This is the ceiling on what may be REQUESTED. What the issued ticket
    /// actually expires at is clamped once more, by the absolute credential
    /// expiry, inside the transaction that stamps it.
    ///
    /// Every term is ALREADY a lattice value or enters through
    /// [`TtlCeiling::at_most`], so the hard floor is applied by CONSTRUCTION
    /// rather than by a `min` this function has to remember; the rest is
    /// `meet`, which cannot raise anything. The dial's own term needs no clamp
    /// at all now — [`PolicyFloors`] cannot hold a ceiling above the floor.
    pub(super) fn effective_ttl_ceiling(
        &self,
        credential: &DoorCredential,
        now: VaultInstant,
    ) -> TtlCeiling {
        let dial_ceiling = self.floors.lease_ttl;
        dial_ceiling
            .meet(credential.ttl_cap)
            .meet_secs(credential.remaining_secs(now))
    }
}

/// Decodes the `secret.door.*` rows of ONE policy-manifest body.
///
/// `Ok(None)` means only "this body canonically decodes to something that is
/// not a map, so it carries no door rows" — the body schema itself belongs to
/// the gate. A body that does not canonically decode at all fails closed
/// instead (see [`policy_manifest_body_map`], the shared canonical-body
/// boundary this door and the custody floor both read through).
pub(crate) fn decode_door_policy_keys(body: &[u8]) -> DoorResult<Option<DoorPolicy>> {
    let Some(entries) = policy_manifest_body_map(body).map_err(manifest_refusal)? else {
        return Ok(None);
    };
    decode_door_policy_rows(&entries).map(Some)
}

/// Decodes the `secret.door.*` rows of one canonically-decoded manifest body.
///
/// An ABSENT effector row means "this pack declares no effector narrowing" and
/// takes the widest safe dial; a PRESENT one is decoded straight into typed
/// members, so a widening name never becomes a set element in the first place.
fn decode_door_policy_rows(entries: &[(Value, Value)]) -> DoorResult<DoorPolicy> {
    reject_floor_naming_rows(entries)?;

    Ok(DoorPolicy {
        floors: decode_floors_row(entries)?,
        dial: decode_effector_row(entries)?.unwrap_or_default(),
    })
}

/// No policy row may name a floor — not to set it, not to read it, not to
/// turn it off.
fn reject_floor_naming_rows(entries: &[(Value, Value)]) -> DoorResult<()> {
    for (key, _) in entries {
        let Some(name) = key.as_str() else {
            continue;
        };
        if names_a_floor(name) {
            return Err(CredentialDoorError::FloorNamed {
                site: "policy manifest row",
                name: name.to_owned(),
            });
        }
    }
    Ok(())
}

/// Decodes the dial-narrowable floors out of one body.
///
/// The refusals are unchanged and stay LOUD: a non-integer ceiling, a
/// duplicated row, and a row that tries to RAISE the ceiling above
/// [`DOOR_MAX_LEASE_TTL_SECS`] each fail closed here rather than being clamped
/// silently by [`TtlCeiling::at_most`] downstream. Only a declaration that
/// genuinely narrows becomes a [`PolicyFloors`].
fn decode_floors_row(entries: &[(Value, Value)]) -> DoorResult<PolicyFloors> {
    let key = door_policy_keys::MAX_LEASE_TTL_SECS;
    let invalid = |reason| CredentialDoorError::InvalidDoorPolicy { key, reason };
    match single_map_value(entries, key) {
        MapValue::Missing => Ok(PolicyFloors::default()),
        MapValue::Present(value) => {
            let Some(secs) = as_u64(value) else {
                return Err(invalid("TTL ceiling must be an unsigned integer"));
            };
            if secs > DOOR_MAX_LEASE_TTL_SECS {
                return Err(invalid("a dial may only narrow the TTL ceiling"));
            }
            Ok(PolicyFloors::at_most_lease_ttl(secs))
        }
        MapValue::Duplicate => Err(invalid("duplicated row leaves the ceiling ambiguous")),
    }
}

/// Decodes the declared effector narrowing out of one body.
///
/// The widen refusal is the SAME predicate the typed effector is built from:
/// [`DoorEffector::parse`] fails exactly when the old `DOOR_EFFECTORS.contains`
/// check failed, and refusing there is what keeps a foreign name out of the
/// resulting [`EffectorDial`] rather than merely out of a later comparison.
fn decode_effector_row(entries: &[(Value, Value)]) -> DoorResult<Option<EffectorDial>> {
    let key = door_policy_keys::ALLOWED_EFFECTORS;
    let invalid = |reason| CredentialDoorError::InvalidDoorPolicy { key, reason };
    match single_map_value(entries, key) {
        MapValue::Missing => Ok(None),
        MapValue::Present(Value::Array(items)) => {
            let mut allowed = BTreeSet::new();
            for item in items {
                let name = item
                    .as_str()
                    .ok_or_else(|| invalid("effector entries must be strings"))?;
                let Some(effector) = DoorEffector::parse(name) else {
                    return Err(invalid("a door dial may only narrow the door's effectors"));
                };
                allowed.insert(effector);
            }
            Ok(Some(EffectorDial(allowed)))
        }
        MapValue::Present(_) => Err(invalid("allowed effectors must be an array")),
        MapValue::Duplicate => Err(invalid("duplicated row leaves the set ambiguous")),
    }
}
