//! ARCH-0069 secret custody — SECRET-02 (ONE-1920): the T0/T1/T2
//! materialization rungs behind a single admission gate.
//!
//! The honest dividing line is memory (S3): a value that enters workspace
//! memory is T1 minimum. The three rungs:
//!
//! * **T0 doored** — [`Vault::inject_secret_at_door`] resolves a secret ref
//!   and hands the value to a closure that runs INSIDE the door and returns
//!   only `()`: the bytes cannot come back through the closure's return
//!   type. The caller receives only a [`DoorInjectionReceipt`].
//! * **T1 leased** — [`Vault::materialize_secret_lease`] admits the request,
//!   then writes the [`SecretLease`] row and its
//!   [`SecretMaterializationReceipt`] durable BEFORE the value returns
//!   (receipt-at-materialization, S3 — environment reads are not
//!   interceptable, so the receipt is stamped at the mint). The value
//!   returns wrapped in [`Zeroizing`]. Expiry is lazy (checked at use) plus
//!   the [`Vault::expire_secret_leases`] maintenance sweep; the engine owns
//!   no timers (ARCH-0026).
//! * **T2 local-registered** — [`Vault::register_secret_local`]
//!   materializes the value to a manifest-declared local path under a live
//!   lease and records a [`LocalRegistration`] so unlease can clean the
//!   file and SECRET-03 (ONE-1921) can exclude the path. Recovery is
//!   re-materialization from the vault (S4), never from a snapshot.
//!
//! # The one admission rule (cap-only, stated once)
//!
//! A request is admitted iff ALL of:
//!
//! 1. the record has a [`SecretBinding`] for `(secret_ref, effector)` —
//!    otherwise [`Error::SecretBindingDenied`] (ONE-1919's binding
//!    discipline, regression-checked here);
//! 2. `requested_tier <= floor.band_for(class).max` against the live vault
//!    floor resolved per ONE-1919 — otherwise [`Error::SecretTierDenied`];
//! 3. `requested_tier <= binding.tier_ceiling` (exposure order
//!    `T0 < T1 < T2`) — otherwise [`Error::SecretTierDenied`].
//!
//! No minimum-exposure rule exists anywhere: floors and ceilings only ever
//! CAP exposure. ONE-1919's keystone makes the band's `min` informational
//! (floors narrow the MAX, never force exposure), so rule (2) is a pure
//! upper cap — a request for a SAFER tier than the band's `min` admits and
//! is never forced upward (K3 disposition of SOL-1920-01: the blueprint's
//! "set-membership" phrase lost to the keystone and to this ticket's own
//! no-minimum-exposure sentence). [`tier_admission`] is the pure function
//! at the rule's center; the doors add only the record lookup and the
//! binding resolution
//! (the binding is resolved from the record, never caller-invented). The
//! custody principal behind the effector string is the host-minted
//! capability slip (OF-452 D1/D7/D10); see [`crate::secret_custody`] module
//! docs — this module does not pretend otherwise either.
//!
//! # Teardown honesty (S3/S6)
//!
//! [`Vault::revoke_secret_lease`] and expiry flip the lease status, revoke
//! door-side use, and — for T2 — remove the registered local file
//! (best-effort, recorded: a failed removal retains the registration row
//! with the error recorded, so a path whose file may still hold the value
//! stays in SECRET-03's exclusion set). Caller-held process memory is out
//! of the vault's reach by construction; that is the ratified lease-scoped
//! contract, not a gap to paper over — there is deliberately no fake
//! "scrub the returned buffer" machinery. Revocation of the SECRET itself
//! (SECRET-04, ONE-1922) is the only path that force-kills leases.
//!
//! A lease minted at rotation generation N remains valid after the record
//! rotates to N+1 (S6): staleness is OBSERVABLE via
//! [`SecretLease::value_generation`], never force-killed here. SECRET-04
//! owns rotation and attaches exhaust taint from
//! [`DoorInjectionReceipt::taint_token`].
//!
//! # Receipt residence
//!
//! The RS1 receipt-family discriminator ([`crate::receipt::ReceiptKind`])
//! is `#[non_exhaustive]` and pinned by OF-367 — an OPEN family set this
//! ticket has no authority to extend — so materialization receipts are
//! generic self-describing receipt bodies: `vault_meta` rows under
//! [`SECRET_MATERIALIZATION_RECEIPT_PREFIX`] carrying
//! `kind = "secret_materialization"`. They never carry value bytes.
//!
//! # Storage
//!
//! Lease rows live in `vault_meta` under [`SECRET_LEASE_KEY_PREFIX`], local
//! registrations under [`SECRET_LOCAL_REGISTRATION_PREFIX`] — the
//! [`crate::secret_custody`] name-index idiom, mirroring the device-lease
//! registry's shape ([`crate::sync::lease`], a different noun, never
//! overloaded). `vault_meta` is local-only: custody records never
//! replicate, so leases minted over them never do either.

use std::fs;
use std::path::{Path, PathBuf};

use rmpv::Value;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::{
    CustodyClass, CustodyTier, SecretBinding, SecretCustodyAdmission, SecretCustodyFloor,
    SecretCustodyStatus, read_secret_custody_admission_in_txn, resolve_secret_ref_in_txn,
};
use crate::store::Store;
use crate::unix_seconds_now;
use crate::vault::Vault;

/// The `vault_meta` key prefix for secret-lease rows
/// (`secret_lease:v1:<lease_id_hex>`).
pub const SECRET_LEASE_KEY_PREFIX: &str = "secret_lease:v1:";
/// The `vault_meta` key prefix for T2 local-registration rows
/// (`secret_local:v1:<lease_id_hex>`).
///
/// SECRET-03 (ONE-1921) reads EVERY row under this prefix into the snapshot
/// exclusion set: a row is deleted only when the registered file is
/// verifiably gone, so any row still present names a path whose file may
/// hold the value.
pub const SECRET_LOCAL_REGISTRATION_PREFIX: &str = "secret_local:v1:";
/// The `vault_meta` key prefix for materialization-receipt rows
/// (`secret_lease_receipt:v1:<receipt_id_hex>`). Generic self-describing
/// receipt bodies — see the module docs' receipt-residence note.
pub const SECRET_MATERIALIZATION_RECEIPT_PREFIX: &str = "secret_lease_receipt:v1:";
/// The `kind` value stamped on materialization-receipt bodies.
pub const SECRET_MATERIALIZATION_RECEIPT_KIND: &str = "secret_materialization";

fn invalid_body(reason: &'static str) -> Error {
    Error::InvalidSecretLeaseBody(reason)
}

// ---------------------------------------------------------------------------
// Lease status & rows
// ---------------------------------------------------------------------------

/// Lifecycle status of a [`SecretLease`]. Wire bytes mirror the
/// device-lease registry precedent (`sync::lease`): `0x01` active, `0x02`
/// expired, `0x03` revoked. Only `Active` admits use; `Revoked` is terminal
/// for the lease (a fresh materialization mints a fresh lease id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SecretLeaseStatus {
    /// Live and usable within its tier.
    Active = 0x01,
    /// Past `expires_at` (lazy check at use, or the maintenance sweep).
    Expired = 0x02,
    /// Terminal. The only door-rejecting status besides `Expired`.
    Revoked = 0x03,
}

impl SecretLeaseStatus {
    /// The wire byte.
    #[must_use]
    pub const fn as_wire_byte(self) -> u8 {
        self as u8
    }

    /// Parses the wire byte.
    #[must_use]
    pub fn from_wire_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Active),
            0x02 => Some(Self::Expired),
            0x03 => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// A T1/T2 lease row (`vault_meta` under [`SECRET_LEASE_KEY_PREFIX`]).
///
/// The row is the escalation ladder: a lease mints at `T1Leased` and climbs
/// to `T2LocalRegistered` when [`Vault::register_secret_local`] records the
/// local file under it. No `Serialize`/`Deserialize`: the engine's
/// [`EntityId`] has no serde form, and the MessagePack body codec below is
/// the ONE serialization of this row — it exists to write the vault-resident
/// body, nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretLease {
    /// The lease identifier (minted by the vault at materialization).
    pub lease_id: EntityId,
    /// The secret name this lease was minted over.
    pub secret_ref: String,
    /// The effector the binding was resolved for at mint time.
    pub binding_effector: String,
    /// The highest rung this lease has reached (`T1Leased` |
    /// `T2LocalRegistered`).
    pub tier: CustodyTier,
    /// Unix seconds at mint.
    pub granted_at: u64,
    /// Unix seconds after which the lease is expired (`granted_at + ttl`).
    pub expires_at: u64,
    /// Lifecycle status.
    pub status: SecretLeaseStatus,
    /// The materialization receipt written durable BEFORE the value
    /// returned (S3).
    pub materialization_receipt: EntityId,
    /// The record's `rotation_generation` at mint (S6 staleness signal).
    pub value_generation: u32,
}

/// The T1 materialization return: the lease row plus the value.
///
/// The value is wrapped in [`Zeroizing`] so the caller's copy is scrubbed on
/// drop — the vault's side of the lease-scoped contract. `Debug` redacts
/// the value (`Zeroizing`'s own `Debug` would print the inner bytes).
#[derive(PartialEq, Eq)]
pub struct SecretLeaseMaterialization {
    /// The durable lease row.
    pub lease: SecretLease,
    /// The secret value (plaintext, zeroized on drop).
    pub value: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for SecretLeaseMaterialization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretLeaseMaterialization")
            .field("lease", &self.lease)
            .field(
                "value",
                &format_args!("<redacted {} bytes>", self.value.len()),
            )
            .finish()
    }
}

/// A T2 local registration (`vault_meta` under
/// [`SECRET_LOCAL_REGISTRATION_PREFIX`], keyed by lease id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRegistration {
    /// The lease this registration lives under.
    pub lease_id: EntityId,
    /// The manifest-declared local path holding the materialized value.
    pub path: PathBuf,
    /// BLAKE3 content hash of the materialized bytes (the
    /// `codebase.rs` `content_hash` convention SECRET-03 compares against).
    pub content_hash: [u8; 32],
    /// The project the path belongs to — SECRET-03's exclusion set reads
    /// this to scope exclusions per snapshot project.
    pub project_id: String,
}

/// The stored form of a local registration: the public row plus the
/// teardown record. A retained row with `removal_error` set is CLOSED (its
/// lease is torn down) but kept so the still-present file's path stays in
/// SECRET-03's exclusion set and the failure is recorded (best-effort,
/// recorded — never a silent drop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredLocalRegistration {
    pub(crate) registration: LocalRegistration,
    pub(crate) removal_error: Option<String>,
    pub(crate) removal_attempted_at: Option<u64>,
}

/// A taint reference for SECRET-04 (ONE-1922): declared here (layer 2)
/// because door/lease returns carry it; SECRET-04 consumes and invalidates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretTaintRef {
    /// The secret name.
    pub secret_ref: String,
    /// The record's rotation generation the value was read at.
    pub generation: u32,
}

/// The T0 door-injection receipt — the ONLY thing the workspace receives
/// from [`Vault::inject_secret_at_door`]. Carries no value bytes by
/// construction; `Debug` and serde are safe (grep-guard tested).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoorInjectionReceipt {
    /// The secret name injected.
    pub secret_ref: String,
    /// The effector the binding was resolved for.
    pub effector: String,
    /// Unix seconds at injection (stamped at materialization, S3 —
    /// environment reads are not interceptable).
    pub injected_at: u64,
    /// The record's rotation generation the value was read at.
    pub value_generation: u32,
    /// SECRET-04 attaches exhaust taint from this token.
    pub taint_token: Vec<SecretTaintRef>,
}

/// The durable materialization receipt (`vault_meta` under
/// [`SECRET_MATERIALIZATION_RECEIPT_PREFIX`]). Written BEFORE the value
/// returns from [`Vault::materialize_secret_lease`]; carries no value
/// bytes. Generic receipt body: `kind =
/// `[`SECRET_MATERIALIZATION_RECEIPT_KIND`] on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMaterializationReceipt {
    /// The receipt identifier (referenced by
    /// [`SecretLease::materialization_receipt`]).
    pub receipt_id: EntityId,
    /// The secret name materialized.
    pub secret_ref: String,
    /// The effector the binding was resolved for.
    pub effector: String,
    /// The tier materialized at (`T1Leased` at mint).
    pub tier: CustodyTier,
    /// The lease this receipt attests.
    pub lease_id: EntityId,
    /// Unix seconds at materialization.
    pub materialized_at: u64,
    /// The record's rotation generation at materialization.
    pub value_generation: u32,
}

// ---------------------------------------------------------------------------
// The one admission rule
// ---------------------------------------------------------------------------

/// The one admission rule, pure: `Ok(requested)` iff `requested` is at or
/// below `floor.band_for(class).max` AND at or below
/// `binding.tier_ceiling`. The binding must be resolved from the record by
/// the caller (a missing binding is [`Error::SecretBindingDenied`],
/// settled before this call) — never caller-invented.
///
/// Rule (b) is a pure upper CAP: ONE-1919's floor keystone narrows the
/// band's `max` and treats `min` as informational, so a request below the
/// band's `min` — a SAFER tier — admits and is never forced upward.
/// Floors and ceilings only ever CAP exposure; there is no
/// minimum-exposure rule anywhere.
pub fn tier_admission(
    class: CustodyClass,
    requested: CustodyTier,
    binding: &SecretBinding,
    floor: &SecretCustodyFloor,
) -> Result<CustodyTier> {
    let band = floor.band_for(class);
    if requested > band.max || requested > binding.tier_ceiling {
        return Err(Error::SecretTierDenied {
            class,
            requested,
            floor_min: band.min,
            floor_max: band.max,
            binding_ceiling: binding.tier_ceiling,
        });
    }
    Ok(requested)
}

/// The door-side half of the admission rule: record liveness plus binding
/// resolution (rule (a)), then the pure tier gate (rules (b)+(c)).
#[allow(clippy::redundant_clone)]
fn admit_record_use(
    rec: &SecretCustodyAdmission,
    effector: &str,
    requested: CustodyTier,
    floor: &SecretCustodyFloor,
) -> Result<()> {
    if rec.status != SecretCustodyStatus::Active {
        return Err(Error::SecretCustodyNotActive {
            name: rec.name.clone(),
        });
    }
    let binding = rec
        .binding_for(effector)
        .ok_or_else(|| Error::SecretBindingDenied {
            effector: effector.to_owned(),
            secret_ref: rec.name.clone(),
        })?;
    tier_admission(rec.class, requested, binding, floor)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Row keys
// ---------------------------------------------------------------------------

fn lease_key(lease_id: &EntityId) -> Vec<u8> {
    format!("{SECRET_LEASE_KEY_PREFIX}{}", lease_id.to_hex()).into_bytes()
}

fn receipt_key(receipt_id: &EntityId) -> Vec<u8> {
    format!(
        "{SECRET_MATERIALIZATION_RECEIPT_PREFIX}{}",
        receipt_id.to_hex()
    )
    .into_bytes()
}

fn registration_key(lease_id: &EntityId) -> Vec<u8> {
    format!("{SECRET_LOCAL_REGISTRATION_PREFIX}{}", lease_id.to_hex()).into_bytes()
}

// ---------------------------------------------------------------------------
// Body codecs (MessagePack key maps — the secret_custody.rs idiom)
// ---------------------------------------------------------------------------

/// Reads a required key out of a MessagePack map's entries. A MISSING or
/// DUPLICATED key both yield `None` — the call site turns that into the
/// typed body reject; an ambiguous body is never defaulted.
fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    let mut found = None;
    for (k, v) in entries {
        if k.as_str() == Some(key) {
            if found.is_some() {
                return None;
            }
            found = Some(v);
        }
    }
    found
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

fn entity_id_at(entries: &[(Value, Value)], key: &str, reason: &'static str) -> Result<EntityId> {
    required_value(entries, key)
        .and_then(|v| v.as_str())
        .and_then(|s| EntityId::from_hex(s).ok())
        .ok_or(invalid_body(reason))
}

fn u64_at(entries: &[(Value, Value)], key: &str, reason: &'static str) -> Result<u64> {
    required_value(entries, key)
        .and_then(as_u64)
        .ok_or(invalid_body(reason))
}

fn string_at(entries: &[(Value, Value)], key: &str, reason: &'static str) -> Result<String> {
    required_value(entries, key)
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or(invalid_body(reason))
}

fn tier_at(entries: &[(Value, Value)], key: &str, reason: &'static str) -> Result<CustodyTier> {
    let n = u64_at(entries, key, reason)?;
    CustodyTier::from_u8(u8::try_from(n).map_err(|_| invalid_body(reason))?)
        .ok_or(invalid_body(reason))
}

/// Decodes a MessagePack key-map body, rejecting non-map bodies and
/// trailing bytes. Shared shape for the three row codecs.
fn decode_map_body(bytes: &[u8], reason: &'static str) -> Result<Vec<(Value, Value)>> {
    use std::io::Cursor;

    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_body(reason))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_body("trailing bytes after secret lease row body"));
    }
    let Value::Map(entries) = value else {
        return Err(invalid_body(reason));
    };
    Ok(entries)
}

fn encode_map_body(pairs: Vec<(&str, Value)>) -> Result<Vec<u8>> {
    let map = Value::Map(
        pairs
            .into_iter()
            .map(|(k, v)| (Value::from(k), v))
            .collect(),
    );
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &map)
        .map_err(|_| invalid_body("encode secret lease row body"))?;
    Ok(out)
}

/// The lease body's MessagePack keys, in field order. `9 keys = 9 fields`.
const SECRET_LEASE_BODY_KEYS: [&str; 9] = [
    "lease_id",
    "secret_ref",
    "binding_effector",
    "tier",
    "granted_at",
    "expires_at",
    "status",
    "materialization_receipt",
    "value_generation",
];

fn encode_secret_lease_body(lease: &SecretLease) -> Result<Vec<u8>> {
    encode_map_body(vec![
        (
            SECRET_LEASE_BODY_KEYS[0],
            Value::from(lease.lease_id.to_hex()),
        ),
        (
            SECRET_LEASE_BODY_KEYS[1],
            Value::from(lease.secret_ref.as_str()),
        ),
        (
            SECRET_LEASE_BODY_KEYS[2],
            Value::from(lease.binding_effector.as_str()),
        ),
        (
            SECRET_LEASE_BODY_KEYS[3],
            Value::from(u64::from(lease.tier.as_u8())),
        ),
        (SECRET_LEASE_BODY_KEYS[4], Value::from(lease.granted_at)),
        (SECRET_LEASE_BODY_KEYS[5], Value::from(lease.expires_at)),
        (
            SECRET_LEASE_BODY_KEYS[6],
            Value::from(u64::from(lease.status.as_wire_byte())),
        ),
        (
            SECRET_LEASE_BODY_KEYS[7],
            Value::from(lease.materialization_receipt.to_hex()),
        ),
        (
            SECRET_LEASE_BODY_KEYS[8],
            Value::from(u64::from(lease.value_generation)),
        ),
    ])
}

fn decode_secret_lease_body(bytes: &[u8]) -> Result<SecretLease> {
    let entries = decode_map_body(bytes, "secret lease body must be a map")?;
    let status_raw = u64_at(&entries, SECRET_LEASE_BODY_KEYS[6], "lease status")?;
    Ok(SecretLease {
        lease_id: entity_id_at(&entries, SECRET_LEASE_BODY_KEYS[0], "lease lease_id")?,
        secret_ref: string_at(&entries, SECRET_LEASE_BODY_KEYS[1], "lease secret_ref")?,
        binding_effector: string_at(
            &entries,
            SECRET_LEASE_BODY_KEYS[2],
            "lease binding_effector",
        )?,
        tier: tier_at(&entries, SECRET_LEASE_BODY_KEYS[3], "lease tier")?,
        granted_at: u64_at(&entries, SECRET_LEASE_BODY_KEYS[4], "lease granted_at")?,
        expires_at: u64_at(&entries, SECRET_LEASE_BODY_KEYS[5], "lease expires_at")?,
        status: SecretLeaseStatus::from_wire_byte(
            u8::try_from(status_raw).map_err(|_| invalid_body("lease status"))?,
        )
        .ok_or(invalid_body("lease status"))?,
        materialization_receipt: entity_id_at(
            &entries,
            SECRET_LEASE_BODY_KEYS[7],
            "lease materialization_receipt",
        )?,
        value_generation: u32::try_from(u64_at(
            &entries,
            SECRET_LEASE_BODY_KEYS[8],
            "lease value_generation",
        )?)
        .map_err(|_| invalid_body("lease value_generation"))?,
    })
}

/// The materialization receipt body's MessagePack keys (`kind` first).
const SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS: [&str; 8] = [
    "kind",
    "receipt_id",
    "secret_ref",
    "effector",
    "tier",
    "lease_id",
    "materialized_at",
    "value_generation",
];

fn encode_materialization_receipt_body(receipt: &SecretMaterializationReceipt) -> Result<Vec<u8>> {
    encode_map_body(vec![
        (
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[0],
            Value::from(SECRET_MATERIALIZATION_RECEIPT_KIND),
        ),
        (
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[1],
            Value::from(receipt.receipt_id.to_hex()),
        ),
        (
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[2],
            Value::from(receipt.secret_ref.as_str()),
        ),
        (
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[3],
            Value::from(receipt.effector.as_str()),
        ),
        (
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[4],
            Value::from(u64::from(receipt.tier.as_u8())),
        ),
        (
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[5],
            Value::from(receipt.lease_id.to_hex()),
        ),
        (
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[6],
            Value::from(receipt.materialized_at),
        ),
        (
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[7],
            Value::from(u64::from(receipt.value_generation)),
        ),
    ])
}

/// Decodes a materialization-receipt body. Test-only today: the row's
/// consumer surface (CSTDY-02/SECRET-04) lands on later stack layers and
/// can ungate this when it needs it.
#[cfg(test)]
fn decode_materialization_receipt_body(bytes: &[u8]) -> Result<SecretMaterializationReceipt> {
    let entries = decode_map_body(bytes, "materialization receipt body must be a map")?;
    let kind = string_at(
        &entries,
        SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[0],
        "receipt kind",
    )?;
    if kind != SECRET_MATERIALIZATION_RECEIPT_KIND {
        return Err(invalid_body("receipt kind"));
    }
    Ok(SecretMaterializationReceipt {
        receipt_id: entity_id_at(
            &entries,
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[1],
            "receipt receipt_id",
        )?,
        secret_ref: string_at(
            &entries,
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[2],
            "receipt secret_ref",
        )?,
        effector: string_at(
            &entries,
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[3],
            "receipt effector",
        )?,
        tier: tier_at(
            &entries,
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[4],
            "receipt tier",
        )?,
        lease_id: entity_id_at(
            &entries,
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[5],
            "receipt lease_id",
        )?,
        materialized_at: u64_at(
            &entries,
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[6],
            "receipt materialized_at",
        )?,
        value_generation: u32::try_from(u64_at(
            &entries,
            SECRET_MATERIALIZATION_RECEIPT_BODY_KEYS[7],
            "receipt value_generation",
        )?)
        .map_err(|_| invalid_body("receipt value_generation"))?,
    })
}

/// The local-registration body's MessagePack keys. `removal_error` and
/// `removal_attempted_at` are the teardown record: both `Nil` while the
/// registration is live.
const SECRET_LOCAL_REGISTRATION_BODY_KEYS: [&str; 6] = [
    "lease_id",
    "path",
    "content_hash",
    "project_id",
    "removal_error",
    "removal_attempted_at",
];

fn encode_local_registration_body(stored: &StoredLocalRegistration) -> Result<Vec<u8>> {
    let registration = &stored.registration;
    encode_map_body(vec![
        (
            SECRET_LOCAL_REGISTRATION_BODY_KEYS[0],
            Value::from(registration.lease_id.to_hex()),
        ),
        (
            SECRET_LOCAL_REGISTRATION_BODY_KEYS[1],
            Value::from(registration.path.to_string_lossy().as_ref()),
        ),
        (
            SECRET_LOCAL_REGISTRATION_BODY_KEYS[2],
            Value::Binary(registration.content_hash.to_vec()),
        ),
        (
            SECRET_LOCAL_REGISTRATION_BODY_KEYS[3],
            Value::from(registration.project_id.as_str()),
        ),
        (
            SECRET_LOCAL_REGISTRATION_BODY_KEYS[4],
            match &stored.removal_error {
                Some(error) => Value::from(error.as_str()),
                None => Value::Nil,
            },
        ),
        (
            SECRET_LOCAL_REGISTRATION_BODY_KEYS[5],
            match stored.removal_attempted_at {
                Some(at) => Value::from(at),
                None => Value::Nil,
            },
        ),
    ])
}

/// Decodes a local-registration body. `pub(crate)` so SECRET-03
/// (ONE-1921) assembles its exclusion set from these rows without a codec
/// fork.
pub(crate) fn decode_local_registration_body(bytes: &[u8]) -> Result<StoredLocalRegistration> {
    let entries = decode_map_body(bytes, "secret local registration body must be a map")?;
    let content_hash: [u8; 32] =
        match required_value(&entries, SECRET_LOCAL_REGISTRATION_BODY_KEYS[2]) {
            Some(Value::Binary(bytes)) => bytes
                .as_slice()
                .try_into()
                .map_err(|_| invalid_body("registration content_hash"))?,
            _ => return Err(invalid_body("registration content_hash")),
        };
    let removal_error = match required_value(&entries, SECRET_LOCAL_REGISTRATION_BODY_KEYS[4]) {
        Some(Value::Nil) | None => None,
        Some(value) => Some(
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(invalid_body("registration removal_error"))?,
        ),
    };
    let removal_attempted_at =
        match required_value(&entries, SECRET_LOCAL_REGISTRATION_BODY_KEYS[5]) {
            Some(Value::Nil) | None => None,
            Some(value) => Some(as_u64(value).ok_or(invalid_body("registration removal_at"))?),
        };
    Ok(StoredLocalRegistration {
        registration: LocalRegistration {
            lease_id: entity_id_at(
                &entries,
                SECRET_LOCAL_REGISTRATION_BODY_KEYS[0],
                "registration lease_id",
            )?,
            path: PathBuf::from(string_at(
                &entries,
                SECRET_LOCAL_REGISTRATION_BODY_KEYS[1],
                "registration path",
            )?),
            content_hash,
            project_id: string_at(
                &entries,
                SECRET_LOCAL_REGISTRATION_BODY_KEYS[3],
                "registration project_id",
            )?,
        },
        removal_error,
        removal_attempted_at,
    })
}

// ---------------------------------------------------------------------------
// Row IO
// ---------------------------------------------------------------------------

fn read_secret_lease_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    lease_id: &EntityId,
) -> Result<Option<SecretLease>> {
    let Some(raw) = store.vault_meta.get(txn, &lease_key(lease_id))? else {
        return Ok(None);
    };
    decode_secret_lease_body(&raw).map(Some)
}

fn write_secret_lease_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    lease: &SecretLease,
) -> Result<()> {
    let body = encode_secret_lease_body(lease)?;
    store
        .vault_meta
        .put(wtxn, &lease_key(&lease.lease_id), &body)?;
    Ok(())
}

/// Writes the materialization receipt row. S3: this lands durable BEFORE
/// the value returns from [`Vault::materialize_secret_lease`]; the
/// `#[cfg(test)]` fault hook fails the write so the done-means matrix can
/// prove no lease row and no value escape a failed receipt.
fn write_materialization_receipt_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    receipt: &SecretMaterializationReceipt,
) -> Result<()> {
    #[cfg(test)]
    if receipt_fault_hook::take_receipt_write_failure() {
        return Err(Error::SecretLeaseReceiptWriteFailed(
            "injected receipt-write failure",
        ));
    }
    let body = encode_materialization_receipt_body(receipt)?;
    store
        .vault_meta
        .put(wtxn, &receipt_key(&receipt.receipt_id), &body)?;
    Ok(())
}

fn read_local_registration_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    lease_id: &EntityId,
) -> Result<Option<StoredLocalRegistration>> {
    let Some(raw) = store.vault_meta.get(txn, &registration_key(lease_id))? else {
        return Ok(None);
    };
    decode_local_registration_body(&raw).map(Some)
}

/// Writes the local-registration row. The `#[cfg(test)]` fault hook fails
/// the write so the T2 file guard can prove a post-write error removes the
/// file this attempt created fresh (SOL-1920-03).
fn write_local_registration_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    stored: &StoredLocalRegistration,
) -> Result<()> {
    #[cfg(test)]
    if registration_fault_hook::take_registration_write_failure() {
        return Err(std::io::Error::other("injected registration-write failure").into());
    }
    let body = encode_local_registration_body(stored)?;
    store.vault_meta.put(
        wtxn,
        &registration_key(&stored.registration.lease_id),
        &body,
    )?;
    Ok(())
}

/// T2 teardown, shared by revoke and both expiry paths: removes the
/// registered file best-effort and records the outcome. The registration
/// row is DELETED only when the file is verifiably gone (removed, or
/// already absent); a failed removal retains the row with the error and
/// the attempt time recorded, so the path stays in SECRET-03's exclusion
/// set for as long as the file may still hold the value.
fn teardown_local_registration_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    lease_id: &EntityId,
    at: u64,
) -> Result<()> {
    let Some(stored) = read_local_registration_in_txn(store, wtxn, lease_id)? else {
        return Ok(());
    };
    let file_gone = match fs::remove_file(&stored.registration.path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => {
            write_local_registration_in_txn(
                store,
                wtxn,
                &StoredLocalRegistration {
                    registration: stored.registration,
                    removal_error: Some(error.to_string()),
                    removal_attempted_at: Some(at),
                },
            )?;
            false
        }
    };
    if file_gone {
        store.vault_meta.delete(wtxn, &registration_key(lease_id))?;
    }
    Ok(())
}

/// Loads a lease for use: unknown id ⇒ [`Error::SecretLeaseNotFound`];
/// a past-due `Active` lease is expired in place (lazy expiry, its T2 file
/// torn down with it) and any non-`Active` status denies with
/// [`Error::SecretLeaseNotActive`]. A lease is expired from `expires_at`
/// on: `now >= expires_at`.
fn read_live_lease_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    lease_id: &EntityId,
    now: u64,
) -> Result<SecretLease> {
    let Some(mut lease) = read_secret_lease_in_txn(store, wtxn, lease_id)? else {
        return Err(Error::SecretLeaseNotFound {
            lease_id: *lease_id,
        });
    };
    if lease.status == SecretLeaseStatus::Active && now >= lease.expires_at {
        lease.status = SecretLeaseStatus::Expired;
        write_secret_lease_in_txn(store, wtxn, &lease)?;
        teardown_local_registration_in_txn(store, wtxn, lease_id, now)?;
    }
    if lease.status != SecretLeaseStatus::Active {
        return Err(Error::SecretLeaseNotActive {
            lease_id: lease.lease_id,
            status: lease.status,
        });
    }
    Ok(lease)
}

/// Resolves a live secret name to its admission projection inside an
/// existing txn, for doors that already hold one. The projection is the
/// value-less read (SOL-1920-04): admission never materializes the value;
/// the ONE plaintext decode is the bound value door's own read.
fn read_record_for_ref_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    secret_ref: &str,
) -> Result<(EntityId, SecretCustodyAdmission)> {
    let id = resolve_secret_ref_in_txn(store, txn, secret_ref)?.ok_or_else(|| {
        Error::SecretRefNotFound {
            name: secret_ref.to_owned(),
        }
    })?;
    let rec = read_secret_custody_admission_in_txn(store, txn, &id)?
        .ok_or(Error::CorruptedIndex("secret custody record for live name"))?;
    Ok((id, rec))
}

/// Reads the value bytes through the ONE bound value door (ONE-1919), for
/// a record already admitted at `requested` tier.
fn read_value_for_ref_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    id: &EntityId,
    effector: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let value = vault
        .get_secret_value_in_txn(txn, id, effector)?
        .ok_or(Error::CorruptedIndex("secret custody value for live name"))?;
    Ok(Zeroizing::new(value))
}

// ---------------------------------------------------------------------------
// T2 file lifecycle (SOL-1920-03)
// ---------------------------------------------------------------------------

/// The T2 file policy, checked BEFORE any byte lands: the declared target
/// and its existing ancestors are never followed through a symlink, and the
/// vault never clobbers an occupant it did not create under this lease. A
/// regular file already at the target is touched only under `replace` —
/// same-path re-materialization, where this lease's live registration row
/// already covers exactly this path. Anything else denies typed
/// ([`Error::SecretLeasePathRefused`]). Ancestors are checked at policy time;
/// an ancestor swap between this check and open is the same race class as the
/// documented leaf check-to-open race. Race-free traversal needs openat2 or
/// dirfd handling and is intentionally out of scope here.
fn check_secret_file_policy(target_path: &Path, replace: bool) -> Result<()> {
    for ancestor in target_path.ancestors().skip(1) {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::SecretLeasePathRefused {
                    path: ancestor.display().to_string(),
                    reason: "ancestor is a symlink (the vault never follows)",
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }

    let metadata = match fs::symlink_metadata(target_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(Error::SecretLeasePathRefused {
            path: target_path.display().to_string(),
            reason: "target is a symlink (the vault never follows)",
        });
    }
    if !file_type.is_file() {
        return Err(Error::SecretLeasePathRefused {
            path: target_path.display().to_string(),
            reason: "target exists and is not a regular file",
        });
    }
    if !replace {
        return Err(Error::SecretLeasePathRefused {
            path: target_path.display().to_string(),
            reason: "target file exists with no live registration under this lease",
        });
    }
    Ok(())
}

/// The cleanup guard for a T2 file written by THIS registration attempt.
/// Armed at creation; [`SecretFileGuard::disarm`] runs only after the
/// registration commits durable. A drop while armed removes the file ONLY
/// when `fresh` — created by this attempt under a lease with no durable
/// registration for the path, so a failed row write, lease write, or
/// commit never strands plaintext no row can clean. A same-path replace is
/// never the guard's to remove: the live registration row still covers the
/// file, so a failure leaves it (and SECRET-03's exclusion) in place.
#[derive(Debug)]
struct SecretFileGuard {
    path: PathBuf,
    fresh: bool,
    armed: bool,
}

impl SecretFileGuard {
    fn new(path: &Path, fresh: bool) -> Self {
        Self {
            path: path.to_path_buf(),
            fresh,
            armed: true,
        }
    }

    /// The registration committed durable: the row owns the file now.
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for SecretFileGuard {
    fn drop(&mut self) {
        if self.armed && self.fresh {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Writes the value file for a T2 registration under
/// [`check_secret_file_policy`] and returns its armed guard. Owner-only
/// permissions BEFORE the first byte: creation carries `mode(0o600)` (the
/// umask can only narrow), and a replace re-asserts the mode through the
/// open handle (fchmod — no path race) ahead of the new bytes. The file
/// holds plaintext and the vault's at-rest DEK plane does not extend to
/// the filesystem, so the declared path gets the tightest default the
/// platform gives us. `O_NOFOLLOW` underpins the policy check against a
/// check-to-open symlink swap.
#[cfg(unix)]
fn write_secret_file(target_path: &Path, value: &[u8], replace: bool) -> Result<SecretFileGuard> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    check_secret_file_policy(target_path, replace)?;
    let mut options = fs::OpenOptions::new();
    options
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    if replace {
        // Same-path re-materialization: truncate the file this lease's
        // registration covers, or recreate it when lost (S4 recovery).
        options.create(true).truncate(true);
    } else {
        // Fresh registration: create_new is the atomic no-clobber guard —
        // anything that appeared at the target after the policy check
        // fails the open instead of being overwritten.
        options.create_new(true);
    }
    let mut file = options.open(target_path)?;
    let guard = SecretFileGuard::new(target_path, !replace);
    if replace {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(test)]
    if file_write_fault_hook::take_file_write_failure() {
        return Err(std::io::Error::other("injected file-write failure").into());
    }
    file.write_all(value)?;
    file.flush()?;
    Ok(guard)
}

/// The non-unix fallback: the same policy and no-clobber create; the
/// platform gives no owner-only mode or no-follow open flag.
#[cfg(not(unix))]
fn write_secret_file(target_path: &Path, value: &[u8], replace: bool) -> Result<SecretFileGuard> {
    use std::io::Write;

    check_secret_file_policy(target_path, replace)?;
    let mut options = fs::OpenOptions::new();
    options.write(true);
    if replace {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options.open(target_path)?;
    let guard = SecretFileGuard::new(target_path, !replace);
    #[cfg(test)]
    if file_write_fault_hook::take_file_write_failure() {
        return Err(std::io::Error::other("injected file-write failure").into());
    }
    file.write_all(value)?;
    file.flush()?;
    Ok(guard)
}

// ---------------------------------------------------------------------------
// Vault doors
// ---------------------------------------------------------------------------

impl Vault {
    /// T0 door injection. Resolves `secret_ref`, admits `T0Doored` under
    /// the one admission rule, and runs `apply` INSIDE the door with the
    /// value. `apply` returns only `()`: the value cannot come back through
    /// the closure's return type, and the workspace receives only the
    /// [`DoorInjectionReceipt`]. The receipt carries no value bytes; the
    /// value is wrapped in [`Zeroizing`] for the door's own lifetime and
    /// scrubbed on drop.
    ///
    /// The door receipt is the return token only — the door CALLER
    /// (CSTDY-02's outbound path) stamps the durable egress receipt for its
    /// own send, and SECRET-04 attaches exhaust taint from
    /// [`DoorInjectionReceipt::taint_token`].
    pub fn inject_secret_at_door(
        &self,
        secret_ref: &str,
        effector: &str,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<DoorInjectionReceipt> {
        let wtxn = self.store.env.write_txn()?;
        let (id, rec) = read_record_for_ref_in_txn(&self.store, &wtxn, secret_ref)?;
        let floor = SecretCustodyFloor::resolve(&self.store, &wtxn)?;
        admit_record_use(&rec, effector, CustodyTier::T0Doored, &floor)?;
        let generation = rec.rotation_generation;
        let value = read_value_for_ref_in_txn(self, &wtxn, &id, effector)?;
        // The value bytes are owned; nothing was written. Release the write
        // txn BEFORE running caller code — caller closures never execute
        // inside an LMDB write txn.
        drop(wtxn);
        apply(&value)?;
        Ok(DoorInjectionReceipt {
            secret_ref: secret_ref.to_owned(),
            effector: effector.to_owned(),
            injected_at: unix_seconds_now(),
            value_generation: generation,
            taint_token: vec![SecretTaintRef {
                secret_ref: secret_ref.to_owned(),
                generation,
            }],
        })
    }

    /// T1 lease materialization. Admits `T1Leased` under the one admission
    /// rule, then writes the [`SecretLease`] row and its
    /// [`SecretMaterializationReceipt`] durable BEFORE the value returns —
    /// receipt-at-materialization (S3). One write txn carries both rows, so
    /// a failed receipt write leaves no lease row and returns no value (the
    /// `#[cfg(test)]` fault hook proves it). Expiry is lazy: the lease is
    /// expired from `expires_at` on, checked at use and by
    /// [`Vault::expire_secret_leases`].
    pub fn materialize_secret_lease(
        &self,
        secret_ref: &str,
        effector: &str,
        ttl_secs: u64,
    ) -> Result<SecretLeaseMaterialization> {
        let mut wtxn = self.store.env.write_txn()?;
        let (id, rec) = read_record_for_ref_in_txn(&self.store, &wtxn, secret_ref)?;
        let floor = SecretCustodyFloor::resolve(&self.store, &wtxn)?;
        admit_record_use(&rec, effector, CustodyTier::T1Leased, &floor)?;
        let value = read_value_for_ref_in_txn(self, &wtxn, &id, effector)?;
        let now = unix_seconds_now();
        let lease = SecretLease {
            lease_id: EntityId::now(),
            secret_ref: secret_ref.to_owned(),
            binding_effector: effector.to_owned(),
            tier: CustodyTier::T1Leased,
            granted_at: now,
            expires_at: now.saturating_add(ttl_secs),
            status: SecretLeaseStatus::Active,
            materialization_receipt: EntityId::now(),
            value_generation: rec.rotation_generation,
        };
        let receipt = SecretMaterializationReceipt {
            receipt_id: lease.materialization_receipt,
            secret_ref: lease.secret_ref.clone(),
            effector: lease.binding_effector.clone(),
            tier: lease.tier,
            lease_id: lease.lease_id,
            materialized_at: now,
            value_generation: lease.value_generation,
        };
        write_materialization_receipt_in_txn(&self.store, &mut wtxn, &receipt)?;
        write_secret_lease_in_txn(&self.store, &mut wtxn, &lease)?;
        wtxn.commit()?;
        Ok(SecretLeaseMaterialization { lease, value })
    }

    /// T2 local registration under a live lease. The lease must be `Active`
    /// (a past-due lease is expired in place and denies); the target must
    /// be a manifest-declared path of the record (exact, file-granularity —
    /// the same granularity SECRET-03 excludes at); and `T2LocalRegistered`
    /// must admit under the one admission rule, re-resolved against the
    /// LIVE floor at registration time. The value re-materializes from the
    /// vault on every call (S4 recovery), the file is written before any
    /// row persists, and the lease climbs to `T2LocalRegistered`.
    pub fn register_secret_local(
        &self,
        lease_id: &EntityId,
        target_path: &Path,
        project_id: &str,
    ) -> Result<LocalRegistration> {
        let mut wtxn = self.store.env.write_txn()?;
        let mut lease =
            match read_live_lease_in_txn(&self.store, &mut wtxn, lease_id, unix_seconds_now()) {
                Ok(lease) => lease,
                Err(error) => {
                    // A lazy-expiry flip (and its T2 teardown) lands durable
                    // even though the use denies: the vault's observed state
                    // converges instead of re-discovering the expiry forever.
                    wtxn.commit()?;
                    return Err(error);
                }
            };
        let (id, rec) = read_record_for_ref_in_txn(&self.store, &wtxn, &lease.secret_ref)?;
        let floor = SecretCustodyFloor::resolve(&self.store, &wtxn)?;
        admit_record_use(
            &rec,
            &lease.binding_effector,
            CustodyTier::T2LocalRegistered,
            &floor,
        )?;
        if !rec
            .declared_paths
            .iter()
            .any(|declared| Path::new(declared) == target_path)
        {
            return Err(Error::SecretLeasePathNotDeclared {
                secret_ref: rec.name,
                path: target_path.display().to_string(),
            });
        }
        // One registration row per lease (SOL-1920-02): a live registration
        // pins the lease to its path. A DIFFERENT declared path under the
        // same lease would overwrite the row and orphan the first plaintext
        // file beyond revoke/expiry — typed conflict; the caller mints a
        // fresh lease for a new path. Same-path re-materialization
        // (`replace`) is the S4 recovery flow and stays admitted.
        let replace = match read_local_registration_in_txn(&self.store, &wtxn, lease_id)? {
            Some(stored) if stored.registration.path.as_path() != target_path => {
                return Err(Error::SecretLeasePathConflict {
                    lease_id: lease.lease_id,
                    registered_path: stored.registration.path.display().to_string(),
                    requested_path: target_path.display().to_string(),
                });
            }
            Some(_) => true,
            None => false,
        };
        let value = read_value_for_ref_in_txn(self, &wtxn, &id, &lease.binding_effector)?;
        // The file write lands before any row persists, under the T2
        // file-lifecycle policy (no-follow, no-clobber, owner-only before
        // the first byte). The returned guard removes a file THIS attempt
        // created fresh if the row write, the lease write, or the commit
        // fails — nothing durable may point at a file the vault cannot
        // clean, and no plaintext may sit untracked. A same-path replace is
        // never the guard's to remove: the live row still covers it.
        let guard = write_secret_file(target_path, &value, replace)?;
        let registration = LocalRegistration {
            lease_id: lease.lease_id,
            path: target_path.to_path_buf(),
            content_hash: *blake3::hash(&value).as_bytes(),
            project_id: project_id.to_owned(),
        };
        write_local_registration_in_txn(
            &self.store,
            &mut wtxn,
            &StoredLocalRegistration {
                registration: registration.clone(),
                removal_error: None,
                removal_attempted_at: None,
            },
        )?;
        lease.tier = CustodyTier::T2LocalRegistered;
        write_secret_lease_in_txn(&self.store, &mut wtxn, &lease)?;
        // A failed commit drops the guard armed: a fresh file is removed,
        // a replaced file stays under its live row.
        wtxn.commit()?;
        guard.disarm();
        Ok(registration)
    }

    /// Tears a lease down: flips the status to `Revoked`, revokes
    /// door-side use, and — for T2 — removes the registered local file
    /// (best-effort, recorded; see [`teardown_local_registration_in_txn`]).
    /// Revoking an already-`Revoked` lease is a no-op returning the row.
    /// `at` is the caller's clock for the teardown record (ARCH-0026: the
    /// engine owns no timers). Caller-held process memory is out of reach
    /// by construction — the ratified lease-scoped contract.
    pub fn revoke_secret_lease(&self, lease_id: &EntityId, at: u64) -> Result<SecretLease> {
        let mut wtxn = self.store.env.write_txn()?;
        let Some(mut lease) = read_secret_lease_in_txn(&self.store, &wtxn, lease_id)? else {
            return Err(Error::SecretLeaseNotFound {
                lease_id: *lease_id,
            });
        };
        if lease.status != SecretLeaseStatus::Revoked {
            lease.status = SecretLeaseStatus::Revoked;
            write_secret_lease_in_txn(&self.store, &mut wtxn, &lease)?;
            teardown_local_registration_in_txn(&self.store, &mut wtxn, lease_id, at)?;
        }
        wtxn.commit()?;
        Ok(lease)
    }

    /// The maintenance sweep: expires every `Active` lease whose
    /// `expires_at` has passed (`now >= expires_at`), tearing down its T2
    /// file with it, and returns how many leases expired. Lazy expiry is
    /// also checked at use; this sweep is the convergence path. No timers —
    /// the caller drives the cadence (ARCH-0026).
    pub fn expire_secret_leases(&self, now: u64) -> Result<usize> {
        let mut wtxn = self.store.env.write_txn()?;
        let mut due = Vec::new();
        for entry in self
            .store
            .vault_meta
            .prefix_iter(&wtxn, SECRET_LEASE_KEY_PREFIX.as_bytes())?
        {
            let (_, raw) = entry?;
            let lease = decode_secret_lease_body(&raw)?;
            if lease.status == SecretLeaseStatus::Active && now >= lease.expires_at {
                due.push(lease);
            }
        }
        let mut expired = 0usize;
        for mut lease in due {
            lease.status = SecretLeaseStatus::Expired;
            write_secret_lease_in_txn(&self.store, &mut wtxn, &lease)?;
            teardown_local_registration_in_txn(&self.store, &mut wtxn, &lease.lease_id, now)?;
            expired += 1;
        }
        wtxn.commit()?;
        Ok(expired)
    }
}

#[cfg(test)]
pub(crate) mod receipt_fault_hook {
    //! One-shot test-only fault injection on the materialization-receipt
    //! write, proving the S3 ordering: a failed receipt write leaves no
    //! lease row and returns no value.

    use std::cell::Cell;

    thread_local! {
        // One-shot: armed by `arm_receipt_write_failure`, consumed by the
        // next receipt write on this thread (the mirror-failure hook idiom
        // from `sync::lease`).
        static RECEIPT_WRITE_FAILURE: Cell<bool> = const { Cell::new(false) };
    }

    /// Arms a one-shot receipt-write failure on the current thread.
    pub(crate) fn arm_receipt_write_failure() {
        RECEIPT_WRITE_FAILURE.with(|c| c.set(true));
    }

    /// Returns and clears the armed flag (one-shot).
    pub(crate) fn take_receipt_write_failure() -> bool {
        RECEIPT_WRITE_FAILURE.with(|c| c.replace(false))
    }
}

#[cfg(test)]
pub(crate) mod file_write_fault_hook {
    //! One-shot test-only fault injection after the T2 file opens, proving
    //! the guard is armed before a file write can fail.

    use std::cell::Cell;

    thread_local! {
        static FILE_WRITE_FAILURE: Cell<bool> = const { Cell::new(false) };
    }

    /// Arms a one-shot file-write failure on the current thread.
    pub(crate) fn arm_file_write_failure() {
        FILE_WRITE_FAILURE.with(|c| c.set(true));
    }

    /// Returns and clears the armed flag (one-shot).
    pub(crate) fn take_file_write_failure() -> bool {
        FILE_WRITE_FAILURE.with(|c| c.replace(false))
    }
}

#[cfg(test)]
pub(crate) mod registration_fault_hook {
    //! One-shot test-only fault injection on the local-registration write,
    //! proving the SOL-1920-03 file guard: a failed row write after the
    //! file lands removes the file the attempt created fresh.

    use std::cell::Cell;

    thread_local! {
        // One-shot, mirroring `receipt_fault_hook`.
        static REGISTRATION_WRITE_FAILURE: Cell<bool> = const { Cell::new(false) };
    }

    /// Arms a one-shot registration-write failure on the current thread.
    pub(crate) fn arm_registration_write_failure() {
        REGISTRATION_WRITE_FAILURE.with(|c| c.set(true));
    }

    /// Returns and clears the armed flag (one-shot).
    pub(crate) fn take_registration_write_failure() -> bool {
        REGISTRATION_WRITE_FAILURE.with(|c| c.replace(false))
    }
}

#[cfg(test)]
mod tests;
