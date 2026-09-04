//! SECRET-04 (ONE-1922): rotation as a first-class vault op, and READ-TIME
//! invalidation of secret-tainted build exhaust.
//!
//! Two halves of ARCH-0069, kept deliberately apart:
//!
//! **S6 — rotation is a vault update.** [`Vault::rotate_secret`] bumps the
//! record's `rotation_generation`, stamps `rotated_at`, and replaces the
//! value bytes inside ONE write transaction. The next lease materializes the
//! new value and doored uses rotate invisibly, because the value never lived
//! workspace-side to begin with. The caveat is stated, not hidden: rotation
//! kills NO live lease. An old lease keeps the `value_generation` it minted
//! at, so its staleness is OBSERVABLE (compare it against the record) rather
//! than silently repaired. Terminal value death is
//! [`Vault::revoke_secret`]'s job alone — that one does walk the leases.
//!
//! **S7 (amended 2026-08-05) — taint invalidation is READ-TIME.** A consumer
//! compares an artifact's STORED taint-ref generations against the custody
//! record's CURRENT `rotation_generation` at the publish and export checks.
//! Three negatives carry the design:
//!
//! * no stored taint STATE — [`ArtifactTaintState`] is derived on every read
//!   and never persisted, so there is no flag that can go stale;
//! * no reverse index from a secret to the artifacts it tainted — the only
//!   stored direction is FORWARD, artifact → refs, written at the action
//!   boundary in the same transaction as the exhaust it marks;
//! * no bulk flip at the moment of rotation — rotation writes the record and
//!   its receipt, nothing else.
//!
//! Nothing to invalidate means nothing to forget to invalidate. A rotation
//! that crashes halfway cannot leave half the exhaust wrongly reading clean,
//! because rotation never touched the exhaust at all.
//!
//! # Where taint refs are stored
//!
//! * blob artifacts carry them IN BODY under the pinned
//!   `secret_taint.refs` key ([`crate::blob_artifact::BLOB_ARTIFACT_BODY_KEYS`]),
//!   so the attach is the artifact put itself;
//! * code-run raw outputs carry them in a `vault_meta` SIDECAR row written in
//!   the same transaction as the raw-output row
//!   (`crate::code_run` owns that key);
//! * any other exhaust ENTITY (the code artifact a build leg produced, which
//!   is what an artifact pointer publishes) carries them in the entity-keyed
//!   sidecar row under [`SECRET_EXHAUST_TAINT_PREFIX`].
//!
//! All three are forward-only. None of them is an index a rotation could
//! walk, and that is the point.
//!
//! # What never crosses this module
//!
//! No value bytes. [`RotationReceipt`] carries a ref, two generations, a
//! timestamp and a kind; [`crate::secret_lease::SecretTaintRef`] carries a
//! ref and a generation. Neither has a value field to leak, and the
//! grep-guard test asserts it of their `Debug` and their wire bodies.

use std::sync::atomic::Ordering;

use rmpv::Value;

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::blob_artifact::decode_blob_artifact_body;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_SECRET_CUSTODY};
use crate::secret_custody::{
    SecretCustodyFloor, SecretCustodyStatus, encode_secret_custody_body,
    policy_manifest_bodies_strict, read_secret_custody_admission_in_txn,
    read_secret_custody_in_txn, resolve_secret_ref_in_txn,
};
use crate::secret_lease::{
    SECRET_LEASE_KEY_PREFIX, SecretLeaseStatus, SecretTaintRef, decode_secret_lease_body,
    teardown_local_registration_in_txn, write_secret_lease_in_txn,
};
use crate::store::Store;
use crate::temporal::TimeRange;

// ---------------------------------------------------------------------------
// Row keys and policy keys
// ---------------------------------------------------------------------------

/// The `vault_meta` prefix for a durable [`RotationReceipt`] row, keyed by
/// the receipt's own [`EntityId`].
pub const SECRET_ROTATION_RECEIPT_PREFIX: &str = "secret_rotation_receipt:v1:";

/// The `vault_meta` prefix for the FORWARD taint-ref sidecar of one exhaust
/// entity, keyed by that entity's [`EntityId`].
///
/// Forward only: `artifact -> refs`. There is deliberately no row anywhere
/// in this crate keyed by a SECRET that lists the artifacts it tainted — the
/// 2026-08-05 amendment forbids exactly that reverse index, and the
/// regression suite asserts its absence.
pub const SECRET_EXHAUST_TAINT_PREFIX: &str = "secret_exhaust_taint:v1:";

/// The POLICY_MANIFEST key that opens the stale-publish dial. Absent or
/// unreadable-as-`true` means CLOSED: a publish gate defaults to refusing.
pub const POLICY_TAINT_ALLOW_STALE_PUBLISH_KEY: &str = "secret.taint.allow_stale_publish";

/// Upper bound on a stored taint ref's secret name, mirroring the bounded
/// text discipline the artifact bodies already keep.
pub const SECRET_TAINT_REF_MAX_BYTES: usize = 512;

/// Upper bound on how many refs one piece of exhaust may carry. An action
/// boundary that consumed more secrets than this is not a taint problem.
pub const SECRET_TAINT_REFS_MAX: usize = 64;

fn invalid_body(reason: &'static str) -> Error {
    Error::InvalidSecretRotationBody(reason)
}

fn receipt_key(receipt_id: &EntityId) -> Vec<u8> {
    format!("{SECRET_ROTATION_RECEIPT_PREFIX}{}", receipt_id.to_hex()).into_bytes()
}

fn exhaust_taint_key(id: &EntityId) -> Vec<u8> {
    format!("{SECRET_EXHAUST_TAINT_PREFIX}{}", id.to_hex()).into_bytes()
}

// ---------------------------------------------------------------------------
// The receipt
// ---------------------------------------------------------------------------

/// Which vault op minted a [`RotationReceipt`].
///
/// A revoke and a rotation both stamp a receipt, and without this they would
/// be indistinguishable on the wire: a revoke's `from_generation` and
/// `to_generation` are equal (the value is not replaced, it DIES), which is
/// also what a hypothetical no-op rotation would look like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RotationKind {
    /// The value was replaced; the generation advanced by one.
    Rotated,
    /// The record went terminal and every lease over it was revoked.
    Revoked,
}

impl RotationKind {
    /// The wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rotated => "rotated",
            Self::Revoked => "revoked",
        }
    }

    /// Parses the wire string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "rotated" => Some(Self::Rotated),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// The durable attestation of one rotation or revoke (`vault_meta` under
/// [`SECRET_ROTATION_RECEIPT_PREFIX`]).
///
/// Carries no value bytes BY CONSTRUCTION — there is no field for them, so
/// neither the derived `Debug` nor the body codec below can leak one. That
/// is the S1 discipline restated at this plane: a receipt attests that a
/// value changed, never what it changed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationReceipt {
    /// The receipt identifier (the row's key).
    pub receipt_id: EntityId,
    /// The secret name that rotated or was revoked.
    pub secret_ref: String,
    /// The record's `rotation_generation` BEFORE the op.
    pub from_generation: u32,
    /// The record's `rotation_generation` AFTER the op (equal to
    /// `from_generation` for a revoke).
    pub to_generation: u32,
    /// Unix seconds the op was stamped at (the caller's clock — ARCH-0026:
    /// the engine owns no timers).
    pub rotated_at: u64,
    /// Which op minted this receipt.
    pub kind: RotationKind,
}

const ROTATION_RECEIPT_BODY_KEYS: [&str; 5] = [
    "secret_ref",
    "from_generation",
    "to_generation",
    "rotated_at",
    "kind",
];

fn encode_rotation_receipt_body(receipt: &RotationReceipt) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::from(ROTATION_RECEIPT_BODY_KEYS[0]),
            Value::from(receipt.secret_ref.as_str()),
        ),
        (
            Value::from(ROTATION_RECEIPT_BODY_KEYS[1]),
            Value::from(u64::from(receipt.from_generation)),
        ),
        (
            Value::from(ROTATION_RECEIPT_BODY_KEYS[2]),
            Value::from(u64::from(receipt.to_generation)),
        ),
        (
            Value::from(ROTATION_RECEIPT_BODY_KEYS[3]),
            Value::from(receipt.rotated_at),
        ),
        (
            Value::from(ROTATION_RECEIPT_BODY_KEYS[4]),
            Value::from(receipt.kind.as_str()),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| invalid_body("encode rotation receipt body"))?;
    Ok(out)
}

fn decode_rotation_receipt_body(receipt_id: EntityId, bytes: &[u8]) -> Result<RotationReceipt> {
    let entries = decode_map_body(bytes, "decode rotation receipt body")?;
    Ok(RotationReceipt {
        receipt_id,
        secret_ref: string_at(
            &entries,
            ROTATION_RECEIPT_BODY_KEYS[0],
            "receipt secret_ref",
        )?,
        from_generation: u32_at(
            &entries,
            ROTATION_RECEIPT_BODY_KEYS[1],
            "receipt from_generation",
        )?,
        to_generation: u32_at(
            &entries,
            ROTATION_RECEIPT_BODY_KEYS[2],
            "receipt to_generation",
        )?,
        rotated_at: u64_at(
            &entries,
            ROTATION_RECEIPT_BODY_KEYS[3],
            "receipt rotated_at",
        )?,
        kind: RotationKind::parse(&string_at(
            &entries,
            ROTATION_RECEIPT_BODY_KEYS[4],
            "receipt kind",
        )?)
        .ok_or(invalid_body("receipt kind"))?,
    })
}

// ---------------------------------------------------------------------------
// Small MessagePack helpers (the secret_custody.rs / secret_lease.rs idiom:
// a MISSING or DUPLICATED key both refuse; an ambiguous body is never
// defaulted)
// ---------------------------------------------------------------------------

fn decode_map_body(bytes: &[u8], reason: &'static str) -> Result<Vec<(Value, Value)>> {
    use std::io::Cursor;

    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_body(reason))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_body(reason));
    }
    let Value::Map(entries) = value else {
        return Err(invalid_body(reason));
    };
    Ok(entries)
}

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
    } else {
        u64::try_from(value.as_i64()?).ok()
    }
}

fn string_at(entries: &[(Value, Value)], key: &str, reason: &'static str) -> Result<String> {
    required_value(entries, key)
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or(invalid_body(reason))
}

fn u64_at(entries: &[(Value, Value)], key: &str, reason: &'static str) -> Result<u64> {
    required_value(entries, key)
        .and_then(as_u64)
        .ok_or(invalid_body(reason))
}

fn u32_at(entries: &[(Value, Value)], key: &str, reason: &'static str) -> Result<u32> {
    u32::try_from(u64_at(entries, key, reason)?).map_err(|_| invalid_body(reason))
}

// ---------------------------------------------------------------------------
// Taint-ref codec — shared with the blob-artifact body key
// ---------------------------------------------------------------------------

const TAINT_REF_KEYS: [&str; 2] = ["secret_ref", "generation"];

/// Encodes taint refs as the canonical MessagePack array-of-maps that both
/// the sidecar rows and the `secret_taint.refs` artifact body key carry.
///
/// ONE shape for both storage planes on purpose: a consumer that learns to
/// read a taint ref has learned to read every taint ref this crate writes.
#[must_use]
pub(crate) fn taint_refs_to_value(refs: &[SecretTaintRef]) -> Value {
    Value::Array(
        refs.iter()
            .map(|r| {
                Value::Map(vec![
                    (
                        Value::from(TAINT_REF_KEYS[0]),
                        Value::from(r.secret_ref.as_str()),
                    ),
                    (
                        Value::from(TAINT_REF_KEYS[1]),
                        Value::from(u64::from(r.generation)),
                    ),
                ])
            })
            .collect(),
    )
}

/// Decodes and VALIDATES taint refs from the canonical shape.
///
/// Returns `None` on any malformation so each call site can raise its own
/// typed body reject (the artifact body says
/// [`Error::InvalidBlobArtifactBody`], a sidecar row says
/// [`Error::InvalidSecretRotationBody`]) instead of importing a foreign
/// error class. Validation is strict: bounded non-empty names, `u32`
/// generations, a bounded ref count, and no duplicate secret names — a
/// duplicated name would let one body assert two different generations for
/// one secret, which has no honest read.
#[must_use]
pub(crate) fn taint_refs_from_value(value: &Value) -> Option<Vec<SecretTaintRef>> {
    let Value::Array(items) = value else {
        return None;
    };
    if items.len() > SECRET_TAINT_REFS_MAX {
        return None;
    }
    let mut refs: Vec<SecretTaintRef> = Vec::with_capacity(items.len());
    for item in items {
        let Value::Map(entries) = item else {
            return None;
        };
        let secret_ref = required_value(entries, TAINT_REF_KEYS[0])?.as_str()?;
        if secret_ref.is_empty() || secret_ref.len() > SECRET_TAINT_REF_MAX_BYTES {
            return None;
        }
        let generation =
            u32::try_from(as_u64(required_value(entries, TAINT_REF_KEYS[1])?)?).ok()?;
        if refs.iter().any(|r| r.secret_ref == secret_ref) {
            return None;
        }
        refs.push(SecretTaintRef {
            secret_ref: secret_ref.to_owned(),
            generation,
        });
    }
    Some(refs)
}

/// The same validation applied to refs a CALLER hands in, before they reach
/// a durable row. Attaching a malformed ref would mint exhaust nobody can
/// derive a state for.
pub(crate) fn validate_taint_refs(refs: &[SecretTaintRef]) -> Result<()> {
    if refs.len() > SECRET_TAINT_REFS_MAX {
        return Err(invalid_body("too many taint refs for one piece of exhaust"));
    }
    for (index, r) in refs.iter().enumerate() {
        if r.secret_ref.is_empty() || r.secret_ref.len() > SECRET_TAINT_REF_MAX_BYTES {
            return Err(invalid_body(
                "taint ref secret_ref must be non-empty and at most 512 bytes",
            ));
        }
        if refs[..index]
            .iter()
            .any(|prev| prev.secret_ref == r.secret_ref)
        {
            return Err(invalid_body("duplicate secret_ref in taint refs"));
        }
    }
    Ok(())
}

pub(crate) fn encode_taint_refs_row(refs: &[SecretTaintRef]) -> Result<Vec<u8>> {
    validate_taint_refs(refs)?;
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &taint_refs_to_value(refs))
        .map_err(|_| invalid_body("encode taint refs row"))?;
    Ok(out)
}

pub(crate) fn decode_taint_refs_row(bytes: &[u8]) -> Result<Vec<SecretTaintRef>> {
    use std::io::Cursor;

    let mut cursor = Cursor::new(bytes);
    let value =
        rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_body("decode taint refs row"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_body("trailing bytes after taint refs row"));
    }
    taint_refs_from_value(&value).ok_or(invalid_body("taint refs row"))
}

// ---------------------------------------------------------------------------
// The derived state (S7 amendment: derived, never stored)
// ---------------------------------------------------------------------------

/// The READ-TIME classification of one piece of build exhaust.
///
/// Derived on every read from the exhaust's stored refs and the custody
/// records' CURRENT generations. Deliberately NOT persisted anywhere: a
/// stored state would need a bulk flip at rotation to stay honest, and the
/// bulk flip is precisely what the 2026-08-05 amendment removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactTaintState {
    /// No secret was consumed producing this exhaust (no stored refs).
    Clean,
    /// Every referenced record is `Active` and still sits at the generation
    /// the exhaust was produced under. The exhaust reflects LIVE values.
    TaintedLive,
    /// At least one referenced record moved: rotated to another generation,
    /// revoked, or gone. The value that justified the taint no longer
    /// exists, so the exhaust is stale evidence of a dead secret.
    TaintedStale,
}

impl ArtifactTaintState {
    /// Whether any secret was consumed producing this exhaust.
    #[must_use]
    pub const fn is_tainted(self) -> bool {
        !matches!(self, Self::Clean)
    }
}

/// Derives the state of `refs` against the LIVE records, inside a txn the
/// caller owns.
///
/// Fail-closed in every uncertain direction: a missing record, a
/// non-`Active` record, and ANY generation disagreement (not merely a
/// higher one — a stored generation ahead of the record is corruption, and
/// corruption must not read live) all classify `TaintedStale`.
///
/// Reads the value-less admission projection, never the full record: a
/// taint check has no business materializing plaintext.
pub(crate) fn taint_state_for_refs_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    refs: &[SecretTaintRef],
) -> Result<ArtifactTaintState> {
    if refs.is_empty() {
        return Ok(ArtifactTaintState::Clean);
    }
    for r in refs {
        let Some(id) = resolve_secret_ref_in_txn(store, txn, &r.secret_ref)? else {
            return Ok(ArtifactTaintState::TaintedStale);
        };
        let Some(rec) = read_secret_custody_admission_in_txn(store, txn, &id)? else {
            return Ok(ArtifactTaintState::TaintedStale);
        };
        if rec.status != SecretCustodyStatus::Active || rec.rotation_generation != r.generation {
            return Ok(ArtifactTaintState::TaintedStale);
        }
    }
    Ok(ArtifactTaintState::TaintedLive)
}

/// Reads the FORWARD taint refs of one exhaust entity inside a txn.
///
/// The union of the two forward planes an entity can carry them on: the
/// entity-keyed sidecar row, and — when the entity is a BLOB_ARTIFACT — the
/// pinned `secret_taint.refs` body key. Union, not precedence: both are
/// action-boundary attachments, and dropping either would under-report
/// taint. A secret named by both keeps its LOWEST recorded generation,
/// which is the fail-closed direction (the older generation is the one more
/// likely to have been rotated away from).
pub(crate) fn exhaust_taint_refs_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<SecretTaintRef>> {
    let mut refs = match store.vault_meta.get(txn, &exhaust_taint_key(id))? {
        Some(raw) => decode_taint_refs_row(&raw)?,
        None => Vec::new(),
    };
    if let Some(raw) = store.entities.get(txn, id.as_bytes())?
        && let Some(header) = EntityMetadataHeader::parse(&raw)
        && header.entity_type == ENTITY_TYPE_BLOB_ARTIFACT
    {
        let body = decode_blob_artifact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        for r in body.secret_taint_refs {
            match refs.iter_mut().find(|held| held.secret_ref == r.secret_ref) {
                Some(held) => held.generation = held.generation.min(r.generation),
                None => refs.push(r),
            }
        }
    }
    refs.sort_by(|a, b| a.secret_ref.cmp(&b.secret_ref));
    Ok(refs)
}

/// Writes the forward taint sidecar for one exhaust entity, inside a
/// transaction the CALLER owns.
///
/// Caller-owned on purpose: this is the S7 same-transaction law. The attach
/// must land with the exhaust row it marks, or neither lands — untainted
/// exhaust surviving a half-failed write is the one failure direction that
/// matters here. An EMPTY ref list clears the row rather than writing an
/// empty one, so "clean" has exactly one representation (absent).
pub(crate) fn mark_exhaust_tainted_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    refs: &[SecretTaintRef],
) -> Result<()> {
    let key = exhaust_taint_key(id);
    if refs.is_empty() {
        store.vault_meta.delete(wtxn, &key)?;
        return Ok(());
    }
    let body = encode_taint_refs_row(refs)?;
    store.vault_meta.put(wtxn, &key, &body)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The stale-publish dial
// ---------------------------------------------------------------------------

/// Resolves [`POLICY_TAINT_ALLOW_STALE_PUBLISH_KEY`] across every
/// POLICY_MANIFEST body, inside a txn the caller owns.
///
/// Follows ONE-1919's floor resolver exactly: the shared strict walk (so a
/// broken indexed declaration REFUSES rather than silently defaulting), an
/// absent key means the default, and a present-but-unreadable key is an
/// error. The default is `false` — a dial that fails open is not a dial.
///
/// Any pack declaring `true` opens it. That is the correct direction for
/// this key specifically: unlike a custody FLOOR (which may only ever
/// narrow), this is an explicit operator override, and an operator who
/// declared it should not have it silently cancelled by a pack that is
/// merely silent on the subject.
pub(crate) fn allow_stale_publish_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<bool> {
    let mut allowed = false;
    for entries in policy_manifest_bodies_strict(store, txn)
        .map_err(|_| Error::CorruptedIndex("policy manifest walk for stale-publish dial"))?
    {
        let mut seen = None;
        for (k, v) in &entries {
            if k.as_str() == Some(POLICY_TAINT_ALLOW_STALE_PUBLISH_KEY) {
                if seen.is_some() {
                    return Err(invalid_body(
                        "duplicate secret.taint.allow_stale_publish in one policy manifest",
                    ));
                }
                seen = Some(v.as_bool().ok_or(invalid_body(
                    "secret.taint.allow_stale_publish must be a boolean",
                ))?);
            }
        }
        allowed |= seen.unwrap_or(false);
    }
    Ok(allowed)
}

// ---------------------------------------------------------------------------
// Vault doors
// ---------------------------------------------------------------------------

impl Vault {
    /// Rotates a secret: the vault-side value update of ARCH-0069 S6.
    ///
    /// ONE write transaction advances `rotation_generation` by one, stamps
    /// `rotated_at`, replaces the value bytes in the custody body, and
    /// writes the [`RotationReceipt`] row. The record must be `Active`
    /// ([`Error::SecretCustodyNotActive`] otherwise) and its bindings must
    /// still fit the LIVE custody floor — a floor narrowed since
    /// registration refuses to re-bless a wider binding through a rotation
    /// ([`Error::ManifestWidensFloor`]), the same narrow-only rule
    /// registration enforces.
    ///
    /// What this deliberately does NOT do:
    ///
    /// * it does not kill or renew a single lease. A lease minted before
    ///   this call keeps its `value_generation` and keeps working until it
    ///   expires — the honest lease-scoped caveat, made observable by
    ///   comparing that field against the record's current generation
    ///   rather than papered over;
    /// * it does not touch one byte of build exhaust. Taint invalidation is
    ///   READ-TIME; the artifacts re-derive `TaintedStale` on their next
    ///   check purely because this generation moved.
    ///
    /// `at` is the caller's clock (ARCH-0026: the engine owns no timers).
    pub fn rotate_secret(
        &self,
        secret_ref: &str,
        new_value: &[u8],
        at: u64,
    ) -> Result<RotationReceipt> {
        let mut wtxn = self.store.env.write_txn()?;
        let id = resolve_secret_ref_in_txn(&self.store, &wtxn, secret_ref)?.ok_or_else(|| {
            Error::SecretRefNotFound {
                name: secret_ref.to_owned(),
            }
        })?;
        let mut rec = read_secret_custody_in_txn(&self.store, &wtxn, &id)?
            .ok_or(Error::CorruptedIndex("secret custody record for live name"))?;
        if rec.status != SecretCustodyStatus::Active {
            return Err(Error::SecretCustodyNotActive { name: rec.name });
        }

        // Narrow-only, re-checked against the LIVE floor: a rotation is a
        // fresh authorization of this record's exposure, not a grandfather
        // clause for the posture it registered under.
        let live_floor = SecretCustodyFloor::resolve(&self.store, &wtxn)?;
        let live_band = live_floor.band_for(rec.class);
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

        let from_generation = rec.rotation_generation;
        let to_generation = from_generation
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("secret rotation generation"))?;
        rec.rotation_generation = to_generation;
        rec.rotated_at = Some(at);
        // The DEK-plane value write. `value_bytes` is `pub(crate)` precisely
        // so this stays inside the crate's custody plane; the new bytes reach
        // no receipt, log, claim or export from here.
        rec.value_bytes = new_value.to_vec();

        let receipt = RotationReceipt {
            receipt_id: EntityId::now(),
            secret_ref: rec.name.clone(),
            from_generation,
            to_generation,
            rotated_at: at,
            kind: RotationKind::Rotated,
        };
        self.write_custody_record_in_txn(&mut wtxn, &id, &rec, at)?;
        self.store.vault_meta.put(
            &mut wtxn,
            &receipt_key(&receipt.receipt_id),
            &encode_rotation_receipt_body(&receipt)?,
        )?;
        wtxn.commit()?;
        Ok(receipt)
    }

    /// Revokes a secret: terminal value death everywhere the vault reaches.
    ///
    /// The one op that DOES walk the leases, and the reason rotation does
    /// not need to. In one write transaction the record flips `Revoked`,
    /// every lease over that ref flips `Revoked` with its T2 file torn down
    /// (the [`Vault::expire_secret_leases`] sweep shape), and a
    /// [`RotationReceipt`] of kind [`RotationKind::Revoked`] lands.
    ///
    /// Afterwards every door and materialization for the ref fails typed
    /// ([`Error::SecretCustodyNotActive`]), and exhaust tainted by the ref
    /// derives [`ArtifactTaintState::TaintedStale`] — derived from the dead
    /// record, with no row rewritten anywhere in the exhaust plane.
    ///
    /// The generation does NOT advance: nothing replaced the value. The
    /// receipt's kind is what tells a revoke apart from a no-op.
    pub fn revoke_secret(&self, secret_ref: &str, at: u64) -> Result<RotationReceipt> {
        let mut wtxn = self.store.env.write_txn()?;
        let id = resolve_secret_ref_in_txn(&self.store, &wtxn, secret_ref)?.ok_or_else(|| {
            Error::SecretRefNotFound {
                name: secret_ref.to_owned(),
            }
        })?;
        let mut rec = read_secret_custody_in_txn(&self.store, &wtxn, &id)?
            .ok_or(Error::CorruptedIndex("secret custody record for live name"))?;
        let generation = rec.rotation_generation;

        if rec.status != SecretCustodyStatus::Revoked {
            rec.status = SecretCustodyStatus::Revoked;
            self.write_custody_record_in_txn(&mut wtxn, &id, &rec, at)?;
        }

        // The prefix sweep, collected before mutating: a cursor is not held
        // across the writes that follow it.
        let mut doomed = Vec::new();
        for entry in self
            .store
            .vault_meta
            .prefix_iter(&wtxn, SECRET_LEASE_KEY_PREFIX.as_bytes())?
        {
            let (_, raw) = entry?;
            let lease = decode_secret_lease_body(&raw)?;
            if lease.secret_ref == secret_ref && lease.status != SecretLeaseStatus::Revoked {
                doomed.push(lease);
            }
        }
        for mut lease in doomed {
            lease.status = SecretLeaseStatus::Revoked;
            write_secret_lease_in_txn(&self.store, &mut wtxn, &lease)?;
            teardown_local_registration_in_txn(&self.store, &mut wtxn, &lease.lease_id, at)?;
        }

        let receipt = RotationReceipt {
            receipt_id: EntityId::now(),
            secret_ref: rec.name.clone(),
            from_generation: generation,
            to_generation: generation,
            rotated_at: at,
            kind: RotationKind::Revoked,
        };
        self.store.vault_meta.put(
            &mut wtxn,
            &receipt_key(&receipt.receipt_id),
            &encode_rotation_receipt_body(&receipt)?,
        )?;
        wtxn.commit()?;
        Ok(receipt)
    }

    /// Re-encodes and re-puts a custody body through the ONE sealed put
    /// shape [`Vault::register_secret`] uses.
    ///
    /// Type-77 bodies are sealed from the raw/CRDT planes until ONE-1865;
    /// `allow_maintenance` with no reserved-predicate grant is the
    /// engine-internal non-replicated shape that seal admits.
    fn write_custody_record_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        rec: &crate::secret_custody::SecretCustodyRecord,
        at: u64,
    ) -> Result<()> {
        let data = encode_secret_custody_body(rec)?;
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_SECRET_CUSTODY,
                occurred: TimeRange { start: at, end: at },
                learned_at: at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted.load(Ordering::Acquire),
            false,
            true,
        )
    }

    /// Reads one durable rotation receipt.
    pub fn rotation_receipt(&self, receipt_id: &EntityId) -> Result<Option<RotationReceipt>> {
        let rtxn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&rtxn, &receipt_key(receipt_id))?
            .map(|raw| decode_rotation_receipt_body(*receipt_id, &raw))
            .transpose()
    }

    /// The FORWARD taint refs stored on one piece of exhaust (empty when
    /// none). Never a state — see [`Vault::artifact_taint_state`].
    pub fn artifact_taint_refs(&self, id: &EntityId) -> Result<Vec<SecretTaintRef>> {
        let rtxn = self.store.env.read_txn()?;
        exhaust_taint_refs_in_txn(&self.store, &rtxn, id)
    }

    /// The READ-TIME taint state of one piece of exhaust (S7 amendment).
    ///
    /// Derived on every call from the stored refs and the custody records'
    /// current generations. Nothing is cached, nothing is written, and
    /// nothing had to be flipped when a secret rotated — the answer simply
    /// changes the next time it is asked.
    pub fn artifact_taint_state(&self, id: &EntityId) -> Result<ArtifactTaintState> {
        let rtxn = self.store.env.read_txn()?;
        let refs = exhaust_taint_refs_in_txn(&self.store, &rtxn, id)?;
        taint_state_for_refs_in_txn(&self.store, &rtxn, &refs)
    }

    /// Attaches taint refs to one exhaust entity through the entity-keyed
    /// sidecar. The thin wrapper over
    /// [`mark_exhaust_tainted_in_txn`] for callers that own no transaction;
    /// callers that DO (an artifact put, a raw-output write) must use the
    /// in-txn form so the attach cannot separate from its exhaust.
    pub fn mark_artifact_tainted(&self, id: &EntityId, refs: &[SecretTaintRef]) -> Result<()> {
        validate_taint_refs(refs)?;
        let mut wtxn = self.store.env.write_txn()?;
        mark_exhaust_tainted_in_txn(&self.store, &mut wtxn, id, refs)?;
        Ok(wtxn.commit()?)
    }

    /// Whether the vault's resolved policy opens the stale-publish dial.
    pub fn taint_allow_stale_publish(&self) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        allow_stale_publish_in_txn(&self.store, &rtxn)
    }
}

#[cfg(test)]
mod tests;
