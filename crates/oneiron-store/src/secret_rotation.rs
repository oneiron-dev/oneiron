//! SECRET-04 (ONE-1922): rotation as a first-class vault op, and READ-TIME
//! invalidation of secret-tainted build exhaust.
//!
//! Two halves of ARCH-0069, kept deliberately apart:
//!
//! **S6 — rotation is a vault update.** [`Vault::rotate_secret_as_owner`] bumps the
//! record's `rotation_generation`, stamps `rotated_at`, and replaces the
//! value bytes inside ONE write transaction. The next lease materializes the
//! new value and doored uses rotate invisibly, because the value never lived
//! workspace-side to begin with. The caveat is stated, not hidden: rotation
//! kills NO live lease. An old lease keeps the `value_generation` it minted
//! at, so its staleness is OBSERVABLE (compare it against the record) rather
//! than silently repaired. Terminal value death is
//! [`Vault::revoke_secret_as_owner`]'s job alone — that one does walk the
//! leases.
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
//!   `secret_taint.refs` key
//!   ([`crate::blob_artifact::BLOB_ARTIFACT_OPTIONAL_BODY_KEYS`]),
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

use crate::ports::records::EntityRecord;
use rmpv::Value;

use crate::secret_lease::types::SecretTaintRef;
use crate::secret_record::types::SecretCustodyStatus;
use crate::side_table::key::HexId;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::error::SecretError;
use oneiron_base::registry::ENTITY_TYPE_ASSET;
use oneiron_base::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use oneiron_contracts::entity_id::EntityId;

/// The custody secret-name bound, also used for stored taint refs.
pub const SECRET_TAINT_REF_MAX_BYTES: usize = crate::secret_record::types::SECRET_NAME_MAX_BYTES;

pub fn invalid_body(reason: &'static str) -> Error {
    Error::Secret(SecretError::InvalidSecretRotationBody(reason))
}

pub fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
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

pub fn as_u64(value: &Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        Some(n)
    } else {
        u64::try_from(value.as_i64()?).ok()
    }
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
pub fn taint_refs_to_value(refs: &[SecretTaintRef]) -> Value {
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
/// [`ArtifactError::InvalidBlobArtifactBody`](crate::error::ArtifactError::InvalidBlobArtifactBody), a sidecar row says
/// [`SecretError::InvalidSecretRotationBody`](crate::error::SecretError::InvalidSecretRotationBody)) instead of importing a foreign
/// error class. Validation is strict: bounded non-empty names, `u32`
/// generations, and no duplicate secret names — a
/// duplicated name would let one body assert two different generations for
/// one secret, which has no honest read.
#[must_use]
pub fn taint_refs_from_value(value: &Value) -> Option<Vec<SecretTaintRef>> {
    let Value::Array(items) = value else {
        return None;
    };
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
pub fn validate_taint_refs(refs: &[SecretTaintRef]) -> Result<()> {
    for (index, r) in refs.iter().enumerate() {
        if r.secret_ref.is_empty() || r.secret_ref.len() > SECRET_TAINT_REF_MAX_BYTES {
            return Err(invalid_body(
                "taint ref secret_ref must be non-empty and within the secret-name byte bound",
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

/// A taint sidecar row is its own pinned MessagePack layout.
impl crate::side_table::codec::RawValue for Vec<SecretTaintRef> {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, crate::side_table::codec::CodecError> {
        Ok(encode_taint_refs_row(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, crate::side_table::codec::CodecError> {
        Ok(decode_taint_refs_row(bytes)?)
    }
}

pub fn encode_taint_refs_row(refs: &[SecretTaintRef]) -> Result<Vec<u8>> {
    validate_taint_refs(refs)?;
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &taint_refs_to_value(refs))
        .map_err(|_| invalid_body("encode taint refs row"))?;
    Ok(out)
}

pub fn decode_taint_refs_row(bytes: &[u8]) -> Result<Vec<SecretTaintRef>> {
    use std::io::Cursor;

    let mut cursor = Cursor::new(bytes);
    let value =
        rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_body("decode taint refs row"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_body("trailing bytes after taint refs row"));
    }
    taint_refs_from_value(&value).ok_or(invalid_body("taint refs row"))
}
