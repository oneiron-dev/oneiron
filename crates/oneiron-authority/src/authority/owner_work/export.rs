//! An export secret work map (FIX 4624(b)): one custody secret the owner's
//! whole-vault export met that its exporting install could not open, asked
//! of the install that holds it.
//!
//! The request carries the export's own act ([`OwnerAct`], kind `export`, on
//! the reserved target [`EXPORT_ACT_TARGET_NAME`], `seen` zero), exactly as
//! the export door authenticated it, whether or not its `ExportAct` was
//! signed: the map links that record when it was. The map names the secret's
//! custody record id and the generation the export met, the export's id and
//! archive digest, and the one recipient machine the owner chose to receive
//! the sealed copy, bound to the profile entry and encryption key he saw.
//! Ids, digests and a generation only: no name, value or plaintext digest
//! enters the main log.
//!
//! The holder seals the value to that recipient alone and keeps the sealed
//! copy under the request's entry; its result names the copy's digest
//! ([`super::SealedWorkOutput`]). Nothing in custody changes: no generation,
//! status or permit, and the exporting install never holds the value.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::custody::{decode_permit, permit_value};
use super::*;

const EXPORT_SECRET_WORK_KEYS: [&str; 7] = [
    OP_KEY_KIND,
    "secret",
    "generation",
    "export",
    "digest",
    "export_act",
    "recipient",
];

/// One custody secret an owner export asks its holder to seal to the
/// owner's chosen recipient. Value-free.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct ExportSecretWork {
    /// The secret's custody record id.
    pub secret: EntityId,
    /// The custody generation the export met: the holder seals that one
    /// alone.
    pub generation: u32,
    /// The export's id, as its audit row names it.
    pub export: EntityId,
    /// BLAKE3 of the archive the export wrote, where its door read it back.
    pub digest: Option<[u8; 32]>,
    /// The export's signed `ExportAct` entry, when its carrier signed one.
    pub export_act: Option<AuthorityEntryHash>,
    /// The machine the owner chose to receive the sealed copy, with the
    /// profile entry and encryption key he saw.
    pub recipient: CustodyRecipientPermit,
}

/// An export secret request carries the export's own act: the reserved
/// export target with a zero `seen`. No digest is zero.
pub(super) fn validate_export_secret(
    request: &OwnerWorkRequest,
    work: &ExportSecretWork,
) -> Result<()> {
    let zero = work.digest == Some([0; 32])
        || work.export_act == Some([0; 32])
        || work.recipient.profile == [0; 32]
        || work.recipient.encryption_key == [0; 32];
    if zero
        || request.act.seen != EXPORT_ACT_SEEN
        || request.act.target != owner_act_target(EXPORT_ACT_TARGET_NAME)?
    {
        return Err(invalid_authority());
    }
    Ok(())
}

/// Canonical field order: kind, secret, generation, export, digest,
/// export_act, then recipient, each optional field nil when absent; the
/// recipient's map is a custody permit's (machine, profile, encryption key).
pub(super) fn export_secret_work_value(work: &ExportSecretWork) -> Value {
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OwnerWorkKind::ExportSecret.as_str()),
        ),
        (Value::from("secret"), Value::from(work.secret.to_hex())),
        (Value::from("generation"), Value::from(work.generation)),
        (Value::from("export"), Value::from(work.export.to_hex())),
        (
            Value::from("digest"),
            work.digest.map_or(Value::Nil, binary_value),
        ),
        (
            Value::from("export_act"),
            work.export_act.map_or(Value::Nil, binary_value),
        ),
        (Value::from("recipient"), permit_value(&work.recipient)),
    ])
}

/// Strict keys; the shape is the request's ([`validate_export_secret`]).
pub(super) fn decode_export_secret_work(work: &[(Value, Value)]) -> Result<OwnerWorkBody> {
    validate_keys(work, &EXPORT_SECRET_WORK_KEYS)?;
    Ok(OwnerWorkBody::ExportSecret(ExportSecretWork {
        secret: decode_canonical_id(required(work, "secret")?)?,
        generation: required(work, "generation")?
            .as_u64()
            .and_then(|generation| u32::try_from(generation).ok())
            .ok_or_else(invalid_authority)?,
        export: decode_canonical_id(required(work, "export")?)?,
        digest: decode_optional_hash(required(work, "digest")?)?,
        export_act: decode_optional_hash(required(work, "export_act")?)?,
        recipient: decode_permit(required(work, "recipient")?)?,
    }))
}
