//! `rmpv::Value` encoding for every authority type.
//!
//! LOCKSTEP PAIR WITH [`super::wire_decode`]. One match arm per
//! [`super::AuthorityOp`] variant, mirrored 1:1 by `decode_op` on the other
//! side: any field or variant change must edit BOTH files (and the golden
//! vectors in `authority/tests.rs`) or the wire format silently drifts.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::{federation_direction_scope_value, federation_pact_scope_value};

use super::*;

pub(super) fn entry_value(entry: &AuthorityLogEntry, include_signatures: bool) -> Value {
    entry_value_with_genesis_delay(entry, include_signatures, true)
}

pub(super) fn entry_value_with_genesis_delay(
    entry: &AuthorityLogEntry,
    include_signatures: bool,
    include_genesis_delay: bool,
) -> Value {
    let mut fields = vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(entry.schema_version),
        ),
        (Value::from(KEY_VAULT_ID), option_hash_value(entry.vault_id)),
        (Value::from(KEY_SEQ), Value::from(entry.seq)),
        (
            Value::from(KEY_PARENT_HASHES),
            Value::Array(
                sorted_hashes(&entry.parent_hashes)
                    .into_iter()
                    .map(binary_value)
                    .collect(),
            ),
        ),
        (
            Value::from(KEY_OP),
            op_value_with_genesis_delay(&entry.op, include_genesis_delay),
        ),
    ];
    if include_signatures {
        fields.push((Value::from(KEY_SIGNER), signature_value(&entry.signer)));
        fields.push((
            Value::from(KEY_COSIGNS),
            Value::Array(entry.cosigns.iter().map(signature_value).collect()),
        ));
    }
    fields.push((Value::from(KEY_TS), Value::from(entry.ts)));
    Value::Map(fields)
}

pub(super) fn op_value_with_genesis_delay(op: &AuthorityOp, include_genesis_delay: bool) -> Value {
    match op {
        AuthorityOp::Genesis {
            device,
            genesis_nonce,
            tier_floor,
            pending_widen_delay_secs,
        } => {
            let mut fields = vec![
                (Value::from(OP_KEY_KIND), Value::from(OP_KIND_GENESIS)),
                (Value::from("device"), device_value(device)),
                (Value::from("genesis_nonce"), binary_value(*genesis_nonce)),
                (Value::from("tier_floor"), Value::from(tier_floor.as_str())),
            ];
            if include_genesis_delay {
                fields.push((
                    Value::from("pending_widen_delay_secs"),
                    Value::from(*pending_widen_delay_secs),
                ));
            }
            Value::Map(fields)
        }
        AuthorityOp::EnrollDevice { device } => Value::Map(vec![
            (Value::from(OP_KEY_KIND), Value::from(OP_KIND_ENROLL_DEVICE)),
            (Value::from("device"), device_value(device)),
        ]),
        AuthorityOp::RevokeDevice { revoked_key } => Value::Map(vec![
            (Value::from(OP_KEY_KIND), Value::from(OP_KIND_REVOKE_DEVICE)),
            (Value::from("revoked_key"), key_value(revoked_key)),
        ]),
        AuthorityOp::SetCeiling {
            authority_key,
            actor_class,
            ceiling,
        } => Value::Map(vec![
            (Value::from(OP_KEY_KIND), Value::from(OP_KIND_SET_CEILING)),
            (Value::from("authority_key"), key_value(authority_key)),
            (
                Value::from("actor_class"),
                Value::from(actor_class.as_str()),
            ),
            (Value::from("ceiling"), Value::from(*ceiling)),
        ]),
        AuthorityOp::RotateKey {
            old_key,
            new_device,
        } => Value::Map(vec![
            (Value::from(OP_KEY_KIND), Value::from(OP_KIND_ROTATE_KEY)),
            (Value::from("old_key"), key_value(old_key)),
            (Value::from("new_device"), device_value(new_device)),
        ]),
        AuthorityOp::SetTierFloor { tier_floor } => Value::Map(vec![
            (
                Value::from(OP_KEY_KIND),
                Value::from(OP_KIND_SET_TIER_FLOOR),
            ),
            (Value::from("tier_floor"), Value::from(tier_floor.as_str())),
        ]),
        AuthorityOp::RecoveryReboot {
            new_genesis_nonce,
            new_device,
            tier_floor,
        } => Value::Map(vec![
            (
                Value::from(OP_KEY_KIND),
                Value::from(OP_KIND_RECOVERY_REBOOT),
            ),
            (
                Value::from("new_genesis_nonce"),
                binary_value(*new_genesis_nonce),
            ),
            (Value::from("new_device"), device_value(new_device)),
            (Value::from("tier_floor"), Value::from(tier_floor.as_str())),
        ]),
        AuthorityOp::CriticalWriteConfirm(action) => Value::Map(vec![
            (
                Value::from(OP_KEY_KIND),
                Value::from(OP_KIND_CRITICAL_WRITE_CONFIRM),
            ),
            (
                Value::from("schema_version"),
                Value::from(action.schema_version),
            ),
            (Value::from("confirm_id"), binary_value(action.confirm_id)),
            (
                Value::from("gate_decision_id"),
                binary_value_16(action.gate_decision_id),
            ),
            (
                Value::from("claim_id"),
                binary_value_16(*action.claim_id.as_bytes()),
            ),
            (
                Value::from("effect_digest"),
                binary_value(action.effect_digest),
            ),
            (
                Value::from("read_frontier_hash"),
                binary_value(action.read_frontier_hash),
            ),
            (Value::from("nonce"), binary_value_16(action.nonce)),
            (Value::from("expires_at"), Value::from(action.expires_at)),
            (
                Value::from("disposition"),
                Value::from(action.disposition.as_str()),
            ),
            (Value::from("method"), Value::from(action.method.as_str())),
        ]),
        AuthorityOp::FederationConfirm(action) => Value::Map(vec![
            (
                Value::from(OP_KEY_KIND),
                Value::from(OP_KIND_FEDERATION_CONFIRM),
            ),
            (
                Value::from("confirm_kind"),
                Value::from(action.kind.as_str()),
            ),
            (Value::from("confirm_id"), binary_value(action.confirm_id)),
            (
                Value::from("peer_vault_id"),
                binary_value(action.peer_vault_id),
            ),
            (Value::from("epoch"), Value::from(action.epoch)),
            (Value::from("nonce"), binary_value_16(action.nonce)),
        ]),
        AuthorityOp::VetoPendingWiden { pending_widen_hash } => Value::Map(vec![
            (
                Value::from(OP_KEY_KIND),
                Value::from(OP_KIND_VETO_PENDING_WIDEN),
            ),
            (
                Value::from("pending_widen_hash"),
                binary_value(*pending_widen_hash),
            ),
        ]),
        AuthorityOp::FederationLifecycle(action) => {
            let mut fields = vec![
                (
                    Value::from(OP_KEY_KIND),
                    Value::from(OP_KIND_FEDERATION_LIFECYCLE),
                ),
                (
                    Value::from("lifecycle_kind"),
                    Value::from(action.kind.as_str()),
                ),
                (Value::from("pact_id"), binary_value(action.pact_id)),
                (
                    Value::from("grant_ref"),
                    Value::from(action.grant_ref.to_hex()),
                ),
                (
                    Value::from("peer_vault_id"),
                    binary_value(action.peer_vault_id),
                ),
                (Value::from("pact_epoch"), Value::from(action.pact_epoch)),
                (
                    Value::from("pact_nonce"),
                    binary_value_16(action.pact_nonce),
                ),
            ];
            if let Some(scope) = &action.pact_scope {
                fields.push((
                    Value::from("pact_scope"),
                    federation_pact_scope_value(scope),
                ));
            }
            if let Some(effective) = &action.effective_scope {
                fields.push((
                    Value::from("effective_scope"),
                    federation_direction_scope_value(effective),
                ));
            }
            if let Some(digest) = &action.scope_digest {
                fields.push((Value::from("scope_digest"), binary_value(*digest)));
            }
            if let Some(gesture) = &action.gesture {
                fields.push((Value::from("gesture"), gesture_value(gesture)));
            }
            if let Some(successor) = &action.successor_vault_id {
                fields.push((Value::from("successor_vault_id"), binary_value(*successor)));
            }
            Value::Map(fields)
        }
        AuthorityOp::BindActor {
            authority_key,
            actor_ref,
            actor_class,
            epoch,
        } => actor_binding_op_value(
            OP_KIND_BIND_ACTOR,
            authority_key,
            actor_ref,
            actor_class,
            *epoch,
        ),
        AuthorityOp::RebindActor {
            authority_key,
            actor_ref,
            actor_class,
            epoch,
        } => actor_binding_op_value(
            OP_KIND_REBIND_ACTOR,
            authority_key,
            actor_ref,
            actor_class,
            *epoch,
        ),
        AuthorityOp::RevokeActor {
            authority_key,
            epoch,
        } => Value::Map(vec![
            (Value::from(OP_KEY_KIND), Value::from(OP_KIND_REVOKE_ACTOR)),
            (Value::from("authority_key"), key_value(authority_key)),
            (Value::from("epoch"), Value::from(*epoch)),
        ]),
    }
}

/// Canonical field order for bind/rebind:
/// `(kind, authority_key, actor_ref, actor_class, epoch)` — byte-pinned by the
/// golden vectors. `actor_ref` rides as 32-hex like the `grant_ref` precedent.
fn actor_binding_op_value(
    kind: &str,
    authority_key: &AuthorityKey,
    actor_ref: &EntityId,
    actor_class: &str,
    epoch: u64,
) -> Value {
    Value::Map(vec![
        (Value::from(OP_KEY_KIND), Value::from(kind)),
        (Value::from("authority_key"), key_value(authority_key)),
        (Value::from("actor_ref"), Value::from(actor_ref.to_hex())),
        (Value::from("actor_class"), Value::from(actor_class)),
        (Value::from("epoch"), Value::from(epoch)),
    ])
}

fn gesture_value(gesture: &FederationPactGesture) -> Value {
    Value::Map(vec![
        (Value::from("signer"), key_value(&gesture.signer)),
        (
            Value::from("signature"),
            Value::Binary(gesture.signature.clone()),
        ),
    ])
}

pub(super) fn legacy_genesis_encoding_candidate(entry: &AuthorityLogEntry) -> bool {
    matches!(
        &entry.op,
        AuthorityOp::Genesis {
            pending_widen_delay_secs,
            ..
        } if *pending_widen_delay_secs == DEFAULT_PENDING_WIDEN_DELAY_SECS
    )
}

pub(super) fn legacy_genesis_signed_entry_bytes(
    entry: &AuthorityLogEntry,
) -> Result<Option<Vec<u8>>> {
    if legacy_genesis_encoding_candidate(entry) {
        encode_value(&entry_value_with_genesis_delay(entry, true, false)).map(Some)
    } else {
        Ok(None)
    }
}

fn device_value(device: &DeviceAuthority) -> Value {
    Value::Map(vec![
        (Value::from("key"), key_value(&device.key)),
        (
            Value::from("transport_key_binding"),
            binary_value(device.transport_key_binding),
        ),
        (
            Value::from("attestation"),
            attestation_value(&device.attestation),
        ),
        (Value::from("tier"), Value::from(device.tier.as_str())),
        (Value::from("roles"), Value::from(u64::from(device.roles))),
    ])
}

pub(super) fn key_value(key: &AuthorityKey) -> Value {
    match key {
        AuthorityKey::Ed25519(bytes) => Value::Map(vec![
            (Value::from(KEY_SUITE), Value::from("ed25519")),
            (Value::from(KEY_PUBLIC_KEY), binary_value(*bytes)),
        ]),
        AuthorityKey::P256(bytes) => Value::Map(vec![
            (Value::from(KEY_SUITE), Value::from("p256")),
            (Value::from(KEY_PUBLIC_KEY), Value::Binary(bytes.clone())),
        ]),
    }
}

fn signature_value(signature: &AuthoritySignature) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SUITE),
            Value::from(signature.suite.as_str()),
        ),
        (
            Value::from(KEY_PUBLIC_KEY),
            key_bytes_value(&signature.public_key),
        ),
        (
            Value::from(KEY_SIGNATURE),
            Value::Binary(signature.signature.clone()),
        ),
    ])
}

fn key_bytes_value(key: &AuthorityKey) -> Value {
    match key {
        AuthorityKey::Ed25519(bytes) => binary_value(*bytes),
        AuthorityKey::P256(bytes) => Value::Binary(bytes.clone()),
    }
}

fn attestation_value(attestation: &AuthorityAttestation) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_ATTEST_KIND),
            Value::from(attestation.kind.as_str()),
        ),
        (
            Value::from(KEY_ATTEST_EVIDENCE),
            Value::Binary(attestation.evidence.clone()),
        ),
    ])
}

fn option_hash_value(value: Option<[u8; 32]>) -> Value {
    value.map_or(Value::Nil, binary_value)
}

pub(super) fn binary_value(value: [u8; 32]) -> Value {
    Value::Binary(value.to_vec())
}

pub(super) fn binary_value_16(value: [u8; 16]) -> Value {
    Value::Binary(value.to_vec())
}

fn sorted_hashes(values: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out = values.to_vec();
    out.sort_unstable();
    out
}

pub(super) fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value)
        .map_err(|_| Error::InvariantViolation("authority log body MessagePack encode failed"))?;
    Ok(out)
}
