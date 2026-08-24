//! `rmpv::Value` decoding for every authority type.
//!
//! LOCKSTEP PAIR WITH [`super::wire_encode`]. This is the exact inverse of
//! `op_value_with_genesis_delay`: any field or variant change must edit BOTH
//! files (and the golden vectors in `authority/tests.rs`) or the wire format
//! silently drifts.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::{
    decode_federation_direction_scope_value, decode_federation_pact_scope_value,
};

use super::*;

pub(super) fn decode_entry_value(value: &Value) -> Result<AuthorityLogEntry> {
    let entries = map_entries(value)?;
    validate_keys(entries, &AUTHORITY_ENTRY_KEYS)?;
    let schema_version = required(entries, KEY_SCHEMA_VERSION)?
        .as_u64()
        .ok_or_else(invalid_authority)?;
    let vault_id = decode_optional_hash(required(entries, KEY_VAULT_ID)?)?;
    let seq = required(entries, KEY_SEQ)?
        .as_u64()
        .ok_or_else(invalid_authority)?;
    let parent_hashes = decode_hash_array(required(entries, KEY_PARENT_HASHES)?)?;
    let op = decode_op(required(entries, KEY_OP)?)?;
    let signer = decode_signature(required(entries, KEY_SIGNER)?)?;
    let cosigns = decode_signature_array(required(entries, KEY_COSIGNS)?)?;
    let ts = required(entries, KEY_TS)?
        .as_u64()
        .ok_or_else(invalid_authority)?;
    Ok(AuthorityLogEntry {
        schema_version,
        vault_id,
        seq,
        parent_hashes,
        op,
        signer,
        cosigns,
        ts,
    })
}

pub(super) fn decode_op(value: &Value) -> Result<AuthorityOp> {
    let entries = map_entries(value)?;
    let kind = required(entries, OP_KEY_KIND)?
        .as_str()
        .ok_or_else(invalid_authority)?;
    match kind {
        OP_KIND_GENESIS => {
            let pending_widen_delay = optional(entries, "pending_widen_delay_secs");
            if pending_widen_delay.is_some() {
                validate_keys(
                    entries,
                    &[
                        OP_KEY_KIND,
                        "device",
                        "genesis_nonce",
                        "tier_floor",
                        "pending_widen_delay_secs",
                    ],
                )?;
            } else {
                validate_keys(
                    entries,
                    &[OP_KEY_KIND, "device", "genesis_nonce", "tier_floor"],
                )?;
            }
            Ok(AuthorityOp::Genesis {
                device: decode_device(required(entries, "device")?)?,
                genesis_nonce: decode_hash(required(entries, "genesis_nonce")?)?,
                tier_floor: decode_tier(required(entries, "tier_floor")?)?,
                pending_widen_delay_secs: pending_widen_delay
                    .map(|value| value.as_u64().ok_or_else(invalid_authority))
                    .transpose()?
                    .unwrap_or(DEFAULT_PENDING_WIDEN_DELAY_SECS),
            })
        }
        OP_KIND_ENROLL_DEVICE => {
            validate_keys(entries, &[OP_KEY_KIND, "device"])?;
            Ok(AuthorityOp::EnrollDevice {
                device: decode_device(required(entries, "device")?)?,
            })
        }
        OP_KIND_REVOKE_DEVICE => {
            validate_keys(entries, &[OP_KEY_KIND, "revoked_key"])?;
            Ok(AuthorityOp::RevokeDevice {
                revoked_key: decode_key(required(entries, "revoked_key")?)?,
            })
        }
        OP_KIND_SET_CEILING => {
            validate_keys(
                entries,
                &[OP_KEY_KIND, "authority_key", "actor_class", "ceiling"],
            )?;
            let ceiling_u64 = required(entries, "ceiling")?
                .as_u64()
                .ok_or_else(invalid_authority)?;
            let ceiling = u8::try_from(ceiling_u64).map_err(|_| invalid_authority())?;
            Ok(AuthorityOp::SetCeiling {
                authority_key: decode_key(required(entries, "authority_key")?)?,
                actor_class: required(entries, "actor_class")?
                    .as_str()
                    .ok_or_else(invalid_authority)?
                    .to_owned(),
                ceiling,
            })
        }
        OP_KIND_ROTATE_KEY => {
            validate_keys(entries, &[OP_KEY_KIND, "old_key", "new_device"])?;
            Ok(AuthorityOp::RotateKey {
                old_key: decode_key(required(entries, "old_key")?)?,
                new_device: decode_device(required(entries, "new_device")?)?,
            })
        }
        OP_KIND_SET_TIER_FLOOR => {
            validate_keys(entries, &[OP_KEY_KIND, "tier_floor"])?;
            Ok(AuthorityOp::SetTierFloor {
                tier_floor: decode_tier(required(entries, "tier_floor")?)?,
            })
        }
        OP_KIND_RECOVERY_REBOOT => {
            validate_keys(
                entries,
                &[OP_KEY_KIND, "new_genesis_nonce", "new_device", "tier_floor"],
            )?;
            Ok(AuthorityOp::RecoveryReboot {
                new_genesis_nonce: decode_hash(required(entries, "new_genesis_nonce")?)?,
                new_device: decode_device(required(entries, "new_device")?)?,
                tier_floor: decode_tier(required(entries, "tier_floor")?)?,
            })
        }
        OP_KIND_CRITICAL_WRITE_CONFIRM => {
            validate_keys(
                entries,
                &[
                    OP_KEY_KIND,
                    "schema_version",
                    "confirm_id",
                    "gate_decision_id",
                    "claim_id",
                    "effect_digest",
                    "read_frontier_hash",
                    "nonce",
                    "expires_at",
                    "disposition",
                    "method",
                ],
            )?;
            let claim = EntityId::from_bytes(decode_16(required(entries, "claim_id")?)?)
                .map_err(|_| invalid_authority())?;
            let action = CriticalWriteConfirmAction {
                schema_version: required(entries, "schema_version")?
                    .as_u64()
                    .ok_or_else(invalid_authority)?,
                confirm_id: decode_hash(required(entries, "confirm_id")?)?,
                gate_decision_id: decode_16(required(entries, "gate_decision_id")?)?,
                claim_id: claim,
                effect_digest: decode_hash(required(entries, "effect_digest")?)?,
                read_frontier_hash: decode_hash(required(entries, "read_frontier_hash")?)?,
                nonce: decode_16(required(entries, "nonce")?)?,
                expires_at: required(entries, "expires_at")?
                    .as_u64()
                    .ok_or_else(invalid_authority)?,
                disposition: required(entries, "disposition")?
                    .as_str()
                    .and_then(CriticalWriteConfirmDisposition::parse)
                    .ok_or_else(invalid_authority)?,
                method: required(entries, "method")?
                    .as_str()
                    .and_then(CriticalWriteConfirmMethod::parse)
                    .ok_or_else(invalid_authority)?,
            };
            Ok(AuthorityOp::CriticalWriteConfirm(action))
        }
        OP_KIND_FEDERATION_CONFIRM => {
            validate_keys(
                entries,
                &[
                    OP_KEY_KIND,
                    "confirm_kind",
                    "confirm_id",
                    "peer_vault_id",
                    "epoch",
                    "nonce",
                ],
            )?;
            let confirm_kind = required(entries, "confirm_kind")?
                .as_str()
                .and_then(AuthorityConfirmKind::parse)
                .ok_or_else(invalid_authority)?;
            Ok(AuthorityOp::FederationConfirm(AuthorityConfirmAction {
                kind: confirm_kind,
                confirm_id: decode_hash(required(entries, "confirm_id")?)?,
                peer_vault_id: decode_hash(required(entries, "peer_vault_id")?)?,
                epoch: required(entries, "epoch")?
                    .as_u64()
                    .ok_or_else(invalid_authority)?,
                nonce: decode_16(required(entries, "nonce")?)?,
            }))
        }
        OP_KIND_VETO_PENDING_WIDEN => {
            validate_keys(entries, &[OP_KEY_KIND, "pending_widen_hash"])?;
            Ok(AuthorityOp::VetoPendingWiden {
                pending_widen_hash: decode_hash(required(entries, "pending_widen_hash")?)?,
            })
        }
        OP_KIND_FEDERATION_LIFECYCLE => decode_federation_lifecycle_op(entries),
        OP_KIND_BIND_ACTOR | OP_KIND_REBIND_ACTOR => {
            let (authority_key, actor_ref, actor_class, epoch) = decode_actor_binding_op(entries)?;
            if kind == OP_KIND_BIND_ACTOR {
                Ok(AuthorityOp::BindActor {
                    authority_key,
                    actor_ref,
                    actor_class,
                    epoch,
                })
            } else {
                Ok(AuthorityOp::RebindActor {
                    authority_key,
                    actor_ref,
                    actor_class,
                    epoch,
                })
            }
        }
        OP_KIND_REVOKE_ACTOR => {
            validate_keys(entries, &[OP_KEY_KIND, "authority_key", "epoch"])?;
            Ok(AuthorityOp::RevokeActor {
                authority_key: decode_key(required(entries, "authority_key")?)?,
                epoch: required(entries, "epoch")?
                    .as_u64()
                    .ok_or_else(invalid_authority)?,
            })
        }
        _ => Err(invalid_authority()),
    }
}

fn decode_actor_binding_op(
    entries: &[(Value, Value)],
) -> Result<(AuthorityKey, EntityId, String, u64)> {
    validate_keys(
        entries,
        &[
            OP_KEY_KIND,
            "authority_key",
            "actor_ref",
            "actor_class",
            "epoch",
        ],
    )?;
    let actor_ref_hex = required(entries, "actor_ref")?
        .as_str()
        .ok_or_else(invalid_authority)?;
    // `from_hex` routes `from_bytes`, so reserved sentinel ids fail closed; the
    // round-trip check rejects non-canonical hex (the `grant_ref` precedent).
    let actor_ref = EntityId::from_hex(actor_ref_hex).map_err(|_| invalid_authority())?;
    if actor_ref.to_hex() != actor_ref_hex {
        return Err(invalid_authority());
    }
    Ok((
        decode_key(required(entries, "authority_key")?)?,
        actor_ref,
        required(entries, "actor_class")?
            .as_str()
            .ok_or_else(invalid_authority)?
            .to_owned(),
        required(entries, "epoch")?
            .as_u64()
            .ok_or_else(invalid_authority)?,
    ))
}

fn decode_federation_lifecycle_op(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    let kind = required(entries, "lifecycle_kind")?
        .as_str()
        .and_then(FederationLifecycleKind::parse)
        .ok_or_else(invalid_authority)?;
    let mut expected = vec![
        OP_KEY_KIND,
        "lifecycle_kind",
        "pact_id",
        "grant_ref",
        "peer_vault_id",
        "pact_epoch",
        "pact_nonce",
    ];
    match kind {
        FederationLifecycleKind::Connect => {
            expected.extend(["pact_scope", "scope_digest", "gesture"]);
        }
        FederationLifecycleKind::Rescope => {
            // The two-form discriminator: `effective_scope` present = narrow
            // form; otherwise the repact key set applies. A mix (or neither)
            // fails both forms' strict key sets below.
            if optional(entries, "effective_scope").is_some() {
                expected.push("effective_scope");
            } else {
                expected.extend(["pact_scope", "scope_digest", "gesture"]);
            }
        }
        FederationLifecycleKind::Disconnect | FederationLifecycleKind::Dissolve => {}
        FederationLifecycleKind::Promote => {
            expected.extend(["scope_digest", "gesture", "successor_vault_id"]);
        }
    }
    validate_keys(entries, &expected)?;
    let grant_ref_hex = required(entries, "grant_ref")?
        .as_str()
        .ok_or_else(invalid_authority)?;
    let grant_ref = EntityId::from_hex(grant_ref_hex).map_err(|_| invalid_authority())?;
    if grant_ref.to_hex() != grant_ref_hex {
        return Err(invalid_authority());
    }
    let pact_scope = optional(entries, "pact_scope")
        .map(|value| decode_federation_pact_scope_value(value).map_err(|_| invalid_authority()))
        .transpose()?;
    let effective_scope = optional(entries, "effective_scope")
        .map(|value| {
            decode_federation_direction_scope_value(value).map_err(|_| invalid_authority())
        })
        .transpose()?;
    let scope_digest = optional(entries, "scope_digest")
        .map(decode_hash)
        .transpose()?;
    let gesture = optional(entries, "gesture")
        .map(decode_gesture)
        .transpose()?;
    let successor_vault_id = optional(entries, "successor_vault_id")
        .map(decode_hash)
        .transpose()?;
    Ok(AuthorityOp::FederationLifecycle(
        FederationLifecycleAction {
            kind,
            pact_id: decode_hash(required(entries, "pact_id")?)?,
            grant_ref,
            peer_vault_id: decode_hash(required(entries, "peer_vault_id")?)?,
            pact_epoch: required(entries, "pact_epoch")?
                .as_u64()
                .ok_or_else(invalid_authority)?,
            pact_scope,
            effective_scope,
            scope_digest,
            gesture,
            successor_vault_id,
            pact_nonce: decode_16(required(entries, "pact_nonce")?)?,
        },
    ))
}

fn decode_gesture(value: &Value) -> Result<FederationPactGesture> {
    let entries = map_entries(value)?;
    validate_keys(entries, &["signer", "signature"])?;
    Ok(FederationPactGesture {
        signer: decode_key(required(entries, "signer")?)?,
        signature: bytes(required(entries, "signature")?)?.to_vec(),
    })
}

fn decode_device(value: &Value) -> Result<DeviceAuthority> {
    let entries = map_entries(value)?;
    validate_keys(
        entries,
        &[
            "key",
            "transport_key_binding",
            "attestation",
            "tier",
            "roles",
        ],
    )?;
    let roles_u64 = required(entries, "roles")?
        .as_u64()
        .ok_or_else(invalid_authority)?;
    let roles = u16::try_from(roles_u64).map_err(|_| invalid_authority())?;
    Ok(DeviceAuthority {
        key: decode_key(required(entries, "key")?)?,
        transport_key_binding: decode_hash(required(entries, "transport_key_binding")?)?,
        attestation: decode_attestation(required(entries, "attestation")?)?,
        tier: decode_tier(required(entries, "tier")?)?,
        roles,
    })
}

fn decode_key(value: &Value) -> Result<AuthorityKey> {
    let entries = map_entries(value)?;
    validate_keys(entries, &[KEY_SUITE, KEY_PUBLIC_KEY])?;
    let suite = required(entries, KEY_SUITE)?
        .as_str()
        .and_then(AuthoritySignatureSuite::parse)
        .ok_or_else(invalid_authority)?;
    let raw = bytes(required(entries, KEY_PUBLIC_KEY)?)?;
    match suite {
        AuthoritySignatureSuite::Ed25519 => Ok(AuthorityKey::Ed25519(
            raw.try_into().map_err(|_| invalid_authority())?,
        )),
        AuthoritySignatureSuite::P256 => Ok(AuthorityKey::P256(canonical_p256_key_bytes(raw)?)),
    }
}

fn decode_signature(value: &Value) -> Result<AuthoritySignature> {
    let entries = map_entries(value)?;
    validate_keys(entries, &SIGNATURE_KEYS)?;
    let suite = required(entries, KEY_SUITE)?
        .as_str()
        .and_then(AuthoritySignatureSuite::parse)
        .ok_or_else(invalid_authority)?;
    let raw_key = bytes(required(entries, KEY_PUBLIC_KEY)?)?;
    let public_key = match suite {
        AuthoritySignatureSuite::Ed25519 => {
            AuthorityKey::Ed25519(raw_key.try_into().map_err(|_| invalid_authority())?)
        }
        AuthoritySignatureSuite::P256 => AuthorityKey::P256(canonical_p256_key_bytes(raw_key)?),
    };
    Ok(AuthoritySignature {
        suite,
        public_key,
        signature: bytes(required(entries, KEY_SIGNATURE)?)?.to_vec(),
    })
}

fn decode_signature_array(value: &Value) -> Result<Vec<AuthoritySignature>> {
    let Value::Array(values) = value else {
        return Err(invalid_authority());
    };
    values.iter().map(decode_signature).collect()
}

fn decode_attestation(value: &Value) -> Result<AuthorityAttestation> {
    let entries = map_entries(value)?;
    validate_keys(entries, &ATTESTATION_KEYS)?;
    Ok(AuthorityAttestation {
        kind: required(entries, KEY_ATTEST_KIND)?
            .as_str()
            .ok_or_else(invalid_authority)?
            .to_owned(),
        evidence: bytes(required(entries, KEY_ATTEST_EVIDENCE)?)?.to_vec(),
    })
}

fn decode_tier(value: &Value) -> Result<AuthorityTier> {
    value
        .as_str()
        .and_then(AuthorityTier::parse)
        .ok_or_else(invalid_authority)
}

fn decode_optional_hash(value: &Value) -> Result<Option<[u8; 32]>> {
    if matches!(value, Value::Nil) {
        Ok(None)
    } else {
        decode_hash(value).map(Some)
    }
}

fn decode_hash_array(value: &Value) -> Result<Vec<[u8; 32]>> {
    let Value::Array(values) = value else {
        return Err(invalid_authority());
    };
    values.iter().map(decode_hash).collect()
}

fn decode_hash(value: &Value) -> Result<[u8; 32]> {
    bytes(value)?.try_into().map_err(|_| invalid_authority())
}

fn decode_16(value: &Value) -> Result<[u8; 16]> {
    bytes(value)?.try_into().map_err(|_| invalid_authority())
}

fn map_entries(value: &Value) -> Result<&[(Value, Value)]> {
    let Value::Map(entries) = value else {
        return Err(invalid_authority());
    };
    Ok(entries)
}

fn validate_keys(entries: &[(Value, Value)], expected: &[&str]) -> Result<()> {
    let mut seen = vec![false; expected.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_authority)?;
        let Some(index) = expected.iter().position(|known| *known == key) else {
            return Err(invalid_authority());
        };
        if seen[index] {
            return Err(invalid_authority());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_authority())
    }
}

fn required<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
        .ok_or_else(invalid_authority)
}

fn optional<'a>(entries: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
}

fn bytes(value: &Value) -> Result<&[u8]> {
    match value {
        Value::Binary(bytes) => Ok(bytes),
        _ => Err(invalid_authority()),
    }
}

pub(super) fn invalid_authority() -> Error {
    Error::InvalidAuthorityLogBody("body failed validation")
}

/// Whether `entry` carries a federation lifecycle op with a TERMINAL kind.
///
/// A cheap shape test on the appended entry, not a transition verdict — whether
/// the op actually applied is the fold's call, and
/// [`crate::federation::apply_federation_stale_stamps`] asks the fold.
pub(super) fn is_terminal_federation_lifecycle(entry: &AuthorityLogEntry) -> bool {
    matches!(
        &entry.op,
        AuthorityOp::FederationLifecycle(action)
            if matches!(
                action.kind,
                FederationLifecycleKind::Disconnect
                    | FederationLifecycleKind::Dissolve
                    | FederationLifecycleKind::Promote
            )
    )
}
