//! The authority op vocabulary and the signed log-entry envelope.
//!
//! Shape and op validation, the body codec entry points, entry hashing, and
//! entity-id / genesis-vault-id derivation. The `rmpv` mapping itself lives in
//! [`super::wire_encode`] and [`super::wire_decode`].

use std::io::Cursor;

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::encode_federation_pact_scope;

use super::*;

/// Pinned operation vocabulary for AUTHORITY_LOG.
// The FederationLifecycle payload (scope pair + gesture) dominates the enum
// size; its unboxed shape is pinned by ONE-1408, so the skew is accepted.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityOp {
    /// Vault genesis. `vault_id` is `None` on the containing entry and is
    /// derived as BLAKE3(canonical signed genesis).
    Genesis {
        device: DeviceAuthority,
        genesis_nonce: [u8; 32],
        tier_floor: AuthorityTier,
        pending_widen_delay_secs: u64,
    },
    /// Enrolls a new authority key.
    EnrollDevice {
        device: DeviceAuthority,
    },
    /// Revokes an authority key.
    RevokeDevice {
        revoked_key: AuthorityKey,
    },
    /// Binds an authority key to an actor-class ceiling.
    SetCeiling {
        authority_key: AuthorityKey,
        actor_class: String,
        ceiling: u8,
    },
    /// Rotates one authority key to another.
    RotateKey {
        old_key: AuthorityKey,
        new_device: DeviceAuthority,
    },
    /// Sets the vault tier floor.
    SetTierFloor {
        tier_floor: AuthorityTier,
    },
    /// Rebootstraps authority after recovery.
    RecoveryReboot {
        new_genesis_nonce: [u8; 32],
        new_device: DeviceAuthority,
        tier_floor: AuthorityTier,
    },
    /// Federation confirm that travels with authority fold verification.
    FederationConfirm(AuthorityConfirmAction),
    CriticalWriteConfirm(CriticalWriteConfirmAction),
    /// Owner veto for a software-tier widen that is still pending.
    VetoPendingWiden {
        /// Target authority entry hash to suppress under most-restrictive-wins.
        pending_widen_hash: AuthorityEntryHash,
    },
    /// Federation relationship lifecycle op (OF-156, option B).
    FederationLifecycle(FederationLifecycleAction),
    /// Binds a roster authority key to a store actor entity at an EXACT actor
    /// class (ONE-1604-D2 tuple). Establishes `epoch` for this key's binding;
    /// rejected in the fold if a live binding already exists (use
    /// `RebindActor`) or the epoch does not advance past the revocation
    /// watermark.
    BindActor {
        /// Roster key the binding attaches to.
        authority_key: AuthorityKey,
        /// Store actor entity the key speaks for.
        actor_ref: EntityId,
        /// EXACT class: `"human"`, `"agent"`, or `"system"`.
        actor_class: String,
        /// Binding epoch; must advance past the revocation watermark.
        epoch: u64,
    },
    /// Replaces the live binding of `authority_key` with a new
    /// actor_ref/class/epoch. Rejected in the fold when no live binding exists.
    RebindActor {
        /// Roster key whose live binding is replaced.
        authority_key: AuthorityKey,
        /// New store actor entity.
        actor_ref: EntityId,
        /// New EXACT class.
        actor_class: String,
        /// New epoch; must be strictly greater than the live binding's.
        epoch: u64,
    },
    /// Revokes the binding of `authority_key` through `epoch` (inclusive
    /// watermark). Applies unconditionally — revocation is always
    /// most-restrictive-safe, in any arrival order.
    RevokeActor {
        /// Roster key whose binding is revoked.
        authority_key: AuthorityKey,
        /// Inclusive revocation watermark.
        epoch: u64,
    },
}

/// A canonical, signed AUTHORITY_LOG entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityLogEntry {
    /// Schema version.
    pub schema_version: u64,
    /// `None` for genesis; `Some(genesis_vault_id)` for all other entries.
    pub vault_id: Option<AuthorityVaultId>,
    /// Per-signer strictly monotonic sequence number.
    pub seq: u64,
    /// Parent entry hashes in the authority DAG.
    pub parent_hashes: Vec<AuthorityEntryHash>,
    /// Operation payload.
    pub op: AuthorityOp,
    /// Primary signer.
    pub signer: AuthoritySignature,
    /// Optional quorum co-signatures.
    pub cosigns: Vec<AuthoritySignature>,
    /// Advisory timestamp. Fold semantics must never branch on this value.
    pub ts: u64,
}

impl AuthorityLogEntry {
    pub(super) fn validate_shape(&self) -> Result<()> {
        if self.schema_version != AUTHORITY_LOG_SCHEMA_VERSION
            || self.parent_hashes.len() > MAX_PARENTS
            || self.cosigns.len() > MAX_COSIGNS
        {
            return Err(invalid_authority());
        }
        let mut parents = self.parent_hashes.clone();
        parents.sort_unstable();
        parents.dedup();
        if parents.len() != self.parent_hashes.len() {
            return Err(invalid_authority());
        }
        match self.op {
            AuthorityOp::Genesis { .. }
                if !self.parent_hashes.is_empty()
                    || self.vault_id.is_some()
                    || !self.cosigns.is_empty() =>
            {
                return Err(invalid_authority());
            }
            AuthorityOp::Genesis { .. } => {}
            _ if self.vault_id.is_none() => return Err(invalid_authority()),
            _ => {}
        }
        validate_op(&self.op)?;
        self.signer.validate()?;
        let mut previous_cosign_key: Option<&AuthorityKey> = None;
        for cosign in &self.cosigns {
            cosign.validate()?;
            if cosign.public_key == self.signer.public_key {
                return Err(invalid_authority());
            }
            if previous_cosign_key.is_some_and(|previous| previous >= &cosign.public_key) {
                return Err(invalid_authority());
            }
            previous_cosign_key = Some(&cosign.public_key);
        }
        Ok(())
    }

    pub(super) fn signer_key(&self) -> &AuthorityKey {
        &self.signer.public_key
    }
}

/// Encodes an authority entry to canonical MessagePack bytes.
pub fn encode_authority_log_entry_body(entry: &AuthorityLogEntry) -> Result<Vec<u8>> {
    entry.validate_shape()?;
    encode_value(&entry_value(entry, true))
}

/// Decodes a canonical authority entry and verifies the embedded origin signature.
pub fn decode_authority_log_entry_body(bytes: &[u8]) -> Result<AuthorityLogEntry> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_authority())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_authority());
    }
    let entry = decode_entry_value(&value)?;
    entry.validate_shape()?;
    let current_canonical = encode_authority_log_entry_body(&entry)?;
    if current_canonical == bytes && verify_entry_signatures_current(&entry).is_ok() {
        return Ok(entry);
    }
    if let Some(legacy_canonical) = legacy_genesis_signed_entry_bytes(&entry)?
        && legacy_canonical == bytes
        && verify_entry_signatures_legacy_genesis(&entry).is_ok()
    {
        return Ok(entry);
    }
    Err(invalid_authority())
}

/// Validates body bytes for write/replay doors.
pub fn validate_authority_log_entry_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_authority_log_entry_body(bytes).map(|_| ())
}

/// BLAKE3 hash of the canonical signed authority entry.
pub fn authority_entry_hash(entry: &AuthorityLogEntry) -> Result<AuthorityEntryHash> {
    let current_canonical = encode_authority_log_entry_body(entry)?;
    if verify_entry_signatures_current(entry).is_err()
        && verify_entry_signatures_legacy_genesis(entry).is_ok()
        && let Some(legacy_canonical) = legacy_genesis_signed_entry_bytes(entry)?
    {
        return Ok(*blake3::hash(&legacy_canonical).as_bytes());
    }
    Ok(*blake3::hash(&current_canonical).as_bytes())
}

/// Content-addressed store key for an AUTHORITY_LOG row: the first 16 bytes
/// of the BLAKE3 [`authority_entry_hash`] (ONE-1604-D1). The store key is a
/// pure function of the canonical signed body, so replacement-at-key cannot
/// edit fold history; `signer + seq` remains the fold GROUPING key (two keys,
/// two jobs). Fails closed on the negligible reserved-sentinel collision.
pub fn authority_log_entity_id_from_hash(hash: &AuthorityEntryHash) -> Result<EntityId> {
    let mut bytes = [0u8; crate::entity_id::ENTITY_ID_LEN];
    bytes.copy_from_slice(&hash[..crate::entity_id::ENTITY_ID_LEN]);
    EntityId::from_bytes(bytes).map_err(|_| {
        Error::InvalidAuthorityLogBody("authority entry hash collides with a reserved entity id")
    })
}

/// Derives the content-addressed entity id for a signed authority entry.
pub fn authority_log_entity_id(entry: &AuthorityLogEntry) -> Result<EntityId> {
    authority_log_entity_id_from_hash(&authority_entry_hash(entry)?)
}

/// BLAKE3 vault id derived from a canonical signed genesis entry.
pub fn genesis_vault_id(entry: &AuthorityLogEntry) -> Result<AuthorityVaultId> {
    if !matches!(entry.op, AuthorityOp::Genesis { .. }) || entry.vault_id.is_some() {
        return Err(invalid_authority());
    }
    authority_entry_hash(entry)
}

/// Domain-separated signature transcript for an authority entry.
pub fn authority_transcript(entry: &AuthorityLogEntry) -> Result<Vec<u8>> {
    authority_transcript_with_genesis_delay(entry, true)
}

pub(super) fn authority_transcript_with_genesis_delay(
    entry: &AuthorityLogEntry,
    include_genesis_delay: bool,
) -> Result<Vec<u8>> {
    let unsigned = encode_value(&transcript_value_with_genesis_delay(
        entry,
        include_genesis_delay,
    ))?;
    let mut transcript = Vec::with_capacity(AUTHORITY_TRANSCRIPT_DOMAIN.len() + unsigned.len());
    transcript.extend_from_slice(AUTHORITY_TRANSCRIPT_DOMAIN);
    transcript.extend_from_slice(&unsigned);
    Ok(transcript)
}

pub(super) fn transcript_value_with_genesis_delay(
    entry: &AuthorityLogEntry,
    include_genesis_delay: bool,
) -> Value {
    Value::Map(vec![
        (
            Value::from("entry"),
            entry_value_with_genesis_delay(entry, false, include_genesis_delay),
        ),
        (Value::from(KEY_SIGNER), key_value(entry.signer_key())),
        (
            Value::from("cosign_keys"),
            Value::Array(
                entry
                    .cosigns
                    .iter()
                    .map(|signature| key_value(&signature.public_key))
                    .collect(),
            ),
        ),
    ])
}

pub(super) fn validate_op(op: &AuthorityOp) -> Result<()> {
    match op {
        AuthorityOp::Genesis {
            device,
            genesis_nonce,
            pending_widen_delay_secs,
            ..
        } => {
            if genesis_nonce.iter().all(|byte| *byte == 0) {
                return Err(invalid_authority());
            }
            validate_pending_widen_delay_secs(*pending_widen_delay_secs)?;
            device.validate()?;
            if !device.can_authority_consent() {
                return Err(invalid_authority());
            }
            Ok(())
        }
        AuthorityOp::EnrollDevice { device } => device.validate(),
        AuthorityOp::RevokeDevice { revoked_key } => revoked_key.validate(),
        AuthorityOp::SetCeiling {
            authority_key,
            actor_class,
            ..
        } => {
            if actor_class.is_empty() || actor_class.len() > MAX_ACTOR_CLASS_BYTES {
                return Err(invalid_authority());
            }
            authority_key.validate()
        }
        AuthorityOp::RotateKey {
            old_key,
            new_device,
        } => {
            old_key.validate()?;
            new_device.validate()?;
            if old_key == &new_device.key {
                return Err(invalid_authority());
            }
            Ok(())
        }
        AuthorityOp::SetTierFloor { .. } | AuthorityOp::FederationConfirm(_) => Ok(()),
        AuthorityOp::CriticalWriteConfirm(action) => {
            if action.schema_version != CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION
                || action.confirm_id.iter().all(|b| *b == 0)
                || action.gate_decision_id.iter().all(|b| *b == 0)
                || action.effect_digest.iter().all(|b| *b == 0)
                || action.read_frontier_hash.iter().all(|b| *b == 0)
                || action.nonce.iter().all(|b| *b == 0)
                || action.expires_at == 0
            {
                Err(invalid_authority())
            } else {
                Ok(())
            }
        }
        AuthorityOp::RecoveryReboot {
            new_genesis_nonce,
            new_device,
            ..
        } => {
            if new_genesis_nonce.iter().all(|byte| *byte == 0) {
                return Err(invalid_authority());
            }
            new_device.validate()?;
            if !new_device.can_authority_consent() {
                return Err(invalid_authority());
            }
            Ok(())
        }
        AuthorityOp::VetoPendingWiden { pending_widen_hash } => {
            if pending_widen_hash.iter().all(|byte| *byte == 0) {
                return Err(invalid_authority());
            }
            Ok(())
        }
        AuthorityOp::FederationLifecycle(action) => validate_federation_lifecycle_action(action),
        AuthorityOp::BindActor {
            authority_key,
            actor_class,
            epoch,
            ..
        }
        | AuthorityOp::RebindActor {
            authority_key,
            actor_class,
            epoch,
            ..
        } => {
            // EXACT class vocabulary, not SetCeiling's free-form string: an
            // unrecognized class must never fold into a binding that some
            // future reader treats as equivalent to "human".
            if !ACTOR_BINDING_CLASSES.contains(&actor_class.as_str()) || *epoch == 0 {
                return Err(invalid_authority());
            }
            authority_key.validate()
        }
        AuthorityOp::RevokeActor {
            authority_key,
            epoch,
        } => {
            if *epoch == 0 {
                return Err(invalid_authority());
            }
            authority_key.validate()
        }
    }
}

fn validate_federation_lifecycle_action(action: &FederationLifecycleAction) -> Result<()> {
    if action.pact_id.iter().all(|byte| *byte == 0)
        || action.pact_nonce.iter().all(|byte| *byte == 0)
        || action.peer_vault_id.iter().all(|byte| *byte == 0)
        || action.pact_epoch == 0
    {
        return Err(invalid_authority());
    }
    let present = (
        action.pact_scope.is_some(),
        action.effective_scope.is_some(),
        action.scope_digest.is_some(),
        action.gesture.is_some(),
        action.successor_vault_id.is_some(),
    );
    // Per-kind optional matrix; Rescope forms are discriminated purely by key
    // presence (repact = pact_scope+scope_digest+gesture, narrow =
    // effective_scope) and a mix fails both.
    let matrix_ok = match action.kind {
        FederationLifecycleKind::Connect => present == (true, false, true, true, false),
        FederationLifecycleKind::Rescope => {
            present == (true, false, true, true, false)
                || present == (false, true, false, false, false)
        }
        FederationLifecycleKind::Disconnect | FederationLifecycleKind::Dissolve => {
            present == (false, false, false, false, false)
        }
        FederationLifecycleKind::Promote => present == (false, false, true, true, true),
    };
    if !matrix_ok {
        return Err(invalid_authority());
    }
    if let Some(scope) = &action.pact_scope {
        let encoded = encode_federation_pact_scope(scope).map_err(|_| invalid_authority())?;
        if encoded.len() > MAX_PACT_SCOPE_BYTES {
            return Err(invalid_authority());
        }
    }
    if let Some(effective) = &action.effective_scope {
        effective.validate().map_err(|_| invalid_authority())?;
    }
    if let Some(successor) = &action.successor_vault_id
        && successor.iter().all(|byte| *byte == 0)
    {
        return Err(invalid_authority());
    }
    if let Some(gesture) = &action.gesture {
        gesture.signer.validate()?;
        if gesture.signature.len() != 64 {
            return Err(invalid_authority());
        }
    }
    Ok(())
}

fn validate_pending_widen_delay_secs(delay_secs: u64) -> Result<()> {
    if (MIN_DEFAULT_PENDING_WIDEN_DELAY_SECS..=MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS)
        .contains(&delay_secs)
    {
        Ok(())
    } else {
        Err(invalid_authority())
    }
}
