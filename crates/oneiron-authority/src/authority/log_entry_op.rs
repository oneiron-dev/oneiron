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
use crate::error::RecordError;

/// Pinned operation vocabulary for AUTHORITY_LOG.
// The FederationLifecycle payload (scope pair + gesture) dominates the enum
// size; its unboxed shape is pinned by ONE-1408, so the skew is accepted.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityOp {
    /// Mints a vault capability under its claims.slip_id; no MAC is stored in history.
    SlipMint(SlipMintAction),
    /// Revokes a capability and every descendant in the slip-id namespace.
    SlipRevoke {
        slip_id: [u8; 32],
    },
    /// Durably consumes a capability in the slip-id namespace.
    SlipConsume {
        slip_id: [u8; 32],
    },
    /// Vault genesis. `vault_id` is `None` on the containing entry and is
    /// derived as BLAKE3(canonical signed genesis).
    Genesis {
        device: DeviceAuthority,
        genesis_nonce: [u8; 32],
        recovery: GenesisRecoveryStep,
    },
    /// Enrolls a new authority key.
    EnrollDevice {
        device: DeviceAuthority,
    },
    /// Revokes an authority key.
    RevokeDevice {
        revoked_key: AuthorityKey,
    },
    /// Rotates one authority key to another.
    RotateKey {
        old_key: AuthorityKey,
        new_device: DeviceAuthority,
    },
    /// In-chain host migration. Replaces the roster without a new genesis.
    ReRoot {
        new_device: DeviceAuthority,
    },
    /// Federation confirm that travels with authority fold verification.
    FederationConfirm(AuthorityConfirmAction),
    CriticalWriteConfirm(CriticalWriteConfirmAction),
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
    /// One revision of a physical machine's standing: the owner's answer at
    /// the pairing ceremony, signed by an owner roster key.
    MachineProfile(MachineProfile),
    /// An owner recovery root, signed by its own anchor (world privacy P6b).
    OwnerRoot(OwnerRootRecord),
    /// One owner edit of a world's settings, signed by the install key of a
    /// machine the owner marked "yours". A side-branch entry: no entry but a
    /// later edit of the same world takes it as a parent.
    WorldPrivacy(WorldPrivacyEdit),
    /// One machine's wraps of one world key, signed by that machine's install
    /// key. A side-branch entry of the key's world, like its settings edits.
    WorldKeyWraps(WorldKeyWrapsRecord),
    /// An Owner handover in a shared vault: an Owner leaving names a
    /// successor or signs their own removal, signed by an owner roster key
    /// like any Owner action (ARCH-0043, OF-163).
    OwnerHandover(OwnerHandover),
    /// An owner's residence directive to one of their machines, signed by an
    /// owner roster key like any owner act through the host (OF-534).
    ResidenceDirective(ResidenceDirective),
    /// A machine's result for a residence directive, signed by the install
    /// key of the machine it names, with the directive among its parents.
    ResidenceResult(ResidenceResult),
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
    /// Public so `oneiron`'s authority code calls it across the crate line.
    pub fn validate_shape(&self) -> Result<()> {
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
        match &self.op {
            AuthorityOp::OwnerRoot(record) => record.validate_entry(self)?,
            AuthorityOp::WorldKeyWraps(record) => record.validate_entry(self)?,
            AuthorityOp::ResidenceResult(result) => result.validate_entry(self)?,
            _ => {}
        }
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

    /// Public so `oneiron`'s authority code calls it across the crate line.
    pub fn signer_key(&self) -> &AuthorityKey {
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
    let canonical = encode_authority_log_entry_body(&entry)?;
    if canonical == bytes && verify_entry_signatures(&entry).is_ok() {
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
    let canonical = encode_authority_log_entry_body(entry)?;
    Ok(*blake3::hash(&canonical).as_bytes())
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
        Error::Record(RecordError::InvalidAuthorityLogBody(
            "authority entry hash collides with a reserved entity id",
        ))
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
    let unsigned = encode_value(&transcript_value(entry))?;
    let mut transcript = Vec::with_capacity(AUTHORITY_TRANSCRIPT_DOMAIN.len() + unsigned.len());
    transcript.extend_from_slice(AUTHORITY_TRANSCRIPT_DOMAIN);
    transcript.extend_from_slice(&unsigned);
    Ok(transcript)
}

pub fn transcript_value(entry: &AuthorityLogEntry) -> Value {
    Value::Map(vec![
        (Value::from("entry"), entry_value(entry, false)),
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

pub fn validate_op(op: &AuthorityOp) -> Result<()> {
    match op {
        AuthorityOp::SlipMint(action) => action.validate(),
        AuthorityOp::SlipRevoke { slip_id } | AuthorityOp::SlipConsume { slip_id } => {
            if *slip_id == [0; 32] {
                return Err(invalid_authority());
            }
            Ok(())
        }
        AuthorityOp::Genesis {
            device,
            genesis_nonce,
            recovery,
        } => {
            if genesis_nonce.iter().all(|byte| *byte == 0) {
                return Err(invalid_authority());
            }
            recovery.validate()?;
            device.validate()?;
            if !device.can_authority_consent() {
                return Err(invalid_authority());
            }
            Ok(())
        }
        AuthorityOp::EnrollDevice { device } => device.validate(),
        AuthorityOp::RevokeDevice { revoked_key } => revoked_key.validate(),
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
        AuthorityOp::FederationConfirm(action) => {
            if action.confirm_id == [0; 32]
                || action.nonce == [0; 16]
                || action.peer_vault_id == [0; 32]
            {
                Err(invalid_authority())
            } else {
                Ok(())
            }
        }
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
        AuthorityOp::ReRoot { new_device } => {
            new_device.validate()?;
            if !new_device.can_authority_consent() {
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
            // EXACT class vocabulary: an
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
        AuthorityOp::MachineProfile(profile) => profile.validate(),
        AuthorityOp::OwnerRoot(record) => record.validate(),
        AuthorityOp::WorldPrivacy(edit) => edit.settings.validate(),
        AuthorityOp::WorldKeyWraps(record) => record.validate(),
        AuthorityOp::OwnerHandover(handover) => handover.validate(),
        AuthorityOp::ResidenceDirective(directive) => directive.validate(),
        AuthorityOp::ResidenceResult(result) => result.validate(),
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
