//! Capability-slip payloads as the authority log commits them: the claims a host mints and
//! their shape and narrowing checks. Signing, holder proof and the verified view stay in
//! `oneiron::authority` (`CapabilitySlip`, `VerifiedSlip`); nothing here verifies a slip.

use std::collections::BTreeSet;

use ed25519_dalek::VerifyingKey;
use oneiron_contracts::error::Result;
use serde::{Deserialize, Serialize};

use super::invalid_authority;
use crate::federation::Scope;

/// Upper bound on a slip's wire form; claims may use at most half of it.
pub const MAX_WIRE_BYTES: usize = 65_536;

/// The immutable, authority-log-committed part of a slip. No secret is stored here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlipClaims {
    pub slip_id: [u8; 32],
    pub vault_id: [u8; 32],
    pub parent_id: Option<[u8; 32]>,
    pub holder_ref: String,
    pub binding_key: [u8; 32],
    pub scope: Scope,
    pub issued_at: u64,
    pub expires_at: u64,
    pub ttl_secs: u64,
    pub single_use: bool,
    /// Exact named secret/repository bounds for credential-door operations.
    pub records: BTreeSet<String>,
    /// Exact named credential-door effectors. Empty means no door channel.
    pub channels: BTreeSet<String>,
    pub actor_class: Option<String>,
    pub org_ref: Option<String>,
}

/// The signed SlipMint payload. The credential signature is not log material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlipMintAction {
    pub claims: SlipClaims,
}
impl SlipMintAction {
    pub fn validate(&self) -> Result<()> {
        self.claims.validate()
    }
}
impl SlipClaims {
    pub fn validate(&self) -> Result<()> {
        if self.slip_id == [0; 32]
            || self.vault_id == [0; 32]
            || self.parent_id == Some(self.slip_id)
            || self.parent_id == Some([0; 32])
            || self.holder_ref.is_empty()
            || self.holder_ref.len() > 256
            || self.issued_at >= self.expires_at
            || self.ttl_secs == 0
            || self.ttl_secs > self.expires_at - self.issued_at
            || (self.single_use
                && self.expires_at - self.issued_at
                    > crate::credential_door::DOOR_ONE_SHOT_MAX_LIFETIME_SECS)
            || matches!(&self.scope.verbs, crate::federation::ScopeAxis::Some(verbs)
                if verbs.iter().any(|verb| crate::credential_door::names_a_floor(verb)))
            || VerifyingKey::from_bytes(&self.binding_key).is_err()
            || self
                .actor_class
                .as_deref()
                .is_some_and(|v| !super::ACTOR_BINDING_CLASSES.contains(&v))
            || self
                .org_ref
                .as_deref()
                .is_some_and(|v| oneiron_contracts::EntityId::from_hex(v).is_err())
            || self
                .records
                .iter()
                .chain(self.channels.iter())
                .any(|v| v.is_empty() || v.len() > 512 || crate::credential_door::names_a_floor(v))
            || canonical(self)?.len() > MAX_WIRE_BYTES / 2
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
    /// True when `self` is a valid narrowing of `parent`. Public so `oneiron`'s slip
    /// verifier (its one caller outside this crate) checks caveat chains across the line.
    pub fn narrows(&self, parent: &Self) -> bool {
        self.vault_id == parent.vault_id
            && self.scope.is_narrowing_of(&parent.scope)
            && self.issued_at >= parent.issued_at
            && self.expires_at <= parent.expires_at
            && self.ttl_secs <= parent.ttl_secs
            && (!parent.single_use || self.single_use)
            && self.binding_key == parent.binding_key
            && self.holder_ref == parent.holder_ref
            && self.actor_class == parent.actor_class
            && self.org_ref == parent.org_ref
            && (self.records == parent.records
                || (!self.records.is_empty()
                    && ((parent.records.is_empty() && parent.channels.is_empty())
                        || self.records.is_subset(&parent.records))))
            && (self.channels == parent.channels
                || (!self.channels.is_empty() && self.channels.is_subset(&parent.channels)))
    }
}

/// Canonical JSON bytes of a slip value: the bytes slip transcripts and size bounds use.
pub fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| invalid_authority())
}
