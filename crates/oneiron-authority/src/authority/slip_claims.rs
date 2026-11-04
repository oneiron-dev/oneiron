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
    /// The FEDERATION_GRANT (entity id hex) a guest slip was minted under
    /// (OF-232); revoking that grant tombstones the slip. Delegation keeps it.
    pub grant_ref: Option<String>,
    /// The shared-vault invitation (entity id hex) an invitee's slip was
    /// minted with (FIX 1925): it admits only that invitation's own doors and
    /// stands only while the invitation is pending. Delegation keeps it.
    pub invitation_ref: Option<String>,
    /// The customer's support delegation (OF-606): set only on a support
    /// slip, which stands only while its signed wall deadline holds on the
    /// recording clock as well. A support slip has no parent and no child,
    /// and delegation keeps it unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<super::SupportDelegation>,
    /// Whom the slip's holder may message (FIX 3899): a ceiling the owner
    /// set at mint, never at redeem or message time. `None` is the
    /// vault-wide reach ([`super::effective_slip_comm`], CALLS C5). A bound
    /// run's reach is the narrower of its own and this; a caveat only
    /// lowers it, and delegation keeps it or narrows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comm: Option<super::CommReach>,
}

/// The signed SlipMint payload. The credential signature is not log material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlipMintAction {
    pub claims: SlipClaims,
    /// The slip this mint renews (FIX 5481): set only on an owner device's
    /// renewal, which is parentless, so a lineage walk follows the renewed
    /// credential back to the one it replaced. A lineage link, never a
    /// parent: no narrowing check, revocation, consumption or liveness walk
    /// crosses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renews: Option<[u8; 32]>,
}
impl SlipMintAction {
    pub fn validate(&self) -> Result<()> {
        // A renewal names another, real slip and has no parent of its own.
        if self.renews.is_some_and(|prior| {
            prior == self.claims.slip_id || prior == [0; 32] || self.claims.parent_id.is_some()
        }) {
            return Err(invalid_authority());
        }
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
            || [&self.org_ref, &self.grant_ref, &self.invitation_ref]
                .into_iter()
                .any(|id| {
                    id.as_deref()
                        .is_some_and(|v| oneiron_contracts::EntityId::from_hex(v).is_err())
                })
            || self
                .records
                .iter()
                .chain(self.channels.iter())
                .any(|v| v.is_empty() || v.len() > 512 || crate::credential_door::names_a_floor(v))
            || canonical(self)?.len() > MAX_WIRE_BYTES / 2
        {
            return Err(invalid_authority());
        }
        self.validate_support_delegation()
    }
    /// A support slip (OF-606) is one holder PERSON's own, minted with no
    /// parent, at the human or agent class, under no other grant, org or
    /// invitation, inside the support bounds
    /// ([`super::support_scope_admissible`]). Its holder is never the owner
    /// who approved it.
    fn validate_support_delegation(&self) -> Result<()> {
        let Some(delegation) = &self.delegation else {
            return Ok(());
        };
        delegation.validate()?;
        let holder_is_person = oneiron_contracts::EntityId::from_hex(&self.holder_ref)
            .is_ok_and(|id| id.to_hex() == self.holder_ref);
        if !holder_is_person
            || self.holder_ref == delegation.owner_ref
            || self.parent_id.is_some()
            || !matches!(self.actor_class.as_deref(), Some("human" | "agent"))
            || self.org_ref.is_some()
            || self.grant_ref.is_some()
            || self.invitation_ref.is_some()
            || super::support_scope_admissible(&self.scope, &self.records, &self.channels).is_err()
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
    /// Whether these claims are a full-vault owner-grade instrument, not
    /// merely `core:read`: the vault-wide comm reach (FIX 3899), the top
    /// scope, no org, record or channel bound, and reusable. `oneiron`'s
    /// verified view asks it of an unattenuated presentation; a host
    /// action's durable identity asks it of its root's own mint (FIX 7231).
    #[must_use]
    pub fn is_full_vault_owner_grade(&self) -> bool {
        super::effective_slip_comm(self.comm) == super::CommReach::Vault
            && self.scope == Scope::top()
            && self.org_ref.is_none()
            && self.records.is_empty()
            && self.channels.is_empty()
            && !self.single_use
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
            && self.grant_ref == parent.grant_ref
            && self.invitation_ref == parent.invitation_ref
            && self.delegation == parent.delegation
            // An absent reach is the vault's, so a child that names none
            // never erases a narrower parent (FIX 3899).
            && super::effective_slip_comm(self.comm) <= super::effective_slip_comm(parent.comm)
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
