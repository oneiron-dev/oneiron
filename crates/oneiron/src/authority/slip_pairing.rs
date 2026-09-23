//! Single-use pairing links bind a throwaway key and mint one log-backed slip.
use super::slip::{canonical, hex, unhex};
use super::slip_vault::{random_slip_id, require_host};
use super::*;
use crate::Vault;
use crate::error::Result;
use crate::federation::{OrgAdminPolicy, OrgAdminPower, Scope, ScopeAxis};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Pairing descriptor is public liveness, not a credential or authority claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingDescriptor {
    pub protocol: String,
    pub slip_version: u8,
    pub binding: String,
    pub pairing_endpoint: String,
}
impl Default for PairingDescriptor {
    fn default() -> Self {
        Self {
            protocol: "oneiron-pairing".into(),
            slip_version: 2,
            binding: "ed25519".into(),
            pairing_endpoint: "/v1/core/pairing/redeem".into(),
        }
    }
}
/// A link/QR payload. The opaque ticket is random and stored only as a hash.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingLink {
    pub ticket: String,
    pub expires_at: u64,
}
/// Owner-approved identity constraints. Redemption can choose a connection key,
/// but cannot replace these claims or add organization authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingPrincipal {
    pub holder_ref: Option<String>,
    pub actor_class: Option<String>,
    pub org_ref: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairingPending {
    expires_at: u64,
    slip_lifetime_secs: u64,
    scope: Scope,
    host_key: [u8; 32],
    principal: PairingPrincipal,
}

/// Client signs this transcript with its newly generated connection key.
/// Ticket possession without that private key cannot authenticate the result.
pub fn pairing_binding_transcript(
    ticket: &str,
    binding_key: &[u8; 32],
    holder_ref: &str,
) -> Result<Vec<u8>> {
    let ticket = unhex(ticket)?;
    if ticket.len() != 32 || holder_ref.is_empty() || holder_ref.len() > 256 {
        return Err(invalid_authority());
    }
    let mut msg = b"oneiron/pairing-binding/v2\0".to_vec();
    msg.extend_from_slice(&ticket);
    msg.extend_from_slice(binding_key);
    msg.extend_from_slice(holder_ref.as_bytes());
    Ok(msg)
}
fn pairing_key(ticket: &str) -> Result<String> {
    let bytes = unhex(ticket)?;
    if bytes.len() != 32 {
        return Err(invalid_authority());
    }
    Ok(format!(
        "authority:pairing:{}",
        blake3::hash(&bytes).to_hex()
    ))
}
impl Vault {
    /// Owner/host API: issue a five-minute enrollment link, scoped at creation.
    pub fn issue_pairing_link(
        &self,
        issuer: &HostSlipIssuer,
        scope: Scope,
        slip_lifetime_secs: u64,
    ) -> Result<PairingLink> {
        self.issue_pairing_link_for_principal(
            issuer,
            scope,
            slip_lifetime_secs,
            PairingPrincipal::default(),
        )
    }
    /// Owner/host enrollment with identity claims fixed before ticket delivery.
    /// Organization tickets require a registered admin and an explicit subset
    /// of the organization's immutable administration policy.
    pub fn issue_pairing_link_for_principal(
        &self,
        issuer: &HostSlipIssuer,
        scope: Scope,
        slip_lifetime_secs: u64,
        principal: PairingPrincipal,
    ) -> Result<PairingLink> {
        if slip_lifetime_secs == 0 || slip_lifetime_secs > 365 * 24 * 60 * 60 {
            return Err(invalid_authority());
        }
        let mut txn = self.store.env.write_txn()?;
        require_host(&self.authority_fold_readonly_in_txn(&txn)?, issuer)?;
        self.validate_pairing_principal_in_txn(&txn, &principal, &scope)?;
        let now = self.instant_in_txn(&txn)?.secs();
        let ticket = hex(&random_slip_id());
        let expires_at = now.saturating_add(300);
        let pending = PairingPending {
            expires_at,
            slip_lifetime_secs,
            scope,
            host_key: issuer.binding_key(),
            principal,
        };
        self.store
            .sync_state
            .put(&mut txn, &pairing_key(&ticket)?, &canonical(&pending)?)?;
        txn.commit()?;
        Ok(PairingLink { ticket, expires_at })
    }
    /// No prior bearer is required. The link is the one-use enrollment grant;
    /// the binding signature proves possession of the receiving connection key.
    /// Consuming the link and appending SlipMint are one LMDB transaction.
    pub fn redeem_pairing_link(
        &self,
        issuer: &HostSlipIssuer,
        ticket: &str,
        holder_ref: &str,
        binding_key: [u8; 32],
        signature: &[u8],
    ) -> Result<CapabilitySlip> {
        let key = VerifyingKey::from_bytes(&binding_key).map_err(|_| invalid_authority())?;
        let signature = Signature::from_slice(signature).map_err(|_| invalid_authority())?;
        key.verify_strict(
            &pairing_binding_transcript(ticket, &binding_key, holder_ref)?,
            &signature,
        )
        .map_err(|_| invalid_authority())?;
        let mut txn = self.store.env.write_txn()?;
        let now = self.instant_in_txn(&txn)?.secs();
        let row_key = pairing_key(ticket)?;
        let raw = self
            .store
            .sync_state
            .get(&txn, &row_key)?
            .ok_or_else(invalid_authority)?;
        let pending: PairingPending =
            serde_json::from_slice(&raw).map_err(|_| invalid_authority())?;
        if now >= pending.expires_at || pending.host_key != issuer.binding_key() {
            return Err(invalid_authority());
        }
        if pending
            .principal
            .holder_ref
            .as_deref()
            .is_some_and(|intended| intended != holder_ref)
        {
            return Err(invalid_authority());
        }
        self.validate_pairing_principal_in_txn(&txn, &pending.principal, &pending.scope)?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        require_host(&fold, issuer)?;
        let claims = SlipClaims {
            slip_id: random_slip_id(),
            vault_id: fold.vault_id.ok_or_else(invalid_authority)?,
            parent_id: None,
            holder_ref: holder_ref.to_owned(),
            binding_key,
            scope: pending.scope,
            issued_at: now,
            expires_at: now.saturating_add(pending.slip_lifetime_secs),
            ttl_secs: pending.slip_lifetime_secs,
            single_use: false,
            records: Default::default(),
            channels: Default::default(),
            actor_class: pending.principal.actor_class,
            org_ref: pending.principal.org_ref,
        };
        let slip = self.mint_slip_in_txn(&mut txn, issuer, claims)?;
        self.store.sync_state.delete(&mut txn, &row_key)?;
        txn.commit()?;
        Ok(slip)
    }
    fn validate_pairing_principal_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        principal: &PairingPrincipal,
        scope: &Scope,
    ) -> Result<()> {
        if principal
            .actor_class
            .as_deref()
            .is_some_and(|class| !matches!(class, "human" | "agent" | "system"))
        {
            return Err(invalid_authority());
        }
        let holder = principal
            .holder_ref
            .as_deref()
            .map(|holder| {
                let id = crate::EntityId::from_hex(holder).map_err(|_| invalid_authority())?;
                if id.to_hex() != holder {
                    return Err(invalid_authority());
                }
                Ok(id)
            })
            .transpose()?;
        let Some(org_ref) = principal.org_ref.as_deref() else {
            // All verbs without an org is a general root, not an org credential.
            if matches!(&scope.verbs, ScopeAxis::Some(verbs) if verbs.iter().any(|verb| verb.starts_with("org:")))
            {
                return Err(invalid_authority());
            }
            return Ok(());
        };
        let org = crate::EntityId::from_hex(org_ref).map_err(|_| invalid_authority())?;
        if org.to_hex() != org_ref {
            return Err(invalid_authority());
        }
        let admin = holder.ok_or_else(invalid_authority)?;
        if self.store.entities.get(txn, admin.as_bytes())?.is_none()
            || self.archive_tombstone_in_txn(txn, &admin)?.is_some()
        {
            return Err(invalid_authority());
        }
        let ScopeAxis::Some(verbs) = &scope.verbs else {
            return Err(invalid_authority());
        };
        if verbs.is_empty() {
            return Err(invalid_authority());
        }
        // Read the fixed setup in the same snapshot as the enrollment/mint.
        let key = format!("org.admin.v1.{}", org.to_hex());
        let raw = self
            .store
            .vault_meta
            .get(txn, key.as_bytes())?
            .ok_or_else(invalid_authority)?;
        let policy: OrgAdminPolicy =
            serde_json::from_slice(&raw).map_err(|_| invalid_authority())?;
        if policy.org_ref() != org {
            return Err(invalid_authority());
        }
        for verb in verbs {
            let power = OrgAdminPower::parse(verb).ok_or_else(invalid_authority)?;
            policy
                .authorize(admin, power)
                .map_err(|_| invalid_authority())?;
        }
        Ok(())
    }
}
