//! A named token agent's own-vault agent binding (PRIVACY-07). ARCH-0028:
//! one name is one agent principal, of class `agent`; ARCH-0052 d5: an agent
//! holds this vault's save grant when it is bound (or is a live AGENT_DEF),
//! and is no contact's.
//!
//! The host root enrolls a software key derived from its own secret for the
//! agent's PERSON and binds the PERSON as `agent` under it, the way it gives
//! an engine MACHINE its key ([`Vault::provision_host_machine_identity`]).
//! The key signs only its own binding: nothing stores or ships its private
//! half. The agent acts through its capability slips, whose connection keys
//! never enter the roster. The binding lands in the writer that grants the
//! agent its ceiling, so a refused grant leaves no binding.

use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::store::GateDecisionRecord;
use crate::store::agent_record::AgentCeiling;
use crate::{EntityId, Vault};

use super::machine_write::denied;
use super::slip_vault::require_host;
use super::{ActorBindingStatus, AuthorityKey, HostSlipIssuer, invalid_authority};

const AGENT_PRINCIPAL_KEY_DOMAIN: &str = "oneiron/agent-principal-authority/v1";
const AGENT_PRINCIPAL_TRANSPORT_DOMAIN: &str = "oneiron/agent-principal-transport/v1";
/// The class an own-vault agent binds as, which `disclosure::is_vault_agent_in` reads.
const AGENT_CLASS: &str = "agent";

fn agent_principal_signing_key(
    issuer: &HostSlipIssuer,
    vault_id: &[u8; 32],
    principal: EntityId,
) -> SigningKey {
    let mut hasher = blake3::Hasher::new_derive_key(AGENT_PRINCIPAL_KEY_DOMAIN);
    hasher.update(vault_id);
    hasher.update(principal.as_bytes());
    hasher.update(issuer.secret());
    let seed = Zeroizing::new(*hasher.finalize().as_bytes());
    SigningKey::from_bytes(&seed)
}

impl Vault {
    /// Binds `principal`, a live PERSON no contact names, as this vault's own
    /// `agent` under a key derived from `issuer`'s secret, and grants it
    /// `ceiling` as [`Vault::grant_agent_principal`] does, in one writer on
    /// the owner's proof: either both land or neither does. The PERSON stays
    /// the room member it is; the binding is what makes it one of the vault's
    /// own agents. A repeat finds the live binding and binds nothing again. A
    /// key whose binding was ever revoked, or that the roster names
    /// otherwise, is refused, so a revoked agent is never bound again by a
    /// new mint.
    ///
    /// # Errors
    ///
    /// A refused owner proof, principal or key, or the grant's own refusal.
    pub fn bind_and_grant_agent_principal(
        &self,
        issuer: &HostSlipIssuer,
        owner: &AuthenticatedOwner,
        principal: EntityId,
        ceiling: AgentCeiling,
    ) -> Result<GateDecisionRecord> {
        self.with_write_txn_grouped(|txn| {
            self.bind_agent_principal_in_txn(txn, issuer, owner, principal)?;
            self.grant_agent_principal_in_txn(txn, owner, &principal.to_hex(), ceiling)
        })
    }

    fn bind_agent_principal_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        owner: &AuthenticatedOwner,
        principal: EntityId,
    ) -> Result<()> {
        owner.revalidate_in_txn(self, txn)?;
        if !crate::consent::person_is_live_in_txn(self, txn, &principal)?
            || !self
                .counterparty_contact_ids_for_identity_in_txn(txn, &principal)?
                .is_empty()
        {
            return Err(denied());
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        require_host(&fold, issuer)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let signing = agent_principal_signing_key(issuer, &vault_id, principal);
        let public_key = signing.verifying_key().to_bytes();
        super::strong_ed25519_key(&public_key).map_err(|_| denied())?;
        let key = AuthorityKey::Ed25519(public_key);
        let bound = fold.actor_bindings.get(&key).is_some_and(|binding| {
            binding.status == ActorBindingStatus::Active
                && binding.actor_ref == principal
                && binding.actor_class == AGENT_CLASS
        });
        if bound {
            return Ok(());
        }
        if fold.roster.contains_key(&key) || fold.actor_bindings.contains_key(&key) {
            return Err(denied());
        }
        let transport = blake3::derive_key(AGENT_PRINCIPAL_TRANSPORT_DOMAIN, &public_key);
        self.land_actor_key_in_txn(
            txn,
            issuer,
            fold,
            principal,
            AGENT_CLASS,
            public_key,
            transport,
            |transcript| Ok(signing.sign(transcript).to_bytes()),
        )
    }
}
