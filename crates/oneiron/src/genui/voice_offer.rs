//! Voice-only disclosure widening is an offer, not an authorization.
//! A device/account-authenticated owner must confirm one exact bound. The
//! offer nonce is engine-issued, vault-local, short-lived, and spent atomically
//! with the standing grant and its receipt.

use crate::consent::{
    AuthenticatedOwner, BoundSubject, ConsentDomain, ConsentReceipt, GrantBound,
    MAX_CONSENT_REF_LEN,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::GateError;
use crate::genui::ConsentSurface;
use crate::{Error, Result, Vault};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

const PREFIX: &[u8] = b"genui.voice_grant_offer.v1:";
const OFFER_LIFETIME_SECONDS: u64 = 600;
const MAX_PENDING_OFFERS: usize = 1024;

/// A displayable offer. Neither the nonce nor the corroborating voice-print
/// result is a credential; only `confirm_voice_grant_offer` can mint a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VoiceGrantOffer {
    pub grant_offer_nonce: String,
    pub owner_voice_print_verified: bool,
    pub principal_ref: String,
    pub bound_digest: String,
    pub expires_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredVoiceOffer {
    version: u8,
    owner_actor: String,
    principal_ref: String,
    bound_digest: String,
    expires_at: u64,
}

fn offer_key(nonce: &str) -> Result<Vec<u8>> {
    if nonce.len() != 64
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(invalid_offer());
    }
    Ok([PREFIX, nonce.as_bytes()].concat())
}

fn invalid_offer() -> Error {
    Error::Gate(GateError::ConsentOwnerNotAuthenticated(
        "voice grant offer is missing, expired, changed, or not owner-confirmed",
    ))
}

impl Vault {
    /// Build a non-authorizing offer from a stored voice roster. The host
    /// supplies the segment locator, never the verification bit. Even a true
    /// match is display corroboration, not speaker authentication: the
    /// beneficiary can spoof voice, so this door does not mint a grant.
    pub fn offer_voice_disclosure_grant(
        &self,
        owner_actor: EntityId,
        principal_ref: &str,
        voice_session_ref: &str,
        segment_id: &str,
        bound: &GrantBound,
    ) -> Result<VoiceGrantOffer> {
        if principal_ref.trim().is_empty()
            || principal_ref.trim() != principal_ref
            || principal_ref.len() > MAX_CONSENT_REF_LEN
            || voice_session_ref.trim().is_empty()
            || segment_id.trim().is_empty()
            || bound.domain() != ConsentDomain::Disclosure
            || !matches!(bound.subject(), BoundSubject::Audience(_))
        {
            return Err(invalid_offer());
        }
        // Missing/corrupt roster is not an owner-attributed offer. An unknown
        // segment can still be displayed as an offer, with verification false.
        let owner_voice_print_verified =
            self.voice_owner_print_verified(voice_session_ref, segment_id, owner_actor)?;
        let expires_at = self
            .now_recorded_at()
            .checked_add(OFFER_LIFETIME_SECONDS)
            .ok_or(Error::ArithmeticOverflow("voice offer expiry"))?;
        let mut random = [0_u8; 32];
        OsRng.fill_bytes(&mut random);
        let grant_offer_nonce = bytes_to_hex_lower(&random);
        let bound_digest = bound.digest().to_hex();
        let row = StoredVoiceOffer {
            version: 1,
            owner_actor: owner_actor.to_hex(),
            principal_ref: principal_ref.to_owned(),
            bound_digest: bound_digest.clone(),
            expires_at,
        };
        let key = offer_key(&grant_offer_nonce)?;
        // Prune in its own committed transaction: rejecting a new offer at
        // capacity must not roll back reclamation of expired rows.
        self.prune_expired_voice_grant_offers()?;
        self.with_write_txn(|txn| {
            let mut pending = 0;
            for entry in self.store.vault_meta.prefix_iter(&*txn, PREFIX)? {
                entry?;
                pending += 1;
                if pending >= MAX_PENDING_OFFERS {
                    return Err(Error::InvalidConfig(
                        "voice grant offer capacity reached".to_owned(),
                    ));
                }
            }
            if self.store.vault_meta.get(&*txn, &key)?.is_some() {
                return Err(invalid_offer());
            }
            self.store.vault_meta.put(
                txn,
                &key,
                &serde_json::to_vec(&row).map_err(|_| invalid_offer())?,
            )?;
            Ok(())
        })?;
        Ok(VoiceGrantOffer {
            grant_offer_nonce,
            owner_voice_print_verified,
            principal_ref: principal_ref.to_owned(),
            bound_digest,
            expires_at,
        })
    }

    /// Remove expired, unconfirmed voice offers from this vault. Safe to call
    /// from maintenance; offer issuance also invokes it before checking the
    /// bounded pending capacity. The transaction commits even when a later
    /// confirmation or issuance is refused.
    pub fn prune_expired_voice_grant_offers(&self) -> Result<usize> {
        let now = self.now_recorded_at();
        self.with_write_txn(|txn| {
            let mut expired = Vec::new();
            for entry in self.store.vault_meta.prefix_iter(&*txn, PREFIX)? {
                let (key, bytes) = entry?;
                let row: StoredVoiceOffer =
                    serde_json::from_slice(&bytes).map_err(|_| invalid_offer())?;
                if row.version != 1 {
                    return Err(invalid_offer());
                }
                if row.expires_at <= now {
                    expired.push(key.to_vec());
                }
            }
            for key in &expired {
                self.store.vault_meta.delete(txn, key)?;
            }
            Ok(expired.len())
        })
    }

    /// Consume an exact offer and mint its disclosure grant in ONE writer.
    /// `surface` is the host's authenticated ingress channel, not an ASR or
    /// shared-room claim. Voice and shared rooms cannot confirm; hosts must
    /// route the owner to a private, device/account-authenticated surface.
    pub fn confirm_voice_grant_offer(
        &self,
        owner: &AuthenticatedOwner,
        grant_offer_nonce: &str,
        bound: GrantBound,
        surface: ConsentSurface,
    ) -> Result<ConsentReceipt> {
        if !super::consent_eval::widening_grant_surface_is_eligible(surface)
            || bound.domain() != ConsentDomain::Disclosure
        {
            return Err(invalid_offer());
        }
        let key = offer_key(grant_offer_nonce)?;
        self.with_write_txn(|txn| {
            let bytes = self
                .store
                .vault_meta
                .get(&*txn, &key)?
                .ok_or_else(invalid_offer)?;
            let row: StoredVoiceOffer =
                serde_json::from_slice(&bytes).map_err(|_| invalid_offer())?;
            if row.version != 1
                || row.owner_actor != owner.actor().to_hex()
                || row.principal_ref != owner.principal_ref()
                || row.bound_digest != bound.digest().to_hex()
                || row.expires_at <= self.now_recorded_at()
            {
                return Err(invalid_offer());
            }
            owner.revalidate_in_txn(self, &*txn)?;
            let receipt = self.create_standing_grant_in_txn(txn, owner, bound)?;
            self.store.vault_meta.delete(txn, &key)?;
            Ok(receipt)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consent::{AudienceBound, DisclosureClass, DisclosureEnvelope};
    use crate::identity_topology::{
        IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp, MergeOp,
        SurvivorshipPlan,
    };
    use crate::ports::ManualClock;
    use crate::registry::ENTITY_TYPE_PERSON;
    use crate::store::GateDecisionId;
    use crate::temporal::TimeRange;

    fn person(vault: &Vault, byte: u8) -> Result<EntityId> {
        let id = crate::test_util::entity(byte);
        vault.put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
        Ok(id)
    }

    fn disclosure() -> Result<GrantBound> {
        GrantBound::disclosure(
            AudienceBound::singleton("contact:friend")?,
            DisclosureClass::new("private")?,
            DisclosureEnvelope::new(["named-set:friends".to_owned()])?,
        )
    }

    fn pending_count(vault: &Vault) -> Result<usize> {
        let rtxn = vault.store.env.read_txn()?;
        let mut count = 0;
        for row in vault.store.vault_meta.prefix_iter(&rtxn, PREFIX)? {
            row?;
            count += 1;
        }
        Ok(count)
    }

    #[test]
    fn cross_axis_bound_substitution_cannot_consume_nonce_or_mint() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
        let actor = person(&vault, 0xC4)?;
        let owner = vault.authenticate_owner(actor, "owner", true, GateDecisionId::now())?;
        let offered = GrantBound::disclosure(
            AudienceBound::singleton("alice")?,
            DisclosureClass::new("health")?,
            DisclosureEnvelope::new(["health".to_owned(), "records".to_owned()])?,
        )?;
        let substituted = GrantBound::disclosure(
            AudienceBound::new(["alice".to_owned(), "health".to_owned()])?,
            DisclosureClass::new("health")?,
            DisclosureEnvelope::new(["records".to_owned()])?,
        )?;
        let offer =
            vault.offer_voice_disclosure_grant(actor, "owner", "room", "segment", &offered)?;
        assert_eq!(offer.bound_digest, offered.digest().to_hex());
        assert_ne!(offer.bound_digest, substituted.digest().to_hex());
        let before_receipts = vault.store.gate_decisions(100)?.len();
        let err = vault
            .confirm_voice_grant_offer(
                &owner,
                &offer.grant_offer_nonce,
                substituted.clone(),
                ConsentSurface::Dashboard,
            )
            .expect_err("extra audience member must not borrow the offered nonce");
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::ConsentOwnerNotAuthenticated
        );
        assert!(
            vault
                .consent_grant(&substituted.digest().to_hex())?
                .is_none()
        );
        assert_eq!(vault.store.gate_decisions(100)?.len(), before_receipts);
        assert_eq!(
            pending_count(&vault)?,
            1,
            "refused substitution cannot spend nonce"
        );

        let receipt = vault.confirm_voice_grant_offer(
            &owner,
            &offer.grant_offer_nonce,
            offered.clone(),
            ConsentSurface::Dashboard,
        )?;
        assert_eq!(
            receipt.grant_ref().as_deref(),
            Some(offer.bound_digest.as_str())
        );
        assert_eq!(
            vault
                .consent_grant(&offer.bound_digest)?
                .expect("offered grant")
                .grant
                .bound(),
            &offered,
        );
        assert!(
            vault
                .consent_grant(&substituted.digest().to_hex())?
                .is_none()
        );
        assert!(
            vault
                .confirm_voice_grant_offer(
                    &owner,
                    &offer.grant_offer_nonce,
                    offered,
                    ConsentSurface::Dashboard,
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn retired_owner_cannot_confirm_cached_offer_or_spend_nonce() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
        let actor = person(&vault, 0xC1)?;
        let survivor = person(&vault, 0xC2)?;
        let owner = vault.authenticate_owner(actor, "owner", true, GateDecisionId::now())?;
        let bound = disclosure()?;
        let offer =
            vault.offer_voice_disclosure_grant(actor, "owner", "room", "segment", &bound)?;
        let op = IdentityTopologyOp::Merge(MergeOp {
            sources: vec![actor],
            survivor,
            evidence: IdentityOpEvidence {
                refs: Vec::new(),
                rationale: "retire owner fixture".to_owned(),
            },
            survivorship_plan: SurvivorshipPlan::ReadThrough,
        });
        assert!(matches!(
            vault.apply_identity_topology_op(
                &op,
                &IdentityOpWrite::auto(crate::claim::ClaimSource::Inferred),
                200,
            )?,
            IdentityOpOutcome::Applied { .. }
        ));
        assert!(
            vault
                .authenticate_owner(actor, "owner", true, GateDecisionId::now())
                .is_err()
        );
        let before_receipts = vault.store.gate_decisions(100)?.len();
        let err = vault
            .confirm_voice_grant_offer(
                &owner,
                &offer.grant_offer_nonce,
                bound.clone(),
                ConsentSurface::Dashboard,
            )
            .expect_err("retired owner handle must not mint");
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::ConsentOwnerNotAuthenticated
        );
        assert!(vault.consent_grant(&bound.digest().to_hex())?.is_none());
        assert_eq!(vault.store.gate_decisions(100)?.len(), before_receipts);
        assert_eq!(
            pending_count(&vault)?,
            1,
            "failed confirm must not spend nonce"
        );
        Ok(())
    }

    #[test]
    fn expired_offers_are_reclaimed_and_live_offer_still_confirms_once() -> Result<()> {
        let clock = ManualClock::new(1_000_000);
        let mut config = crate::VaultConfig::device();
        config.store_clock = clock.bundle();
        let (_dir, vault) = crate::test_util::open_test_vault_with(config);
        let actor = person(&vault, 0xC3)?;
        let bound = disclosure()?;
        assert!(
            vault
                .offer_voice_disclosure_grant(
                    actor,
                    &"x".repeat(MAX_CONSENT_REF_LEN + 1),
                    "room",
                    "oversized",
                    &bound,
                )
                .is_err()
        );
        assert_eq!(pending_count(&vault)?, 0);
        let first = vault.offer_voice_disclosure_grant(actor, "owner", "room", "one", &bound)?;
        let second = vault.offer_voice_disclosure_grant(actor, "owner", "room", "two", &bound)?;
        assert_eq!(pending_count(&vault)?, 2);
        clock.set(first.expires_at);
        let owner = vault.authenticate_owner(actor, "owner", true, GateDecisionId::now())?;
        assert!(
            vault
                .confirm_voice_grant_offer(
                    &owner,
                    &first.grant_offer_nonce,
                    bound.clone(),
                    ConsentSurface::Dashboard,
                )
                .is_err()
        );
        assert_eq!(
            pending_count(&vault)?,
            2,
            "failed confirmation cannot commit deletion"
        );
        let live = vault.offer_voice_disclosure_grant(actor, "owner", "room", "new", &bound)?;
        assert_eq!(
            pending_count(&vault)?,
            1,
            "issuance prunes both expired offers"
        );
        assert_eq!(vault.prune_expired_voice_grant_offers()?, 0);
        assert_ne!(first.grant_offer_nonce, live.grant_offer_nonce);
        assert_ne!(second.grant_offer_nonce, live.grant_offer_nonce);
        assert!(
            vault
                .confirm_voice_grant_offer(
                    &owner,
                    &first.grant_offer_nonce,
                    bound.clone(),
                    ConsentSurface::Dashboard,
                )
                .is_err()
        );
        let receipt = vault.confirm_voice_grant_offer(
            &owner,
            &live.grant_offer_nonce,
            bound.clone(),
            ConsentSurface::Dashboard,
        )?;
        let grant_ref = bound.digest().to_hex();
        assert_eq!(receipt.grant_ref().as_deref(), Some(grant_ref.as_str()));
        assert!(
            vault
                .confirm_voice_grant_offer(
                    &owner,
                    &live.grant_offer_nonce,
                    bound,
                    ConsentSurface::Dashboard,
                )
                .is_err()
        );
        assert_eq!(pending_count(&vault)?, 0);
        Ok(())
    }
}
