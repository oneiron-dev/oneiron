//! Voice-only disclosure widening is an offer, not an authorization.
//! A device/account-authenticated owner must confirm one exact bound. The
//! offer nonce is engine-issued, vault-local, short-lived, and spent atomically
//! with the standing grant and its receipt.

use crate::consent::{AuthenticatedOwner, BoundSubject, ConsentDomain, ConsentReceipt, GrantBound};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::GateError;
use crate::genui::ConsentSurface;
use crate::{Error, Result, Vault};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

const PREFIX: &[u8] = b"genui.voice_grant_offer.v1:";
const OFFER_LIFETIME_SECONDS: u64 = 600;

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
        self.with_write_txn(|txn| {
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
            let receipt = self.create_standing_grant_in_txn(txn, owner, bound)?;
            self.store.vault_meta.delete(txn, &key)?;
            Ok(receipt)
        })
    }
}
