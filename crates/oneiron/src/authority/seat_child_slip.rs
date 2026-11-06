//! FIX 10624: the credential of an official CLI a seat host runs under one
//! claimed BYOA attempt (ARCH-0069 T1, the credential-helper shim).
//!
//! The seat host mints it as the run starts, under the host's issuer, for a
//! per-claim Agent PERSON and a key the host generated for the run. Its
//! signed claims name the claim (`seat_claim`: attempt, lease owner, lease
//! generation) and the secret names the run may ask for (`records`); it
//! carries no verb. General verification never admits it. Its own verifier
//! admits it only while that exact claim holds, and every slip door reads
//! the claim beside the fold's revocation check, so a lost, expired or
//! retried lease ends it at once. The host revokes it at teardown.

use std::collections::BTreeSet;

use super::slip_vault::random_slip_id;
use super::*;
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::entity_id::EntityId;
use crate::error::Result;
use oneiron_authority::federation::{Scope, ScopeAxis};

impl Vault {
    /// Mints the slip of the official CLI run under `claim`, under the
    /// host's `issuer` (FIX 10624). It holds for `holder`, an existing
    /// per-claim Agent PERSON; it binds `holder_key`, the public half of the
    /// key the host generated for this run; it names `records`, the secret
    /// names the run may ask for; it carries no verb; and it ends `ttl_secs`
    /// from now. Refused unless `claim` holds as the mint commits.
    pub fn mint_seat_child_slip(
        &self,
        issuer: &HostSlipIssuer,
        claim: SeatClaimSlipBinding,
        holder: EntityId,
        holder_key: [u8; 32],
        records: BTreeSet<String>,
        ttl_secs: u64,
    ) -> Result<CapabilitySlip> {
        let mut txn = self.store.env.write_txn()?;
        if !self.seat_claim_holds_in_txn(&txn, &claim)?
            || self.get_entity_type_in_txn(&txn, &holder)?
                != Some(crate::registry::ENTITY_TYPE_PERSON)
        {
            return Err(invalid_authority());
        }
        let vault_id = self
            .authority_view_readonly_in_txn(&txn)?
            .vault_id
            .ok_or_else(invalid_authority)?;
        let now = self.instant_in_txn(&txn)?.secs();
        let claims = SlipClaims {
            slip_id: random_slip_id(),
            vault_id,
            parent_id: None,
            holder_ref: holder.to_hex(),
            binding_key: holder_key,
            scope: Scope {
                verbs: ScopeAxis::Bottom,
                ..Scope::top()
            },
            issued_at: now,
            expires_at: now.checked_add(ttl_secs).ok_or_else(invalid_authority)?,
            ttl_secs,
            single_use: false,
            records,
            channels: BTreeSet::new(),
            actor_class: Some("agent".to_owned()),
            org_ref: None,
            grant_ref: None,
            invitation_ref: None,
            delegation: None,
            comm: None,
            trusted_contact: None,
            seat_claim: Some(claim),
        };
        let slip = self.mint_slip_in_txn(&mut txn, issuer, claims)?;
        txn.commit()?;
        Ok(slip)
    }

    /// Verifies a seat-child slip and its holder proof (FIX 10624): the same
    /// host, caveat and holder checks as [`Self::verify_capability_slip`],
    /// admitting only a seat-child slip and returning only the opaque
    /// [`SeatChildCredential`]. Its claim holds in this snapshot; the seat
    /// child's doors recheck it in their acting transaction.
    pub fn verify_seat_child_slip(
        &self,
        host_public_key: &AuthorityKey,
        slip: &CapabilitySlip,
        challenge: &[u8],
        signature: &[u8],
    ) -> Result<SeatChildCredential> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let now = self.instant_in_txn(&txn)?.secs();
        let credential =
            slip.verify_seat_child(host_public_key, &fold, now, challenge, signature)?;
        self.require_live_slip_refs_in_txn(&txn, credential.claims(), now)?;
        Ok(credential)
    }

    /// Whether a seat-child credential verified earlier still holds in `txn`
    /// (FIX 10624): its slip live on this vault's clock and fold, its claim
    /// still held. The seat child's doors recheck it in their acting
    /// transaction, as an owner act rechecks its proof.
    pub fn seat_child_holds_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        credential: &SeatChildCredential,
    ) -> Result<bool> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let now = self.instant_in_txn(txn)?.secs();
        let claims = credential.claims();
        Ok(now >= claims.issued_at
            && now < claims.expires_at
            && fold.vault_id == Some(claims.vault_id)
            && fold.slip_is_live(&claims.slip_id)
            && self.slip_refs_stand_in_txn(txn, claims, now)?)
    }

    /// A seat-child slip stands only while its claim does: the attempt it
    /// names is leased, to that lease owner, at that lease generation, as
    /// every writer acting on a claimed try checks it (FIX 5088). The queue
    /// keeps no lease deadline: a lease ends when a reclaim, retry, cancel
    /// or settle moves the row, and the slip ends with it; its own
    /// `expires_at`, the run's budget, bounds it otherwise. A slip that
    /// names no claim passes.
    pub(super) fn require_live_seat_claim_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claims: &SlipClaims,
    ) -> Result<()> {
        let Some(claim) = &claims.seat_claim else {
            return Ok(());
        };
        if !self.seat_claim_holds_in_txn(txn, claim)? {
            return Err(invalid_authority());
        }
        Ok(())
    }

    fn seat_claim_holds_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claim: &SeatClaimSlipBinding,
    ) -> Result<bool> {
        let attempt = AttemptId::from_bytes(&claim.attempt).map_err(|_| invalid_authority())?;
        AttemptQueue::new(self).holds_lease_in_txn(
            txn,
            attempt,
            &claim.lease_owner,
            claim.attempt_count,
        )
    }
}
