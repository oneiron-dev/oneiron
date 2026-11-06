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
    /// names the run may ask for; it carries no verb; `model_door` gives it
    /// the model door's channel ([`SEAT_MODEL_CHANNEL`], FIX 15702), and no
    /// other channel rides it; and it ends `ttl_secs` from now. Refused
    /// unless `claim` holds as the mint commits.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_seat_child_slip(
        &self,
        issuer: &HostSlipIssuer,
        claim: SeatClaimSlipBinding,
        holder: EntityId,
        holder_key: [u8; 32],
        records: BTreeSet<String>,
        model_door: bool,
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
            channels: if model_door {
                BTreeSet::from([SEAT_MODEL_CHANNEL.to_owned()])
            } else {
                BTreeSet::new()
            },
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

    /// Admits one request a seat child signed with its slip (FIX 10624): the
    /// same holder proof and request challenge as
    /// [`Self::admit_capability_slip_request`], admitting only a seat-child
    /// slip whose claim holds, and spending the request's nonce in the same
    /// writer, so a replayed request is refused.
    pub fn admit_seat_child_slip_request(
        &self,
        slip: &CapabilitySlip,
        timestamp: u64,
        signature: &[u8],
        nonce: &[u8],
    ) -> Result<SeatChildCredential> {
        let _spend_guard = super::slip_replay::spend_guard(self)?;
        let mut txn = self.store.env.write_txn()?;
        let request_now = super::slip_replay::admission_now_in_txn(self, &mut txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let now = self.instant_in_txn(&txn)?.secs();
        let challenge = super::slip_replay::request_challenge(timestamp, nonce, request_now)?;
        let key = &fold
            .slips
            .mints
            .get(&slip.claims.slip_id)
            .ok_or_else(invalid_authority)?
            .signer;
        let credential = slip.verify_seat_child(key, &fold, now, &challenge, signature)?;
        self.require_live_slip_refs_in_txn(&txn, credential.claims(), now)?;
        super::slip_replay::record_nonce(
            self,
            &mut txn,
            &slip.current_binding_key(),
            nonce,
            timestamp,
            request_now,
        )?;
        txn.commit()?;
        Ok(credential)
    }

    /// Whether the model door would release `secret_ref` for `credential`'s
    /// run now (FIX 15702), checked without reading its value: the slip
    /// carries the model door's channel and names the secret in its signed
    /// records, its claim holds, and the custody door would release the
    /// secret to [`SEAT_MODEL_CHANNEL`], all on one snapshot.
    pub fn check_seat_model_key(
        &self,
        credential: &SeatChildCredential,
        secret_ref: &str,
    ) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        if !self.seat_model_key_admitted_in_txn(&txn, credential, secret_ref)? {
            return Err(invalid_authority());
        }
        self.check_secret_at_door_in_txn(&txn, secret_ref, SEAT_MODEL_CHANNEL)
    }

    /// The model door's T0 key release for a seat child (FIX 15702): the
    /// checks of [`Self::check_seat_model_key`] and the value copy in one
    /// writer, so a claim lost, a slip revoked or a secret's binding changed
    /// before it refuses the copy. `apply` runs with the value once the
    /// writer is released, as at every T0 door; the key goes to the broker,
    /// never to the seat.
    pub fn inject_seat_model_key(
        &self,
        credential: &SeatChildCredential,
        secret_ref: &str,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<crate::secret_lease::DoorInjectionReceipt> {
        let wtxn = self.store.env.write_txn()?;
        if !self.seat_model_key_admitted_in_txn(&wtxn, credential, secret_ref)? {
            return Err(invalid_authority());
        }
        self.inject_secret_at_door_in_txn(wtxn, secret_ref, SEAT_MODEL_CHANNEL, apply)
    }

    fn seat_model_key_admitted_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        credential: &SeatChildCredential,
        secret_ref: &str,
    ) -> Result<bool> {
        Ok(credential.admits_model_door()
            && credential.records().contains(secret_ref)
            && self.seat_child_holds_in_txn(txn, credential)?)
    }

    /// [`Self::seat_child_holds_in_txn`] in its own snapshot, for a door that
    /// checks the claim again before it hands a value out.
    pub fn seat_child_holds(&self, credential: &SeatChildCredential) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        self.seat_child_holds_in_txn(&txn, credential)
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
