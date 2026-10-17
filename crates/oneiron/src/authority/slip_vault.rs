//! Host-root bootstrap and atomic authority-log capability issuance.
use super::*;
use crate::Vault;
use crate::error::Result;
use crate::federation::Scope;
use crate::secret_lease::VaultInstant;
use crate::side_table::{self, Raw, SideTable};
use crate::temporal::TimeRange;
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

mod courtesy;

const ROOT_LIFETIME: u64 = 10 * 365 * 24 * 60 * 60;
/// The attestation a host's own root roster row carries.
pub(super) const HOST_ROOT_ATTESTATION: &str = "HostRoot";

/// Cached minted host-root capability-slip token for one host signing key. Key: `:` + hex64.
const HOST_ROOT_SLIP_CACHE: SideTable<String, String, Raw> =
    SideTable::new(&side_table::AUTHORITY_HOST_ROOT_SLIP_CACHE);

/// A dedicated host signing key. Never loaded from device-key residue.
/// The configured retained root secret is the recovery material for bootstrap.
pub struct HostSlipIssuer {
    secret: Zeroizing<Vec<u8>>,
    signing: SigningKey,
}
impl HostSlipIssuer {
    pub fn from_secret(secret: &[u8]) -> Result<Self> {
        if secret.is_empty() {
            return Err(invalid_authority());
        }
        let seed = Zeroizing::new(blake3::derive_key(
            "oneiron/host-authority-signing/v2",
            secret,
        ));
        Ok(Self {
            secret: Zeroizing::new(secret.to_vec()),
            signing: SigningKey::from_bytes(&seed),
        })
    }
    #[must_use]
    pub fn public_key(&self) -> AuthorityKey {
        AuthorityKey::Ed25519(self.binding_key())
    }
    #[must_use]
    pub fn binding_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }
    /// The roster row this host's key holds as the vault's root. A Hosted root is
    /// stamped `ROLE_CLOUD` and `CloudCustodial`: the host holds it, so it never counts
    /// as an owner-held key (E2). That is a fact in the log, so every replica's fold
    /// sees it.
    pub(super) fn root_device(&self, posture: crate::HostingPrivacyPosture) -> DeviceAuthority {
        let (cloud, tier) = if posture == crate::HostingPrivacyPosture::Hosted {
            (ROLE_CLOUD, AuthorityTier::CloudCustodial)
        } else {
            (0, AuthorityTier::Software)
        };
        DeviceAuthority {
            key: self.public_key(),
            transport_key_binding: self.binding_key(),
            attestation: AuthorityAttestation {
                kind: HOST_ROOT_ATTESTATION.into(),
                evidence: Vec::new(),
            },
            tier,
            roles: ROLE_OWNER | ROLE_ADMIN | cloud,
        }
    }
    pub(super) fn sign_mesh(&self, transcript: &[u8]) -> [u8; 64] {
        self.signing.sign(transcript).to_bytes()
    }
    pub(crate) fn sign_claim_handoff(&self, transcript: &[u8]) -> [u8; 64] {
        self.signing.sign(transcript).to_bytes()
    }
    pub(super) fn sign_slip(&self, transcript: &[u8]) -> Vec<u8> {
        self.signing.sign(transcript).to_bytes().to_vec()
    }
    pub(super) fn secret(&self) -> &[u8] {
        &self.secret
    }
    /// Narrow a slip held by this host, using its private binding key.
    pub fn attenuate(&self, slip: &mut CapabilitySlip, caveat: SlipCaveat) -> Result<()> {
        slip.attenuate(caveat, &self.signing)
    }
    /// Transfer an attenuated slip to a new holder without sharing this key.
    pub fn attenuate_to(
        &self,
        slip: &mut CapabilitySlip,
        caveat: SlipCaveat,
        next_binding_key: [u8; 32],
    ) -> Result<()> {
        slip.attenuate_to(caveat, &self.signing, next_binding_key)
    }
    pub fn binding_proof(&self, slip: &CapabilitySlip, challenge: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .signing
            .sign(&slip.binding_transcript(challenge)?)
            .to_bytes()
            .to_vec())
    }
    pub(super) fn sign_entry(
        &self,
        vault_id: Option<[u8; 32]>,
        seq: u64,
        parents: Vec<[u8; 32]>,
        op: AuthorityOp,
        now: u64,
    ) -> Result<AuthorityLogEntry> {
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id,
            seq,
            parent_hashes: parents,
            op,
            signer: AuthoritySignature {
                suite: AuthoritySignatureSuite::Ed25519,
                public_key: self.public_key(),
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: now,
        };
        self.resign_entry(&mut entry)?;
        Ok(entry)
    }

    pub(super) fn resign_entry(&self, entry: &mut AuthorityLogEntry) -> Result<()> {
        entry.signer.signature = self
            .signing
            .sign(&authority_transcript(entry)?)
            .to_bytes()
            .to_vec();
        Ok(())
    }
}

impl AuthorityFold {
    /// Whether the slip minted as `id` is live at `instant`: live in this
    /// fold, and minted for a lifetime that holds `instant`.
    pub(crate) fn slip_is_live_at(&self, id: &[u8; 32], instant: VaultInstant) -> bool {
        let now = instant.secs();
        self.slip_is_live(id)
            && self.slips.mints.get(id).is_some_and(|mint| {
                now >= mint.action.claims.issued_at && now < mint.action.claims.expires_at
            })
    }
}

impl Vault {
    /// Rechecks a verified capability against one vault clock/authority snapshot.
    pub fn capability_slip_is_live(&self, verified: &VerifiedSlip) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        self.capability_slip_is_live_in_txn(&txn, verified)
    }
    pub fn capability_slip_is_live_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        verified: &VerifiedSlip,
    ) -> Result<bool> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let now = self.instant_in_txn(txn)?.secs();
        let claims = verified.claims();
        Ok(now >= claims.issued_at
            && now < claims.expires_at
            && fold.vault_id == Some(claims.vault_id)
            && fold.slip_is_live(&claims.slip_id)
            && verified.witness_pact(&fold).is_ok())
    }
    /// Sample the authority plane's local monotonic clock before constructing
    /// a slip mint. Using the wall/store recording clock for `issued_at` can
    /// race one second ahead of the authority fold's observation and cause a
    /// valid OAuth sign-in to be refused at mint.
    pub fn capability_slip_now(&self) -> Result<u64> {
        let txn = self.store.env.read_txn()?;
        Ok(self.instant_in_txn(&txn)?.secs())
    }

    /// A session already proved its uncaveated instrument. Its mint's lifetime
    /// and the current fold still bound every subsequent frame.
    pub fn capability_slip_id_is_live(&self, id: &[u8; 32]) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        self.capability_slip_id_is_live_in_txn(&txn, id)
    }
    pub fn capability_slip_id_is_live_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &[u8; 32],
    ) -> Result<bool> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let now = self.instant_in_txn(txn)?;
        Ok(fold.slip_is_live_at(id, now))
    }

    /// Bootstrap Genesis + host root slip atomically, and only on a truly empty
    /// log; a self-hosted root binds the vault's embedded owner as `human` in
    /// the same transaction, so owner verbs hold for the owner alone (H149).
    /// A rooted vault must already recognize this host. A rejected cached
    /// root is never silently replaced (revocation stays terminal).
    pub fn ensure_host_root_slip(&self, issuer: &HostSlipIssuer) -> Result<CapabilitySlip> {
        let mut txn = self.store.env.write_txn()?;
        let slip = self.ensure_host_root_slip_in_txn(&mut txn, issuer)?;
        txn.commit()?;
        Ok(slip)
    }
    pub(super) fn ensure_host_root_slip_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
    ) -> Result<CapabilitySlip> {
        if self.privacy_posture() == crate::HostingPrivacyPosture::Relay {
            return Err(invalid_authority());
        }
        let cache_key = format!(":{}", blake3::hash(&issuer.binding_key()).to_hex());
        let now = self.instant_in_txn(txn)?.secs();
        let mut fold = self.authority_fold_readonly_in_txn(txn)?;
        let mut pending = Vec::new();
        if fold.append_sequences.is_empty() {
            let recovery = blake3::derive_key("oneiron/host-genesis-recovery/v2", issuer.secret());
            let genesis = issuer.sign_entry(
                None,
                0,
                Vec::new(),
                AuthorityOp::Genesis {
                    device: issuer.root_device(self.privacy_posture()),
                    genesis_nonce: random_slip_id(),
                    recovery: GenesisRecoveryStep::acknowledge(&recovery, true)?,
                },
                now,
            )?;
            pending.push(genesis);
            // Only bootstrap on no records, never on a confused/invalid fold.
            let pin = super::pinned_root::read_pinned_root_in_txn(&self.store, txn)?;
            fold = super::fold_engine::fold_own_authority_log(
                &pending,
                self.privacy_posture(),
                pin.as_ref(),
            );
        }
        require_host(&fold, issuer)?;
        if let Some(token) = HOST_ROOT_SLIP_CACHE.get(&self.store, txn, &cache_key)? {
            let slip = CapabilitySlip::from_token(&token)?;
            slip.verify_authority(&issuer.public_key(), &fold, now)?;

            return Ok(slip);
        }
        let claims = SlipClaims {
            slip_id: random_slip_id(),
            vault_id: fold.vault_id.ok_or_else(invalid_authority)?,
            parent_id: None,
            holder_ref: "host".into(),
            binding_key: issuer.binding_key(),
            scope: Scope::top(),
            issued_at: now,
            expires_at: now.saturating_add(ROOT_LIFETIME),
            ttl_secs: ROOT_LIFETIME,
            single_use: false,
            records: BTreeSet::new(),
            channels: BTreeSet::new(),
            actor_class: None,
            org_ref: None,
            grant_ref: None,
        };
        let slip = CapabilitySlip::mint(claims.clone(), issuer)?;
        let mint = next_entry(
            issuer,
            &fold,
            AuthorityOp::SlipMint(SlipMintAction { claims }),
            now,
        )?;
        pending.push(mint);
        let rows: Vec<_> = pending
            .iter()
            .map(|entry| {
                (
                    entry.clone(),
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                )
            })
            .collect();
        self.put_authority_log_entries_in_txn(txn, &rows)?;
        let fresh = self.authority_view_readonly_in_txn(txn)?;
        slip.verify_authority(&issuer.public_key(), &fresh, now)?;
        HOST_ROOT_SLIP_CACHE.put(&self.store, txn, &cache_key, &slip.to_token()?)?;
        // A root written here binds the vault's owner with it (H149).
        if pending
            .first()
            .is_some_and(|entry| matches!(entry.op, AuthorityOp::Genesis { .. }))
        {
            self.bind_rooted_owner_in_txn(txn, issuer)?;
        }
        Ok(slip)
    }
    /// Proves the local retained host secret through its actual logged root slip.
    pub fn verified_host_root_slip(&self, issuer: &HostSlipIssuer) -> Result<VerifiedSlip> {
        let slip = self.ensure_host_root_slip(issuer)?;
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        slip.verify(
            &issuer.public_key(),
            &fold,
            self.instant_in_txn(&txn)?.secs(),
            b"local-host-root",
            &issuer.binding_proof(&slip, b"local-host-root")?,
        )
    }
    /// Read-only holder verification for repeatable credential checks. One-shot
    /// redemption uses authenticate_capability_slip or the secret door instead.
    pub fn verify_capability_slip(
        &self,
        host_public_key: &AuthorityKey,
        slip: &CapabilitySlip,
        challenge: &[u8],
        signature: &[u8],
    ) -> Result<VerifiedSlip> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let now = self.instant_in_txn(&txn)?.secs();
        let verified = slip.verify(host_public_key, &fold, now, challenge, signature)?;
        self.require_live_slip_grant_in_txn(&txn, verified.claims(), now)?;
        Ok(verified)
    }
    /// Verify a slip and its holder-signed caveats against the logged issuing host key.
    pub fn verify_capability_slip_with_host_key(
        &self,
        host_key: &AuthorityKey,
        slip: &CapabilitySlip,
        challenge: &[u8],
        signature: &[u8],
    ) -> Result<VerifiedSlip> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let now = self.instant_in_txn(&txn)?.secs();
        let verified = slip.verify_with_host_key(host_key, &fold, now, challenge, signature)?;
        self.require_live_slip_grant_in_txn(&txn, verified.claims(), now)?;
        Ok(verified)
    }
    /// Verify a transport proof without consuming its nonce, using the same
    /// vault clock and signed challenge as atomic request admission.
    pub fn verify_capability_slip_request(
        &self,
        host_public_key: &AuthorityKey,
        slip: &CapabilitySlip,
        timestamp: u64,
        signature: &[u8],
        nonce: &[u8],
    ) -> Result<VerifiedSlip> {
        let txn = self.store.env.read_txn()?;
        let now = self.instant_in_txn(&txn)?.secs();
        let challenge = super::slip_replay::request_challenge(
            timestamp,
            nonce,
            super::slip_replay::request_now_in_txn(self, &txn)?,
        )?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let verified = slip.verify(host_public_key, &fold, now, &challenge, signature)?;
        self.require_live_slip_grant_in_txn(&txn, verified.claims(), now)?;
        Ok(verified)
    }

    /// Log-derived minting key is the authority source, not a registry row or
    /// retained server secret. Admission and nonce consumption share a txn.
    pub fn admit_capability_slip_request(
        &self,
        slip: &CapabilitySlip,
        timestamp: u64,
        signature: &[u8],
        nonce: &[u8],
    ) -> Result<VerifiedSlip> {
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
        let verified = slip.verify(key, &fold, now, &challenge, signature)?;
        self.require_live_slip_grant_in_txn(&txn, verified.claims(), now)?;
        if verified.claims().single_use {
            return Err(invalid_authority());
        }
        super::slip_replay::record_nonce(
            self,
            &mut txn,
            &verified.claims().binding_key,
            nonce,
            timestamp,
            request_now,
        )?;
        txn.commit()?;
        Ok(verified)
    }
    /// Read-only transport verification from the signed authority-log mint.
    pub fn verify_logged_capability_slip_request(
        &self,
        slip: &CapabilitySlip,
        timestamp: u64,
        signature: &[u8],
        nonce: &[u8],
    ) -> Result<VerifiedSlip> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let now = self.instant_in_txn(&txn)?.secs();
        let challenge = super::slip_replay::request_challenge(
            timestamp,
            nonce,
            super::slip_replay::request_now_in_txn(self, &txn)?,
        )?;
        let key = &fold
            .slips
            .mints
            .get(&slip.claims.slip_id)
            .ok_or_else(invalid_authority)?
            .signer;
        let verified = slip.verify(key, &fold, now, &challenge, signature)?;
        self.require_live_slip_grant_in_txn(&txn, verified.claims(), now)?;
        Ok(verified)
    }

    /// Appends a signed mint in the same transaction that checks its ancestry.
    /// OAuth sign-in mints under the trusted manifest and JWT ceiling in one
    /// transaction. The caller's requested lifetime can only narrow both.
    pub fn mint_oauth_capability_slip(
        &self,
        issuer: &HostSlipIssuer,
        mut claims: SlipClaims,
        jwt_remaining_secs: u64,
        requested_secs: Option<u64>,
    ) -> Result<CapabilitySlip> {
        if jwt_remaining_secs == 0 || requested_secs == Some(0) {
            return Err(invalid_authority());
        }
        let mut txn = self.store.env.write_txn()?;
        let ceiling = crate::gate::resolve_credential_lifetimes(&self.store, &txn)?;
        let now = self.instant_in_txn(&txn)?.secs();
        let ttl = jwt_remaining_secs
            .min(ceiling.oauth_exchange_secs)
            .min(requested_secs.unwrap_or(u64::MAX));
        claims.issued_at = now;
        claims.expires_at = now.checked_add(ttl).ok_or_else(invalid_authority)?;
        claims.ttl_secs = ttl;
        let slip = self.mint_slip_in_txn(&mut txn, issuer, claims)?;
        txn.commit()?;
        Ok(slip)
    }

    pub fn mint_capability_slip(
        &self,
        issuer: &HostSlipIssuer,
        claims: SlipClaims,
    ) -> Result<CapabilitySlip> {
        let mut txn = self.store.env.write_txn()?;
        let slip = self.mint_slip_in_txn(&mut txn, issuer, claims)?;
        txn.commit()?;
        Ok(slip)
    }
    pub(crate) fn mint_slip_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        claims: SlipClaims,
    ) -> Result<CapabilitySlip> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        require_host(&fold, issuer)?;
        let now = self.instant_in_txn(txn)?.secs();
        if claims.issued_at > now || claims.expires_at <= now {
            return Err(invalid_authority());
        }
        let slip = CapabilitySlip::mint(claims.clone(), issuer)?;
        let entry = next_entry(
            issuer,
            &fold,
            AuthorityOp::SlipMint(SlipMintAction { claims }),
            now,
        )?;
        self.put_authority_log_entries_in_txn(
            txn,
            &[(
                entry,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )],
        )?;
        let fresh = self.authority_view_readonly_in_txn(txn)?;
        slip.verify_authority(&issuer.public_key(), &fresh, now)?;
        Ok(slip)
    }
    pub fn revoke_capability_slip(&self, issuer: &HostSlipIssuer, slip_id: [u8; 32]) -> Result<()> {
        self.revoke_capability_slip_once(issuer, slip_id).map(drop)
    }
    /// Revokes, in one transaction, every live unexpired slip `holder_ref`
    /// holds other than `keep`, and returns their ids: a credential that
    /// replaces a holder's earlier ones, rather than standing beside them.
    pub fn revoke_held_capability_slips(
        &self,
        issuer: &HostSlipIssuer,
        holder_ref: &str,
        keep: [u8; 32],
    ) -> Result<Vec<[u8; 32]>> {
        let mut txn = self.store.env.write_txn()?;
        let held =
            self.revoke_held_capability_slips_in_txn(&mut txn, issuer, holder_ref, Some(keep))?;
        txn.commit()?;
        Ok(held)
    }
    /// [`Self::revoke_held_capability_slips`] inside a caller's writer, so a
    /// membership change and the revocations it implies commit together.
    /// `None` keeps no slip.
    pub(crate) fn revoke_held_capability_slips_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        holder_ref: &str,
        keep: Option<[u8; 32]>,
    ) -> Result<Vec<[u8; 32]>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        require_host(&fold, issuer)?;
        let now = self.instant_in_txn(txn)?.secs();
        let held: Vec<[u8; 32]> = fold
            .slips
            .mints
            .iter()
            .filter(|(id, mint)| {
                Some(**id) != keep
                    && mint.action.claims.holder_ref == holder_ref
                    && now < mint.action.claims.expires_at
                    && fold.slip_is_live(id)
            })
            .map(|(id, _)| *id)
            .collect();
        for slip_id in &held {
            self.append_slip_op_in_txn(txn, issuer, AuthorityOp::SlipRevoke { slip_id: *slip_id })?;
        }
        Ok(held)
    }
    /// Appends a signed revocation once per slip id. `true` means this call
    /// appended the first explicit revoke; expiry, ancestor revocation, or an
    /// absent mint does not prevent a first tombstone for a late mint.
    pub fn revoke_capability_slip_once(
        &self,
        issuer: &HostSlipIssuer,
        slip_id: [u8; 32],
    ) -> Result<bool> {
        let mut txn = self.store.env.write_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        require_host(&fold, issuer)?;
        if fold.slips.explicit_revoked.contains(&slip_id) {
            return Ok(false);
        }
        self.append_slip_op_in_txn(&mut txn, issuer, AuthorityOp::SlipRevoke { slip_id })?;
        txn.commit()?;
        Ok(true)
    }
    /// Verifies the binding and burns single-use authority before returning it.
    /// Request nonce consumption is transactionally shared with SlipConsume.
    pub fn authenticate_capability_slip(
        &self,
        issuer: &HostSlipIssuer,
        slip: &CapabilitySlip,
        request_timestamp: u64,
        signature: &[u8],
        request_nonce: &[u8],
    ) -> Result<VerifiedSlip> {
        let mut txn = self.store.env.write_txn()?;
        let request_now = super::slip_replay::admission_now_in_txn(self, &mut txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        require_host(&fold, issuer)?;
        let now = self.instant_in_txn(&txn)?.secs();
        let challenge =
            super::slip_replay::request_challenge(request_timestamp, request_nonce, request_now)?;
        let verified = slip.verify(&issuer.public_key(), &fold, now, &challenge, signature)?;
        self.require_live_slip_grant_in_txn(&txn, verified.claims(), now)?;
        super::slip_replay::record_nonce(
            self,
            &mut txn,
            &verified.claims().binding_key,
            request_nonce,
            request_timestamp,
            request_now,
        )?;
        if verified.claims().single_use {
            self.append_slip_op_in_txn(
                &mut txn,
                issuer,
                AuthorityOp::SlipConsume {
                    slip_id: slip.claims.slip_id,
                },
            )?;
        }
        txn.commit()?;
        Ok(verified)
    }
    /// Lands the host-signed record of an executed ownership change in the
    /// change's own writer, answering the entry's hash for the receipt to
    /// name. The fold admits it as a roster-signed Owner action and keeps no
    /// state for it; the change itself is the shared act's.
    pub(crate) fn append_owner_handover_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        handover: OwnerHandover,
    ) -> Result<AuthorityEntryHash> {
        handover.validate()?;
        self.append_hashed_slip_op_in_txn(txn, issuer, AuthorityOp::OwnerHandover(handover))
    }
    pub(super) fn append_slip_op_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        op: AuthorityOp,
    ) -> Result<()> {
        self.append_hashed_slip_op_in_txn(txn, issuer, op)
            .map(|_| ())
    }
    fn append_hashed_slip_op_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        op: AuthorityOp,
    ) -> Result<AuthorityEntryHash> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        require_host(&fold, issuer)?;
        let now = self.instant_in_txn(txn)?.secs();
        let entry = next_entry(issuer, &fold, op, now)?;
        let hash = authority_entry_hash(&entry)?;
        self.put_authority_log_entries_in_txn(
            txn,
            &[(
                entry,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )],
        )?;
        if !self
            .authority_view_readonly_in_txn(txn)?
            .valid_entries
            .contains(&hash)
        {
            return Err(invalid_authority());
        }
        Ok(hash)
    }
}
pub(super) fn next_entry(
    issuer: &HostSlipIssuer,
    fold: &AuthorityFold,
    op: AuthorityOp,
    now: u64,
) -> Result<AuthorityLogEntry> {
    let seq = fold
        .append_sequences
        .get(&issuer.public_key())
        .map(|seq| seq.checked_add(1).ok_or_else(invalid_authority))
        .transpose()?
        .unwrap_or(0);
    if fold.append_heads.is_empty() {
        return Err(invalid_authority());
    }
    issuer.sign_entry(
        fold.vault_id,
        seq,
        fold.append_heads.iter().copied().collect(),
        op,
        now,
    )
}
#[cfg(any(test, feature = "test-support"))]
impl Vault {
    /// Binds a test owner person as the human owner under the host root, so
    /// owner verbs keep working once a fixture roots its vault.
    pub(crate) fn bind_host_owner_for_test(
        &self,
        issuer: &HostSlipIssuer,
        person: crate::EntityId,
    ) -> Result<()> {
        self.bind_host_actor_for_test(issuer, person, "human")
    }

    /// Binds `person` at `class` under the host root. The host key holds one
    /// live binding, and a self-hosted root binds the embedded owner, so a
    /// fixture that names another actor rebinds the key to it.
    pub(crate) fn bind_host_actor_for_test(
        &self,
        issuer: &HostSlipIssuer,
        person: crate::EntityId,
        class: &str,
    ) -> Result<()> {
        let fold = self.authority_fold()?;
        let held = fold.actor_bindings.get(&issuer.public_key());
        if held.is_some_and(|binding| {
            binding.status == ActorBindingStatus::Active
                && binding.actor_ref == person
                && binding.actor_class == class
        }) {
            return Ok(());
        }
        let epoch = held.map_or(1, |binding| binding.epoch + 1);
        let (authority_key, actor_ref, actor_class) = (issuer.public_key(), person, class.into());
        let op = match held {
            Some(binding) if binding.status == ActorBindingStatus::Active => {
                AuthorityOp::RebindActor {
                    authority_key,
                    actor_ref,
                    actor_class,
                    epoch,
                }
            }
            _ => AuthorityOp::BindActor {
                authority_key,
                actor_ref,
                actor_class,
                epoch,
            },
        };
        let now = self.now_recorded_at();
        let bind = next_entry(issuer, &fold, op, now)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries(&[(bind, at, now)])?;
        Ok(())
    }

    /// Revokes the actor the host root binds, as unbinding the owner does;
    /// the host root and the slips it minted stay live.
    #[cfg(test)]
    pub(crate) fn revoke_host_actor_for_test(&self, issuer: &HostSlipIssuer) -> Result<()> {
        let fold = self.authority_fold()?;
        let now = self.now_recorded_at();
        let epoch = fold
            .actor_bindings
            .get(&issuer.public_key())
            .map_or(1, |binding| binding.epoch);
        let revoke = next_entry(
            issuer,
            &fold,
            AuthorityOp::RevokeActor {
                authority_key: issuer.public_key(),
                epoch,
            },
            now,
        )?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries(&[(revoke, at, now)])?;
        Ok(())
    }

    /// Logs `op` under the host root, the owner's own device in a self-host
    /// vault, as an owner's answer to a critical confirm arrives.
    #[cfg(test)]
    pub(crate) fn log_host_op_for_test(
        &self,
        issuer: &HostSlipIssuer,
        op: AuthorityOp,
    ) -> Result<()> {
        let fold = self.authority_fold()?;
        let now = self.now_recorded_at();
        let entry = next_entry(issuer, &fold, op, now)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries(&[(entry, at, now)])?;
        Ok(())
    }
}
pub(super) fn require_host(fold: &AuthorityFold, issuer: &HostSlipIssuer) -> Result<()> {
    if fold.vault_id.is_none()
        || fold.vault_root_is_conflicted()
        || !roster_has_live_owner(&fold.roster, &issuer.public_key())
    {
        return Err(invalid_authority());
    }
    Ok(())
}
pub(super) fn random_slip_id() -> [u8; 32] {
    use rand_core::{OsRng, RngCore};
    let mut id = [0; 32];
    OsRng.fill_bytes(&mut id);
    id
}
