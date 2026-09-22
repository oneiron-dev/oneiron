//! Host-root bootstrap and atomic authority-log capability issuance.
use super::*;
use crate::Vault;
use crate::error::Result;
use crate::federation::Scope;
use crate::temporal::TimeRange;
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

const ROOT_CACHE: &str = "authority:host-root-slip:v2";
const ROOT_LIFETIME: u64 = 10 * 365 * 24 * 60 * 60;

/// A dedicated host signing/MAC key. Never loaded from device-key residue.
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
    pub(super) fn secret(&self) -> &[u8] {
        &self.secret
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
        entry.signer.signature = self
            .signing
            .sign(&authority_transcript(&entry)?)
            .to_bytes()
            .to_vec();
        Ok(entry)
    }
}

impl Vault {
    /// Rechecks a verified capability against one vault clock/authority snapshot.
    pub fn capability_slip_is_live(&self, verified: &VerifiedSlip) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        let now = self.instant_in_txn(&txn)?.secs();
        let claims = verified.claims();
        Ok(now >= claims.issued_at
            && now < claims.expires_at
            && fold.vault_id == Some(claims.vault_id)
            && fold.slip_is_live(&claims.slip_id)
            && claims.witness_pact(&fold).is_ok())
    }
    /// A session already proved its uncaveated instrument. Its mint's lifetime
    /// and the current fold still bound every subsequent frame.
    pub fn capability_slip_id_is_live(&self, id: &[u8; 32]) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        let now = self.instant_in_txn(&txn)?.secs();
        Ok(fold.slip_is_live(id)
            && fold.slips.mints.get(id).is_some_and(|mint| {
                now >= mint.action.claims.issued_at
                    && now < mint.action.claims.expires_at
                    && mint.action.claims.witness_pact(&fold).is_ok()
            }))
    }

    /// Bootstrap Genesis + host root slip atomically, and only on a truly empty
    /// log. A rooted vault must already recognize this host. A rejected cached
    /// root is never silently replaced (revocation stays terminal).
    pub fn ensure_host_root_slip(&self, issuer: &HostSlipIssuer) -> Result<CapabilitySlip> {
        if self.privacy_posture() == crate::HostingPrivacyPosture::Relay {
            return Err(invalid_authority());
        }
        let mut txn = self.store.env.write_txn()?;
        let cache_key = format!(
            "{ROOT_CACHE}:{}",
            blake3::hash(&issuer.binding_key()).to_hex()
        );
        let entries = self.slip_log_entries(&txn)?;
        let now = self.instant_in_txn(&txn)?.secs();
        let mut fold = self.authority_fold_readonly_in_txn(&txn)?;
        let mut pending = Vec::new();
        if entries.is_empty() {
            let recovery = blake3::derive_key("oneiron/host-genesis-recovery/v2", issuer.secret());
            let genesis = issuer.sign_entry(
                None,
                0,
                Vec::new(),
                AuthorityOp::Genesis {
                    device: DeviceAuthority {
                        key: issuer.public_key(),
                        transport_key_binding: issuer.binding_key(),
                        attestation: AuthorityAttestation {
                            kind: "HostRoot".into(),
                            evidence: Vec::new(),
                        },
                        tier: AuthorityTier::Software,
                        roles: ROLE_OWNER | ROLE_ADMIN,
                    },
                    genesis_nonce: random_slip_id(),
                    recovery: GenesisRecoveryStep::acknowledge(&recovery, true)?,
                    tier_floor: AuthorityTier::Software,
                    pending_widen_delay_secs: 86_400,
                },
                now,
            )?;
            pending.push(genesis);
            // Only bootstrap on no records, never on a confused/invalid fold.
            fold = fold_authority_log(&pending);
        }
        require_host(&fold, issuer)?;
        if let Some(raw) = self.store.sync_state.get(&txn, &cache_key)? {
            let token = std::str::from_utf8(&raw).map_err(|_| invalid_authority())?;
            let slip = CapabilitySlip::from_token(token)?;
            slip.verify_authority(issuer.secret(), &fold, now)?;
            return Ok(slip);
        }
        let claims = SlipClaims {
            slip_id: random_slip_id(),
            vault_id: fold.vault_id.ok_or_else(invalid_authority)?,
            pact: None,
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
        };
        let slip = CapabilitySlip::mint(claims.clone(), issuer.secret())?;
        let log = if pending.is_empty() {
            &entries
        } else {
            &pending
        };
        let mint = next_entry(
            issuer,
            &fold,
            log,
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
        self.put_authority_log_entries_in_txn(&mut txn, &rows)?;
        let fresh = self.authority_fold_readonly_in_txn(&txn)?;
        slip.verify_authority(issuer.secret(), &fresh, now)?;
        self.store
            .sync_state
            .put(&mut txn, &cache_key, slip.to_token()?.as_bytes())?;
        txn.commit()?;
        Ok(slip)
    }
    /// Proves the local retained host secret through its actual logged root slip.
    pub fn verified_host_root_slip(&self, issuer: &HostSlipIssuer) -> Result<VerifiedSlip> {
        let slip = self.ensure_host_root_slip(issuer)?;
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        slip.verify(
            issuer.secret(),
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
        issuer: &HostSlipIssuer,
        slip: &CapabilitySlip,
        challenge: &[u8],
        signature: &[u8],
    ) -> Result<VerifiedSlip> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        require_host(&fold, issuer)?;
        slip.verify(
            issuer.secret(),
            &fold,
            self.instant_in_txn(&txn)?.secs(),
            challenge,
            signature,
        )
    }
    /// Verify a transport proof without consuming its nonce, using the same
    /// vault clock and signed challenge as atomic request admission.
    pub fn verify_capability_slip_request(
        &self,
        issuer: &HostSlipIssuer,
        slip: &CapabilitySlip,
        timestamp: u64,
        signature: &[u8],
        nonce: &[u8],
    ) -> Result<VerifiedSlip> {
        let txn = self.store.env.read_txn()?;
        let now = self.instant_in_txn(&txn)?.secs();
        let challenge = super::slip_replay::request_challenge(timestamp, nonce, now)?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        require_host(&fold, issuer)?;
        slip.verify(issuer.secret(), &fold, now, &challenge, signature)
    }

    /// Appends a signed mint in the same transaction that checks its ancestry.
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
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        require_host(&fold, issuer)?;
        let now = self.instant_in_txn(txn)?.secs();
        if claims.issued_at > now || claims.expires_at <= now {
            return Err(invalid_authority());
        }
        let slip = CapabilitySlip::mint(claims.clone(), issuer.secret())?;
        let entry = next_entry(
            issuer,
            &fold,
            &self.slip_log_entries(txn)?,
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
        slip.verify_authority(
            issuer.secret(),
            &self.authority_fold_readonly_in_txn(txn)?,
            now,
        )?;
        Ok(slip)
    }
    pub fn revoke_capability_slip(&self, issuer: &HostSlipIssuer, slip_id: [u8; 32]) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        self.append_slip_op_in_txn(&mut txn, issuer, AuthorityOp::SlipRevoke { slip_id })?;
        txn.commit()?;
        Ok(())
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
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        require_host(&fold, issuer)?;
        let now = self.instant_in_txn(&txn)?.secs();
        let challenge =
            super::slip_replay::request_challenge(request_timestamp, request_nonce, now)?;
        let verified = slip.verify(issuer.secret(), &fold, now, &challenge, signature)?;
        super::slip_replay::record_nonce(
            self,
            &mut txn,
            &slip.claims.binding_key,
            request_nonce,
            request_timestamp,
            now,
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
    pub(crate) fn consume_slip(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        slip_id: [u8; 32],
    ) -> Result<()> {
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        if !fold.slip_is_live(&slip_id) {
            return Err(invalid_authority());
        }
        self.append_slip_op_in_txn(txn, issuer, AuthorityOp::SlipConsume { slip_id })
    }
    pub(super) fn append_slip_op_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        op: AuthorityOp,
    ) -> Result<()> {
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        require_host(&fold, issuer)?;
        let now = self.instant_in_txn(txn)?.secs();
        let entry = next_entry(issuer, &fold, &self.slip_log_entries(txn)?, op, now)?;
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
            .authority_fold_readonly_in_txn(txn)?
            .valid_entries
            .contains(&hash)
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
    pub(super) fn slip_log_entries(&self, txn: &heed::RoTxn<'_>) -> Result<Vec<AuthorityLogEntry>> {
        authority_log_rows_in_txn(&self.store, txn)?
            .into_iter()
            .map(|(_, body)| decode_authority_log_entry_body(&body))
            .collect()
    }
}
fn next_entry(
    issuer: &HostSlipIssuer,
    fold: &AuthorityFold,
    entries: &[AuthorityLogEntry],
    op: AuthorityOp,
    now: u64,
) -> Result<AuthorityLogEntry> {
    let mut heads = fold.valid_entries.clone();
    let mut seq = 0;
    for entry in entries {
        let hash = authority_entry_hash(entry)?;
        // Advance beyond even a signed rejected local entry. Reusing a seq
        // would create an equivocation, not a retry.
        if entry.signer.public_key == issuer.public_key() {
            seq = seq.max(entry.seq.checked_add(1).ok_or_else(invalid_authority)?);
        }
        if !fold.valid_entries.contains(&hash) {
            continue;
        }
        for parent in &entry.parent_hashes {
            heads.remove(parent);
        }
    }
    if heads.is_empty() {
        return Err(invalid_authority());
    }
    issuer.sign_entry(fold.vault_id, seq, heads.into_iter().collect(), op, now)
}
pub(super) fn require_host(fold: &AuthorityFold, issuer: &HostSlipIssuer) -> Result<()> {
    if fold.vault_id.is_none()
        || fold.vault_root_is_conflicted()
        || fold.authority_forks.iter().any(|fork| {
            fork.signer == issuer.public_key() && fork.status == AuthorityForkStatus::Quarantined
        })
        || !fold
            .roster
            .get(&issuer.public_key())
            .is_some_and(|d| !d.revoked && d.roles & ROLE_OWNER != 0)
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
