//! The host's own root slip: its bootstrap with Genesis on an empty log,
//! the cache that retains the minted root for this install's issuer key,
//! and the proof of the retained host secret through that logged root.

use std::collections::BTreeSet;

use oneiron_authority::federation::Scope;

use super::{HostSlipIssuer, next_entry, random_slip_id, require_host};
use crate::Vault;
use crate::authority::{
    AuthorityOp, CapabilitySlip, GenesisRecoveryStep, SlipClaims, SlipMintAction, VerifiedSlip,
    invalid_authority,
};
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::temporal::TimeRange;

const ROOT_LIFETIME: u64 = 10 * 365 * 24 * 60 * 60;

/// Cached minted host-root capability-slip token for one host signing key. Key: `:` + hex64.
const HOST_ROOT_SLIP_CACHE: SideTable<String, String, Raw> =
    SideTable::new(&side_table::AUTHORITY_HOST_ROOT_SLIP_CACHE);

impl Vault {
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
    pub(in crate::authority) fn ensure_host_root_slip_in_txn(
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
            let recovery = issuer.genesis_recovery();
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
            let pin = crate::authority::pinned_root::read_pinned_root_in_txn(&self.store, txn)?;
            fold = crate::authority::fold_engine::fold_own_authority_log(
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
            invitation_ref: None,
            delegation: None,
            comm: None,
            trusted_contact: None,
            seat_claim: None,
        };
        let slip = CapabilitySlip::mint(claims.clone(), issuer)?;
        let mint = next_entry(
            issuer,
            &fold,
            AuthorityOp::SlipMint(SlipMintAction {
                claims,
                renews: None,
            }),
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
}
