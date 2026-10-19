//! A removed person's own notices of losing a shared vault (OF-158 client
//! leave). Leave and removal revoke the person's slips, so the person-tier
//! outcome read refuses them; this door takes the revoked slip itself,
//! proven by the device that holds its binding key over a fresh request
//! challenge, and answers only that person's loss-of-access notices, and
//! the archives export-first removals delivered to them (OF-150, FIX 1300),
//! each retrievable for its 90-day term. It grants no other read: no proof
//! is minted and no scope is consulted. Every notice is signed by the host
//! root key (FIX 2053); there is no unsigned answer. Beside the notices
//! rides the handoff from where the person's env stands to that key, so a
//! device whose env never folded a re-root still verifies them.
use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{RemovalExportCopy, SignedSharedActOutcome};

/// Which signed rows ride beside a removed person's notices as the handoff
/// to the root that signed them (FIX 2053, a call; canon is silent on that
/// delivery): the ReRoot chain alone. The rest of the log names grants,
/// machines and settings, which only the owner's machines read.
const LEAVE_NOTICE_HANDOFF_EVIDENCE: fn(&AuthorityOp) -> bool =
    |op| matches!(op, AuthorityOp::ReRoot { .. });

impl Vault {
    /// The holder of `slip` proves possession of its binding key over the
    /// request challenge (`request_timestamp`, `request_nonce`, `signature`,
    /// the same proof every slip request carries). The slip must be one this
    /// vault's authority log minted, unchanged, whatever its standing since:
    /// revoked and expired slips pass, as a removed device holds no other.
    /// Answers the slip holder's own MemberLeft, MemberRemoved and
    /// role-losing Owner notices, and the vault's deletion, each signed in
    /// this snapshot by `issuer`, which must stand as this vault's live host
    /// root. Beside them, the signed handoff to `issuer` from where the
    /// holder's chain stands, `member_heads` being the heads its env folded
    /// (FIX 2053): the ReRoot rows, parents first, it did not fold. The
    /// nonce is spent once, only when every notice is signed.
    pub fn removed_member_notices_signed(
        &self,
        issuer: &HostSlipIssuer,
        slip: &CapabilitySlip,
        request_timestamp: u64,
        signature: &[u8],
        request_nonce: &[u8],
        member_heads: &BTreeSet<AuthorityEntryHash>,
    ) -> Result<(Vec<SignedSharedActOutcome>, Vec<Vec<u8>>)> {
        let mut txn = self.store.env.write_txn()?;
        let person =
            self.left_person_in_txn(&mut txn, slip, request_timestamp, signature, request_nonce)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        super::slip_vault::require_host(&fold, issuer)?;
        let authority_vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let notices = self
            .removal_outcomes_in_txn(&txn, person)?
            .iter()
            .map(|outcome| issuer.sign_shared_act_outcome(authority_vault_id, outcome))
            .collect::<Result<Vec<_>>>()?;
        let handoff =
            self.leave_notice_handoff_in_txn(&txn, &fold, &issuer.public_key(), member_heads)?;
        txn.commit()?;
        Ok((notices, handoff))
    }

    /// The signed handoff a removed person's notices ride with (FIX 2053):
    /// the ReRoot rows `fold` settled that hand the root on to `signer`, in
    /// chain order from the genesis root's own handoff, less those at or
    /// below `member_heads`, which the person's env folded. When this vault
    /// does not hold one of those heads, or the request named none, it
    /// cannot tell where that chain stands and the whole chain rides: never
    /// more rows than the handoffs this vault settled.
    fn leave_notice_handoff_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        signer: &AuthorityKey,
        member_heads: &BTreeSet<AuthorityEntryHash>,
    ) -> Result<Vec<Vec<u8>>> {
        // A vault no handoff ever re-rooted has none to send.
        if fold.retired_keys.is_empty() {
            return Ok(Vec::new());
        }
        let history = super::history_transfer::history_in_txn(self, txn)?;
        // Each settled handoff, by the key it handed the root to.
        let mut handoffs = BTreeMap::new();
        for (hash, (bytes, entry)) in &history {
            if LEAVE_NOTICE_HANDOFF_EVIDENCE(&entry.op)
                && fold.valid_entries.contains(hash)
                && let AuthorityOp::ReRoot { new_device } = &entry.op
            {
                handoffs.insert(&new_device.key, (*hash, bytes, entry));
            }
        }
        // Walk back from the signer, each handoff to the key that signed it.
        let mut chain = Vec::new();
        let mut key = signer;
        while let Some((hash, bytes, entry)) = handoffs.get(key) {
            if chain.len() == handoffs.len() {
                break;
            }
            chain.push((*hash, (*bytes).clone()));
            key = entry.signer_key();
        }
        chain.reverse();
        if !member_heads.is_empty() && member_heads.iter().all(|head| history.contains_key(head)) {
            let mut folded = BTreeSet::new();
            let mut stack: Vec<_> = member_heads.iter().copied().collect();
            while let Some(hash) = stack.pop() {
                if folded.insert(hash)
                    && let Some((_, entry)) = history.get(&hash)
                {
                    stack.extend(entry.parent_hashes.iter().copied());
                }
            }
            chain.retain(|(hash, _)| !folded.contains(hash));
        }
        Ok(chain.into_iter().map(|(_, bytes)| bytes).collect())
    }

    /// The signed ReRoot rows that hand this vault's root on to `signer`, in
    /// chain order from the genesis root's own handoff: what a courtesy ask
    /// or answer `signer` signed rides behind, so a former peer that pinned
    /// any earlier root still verifies it (FIX 3014). Empty when no handoff
    /// names `signer`.
    pub(crate) fn root_handoff_to(&self, signer: &AuthorityKey) -> Result<Vec<Vec<u8>>> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        self.leave_notice_handoff_in_txn(&txn, &fold, signer, &BTreeSet::new())
    }

    /// Whether `fold`'s settled handoffs hand this vault's root on from
    /// `from` to `to`: `from` signed a ReRoot row on the chain
    /// [`Self::root_handoff_to`] walks back from `to`, in `txn`'s snapshot
    /// (FIX 5088: only `from`'s successor re-signs a courtesy try `from`
    /// signed).
    pub(crate) fn root_handed_on_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        from: &AuthorityKey,
        to: &AuthorityKey,
    ) -> Result<bool> {
        for row in self.leave_notice_handoff_in_txn(txn, fold, to, &BTreeSet::new())? {
            if decode_authority_log_entry_body(&row)?.signer_key() == from {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The heads this vault's authority fold stands at: what a removed
    /// member's leave-notice request names, so its home sends only the
    /// handoff past them (FIX 2053).
    ///
    /// # Errors
    ///
    /// Storage errors.
    #[cfg(feature = "sync")]
    pub(crate) fn leave_notice_heads(&self) -> Result<BTreeSet<AuthorityEntryHash>> {
        let txn = self.store.env.read_txn()?;
        Ok(self
            .authority_view_readonly_in_txn(&txn)?
            .append_heads
            .clone())
    }

    /// The archives export-first removals delivered to the holder of `slip`
    /// (OF-150, FIX 1300), still within their term, under the same proof as
    /// [`Vault::removed_member_notices_signed`]; the nonce is spent once.
    pub fn removed_owner_exports(
        &self,
        slip: &CapabilitySlip,
        request_timestamp: u64,
        signature: &[u8],
        request_nonce: &[u8],
    ) -> Result<Vec<RemovalExportCopy>> {
        let mut txn = self.store.env.write_txn()?;
        let person =
            self.left_person_in_txn(&mut txn, slip, request_timestamp, signature, request_nonce)?;
        let copies =
            self.removal_exports_in_txn(&txn, person, self.store.clock.now_recorded_at())?;
        txn.commit()?;
        Ok(copies)
    }

    /// The one archive the removal receipt `receipt_id` delivered to the
    /// holder of `slip` (FIX 1300), under the same proof as
    /// [`Vault::removed_member_notices_signed`]: answered while it is within
    /// its term ([`crate::federation::REMOVAL_EXPORT_RETAIN_SECS`] from its
    /// latest delivery), `None` after it or when that removal delivered this
    /// person none. Only the removed person reaches it; the nonce is spent
    /// once, and a malformed `receipt_id` is refused before it is.
    pub fn removed_owner_archive(
        &self,
        slip: &CapabilitySlip,
        request_timestamp: u64,
        signature: &[u8],
        request_nonce: &[u8],
        receipt_id: &str,
    ) -> Result<Option<RemovalExportCopy>> {
        let receipt_id = EntityId::from_hex(receipt_id)?;
        let mut txn = self.store.env.write_txn()?;
        let person =
            self.left_person_in_txn(&mut txn, slip, request_timestamp, signature, request_nonce)?;
        let copy = self.removal_export_in_txn(
            &txn,
            person,
            receipt_id,
            self.store.clock.now_recorded_at(),
        )?;
        txn.commit()?;
        Ok(copy)
    }

    /// The person whose slip, minted here whatever its standing since, the
    /// request proves: its holder signed the request challenge, and the
    /// nonce is spent in the caller's writer.
    fn left_person_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        slip: &CapabilitySlip,
        request_timestamp: u64,
        signature: &[u8],
        request_nonce: &[u8],
    ) -> Result<EntityId> {
        let request_now = super::slip_replay::admission_now_in_txn(self, txn)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let challenge =
            super::slip_replay::request_challenge(request_timestamp, request_nonce, request_now)?;
        slip.verify_origin(&fold, &challenge, signature)?;
        let person = EntityId::from_hex(&slip.claims.holder_ref)?;
        super::slip_replay::record_nonce(
            self,
            txn,
            &slip.current_binding_key(),
            request_nonce,
            request_timestamp,
            request_now,
        )?;
        Ok(person)
    }
}
