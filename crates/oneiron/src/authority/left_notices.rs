//! A removed person's own notices of losing a shared vault (OF-158 client
//! leave). Leave and removal revoke the person's slips, so the person-tier
//! outcome read refuses them; this door takes the revoked slip itself,
//! proven by the device that holds its binding key over a fresh request
//! challenge, and answers only that person's loss-of-access notices, and
//! the archives export-first removals delivered to them (OF-150, FIX 1300),
//! each retrievable for its 90-day term. It grants no other read: no proof
//! is minted and no scope is consulted. Every notice is signed by the host
//! root key (FIX 2053); there is no unsigned answer. Beside the notices
//! rides the handoff from where the person's env stands to that key, and the
//! rows it stands on, so a device whose env never folded a re-root or a host
//! root rotation folds them as this vault did and verifies the notices.
use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{RemovalExportCopy, SignedSharedActOutcome};

// The host's delivery of those archives to their removed holder, beside
// these pull doors (FIX 3215, 3396).
mod delivery;

/// What rides beside a removed person's notices as the handoff to the root
/// that signed them.
enum HandoffEvidence {
    /// The settled root edges that hand the root on ([`root_edge`]), and
    /// every row they stand on that the person's env did not fold, so it
    /// folds them as this vault did (FIX 3797). Those rows name grants,
    /// machines and settings: only a removed person's own notices carry them,
    /// and courtesy ([`Vault::root_handoff_to`]) takes the edges alone.
    RootEdgesAndParents,
}

/// Which signed rows ride beside a removed person's notices (FIX 2053, FIX
/// 3797, FIX 3798, a call; canon is silent on that delivery).
const LEAVE_NOTICE_HANDOFF_EVIDENCE: HandoffEvidence = HandoffEvidence::RootEdgesAndParents;

/// The key `entry` hands the host root on to, when it is a root edge: a
/// ReRoot, or a RotateKey its own old key signed naming a distinct Owner
/// successor (FIX 3798). A rotation another key signed hands nothing on.
fn root_edge(entry: &AuthorityLogEntry) -> Option<&AuthorityKey> {
    match &entry.op {
        AuthorityOp::ReRoot { new_device } => Some(&new_device.key),
        AuthorityOp::RotateKey {
            old_key,
            new_device,
        } if old_key == entry.signer_key()
            && new_device.key != *old_key
            && new_device.roles & ROLE_OWNER != 0 =>
        {
            Some(&new_device.key)
        }
        _ => None,
    }
}

/// The settled root edges ([`root_edge`]) that hand the root on to `signer`,
/// in chain order from the genesis root's own: from `signer`, each step back
/// takes the one edge `fold` holds valid that hands on to the key the walk
/// stands at. Two edges to one key, or a step back to a key the walk passed,
/// refuse: a fork or a cycle is never cut short. Empty when no edge names
/// `signer`.
fn root_chain(
    history: &BTreeMap<AuthorityEntryHash, (Vec<u8>, AuthorityLogEntry)>,
    fold: &AuthorityFold,
    signer: &AuthorityKey,
) -> Result<Vec<AuthorityEntryHash>> {
    let mut handoffs = BTreeMap::new();
    for (hash, (_, entry)) in history {
        if let Some(next) = root_edge(entry)
            && fold.valid_entries.contains(hash)
            && handoffs.insert(next, (*hash, entry.signer_key())).is_some()
        {
            return Err(invalid_authority());
        }
    }
    let mut chain = Vec::new();
    let mut passed = BTreeSet::from([signer]);
    let mut key = signer;
    while let Some(&(hash, from)) = handoffs.get(key) {
        if !passed.insert(from) {
            return Err(invalid_authority());
        }
        chain.push(hash);
        key = from;
    }
    chain.reverse();
    Ok(chain)
}

/// The rows at or below `member_heads`, which the person's env folded; none
/// when the request named no head or this vault does not hold one, and then
/// all of it rides.
fn member_folded(
    history: &BTreeMap<AuthorityEntryHash, (Vec<u8>, AuthorityLogEntry)>,
    member_heads: &BTreeSet<AuthorityEntryHash>,
) -> BTreeSet<AuthorityEntryHash> {
    let mut folded = BTreeSet::new();
    if member_heads.is_empty() || !member_heads.iter().all(|head| history.contains_key(head)) {
        return folded;
    }
    let mut stack: Vec<_> = member_heads.iter().copied().collect();
    while let Some(hash) = stack.pop() {
        if folded.insert(hash)
            && let Some((_, entry)) = history.get(&hash)
        {
            stack.extend(entry.parent_hashes.iter().copied());
        }
    }
    folded
}

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
    /// (FIX 2053): the root edges and the rows they stand on, parents first,
    /// it did not fold ([`LEAVE_NOTICE_HANDOFF_EVIDENCE`]). The nonce is
    /// spent once, only when every notice is signed.
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
        let signer = issuer.public_key();
        let handoff = match LEAVE_NOTICE_HANDOFF_EVIDENCE {
            HandoffEvidence::RootEdgesAndParents => {
                self.leave_notice_closure_in_txn(&txn, &fold, &signer, member_heads)?
            }
        };
        txn.commit()?;
        Ok((notices, handoff))
    }

    /// The signed root edges `fold` settled that hand the root on to
    /// `signer` (FIX 2053, FIX 3798), in chain order from the genesis root's
    /// own handoff ([`root_chain`]), less those at or below `member_heads`
    /// ([`member_folded`]): never more rows than the edges this vault
    /// settled.
    fn leave_notice_handoff_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        signer: &AuthorityKey,
        member_heads: &BTreeSet<AuthorityEntryHash>,
    ) -> Result<Vec<Vec<u8>>> {
        let history = super::history_transfer::history_in_txn(self, txn)?;
        let folded = member_folded(&history, member_heads);
        Ok(root_chain(&history, fold, signer)?
            .iter()
            .filter(|hash| !folded.contains(*hash))
            .filter_map(|hash| history.get(hash).map(|(bytes, _)| bytes.clone()))
            .collect())
    }

    /// The handoff a removed person's notices ride with (FIX 3797): the root
    /// edges to `signer` the person's env did not fold, each after every row
    /// it stands on that the env did not fold either, parents first, so the
    /// env folds them with its own rows as this vault folded them. A row this
    /// vault does not hold is not sent; the env then judges the edges alone.
    fn leave_notice_closure_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        signer: &AuthorityKey,
        member_heads: &BTreeSet<AuthorityEntryHash>,
    ) -> Result<Vec<Vec<u8>>> {
        let history = super::history_transfer::history_in_txn(self, txn)?;
        let mut sent = member_folded(&history, member_heads);
        let mut rows = Vec::new();
        for edge in root_chain(&history, fold, signer)? {
            // A row goes once its parents have: `Some` marks one whose
            // parents were pushed above it.
            let mut stack = vec![(edge, None)];
            while let Some((hash, bytes)) = stack.pop() {
                if let Some(bytes) = bytes {
                    if sent.insert(hash) {
                        rows.push(Vec::clone(bytes));
                    }
                } else if !sent.contains(&hash)
                    && let Some((bytes, entry)) = history.get(&hash)
                {
                    stack.push((hash, Some(bytes)));
                    stack.extend(entry.parent_hashes.iter().map(|parent| (*parent, None)));
                }
            }
        }
        Ok(rows)
    }

    /// The signed root edges ([`root_edge`]) that hand this vault's root on
    /// to `signer`, in chain order from the genesis root's own handoff: what
    /// a courtesy ask or answer `signer` signed rides behind, so a former
    /// peer that pinned any earlier root still verifies it (FIX 3014). Empty
    /// when no edge names `signer`.
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
    /// The removed Owner proving the mint's own key takes each as stored; a
    /// holder the slip was transferred to takes each cut down to what its
    /// caveats admit, and none they admit nothing of (FIX-LIST 8224), all
    /// before the nonce commits.
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
        let now = self.store.clock.now_recorded_at();
        let copies = match slip.transferred_bounds() {
            None => self.removal_exports_in_txn(&txn, person, now)?,
            Some(bounds) => {
                self.transferred_exports_in_txn(&mut txn, slip, person, None, now, bounds)?
            }
        };
        txn.commit()?;
        Ok(copies)
    }

    /// The one archive the removal receipt `receipt_id` delivered to the
    /// holder of `slip` (FIX 1300), under the same proof as
    /// [`Vault::removed_member_notices_signed`]: answered while it is within
    /// its term ([`crate::federation::REMOVAL_EXPORT_RETAIN_SECS`] from its
    /// latest delivery), `None` after it or when that removal delivered this
    /// person none. Only the removed person reaches it; the nonce is spent
    /// once, and a malformed `receipt_id` is refused before it is. A holder
    /// the slip was transferred to takes it cut down to what its caveats
    /// admit, `None` when they admit nothing of it (FIX-LIST 8224).
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
        let now = self.store.clock.now_recorded_at();
        let copy = match slip.transferred_bounds() {
            None => self.removal_export_in_txn(&txn, person, receipt_id, now)?,
            Some(bounds) => self
                .transferred_exports_in_txn(&mut txn, slip, person, Some(receipt_id), now, bounds)?
                .pop(),
        };
        txn.commit()?;
        Ok(copy)
    }

    /// The copies a transferred holder's `bounds` take at `now` of
    /// `person`'s archives (the one `receipt_id` names, else every one),
    /// each cut down to what they admit. A one-shot transfer is served once
    /// (FIX-LIST 10773): a slip any door already consumed, or one an archive
    /// door already served, takes nothing, and the first answer that takes
    /// anything spends it on every archive of `person`, in this writer. A
    /// pact-bound transfer takes only what its pact still leaves it, read in
    /// this writer, and each answer that takes anything is logged under that
    /// pact on the archives it served (FIX 11860).
    fn transferred_exports_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        slip: &CapabilitySlip,
        person: EntityId,
        receipt_id: Option<EntityId>,
        now: u64,
        bounds: Result<super::slip::TransferredBounds>,
    ) -> Result<Vec<RemovalExportCopy>> {
        let single_use = bounds
            .as_ref()
            .is_ok_and(super::slip::TransferredBounds::single_use);
        let slip_id = slip.claims.slip_id;
        if single_use
            && (self
                .authority_view_readonly_in_txn(txn)?
                .slips
                .consumed
                .contains(&slip_id)
                || self.removal_archive_slip_spent_in_txn(txn, person, &slip_id)?)
        {
            return Ok(Vec::new());
        }
        let pact_grant = bounds
            .as_ref()
            .ok()
            .and_then(super::slip::TransferredBounds::pact_grant);
        let served_pact = match (&bounds, pact_grant) {
            (Ok(bounds), Some(_)) => {
                bounds.served_pact_scope(&self.authority_fold_readonly_in_txn(txn)?)
            }
            _ => None,
        };
        let admits = transferred_admission(bounds, now, served_pact);
        let copies = match receipt_id {
            Some(receipt_id) => self
                .projected_removal_export_in_txn(txn, person, receipt_id, now, &admits)?
                .into_iter()
                .collect(),
            None => self.projected_removal_exports_in_txn(txn, person, now, &admits)?,
        };
        if single_use && !copies.is_empty() {
            self.spend_removal_archive_slip_in_txn(txn, person, slip_id)?;
        }
        if let Some(grant) = pact_grant {
            self.log_removal_archive_pact_serve_in_txn(txn, &copies, grant, slip_id, now)?;
        }
        Ok(copies)
    }

    /// The person whose slip, minted here whatever its standing since, the
    /// request proves: its holder signed the request challenge, and the
    /// nonce is spent in the caller's writer.
    pub(crate) fn left_person_in_txn(
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

/// Which archived records a transferred holder takes at `now`: those its
/// authenticated caveat bounds admit, a pact-bound one within `served_pact`.
/// Caveats the meet refuses (a floor, a second pact) leave the holder
/// nothing; they are its own bytes.
fn transferred_admission(
    bounds: Result<super::slip::TransferredBounds>,
    now: u64,
    served_pact: Option<crate::federation::FederationDirectionScope>,
) -> impl Fn(EntityId, Option<&crate::federation::Scope>) -> bool {
    move |id: EntityId, position: Option<&crate::federation::Scope>| {
        bounds
            .as_ref()
            .is_ok_and(|bounds| bounds.admits(id, position, now, served_pact.as_ref()))
    }
}
