//! Removal archives, the held-erase completion, and the receipt, outcome and deletion reads.

use super::*;

impl Vault {
    /// The export-first removal archives delivered to `member` that are still
    /// within their term at `now`.
    pub(crate) fn removal_exports_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        member: EntityId,
        now: u64,
    ) -> Result<Vec<RemovalExportCopy>> {
        let prefix = removal_export_key(&member.to_hex(), "");
        Ok(REMOVAL_EXPORT
            .scan_from(&self.store, txn, prefix.as_bytes())?
            .into_iter()
            .map(|(_, stored)| stored.copy)
            .filter(|copy| now < copy.expires_at)
            .collect())
    }

    /// The archive the removal receipt `receipt_id` delivered to `member`,
    /// while it is within its term at `now`; `None` after it, or when that
    /// removal delivered `member` none.
    pub(crate) fn removal_export_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        member: EntityId,
        receipt_id: EntityId,
        now: u64,
    ) -> Result<Option<RemovalExportCopy>> {
        let row_key = removal_export_key(&member.to_hex(), &receipt_id.to_hex());
        Ok(REMOVAL_EXPORT
            .get(&self.store, txn, &row_key)?
            .map(|stored| stored.copy)
            .filter(|copy| now < copy.expires_at))
    }

    /// Drops every export-first removal archive past its term. It reads
    /// first and opens a writer only when one has expired; the writer checks
    /// each again, so an archive a re-run delivered anew in between stays. It
    /// answers how many it dropped.
    pub(crate) fn drop_expired_removal_exports(&self) -> Result<usize> {
        let expired: Vec<String> = {
            let txn = self.store.env.read_txn()?;
            let now = self.store.clock.now_recorded_at();
            REMOVAL_EXPORT
                .scan(&self.store, &txn)?
                .into_iter()
                .filter(|(_, stored)| now >= stored.copy.expires_at)
                .map(|(row_key, _)| row_key)
                .collect()
        };
        if expired.is_empty() {
            return Ok(0);
        }
        let mut txn = self.store.env.write_txn()?;
        let now = self.store.clock.now_recorded_at();
        let mut dropped = 0;
        for row_key in &expired {
            let lapsed = REMOVAL_EXPORT
                .get(&self.store, &txn, row_key)?
                .is_some_and(|stored| now >= stored.copy.expires_at);
            if lapsed && REMOVAL_EXPORT.delete(&self.store, &mut txn, row_key)? {
                self.drop_removal_deliveries_for_export_in_txn(&mut txn, row_key)?;
                dropped += 1;
            }
        }
        txn.commit()?;
        Ok(dropped)
    }

    /// The completion of a held `erase` act (OF-150): once its own executor
    /// ([`crate::Memory::execute_completed_entity_erase`]) has erased the
    /// record the act names, its receipt, keyed by the act's own id, and one
    /// notice to each live Owner and the executor, the act's starter. A
    /// repeat returns the first receipt. Refused while the act is unclaimed
    /// or its erase is still under way.
    pub fn record_erase_completion(
        &self,
        executor: &AuthenticatedOwner,
        act_id: &str,
    ) -> Result<SharedActExecutionReceipt> {
        let mut txn = self.store.env.write_txn()?;
        let actor = executor.revalidate_person_in_txn(self, &txn)?;
        let act = self
            .pending_authority_act_in_txn(&txn, act_id)?
            .ok_or_else(invalid)?;
        if SharedActKind::parse(&act.act) != Some(SharedActKind::Erase)
            || act.starter != actor.to_hex()
        {
            return Err(invalid());
        }
        if let Some(receipt) = self.shared_act_receipt_in_txn(&txn, &act.id)? {
            return Ok(receipt);
        }
        let execution = act.execution.clone().ok_or_else(invalid)?;
        let record = self.held_erase_record(&act).ok_or_else(invalid)?;
        if execution.receipt.is_none()
            && !self.local_hard_delete_marker_exists_in_txn(&txn, &record)?
        {
            return Err(Error::ConcurrentWrite("the held erase is still under way"));
        }
        check_vault(self, &txn, act.vault_id)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let owners = live_owners(&self.live_act_holders(&txn, act.vault_id, now)?, None);
        let effect = Effect {
            change: SharedVaultChange::RecordErased {
                record: record.to_hex(),
                redaction: execution.receipt,
            },
            grants: Vec::new(),
            revoked_slips: Vec::new(),
            notify: BTreeSet::new(),
        };
        let receipt = self.record_shared_change_in_txn(
            &mut txn,
            act.id.clone(),
            act.vault_id,
            Some((act.id, execution.request)),
            actor,
            owners,
            effect,
            None,
            None,
            None,
            now,
        )?;
        txn.commit()?;
        Ok(receipt)
    }

    /// A receipt its reader was told about: every live Owner at the time,
    /// the actor and each holder the change concerned. Anyone else is refused.
    pub fn shared_act_receipt(
        &self,
        reader: &AuthenticatedOwner,
        receipt_id: &str,
    ) -> Result<SharedActExecutionReceipt> {
        let txn = self.store.env.read_txn()?;
        // Person tier: a holder reads the receipts they were told about.
        let reader = reader.revalidate_person_in_txn(self, &txn)?;
        let receipt_id = EntityId::from_hex(receipt_id)?.to_hex();
        if !self.reader_was_told_in_txn(&txn, reader, &receipt_id)? {
            return Err(invalid());
        }
        self.shared_act_receipt_in_txn(&txn, &receipt_id)?
            .ok_or_else(invalid)
    }

    /// The reader's own outcome notices for `vault_id`. A holder a change
    /// removed still reads the notice of that change.
    pub fn shared_act_outcomes(
        &self,
        reader: &AuthenticatedOwner,
        vault_id: u64,
    ) -> Result<Vec<SharedActOutcome>> {
        let txn = self.store.env.read_txn()?;
        // Person tier: a holder reads only their own prefix.
        let reader = reader.revalidate_person_in_txn(self, &txn)?;
        let prefix = key(OUTCOME_PREFIX, &format!("{}:", reader.to_hex()));
        let mut outcomes = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&txn, &prefix)? {
            let (_, bytes) = entry?;
            let outcome: SharedActOutcome = decode(&bytes)?;
            if outcome.vault_id == vault_id {
                outcomes.push(outcome);
            }
        }
        Ok(outcomes)
    }

    /// `person`'s own notices of losing the vault: their leave, their
    /// removal, an ownership change that left them no role, and the vault's
    /// deletion, made for `person` from the stored deletion marker whether or
    /// not a notice row names them (FIX 2053). Read for the holder a
    /// home-minted slip proves, whose slips may no longer authenticate
    /// (`Vault::removed_member_notices_signed`).
    pub(crate) fn removal_outcomes_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
    ) -> Result<Vec<SharedActOutcome>> {
        let person = person.to_hex();
        let prefix = key(OUTCOME_PREFIX, &format!("{person}:"));
        let mut outcomes = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(txn, &prefix)? {
            let (_, bytes) = entry?;
            let outcome: SharedActOutcome = decode(&bytes)?;
            let lost = match &outcome.change {
                SharedVaultChange::MemberLeft { member }
                | SharedVaultChange::MemberRemoved { member } => *member == person,
                SharedVaultChange::OwnerRemoved {
                    target,
                    target_keeps: None,
                    ..
                } => *target == person,
                SharedVaultChange::OwnershipTransferred {
                    from,
                    from_keeps: None,
                    ..
                }
                | SharedVaultChange::OwnerRecovered { from, .. } => *from == person,
                _ => false,
            };
            if lost {
                outcomes.push(outcome);
            }
        }
        if let Some(deletion) = self.shared_vault_deletion_in_txn(txn)? {
            outcomes.push(SharedActOutcome {
                receipt_id: deletion.receipt_id,
                act_id: Some(deletion.act_id),
                vault_id: deletion.vault_id,
                recipient: person,
                change: SharedVaultChange::VaultDeleted {
                    backup_retain_until: deletion.backup_retain_until,
                },
                completed_at: deletion.deleted_at,
            });
        }
        Ok(outcomes)
    }

    pub(crate) fn shared_vault_deletion_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<SharedVaultDeletion>> {
        shared_vault_deletion_for_store_in_txn(&self.store, txn)
    }

    /// The executed delete-the-vault act, if any. A host stops serving the
    /// vault once this is present and keeps backups only until its deadline.
    pub fn shared_vault_deletion(&self) -> Result<Option<SharedVaultDeletion>> {
        let txn = self.store.env.read_txn()?;
        self.shared_vault_deletion_in_txn(&txn)
    }
}
