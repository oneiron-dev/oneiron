//! Executing a matured delete-the-vault, ownership-transfer or owner-removal act.

use super::membership::MemberMove;
use super::*;

impl Vault {
    /// Execute a completed `delete_vault`, `transfer_ownership` or
    /// `remove_owner` act. Any live Owner may run it once its window has
    /// passed on the store clock with no live objection, while its starter
    /// is still a live Owner. The claim, the effect, the receipt and every
    /// recipient's notice commit in one writer, so the act takes effect at
    /// most once; running it again returns the same receipt, to a reader
    /// that receipt told and no one else (FIX 3216). With `slips`,
    /// the capability slips of anyone who lost a role are revoked with it,
    /// and the host signs an ownership change into the authority log as an
    /// `OwnerHandover` naming the act and its receipt.
    /// An export-first removal, once its executor and starter stand as live
    /// Owners holding the act's verb (FIX 3217), exports what its target
    /// could read before the writer opens, records that export's digest in
    /// the receipt, and delivers the archive to the removed Owner alone,
    /// retrievable by them for [`REMOVAL_EXPORT_RETAIN_SECS`] (FIX 1300);
    /// the answer names that delivery, never the archive. A remaining live
    /// Owner's re-run of an executed export-first removal answers the same
    /// receipt and delivers the stored archive to the removed Owner again
    /// for a full term; the removal never runs twice, and an archive already
    /// purged past its term is not rebuilt.
    pub fn execute_completed_shared_act(
        &self,
        executor: &AuthenticatedOwner,
        act_id: &str,
        slips: Option<&HostSlipIssuer>,
    ) -> Result<SharedActExecution> {
        let mut export = self
            .removal_export(executor, act_id)?
            .map(|(member, records)| {
                let ids = records.iter().map(|record| record.id).collect();
                // Its diary reads are the removed owner's, who receives it.
                let reader = crate::write_envelope::WriteActor::new(
                    member,
                    crate::edge::EdgeActorClass::Human,
                );
                self.export_records_archive(&ids, reader, |txn| {
                    removal_archive::freeze_positions_in_txn(self, txn, &ids)
                })
                .map(|frozen| (member, records.len() as u64, frozen, ids))
            })
            .transpose()?;
        let mut txn = self.store.env.write_txn()?;
        let actor = executor.revalidate_person_in_txn(self, &txn)?;
        let act = self
            .pending_authority_act_in_txn(&txn, act_id)?
            .ok_or_else(invalid)?;
        let kind = SharedActKind::parse(&act.act).ok_or_else(invalid)?;
        if kind == SharedActKind::Erase {
            // A held erase runs through its own door, which binds the record.
            return Err(invalid());
        }
        if let Some(execution) = &act.execution {
            let receipt = execution
                .receipt
                .as_deref()
                .map(|id| self.shared_act_receipt_in_txn(&txn, id))
                .transpose()?
                .flatten()
                .ok_or(Error::ConcurrentWrite("authority act already executed"))?;
            if !self.reader_was_told_in_txn(&txn, actor, &receipt.id)? {
                return Err(invalid());
            }
            let delivery = match &receipt.export {
                Some(summary) => self.redeliver_removal_export_in_txn(
                    &mut txn,
                    &act,
                    actor,
                    &summary.member,
                    &receipt.id,
                )?,
                None => None,
            };
            txn.commit()?;
            return Ok(SharedActExecution {
                receipt,
                delivery,
                export_records: None,
            });
        }
        let creation = check_vault(self, &txn, act.vault_id)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let owners = self.act_executors_in_txn(&txn, &act, actor, now)?;
        let receipt_id = self.store.clock.entity_id()?.to_hex();
        let request_id = self.store.clock.entity_id()?.to_hex();
        self.claim_completed_authority_act_in_txn(
            &mut txn,
            &act.id,
            request_id.clone(),
            Some(receipt_id.clone()),
        )?;
        // The grant ids an Owner handover wrote and retired, for its signed
        // entry (FIX 5765).
        let mut handover_ids = (Vec::new(), Vec::new());
        let effect = match kind {
            SharedActKind::DeleteVault => {
                let plan: DeleteVaultPlan = decode(&act.payload)?;
                if plan.v != PLAN_VERSION {
                    return Err(invalid());
                }
                let deletion = SharedVaultDeletion {
                    vault_id: creation.vault_id,
                    act_id: act.id.clone(),
                    receipt_id: receipt_id.clone(),
                    deleted_at: now,
                    backup_retain_until: now
                        .checked_add(DELETED_VAULT_BACKUP_RETENTION_SECS)
                        .ok_or_else(invalid)?,
                };
                SHARED_VAULT_DELETION.put(&self.store, &mut txn, &(), &deletion)?;
                Effect {
                    change: SharedVaultChange::VaultDeleted {
                        backup_retain_until: deletion.backup_retain_until,
                    },
                    grants: Vec::new(),
                    revoked_slips: Vec::new(),
                    notify: BTreeSet::new(),
                }
            }
            SharedActKind::TransferOwnership => {
                let plan: TransferOwnershipPlan = decode(&act.payload)?;
                let (from, to) = (hex_id(&plan.from)?, hex_id(&plan.to)?);
                if plan.v != PLAN_VERSION || plan.from != act.starter {
                    return Err(invalid());
                }
                let moved = self.hand_over_in_txn(
                    &mut txn,
                    act.vault_id,
                    &owners,
                    from,
                    plan.from_keeps,
                    Some(to),
                    slips,
                    now,
                )?;
                handover_ids = moved.handover_ids();
                let MemberMove {
                    grants,
                    revoked_slips,
                    ..
                } = moved;
                Effect {
                    change: SharedVaultChange::OwnershipTransferred {
                        from: plan.from,
                        to: plan.to,
                        from_keeps: plan.from_keeps,
                    },
                    grants,
                    revoked_slips,
                    notify: BTreeSet::from([from, to]),
                }
            }
            SharedActKind::RemoveOwner => {
                let plan: RemoveOwnerPlan = decode(&act.payload)?;
                let target = hex_id(&plan.target)?;
                let successor = plan.successor.as_deref().map(hex_id).transpose()?;
                if plan.v != PLAN_VERSION
                    || plan.export_first != export.as_ref().is_some_and(|(of, ..)| *of == target)
                {
                    return Err(invalid());
                }
                let moved = self.hand_over_in_txn(
                    &mut txn,
                    act.vault_id,
                    &owners,
                    target,
                    plan.target_keeps,
                    successor,
                    slips,
                    now,
                )?;
                handover_ids = moved.handover_ids();
                let MemberMove {
                    grants,
                    revoked_slips,
                    ..
                } = moved;
                Effect {
                    change: SharedVaultChange::OwnerRemoved {
                        target: plan.target,
                        successor: plan.successor,
                        target_keeps: plan.target_keeps,
                    },
                    grants,
                    revoked_slips,
                    notify: BTreeSet::from_iter([Some(target), successor].into_iter().flatten()),
                }
            }
            SharedActKind::Erase => return Err(invalid()),
        };
        let mut authority_entry = None;
        if let Some(issuer) = slips {
            let handover = match &effect.change {
                SharedVaultChange::OwnershipTransferred {
                    from,
                    to,
                    from_keeps,
                } => Some((OwnerHandoverCause::Transfer, from, Some(to), from_keeps)),
                SharedVaultChange::OwnerRemoved {
                    target,
                    successor,
                    target_keeps,
                } => Some((
                    OwnerHandoverCause::Removal,
                    target,
                    successor.as_ref(),
                    target_keeps,
                )),
                _ => None,
            };
            if let Some((cause, from, to, keeps)) = handover {
                let (affected_grants, retired_own_device_grants) = handover_ids;
                authority_entry = Some(self.append_owner_handover_in_txn(
                    &mut txn,
                    issuer,
                    OwnerHandover {
                        shared_vault: act.vault_id,
                        cause,
                        from: hex_id(from)?,
                        to: to.map(|to| hex_id(to)).transpose()?,
                        from_keeps: keeps.map(|role| role.as_str().to_owned()),
                        act: Some(act.id.clone()),
                        proof: None,
                        authorizer: None,
                        receipt: receipt_id.clone(),
                        affected_grants,
                        retired_own_device_grants,
                    },
                )?);
            }
        }
        let mut export_records = None;
        let export = export.take().map(|(member, records, archive, ids)| {
            export_records = Some(ids.into_iter().collect());
            let summary = SharedActExport {
                member: member.to_hex(),
                records,
                digest: blake3::hash(archive.0.bytes()).to_hex().to_string(),
                diary_reads: archive.0.diary_reads().to_vec(),
            };
            (summary, archive)
        });
        let (summary, archive) = export.unzip();
        let receipt = self.record_shared_change_in_txn(
            &mut txn,
            receipt_id,
            act.vault_id,
            Some((act.id.clone(), request_id)),
            actor,
            owners,
            effect,
            summary,
            authority_entry,
            None,
            now,
        )?;
        let delivery = match (&receipt.export, archive) {
            (Some(summary), Some((archive, positions))) => {
                let copy = RemovalExportCopy {
                    receipt_id: receipt.id.clone(),
                    vault_id: act.vault_id,
                    member: summary.member.clone(),
                    delivered_at: now,
                    expires_at: now
                        .checked_add(REMOVAL_EXPORT_RETAIN_SECS)
                        .ok_or_else(invalid)?,
                    export: crate::memory::MemoryExport {
                        format: crate::batch::export::VAULT_ARCHIVE_FORMAT.to_owned(),
                        archive: archive.bytes,
                        digest: summary.digest.clone(),
                    },
                };
                let row_key = removal_export_key(&copy.member, &copy.receipt_id);
                let delivery = copy.delivery();
                let stored = removal_archive::StoredRemovalExport::new(copy, positions);
                REMOVAL_EXPORT.put(&self.store, &mut txn, &row_key, &stored)?;
                Some(delivery)
            }
            _ => None,
        };
        txn.commit()?;
        if !receipt.revoked_slips.is_empty() {
            self.store.notify_credential_revocations();
        }
        Ok(SharedActExecution {
            receipt,
            delivery,
            export_records,
        })
    }
}
