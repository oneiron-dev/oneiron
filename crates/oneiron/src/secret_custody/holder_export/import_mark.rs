//! The owner's mark that he imported one export secret supplement (FIX
//! 12062), signed in the import's own writer: once its secret is restored
//! here, or found here already the same, this install, the recipient
//! machine the export named, carries his act to every install. Each stops
//! relaying the request's sealed copy on the window plane once it folds the
//! mark; every kept copy, and the owner's read of it, stay.
//!
//! The import's writer files the mark as owed before it signs it (FIX
//! 12291): one value-free intent under the request's entry, with the owner
//! the import revalidated, the surface he imported from (audit only) and the
//! second the import was at. No secret byte, ciphertext, secret name, proof,
//! credential or key is kept, and an intent already filed by an earlier
//! import is kept as it is. Only a failure to file the intent refuses the
//! import; a mark this install cannot sign, with no live machine profile or
//! no install key loaded, or one that fails to sign or fold, leaves the
//! intent owed and the import standing.
//!
//! The next pass on which this install can sign carries it, with no other
//! step from the owner: the moment its install key loads, and the owner work
//! pickup after an authority catch-up and on the served tick. Each intent is
//! judged again in a writer of its own and signed as the import's writer
//! signs it, by this install under the profile the roster then admits, and
//! dropped there once the fold counts the mark. It is dropped unsigned when
//! the fold counts an equal mark already, its request folds without effect
//! or answered refused, the request is not this owner's export secret
//! request, an admitted revoke or an erase here ended its secret, or the
//! owner is no longer a live vault owner. It waits while the request or this
//! install's profile is not folded here, or its key is not loaded.

use crate::Vault;
use crate::authority::{
    ActSurface, AuthorityEntryHash, AuthorityKey, AuthorityOp, EXPORT_ACT_TARGET_NAME,
    ExportSupplementImported, FrontierSigner, MAX_PARENTS, OwnerAct, OwnerActKind, OwnerWorkBody,
    OwnerWorkOutcome, invalid_authority, next_sequence, sign_side_entry,
};
use crate::error::{Error, Result, SecretError};
use crate::policy_setting_doors::owner_act_target;
use crate::store::pending_import_mark::{PENDING_IMPORT_MARK, PendingImportMark};
use crate::{EntityId, TimeRange};

/// What one owed mark came to in its writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkCarry {
    /// This writer signed the mark and the fold counts it; the intent is
    /// gone.
    Signed,
    /// Nothing is owed any more, or no intent is filed; the intent is gone
    /// and nothing is signed.
    Settled,
    /// The intent stays owed: the request or this install's profile is not
    /// folded here yet, or its key is not loaded.
    Owed,
}

/// What an owed mark's writer finds before it signs.
enum MarkJudgment {
    /// Sign it now.
    Sign,
    /// Keep it owed: its request is not folded here yet.
    Wait,
    /// Drop it unsigned, for the reason named.
    Drop(&'static str),
}

impl Vault {
    /// Marks the supplement of the export secret request signed as entry
    /// `request` imported, in the import's writer `txn`, for `actor`, the
    /// owner the import revalidated in it, from `surface`: files the mark
    /// as owed, keeping an intent already filed, then signs it in a
    /// savepoint of `txn` when this install can carry it now. Returns
    /// whether this writer signed a mark the fold counts. A fault past the
    /// intent's write is logged by kind and leaves the intent owed, the
    /// import standing and the request's rows riding on until a pass signs
    /// it. A request already marked takes no second mark.
    ///
    /// # Errors
    /// The intent's own write.
    pub(crate) fn mark_supplement_imported_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        surface: ActSurface,
        request: AuthorityEntryHash,
    ) -> Result<bool> {
        if !PENDING_IMPORT_MARK.contains(&self.store, txn, &request)? {
            let pending = PendingImportMark {
                owner: actor,
                surface,
                imported_at: self.instant_in_txn(txn)?.secs(),
            };
            PENDING_IMPORT_MARK.put(&self.store, txn, &request, &pending)?;
        }
        let carried = self
            .store
            .env
            .nested_write_txn(txn)
            .map_err(Error::from)
            .and_then(|mut savepoint| {
                let carried = self.carry_import_mark_in_txn(&mut savepoint, request)?;
                savepoint.commit().map_err(Error::from)?;
                Ok(carried)
            });
        match carried {
            Ok(carried) => Ok(carried == MarkCarry::Signed),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "an imported export secret supplement was not marked in its writer; its mark stays owed"
                );
                Ok(false)
            }
        }
    }

    /// Signs every import mark this install still owes (FIX 12291), each in
    /// a writer of its own, and returns how many it signed. The caller loads
    /// the install key first; what it signs reaches the live windows on
    /// their next refresh or open. A writer that fails is logged by kind,
    /// never with a value, and its intent stays owed; the others are still
    /// tried.
    pub(crate) fn carry_pending_import_marks_logged(&self) -> usize {
        let owed = match self.owed_import_marks() {
            Ok(owed) => owed,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "owed export supplement import marks were not read on this install"
                );
                return 0;
            }
        };
        let mut signed = 0;
        for request in owed {
            match self.with_write_txn(|txn| self.carry_import_mark_in_txn(txn, request)) {
                Ok(MarkCarry::Signed) => signed += 1,
                Ok(MarkCarry::Settled | MarkCarry::Owed) => {}
                Err(error) => {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "an owed export supplement import mark was not signed on this install; it stays owed"
                    );
                }
            }
        }
        if signed > 0 {
            tracing::debug!(signed, "owed export supplement import marks signed");
        }
        signed
    }

    /// The owner work pickup's arm (FIX 12291): with an import mark owed,
    /// loads this install's key, signs what it can, and mirrors what it
    /// settled into the live windows, so their relayed copies leave.
    /// Nothing is read from the keystore while none is owed.
    pub(crate) fn carry_owed_import_marks(&self) {
        let before = match self.owed_import_marks() {
            Ok(owed) if owed.is_empty() => return,
            Ok(owed) => owed.len(),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "owed export supplement import marks were not read on this install"
                );
                return;
            }
        };
        // A key that loads now signs them as it loads; this pass signs them
        // with a key loaded before.
        let _ = self.load_install_signing_if_minted();
        self.carry_pending_import_marks_logged();
        #[cfg(feature = "sync")]
        if self
            .owed_import_marks()
            .is_ok_and(|after| after.len() < before)
        {
            self.refresh_custody_in_live_windows();
        }
        #[cfg(not(feature = "sync"))]
        let _ = before;
    }

    /// The requests whose import mark this install still owes.
    fn owed_import_marks(&self) -> Result<Vec<AuthorityEntryHash>> {
        let txn = self.store.env.read_txn()?;
        PENDING_IMPORT_MARK.scan_keys(&self.store, &txn, &[])
    }

    /// Carries the mark owed under `request` in `txn`, judged again here:
    /// signed and dropped once the fold counts it, dropped unsigned when
    /// nothing is owed any more, kept while this install cannot sign it.
    fn carry_import_mark_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        request: AuthorityEntryHash,
    ) -> Result<MarkCarry> {
        let Some(pending) = PENDING_IMPORT_MARK.get(&self.store, txn, &request)? else {
            return Ok(MarkCarry::Settled);
        };
        let carried = match self.judge_import_mark_in_txn(txn, &request, &pending)? {
            MarkJudgment::Wait => MarkCarry::Owed,
            MarkJudgment::Drop(reason) => {
                tracing::debug!(
                    reason,
                    "an owed export supplement import mark was dropped unsigned"
                );
                MarkCarry::Settled
            }
            MarkJudgment::Sign => {
                if self.sign_import_mark_in_txn(txn, pending.owner, pending.surface, request)? {
                    MarkCarry::Signed
                } else {
                    MarkCarry::Owed
                }
            }
        };
        if carried != MarkCarry::Owed {
            PENDING_IMPORT_MARK.delete(&self.store, txn, &request)?;
        }
        Ok(carried)
    }

    /// What `txn` holds of the mark `pending` owes for `request`: still to
    /// sign while the request is this owner's export secret request, on the
    /// fold with no equal mark, no refusal and its secret not ended by an
    /// admitted revoke or an erase here, and the owner is still a live vault
    /// owner; owed while the fold does not hold the request yet.
    fn judge_import_mark_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        request: &AuthorityEntryHash,
        pending: &PendingImportMark,
    ) -> Result<MarkJudgment> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if fold.export_supplement_imported(request) {
            return Ok(MarkJudgment::Drop("an equal mark counts already"));
        }
        if fold.refused_owner_work().contains(request) {
            return Ok(MarkJudgment::Drop("its request folds without effect"));
        }
        let Some(asked) = fold.owner_work_request(request) else {
            return Ok(MarkJudgment::Wait);
        };
        let OwnerWorkBody::ExportSecret(work) = &asked.work else {
            return Ok(MarkJudgment::Drop(
                "its request is no export secret request",
            ));
        };
        if asked.act.owner != pending.owner {
            return Ok(MarkJudgment::Drop(
                "its request carries another owner's export",
            ));
        }
        if fold
            .owner_work_result(request)
            .is_some_and(|answer| matches!(answer.outcome, OwnerWorkOutcome::Refused { .. }))
        {
            return Ok(MarkJudgment::Drop("its request was answered refused"));
        }
        if fold.custody_revoked(&work.secret)
            || self.store.credential_fenced_in_txn(txn, &work.secret)
        {
            return Ok(MarkJudgment::Drop("its secret was revoked or erased"));
        }
        if !crate::policy_model::is_live_vault_owner_in_txn(self, txn, &pending.owner)? {
            return Ok(MarkJudgment::Drop(
                "its owner is no longer a live vault owner",
            ));
        }
        Ok(MarkJudgment::Sign)
    }

    /// Signs and lands the mark in `txn`, for `actor` from `surface`, and
    /// returns whether the fold counts it there: `false`, with nothing
    /// written, while this install has no live machine profile or no
    /// install key loaded. Its parents are the main-log heads alone, which
    /// carry the request (FIX 4987). The fold is the judge: a mark it does
    /// not take refuses `txn`.
    fn sign_import_mark_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        surface: ActSurface,
        request: AuthorityEntryHash,
    ) -> Result<bool> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if fold.export_supplement_imported(&request) {
            return Ok(true);
        }
        // Key possession: this install carries the act with its own install
        // key, under a live profile of any role (mesh contract §3). Keys
        // not loaded here are a "not yet", never a failure.
        let carrier = match self.owner_work_carrier_in_txn(txn, &fold) {
            Ok(carrier) => carrier,
            Err(Error::Secret(SecretError::KeystoreUnavailable(_))) => None,
            Err(error) => return Err(error),
        };
        let Some((machine, signing)) = carrier else {
            return Ok(false);
        };
        let public_key = signing.verifying_key().to_bytes();
        let act = OwnerAct::by_owner(
            actor,
            OwnerActKind::Export,
            owner_act_target(EXPORT_ACT_TARGET_NAME)?,
            surface,
            ExportSupplementImported::seen_for(request),
        );
        // FIX 7908: join a frontier wider than one entry names, else today's path.
        let joiner = FrontierSigner::Install(machine, &signing);
        let fold = self
            .prepare_authority_frontier_in_txn(txn, &fold, joiner, MAX_PARENTS)?
            .unwrap_or(fold);
        let parents = fold.owner_work_parents();
        if parents.len() > MAX_PARENTS {
            return Err(invalid_authority());
        }
        let mark = ExportSupplementImported {
            carrier: machine,
            act,
            request,
        };
        let seq = next_sequence(&fold, &AuthorityKey::Ed25519(public_key))?;
        let now = self.instant_in_txn(txn)?.secs();
        let entry = sign_side_entry(
            &fold,
            &signing,
            seq,
            parents,
            AuthorityOp::ExportSupplementImported(mark),
            now,
        )?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        if !self
            .authority_view_readonly_in_txn(txn)?
            .export_supplement_imported(&request)
        {
            return Err(invalid_authority());
        }
        Ok(true)
    }
}
