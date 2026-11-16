//! Answers to a recovery hold: an owner device's "it is me" or "Cancel it", and
//! the kit's Cancel through R (WAYBACK-RECOVERY-HOLD-WIRE = A, ANCHORS-E6).

use super::*;

impl Vault {
    /// Answers the live recovery hold `hold` with `answer`, signed by this
    /// install's held live owner key: the device unlock is the confirm
    /// sheet, and the surface stays audit-only. The key is any key this
    /// install holds that may answer ([`answers_recovery_holds`]: a live
    /// owner device key, never an admin's or a host's), is not the hold's
    /// successor and is not the root's authority kind; R's held seed
    /// answers nothing. The answer is marked for the live mirror and
    /// announced, so the door install sees it at the next mirror pass. An
    /// unknown hold is [`HOLD_NOT_LIVE`]; a terminal one too, once no held
    /// key speaks for it first.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] for an agent's act, a
    /// hold that is not live, a held key that is the successor or the root's
    /// key, and this install holding no live owner key; an answer the fold
    /// does not count; the store's, the clock's and the keystore's.
    pub fn answer_recovery_hold_as(
        &self,
        authority: &ActAuthority,
        hold: AuthorityEntryHash,
        answer: RecoveryHoldAnswerKind,
    ) -> Result<()> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(ANSWER_OWNER_ONLY)),
        };
        let machine = self.prepare_install_signing()?;
        let mut candidates: Vec<(AuthorityKey, AnswerKey)> = self
            .checkpoint_root_signers()
            .into_iter()
            .map(|signer| (signer.root(), AnswerKey::Held(signer)))
            .collect();
        if let Some(slot) = self.existing_device_owner_signing_key()? {
            let key = AuthorityKey::Ed25519(slot.public_key());
            if !candidates.iter().any(|(held, _)| *held == key) {
                candidates.push((key, AnswerKey::Slot(slot)));
            }
        }
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let view = self
            .recovery_holds_in_txn(&txn)?
            .into_iter()
            .find(|found| found.hold == hold)
            .ok_or_else(|| authority_refused(HOLD_NOT_LIVE))?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let enrolled = self.enrolled_owner_keys_in_txn(&txn)?;
        let live_owner =
            |key: &AuthorityKey| fold.roster.get(key).is_some_and(answers_recovery_holds);
        let is_root_kind = |key: &AuthorityKey| {
            enrolled.iter().any(|listed| {
                AuthorityKey::Ed25519(listed.public_key) == *key
                    && listed.kind == EnrolledOwnerKeyKind::RecoveryAuthority
            })
        };
        let answered = candidates
            .iter()
            .find(|(key, _)| *key != view.successor_key && !is_root_kind(key) && live_owner(key));
        let Some((key, answered)) = answered else {
            if candidates.iter().any(|(key, _)| *key == view.successor_key) {
                return Err(authority_refused(ANSWER_KEY_IS_SUCCESSOR));
            }
            let AuthorityKey::Ed25519(successor) = view.successor_key else {
                return Err(invalid_authority());
            };
            let slot = self.recovery_hold_slot(&vault_id, machine, &successor);
            let holds_root = candidates.iter().any(|(key, _)| is_root_kind(key))
                || self.read_recovery_hold_seed(&slot)?.is_some();
            if holds_root {
                return Err(authority_refused(ANSWER_KEY_IS_ROOT));
            }
            return Err(authority_refused(NO_OWNER_KEY));
        };
        if !matches!(
            view.state,
            RecoveryHoldState::Waiting | RecoveryHoldState::Due
        ) {
            return Err(authority_refused(HOLD_NOT_LIVE));
        }
        let now = self.instant_in_txn(&txn)?.secs();
        let sign = |transcript: &[u8]| answered.sign(transcript);
        self.append_recovery_hold_answer_in_txn(
            &mut txn,
            key,
            &sign,
            RecoveryHoldAnswer { hold, answer },
            now,
        )?;
        let rows = self.mark_authority_rows_counted_since_in_txn(&mut txn, &fold)?;
        txn.commit()?;
        self.note_committed_authority_rows(rows);
        Ok(())
    }

    /// Cancels the live recovery hold `hold`, or every live hold when none
    /// is named, with the kit's live root key R, which the kit `pieces`
    /// rebuild (with `passphrase` when the kit takes one): the kit stops the
    /// attempt, through R like any owner key (lead ANCHORS-3 = A). A kit
    /// cancels only the live holds its live root key R signed: cancelling
    /// every hold skips another root's holds, and a named hold another key
    /// signed is refused. A kit holds no other root's key (a co-owner's, or
    /// an earlier kit's that is still live), so that root's hold stays live
    /// until the key is revoked, which voids it. With no live R from the
    /// kit, cancelling every hold
    /// cancels nothing. One write transaction; cancelling nothing is no
    /// refusal.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] for an agent's act,
    /// unreadable kit pieces, a named hold that is not live, and a named
    /// hold this kit's root key did not sign; a cancellation the fold does
    /// not count; the store's and the clock's.
    pub fn cancel_recovery_holds_with_kit_as(
        &self,
        authority: &ActAuthority,
        pieces: &[&KitPiece],
        passphrase: Option<&KitPassphrase>,
        hold: Option<AuthorityEntryHash>,
    ) -> Result<()> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(ANSWER_OWNER_ONLY)),
        };
        let vault_id = {
            let txn = self.store.env.read_txn()?;
            self.authority_view_readonly_in_txn(&txn)?
                .vault_id
                .ok_or_else(invalid_authority)?
        };
        let secret =
            crate::recovery::restore_kit(vault_id, KitSecretKind::RecoveryRoot, pieces, passphrase)
                .map_err(|_| authority_refused(KIT_PIECES_UNREADABLE))?;
        let seed = crate::world_keys::RecoveryRootSeed::from_restored_kit(secret)?;
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let views = self.recovery_holds_in_txn(&txn)?;
        let live = |state: RecoveryHoldState| {
            matches!(state, RecoveryHoldState::Waiting | RecoveryHoldState::Due)
        };
        let live_r = self
            .recovery_authority_generations_in_txn(&txn, &seed, &vault_id)?
            .live
            .map(|(_, signer)| signer);
        let targets: Vec<AuthorityEntryHash> = match hold {
            Some(named) => {
                let view = views
                    .into_iter()
                    .find(|found| found.hold == named)
                    .ok_or_else(|| authority_refused(HOLD_NOT_LIVE))?;
                if !live(view.state) {
                    return Err(authority_refused(HOLD_NOT_LIVE));
                }
                let Some(r) = &live_r else {
                    return Err(authority_refused(KIT_ROOT_NOT_HOLD_SIGNER));
                };
                if view.root_key != r.authority_key() {
                    return Err(authority_refused(KIT_ROOT_NOT_HOLD_SIGNER));
                }
                vec![named]
            }
            None => match &live_r {
                Some(r) => {
                    let r_key = r.authority_key();
                    views
                        .into_iter()
                        .filter(|found| live(found.state) && found.root_key == r_key)
                        .map(|found| found.hold)
                        .collect()
                }
                None => Vec::new(),
            },
        };
        let before = self.authority_view_readonly_in_txn(&txn)?;
        if !targets.is_empty() {
            let Some(r) = &live_r else {
                return Err(authority_refused(KIT_ROOT_NOT_HOLD_SIGNER));
            };
            self.append_root_key_cancels_in_txn(&mut txn, r, &targets)?;
        }
        let rows = self.mark_authority_rows_counted_since_in_txn(&mut txn, &before)?;
        txn.commit()?;
        self.note_committed_authority_rows(rows);
        Ok(())
    }
}
