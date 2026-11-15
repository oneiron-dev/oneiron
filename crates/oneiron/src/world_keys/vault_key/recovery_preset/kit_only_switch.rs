//! The switch to Nobody but me with the kit present: the kit's doors, and the
//! rotation of the root's authority key R in the switch's write (pass 27 kit-only).

use super::*;

const KIT_NOT_THIS_VAULTS: &str = "this recovery kit does not hold this vault's live way back; nothing \
                                   was written";

impl Vault {
    /// [`Vault::set_recovery_preset_as`] with the recovery kit: `pieces` and
    /// `passphrase` read as [`Vault::confirm_world_kit`] reads them. Entering
    /// "Nobody but me" from `Standard` while a generation is live enrols the
    /// next generation and revokes the live one in the same write as the
    /// preset change; the kit's generation must be the live one, else
    /// `KIT_NOT_THIS_VAULTS`. Kit-only to kit-only, re-entering the same
    /// preset and the switch back change no roster. No seed is handed out.
    pub fn set_recovery_preset_with_kit_as(
        &self,
        authority: &crate::authority::ActAuthority,
        preset: RecoveryPreset,
        pieces: &[&KitPiece],
        passphrase: Option<&KitPassphrase>,
        keep_sheet: impl FnOnce(&RecoverySheet) -> Result<()>,
        box_hold: &dyn RecoveryBoxHold,
    ) -> Result<RecoveryPresetChange> {
        if matches!(authority, crate::authority::ActAuthority::Agent(_)) {
            return Err(crate::authority::authority_refused(PRESET_OWNER_ONLY));
        }
        let (rotation, any_live) = self.prepare_kit_rotation(pieces, passphrase)?;
        if self.recovery_preset()? == RecoveryPreset::Standard
            && preset.is_nobody_but_me()
            && rotation.live_pre.is_none()
            && any_live
        {
            return Err(crate::authority::authority_refused(KIT_NOT_THIS_VAULTS));
        }
        self.set_recovery_preset_handed_over(
            authority,
            preset,
            keep_sheet,
            SheetHandover::Kept,
            Some(rotation),
            box_hold,
        )
    }

    /// [`Vault::set_recovery_preset_with_kit_as`] for a caller whose answer is
    /// the sheet's only hand-over, as the owner API's is: entering needs this
    /// install's device wrap to stay, as
    /// [`Vault::set_recovery_preset_answered_as`] needs it.
    pub fn set_recovery_preset_answered_with_kit_as(
        &self,
        authority: &crate::authority::ActAuthority,
        preset: RecoveryPreset,
        pieces: &[&KitPiece],
        passphrase: Option<&KitPassphrase>,
        box_hold: &dyn RecoveryBoxHold,
    ) -> Result<RecoveryPresetChange> {
        if matches!(authority, crate::authority::ActAuthority::Agent(_)) {
            return Err(crate::authority::authority_refused(PRESET_OWNER_ONLY));
        }
        let device_wrap = self.device_wrap_held_here()?;
        let (rotation, any_live) = self.prepare_kit_rotation(pieces, passphrase)?;
        if self.recovery_preset()? == RecoveryPreset::Standard
            && preset.is_nobody_but_me()
            && rotation.live_pre.is_none()
            && any_live
        {
            return Err(crate::authority::authority_refused(KIT_NOT_THIS_VAULTS));
        }
        self.set_recovery_preset_handed_over(
            authority,
            preset,
            |_| Ok(()),
            SheetHandover::Answer { device_wrap },
            Some(rotation),
            box_hold,
        )
    }

    /// Restores the kit's seed from `pieces` and `passphrase` (as
    /// [`Vault::confirm_world_kit`] reads them: two pieces, or one and the
    /// passphrase) and finds the live generation it held on a read snapshot,
    /// deriving the next generation pre-write. No store or keystore write.
    /// Returns the prepared rotation with whether any generation is live at
    /// all (for the wrong-kit check). The write finds the live generation
    /// again in its txn.
    pub(super) fn prepare_kit_rotation(
        &self,
        pieces: &[&KitPiece],
        passphrase: Option<&KitPassphrase>,
    ) -> Result<(PreparedRotation, bool)> {
        let seed = self.kit_seed(pieces, passphrase)?.seed;
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold
            .vault_id
            .ok_or_else(crate::authority::invalid_authority)?;
        let live_pre = self
            .recovery_authority_generations_in_txn(&txn, &seed, &vault_id)?
            .live
            .map(|(generation, _)| generation);
        if let Some(generation) = live_pre {
            let next = generation
                .checked_add(1)
                .ok_or_else(crate::authority::invalid_authority)?;
            let _ = crate::world_keys::RecoveryAuthoritySigner::from_seed(&seed, &vault_id, next)?;
        }
        let any_live = self.any_live_recovery_authority_in_txn(&txn)?;
        Ok((PreparedRotation { seed, live_pre }, any_live))
    }

    /// Rotates the recovery authority key in the preset's write `txn`, which
    /// enters kit-only from `Standard`: with `rotation` (a kit door), the
    /// kit's generation must be the live one, else `KIT_NOT_THIS_VAULTS`,
    /// then the rotation step; without it (a kitless door), a live
    /// generation refuses `KIT_ONLY_NEEDS_KIT`. No live generation writes no
    /// roster row. Returns the new live generation, if it rotated.
    pub(super) fn maybe_rotate_recovery_authority_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        authority: &crate::authority::ActAuthority,
        rotation: &Option<PreparedRotation>,
    ) -> Result<Option<u32>> {
        let Some(prepared) = rotation else {
            if self.any_live_recovery_authority_in_txn(txn)? {
                return Err(crate::authority::authority_refused(KIT_ONLY_NEEDS_KIT));
            }
            return Ok(None);
        };
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let vault_id = fold
            .vault_id
            .ok_or_else(crate::authority::invalid_authority)?;
        let found = self.recovery_authority_generations_in_txn(txn, &prepared.seed, &vault_id)?;
        match found.live {
            Some((live, _)) => {
                if prepared.live_pre.is_some_and(|before| before != live) {
                    return Err(crate::authority::authority_refused(KIT_NOT_THIS_VAULTS));
                }
                let (next, _, _) = self.rotate_recovery_authority_key_in_txn(
                    txn,
                    authority,
                    &prepared.seed,
                    live,
                )?;
                Ok(Some(next))
            }
            None => {
                if self.any_live_recovery_authority_in_txn(txn)? {
                    return Err(crate::authority::authority_refused(KIT_NOT_THIS_VAULTS));
                }
                Ok(None)
            }
        }
    }

    /// [`Vault::set_recovery_preset_any_two_as`] with the recovery kit:
    /// `pieces` and `passphrase` read as [`Vault::confirm_world_kit`] reads
    /// them. Entering from `Standard` while a generation is live enrols the
    /// next generation and revokes the live one in the same write; the kit's
    /// generation must be the live one, else `KIT_NOT_THIS_VAULTS`. With the
    /// switch already on, the new kit is issued and no roster changes. No
    /// seed is handed out.
    pub fn set_recovery_preset_any_two_with_kit_as(
        &self,
        authority: &crate::authority::ActAuthority,
        issue: &KitIssue<'_>,
        passkey: Option<KitPasskey<'_>>,
        pieces: &[&KitPiece],
        passphrase: Option<&KitPassphrase>,
        keep_pieces: impl FnOnce(&[KitPiece]) -> Result<()>,
        box_hold: &dyn RecoveryBoxHold,
    ) -> Result<RecoveryPresetAnyTwoChange> {
        if matches!(authority, crate::authority::ActAuthority::Agent(_)) {
            return Err(crate::authority::authority_refused(PRESET_OWNER_ONLY));
        }
        let (rotation, any_live) = self.prepare_kit_rotation(pieces, passphrase)?;
        if self.recovery_preset()? == RecoveryPreset::Standard
            && rotation.live_pre.is_none()
            && any_live
        {
            return Err(crate::authority::authority_refused(KIT_NOT_THIS_VAULTS));
        }
        self.set_recovery_preset_any_two_handed_over(
            authority,
            issue,
            passkey,
            keep_pieces,
            Some(rotation),
            box_hold,
        )
    }

    pub(super) fn set_recovery_preset_any_two_handed_over(
        &self,
        authority: &crate::authority::ActAuthority,
        issue: &KitIssue<'_>,
        passkey: Option<KitPasskey<'_>>,
        keep_pieces: impl FnOnce(&[KitPiece]) -> Result<()>,
        rotation: Option<PreparedRotation>,
        box_hold: &dyn RecoveryBoxHold,
    ) -> Result<RecoveryPresetAnyTwoChange> {
        let owner = match authority {
            crate::authority::ActAuthority::Owner(owner, _) => owner,
            crate::authority::ActAuthority::Agent(_) => {
                return Err(crate::authority::authority_refused(PRESET_OWNER_ONLY));
            }
        };
        if !matches!(self.data_key_custody(), VaultDataKeyCustody::OwnerHeldLocal) {
            return Err(refused(PRESET_CUSTODY));
        }
        // Entering from Standard without the kit while a generation is live
        // is refused before anything is drawn or kept. The write checks
        // again. The target is always kit-only here.
        if rotation.is_none() && self.recovery_preset()? == RecoveryPreset::Standard {
            let txn = self.store.env.read_txn()?;
            if self.any_live_recovery_authority_in_txn(&txn)? {
                return Err(crate::authority::authority_refused(KIT_ONLY_NEEDS_KIT));
            }
        }
        let held = self
            .held_vault_key()
            .ok_or_else(|| refused("the vault key is not held on this handle: unlock it first"))?;
        let mut drawn = self.draw_vault_key_kit(&held, owner, issue, passkey)?;
        let point = drawn.point.take();
        let commitment = drawn.commitment;
        // The owner's pieces are kept before this install's slot is
        // replaced, so a failed keep leaves the earlier kit's local piece.
        drawn.keep_owner_pieces(keep_pieces)?;
        let kit = drawn.hand_over(true)?;
        let preset = RecoveryPreset::NobodyButMeAnyTwo;
        // The target is always kit-only: write the box-hold-pending marker in
        // its own write before holding the box, after the no-write checks pass;
        // the switch's own write clears it. A failure after the hold releases
        // the box again on a vault still on `Standard`.
        let attempt = fresh_box_hold_attempt()?;
        self.with_write_txn(|txn| {
            self.put_recovery_box_hold_pending_in_txn(
                txn,
                &RecoveryBoxHoldPending {
                    target_kit_only: true,
                    attempt,
                },
            )
        })?;
        box_hold.hold_kit_only(true)?;
        let transition = self.release_box_hold_on_failure(
            self.begin_wrap_transition(),
            true,
            Some(attempt),
            box_hold,
        )?;
        let written = self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            self.clear_recovery_box_hold_pending_in_txn(txn, attempt)?;
            let mut state = STATE
                .get(&self.store, txn, &())?
                .ok_or_else(|| refused("the vault has no data key"))?;
            if state.commitment != commitment {
                return Err(refused("this handle holds another vault key"));
            }
            // Rotation happens iff Standard goes to kit-only and a generation
            // is live. With the switch already on, the new kit is issued and
            // no roster changes.
            if state.recovery == RecoveryPreset::Standard {
                self.maybe_rotate_recovery_authority_in_txn(txn, authority, &rotation)?;
            }
            self.list_vault_key_kit_in_txn(txn, owner, &kit.manifest)?;
            let (removed, retired) =
                self.enter_nobody_but_me_in_txn(txn, &transition, preset, point)?;
            let change = RecoveryPresetChange {
                previous: state.recovery,
                preset,
                sheet: None,
                removed,
                retired,
                mirror_pending: false,
                box_release_pending: false,
            };
            state.recovery = preset;
            // [VAULT-DATA-KEY-ROTATION]: its `start_data_key_generation_in_txn`
            // will run last in this write, after the STATE put.
            STATE.put(&self.store, txn, &(), &state)?;
            Ok(change)
        });
        let mut change =
            self.release_box_hold_on_failure(written, true, Some(attempt), box_hold)?;
        change.mirror_pending = finish_or_pending(transition);
        Ok(RecoveryPresetAnyTwoChange { change, kit })
    }
}
