//! The kit restore door: a kit's seed brings this install's world keys back,
//! and the kit's root authority key R puts this machine on the roster.

use super::*;

/// A kit restore whose kit's authority key R is not a live owner key on the
/// vault's roster (WAYBACK-KIT-RESTORE-NO-LIVE-R = A): a newer kit's
/// activation revoked it, or the kit was never confirmed. Only R puts the
/// restored machine on the roster, so the door refuses before any write.
const KIT_NOT_CURRENT: &str = "this recovery kit is not the vault's current kit: a newer kit \
                               replaced it, or it was never confirmed; use your newest kit, or \
                               sign in from a device that is still yours; nothing was written";

impl Vault {
    /// Kit restore: finds the stored root that matches the seed's id and both
    /// its keys, or publishes it when the kit-restored seed rule allows;
    /// anchors this install's own request under it unless this machine is
    /// already mine there with its own keys; pins it; and opens each key
    /// wrapped to it whose world is live here. Every root-wrapped key lands in
    /// exactly one list. The caller's origin does not narrow it: the owner's
    /// say-so counts from any surface the owner is authenticated on (owner,
    /// 10-19), so a peer's request restores as this machine's does. The
    /// revalidated owner proof and the kit's seed gate are what stand.
    ///
    /// This machine goes on the roster too, signed by the kit's root
    /// authority key R, before its re-wraps (ANCHORS-1 = A; FIX
    /// KIT-RESTORE-ANCHOR-ONLY-INSTALL-COUNTS-NO-WRAP): only the roster's
    /// chain admits an owner act's carrier and a world key wrap's publisher.
    /// A kit whose R is not a live owner key on the roster is refused before
    /// any write, its identity mint included (WAYBACK-KIT-RESTORE-NO-LIVE-R =
    /// A).
    pub fn restore_world_keys(
        &self,
        owner: &AuthenticatedOwner,
        seed: &RecoveryRootSeed,
        confirm: Option<KitConfirmation>,
    ) -> Result<RootRestore> {
        let (secret, request) = self.restore_prep(owner, seed, confirm)?;
        let (restore, usable) = self.with_write_txn(|txn| {
            self.restore_world_keys_in_txn(txn, owner, &secret, &request, seed, confirm)
        })?;
        for key in usable {
            self.ring_world_key(key);
        }
        Ok(restore)
    }

    /// A restore's checks before its transaction: the seed door's, and the
    /// kit's root authority key R live on the roster
    /// ([`Self::kit_root_authority_signer`]), both in one read snapshot
    /// before this install's machine identity is minted; then its own
    /// request and secret.
    pub(in crate::world_keys) fn restore_prep(
        &self,
        owner: &AuthenticatedOwner,
        seed: &RecoveryRootSeed,
        confirm: Option<KitConfirmation>,
    ) -> Result<(MachineSecret, MachineEnrolmentRequest)> {
        self.precheck_root_door(owner, |txn, fold| {
            self.kit_seed_gate_in_txn(txn, fold, seed, confirm)?;
            self.kit_root_authority_signer(txn, fold, seed).map(drop)
        })?;
        self.own_request()
    }

    /// The kit's root authority key R for this vault, at the kit's live
    /// generation, while `fold`'s roster holds it as a live owner key: what
    /// signs the restored machine's roster row. Old kits read as generation
    /// 0, and after a switch to kit-only the same kit holds the rotated
    /// generation ([`Self::recovery_authority_generations_in_txn`]). Refused
    /// with [`KIT_NOT_CURRENT`] when no generation of the kit is live
    /// (WAYBACK-KIT-RESTORE-NO-LIVE-R = A). The sealed bundle's kit restore
    /// asks it too, before its first window lands.
    pub(crate) fn kit_root_authority_signer(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        seed: &RecoveryRootSeed,
    ) -> Result<RecoveryAuthoritySigner> {
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let Some((_, signer)) = self
            .recovery_authority_generations_in_txn(txn, seed, &vault_id)?
            .live
        else {
            return Err(authority_refused(KIT_NOT_CURRENT));
        };
        let live = fold
            .roster
            .get(&signer.authority_key())
            .is_some_and(|device| {
                !device.revoked && device.roles & crate::authority::ROLE_OWNER != 0
            });
        if !live {
            return Err(authority_refused(KIT_NOT_CURRENT));
        }
        Ok(signer)
    }

    /// [`Self::restore_world_keys`]'s transaction, with `secret` and
    /// `request` from [`Self::restore_prep`]: the restore, and the keys
    /// this machine may read, for the session ring once it commits.
    pub(in crate::world_keys) fn restore_world_keys_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        secret: &MachineSecret,
        request: &MachineEnrolmentRequest,
        seed: &RecoveryRootSeed,
        confirm: Option<KitConfirmation>,
    ) -> Result<(RootRestore, Vec<WorldKey>)> {
        let anchor = seed.anchor();
        let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
        let signing = self.door_signing_key_in_txn(txn, secret.machine)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let (root, publish) = self.kit_seed_gate_in_txn(txn, &fold, seed, confirm)?;
        let authority = self.kit_root_authority_signer(txn, &fold, seed)?;
        let pin = PinnedRoot {
            id: root.id,
            anchor_key: root.anchor_key,
        };
        let door = RepinDoor {
            secret,
            signing: &signing,
            new_root: root.id,
            seed: Some(seed),
            restore: true,
        };
        let start = self.repin_start_in_txn(txn, &door)?;
        self.pin_first_in_txn(txn, fold.pinned_root, pin, start.earlier_admitter)?;
        if publish {
            self.publish_owner_root_in_txn(txn, &anchor, root_record(&root, actor))?;
        }
        let now = self.authority_view_readonly_in_txn(txn)?;
        let already = now
            .machine(request.machine)
            .and_then(|folded| {
                folded.trusted_under(&crate::authority::MachineAdmitter::Anchor(root.anchor_key))
            })
            .is_some_and(|trusted| {
                trusted.profile.machine_key == request.machine_key
                    && trusted.profile.encryption_key == request.encryption_key
            });
        let mark = if already {
            None
        } else {
            Some(self.append_anchor_mark_in_txn(txn, &anchor, actor, request)?)
        };
        self.move_pin_in_txn(txn, fold.pinned_root, pin, start.earlier_admitter)?;
        self.end_wait_in_txn(txn, root.id, None, None)?;
        let mid = self.authority_view_readonly_in_txn(txn)?;
        let stands =
            mark.is_none_or(|mark| anchor_mark_stands(&mid, root.anchor_key, mark, request));
        if !stands || mid.pinned_root != Some(pin) {
            return Err(refused("the kit's root does not stand on this install"));
        }
        // R puts this machine on the roster before the re-wraps it
        // publishes, so they count on every install (FIX
        // KIT-RESTORE-ANCHOR-ONLY-INSTALL-COUNTS-NO-WRAP); already there
        // live with these keys, no row.
        let key = authority.authority_key();
        let sign = |transcript: &[u8]| authority.sign_authority_transcript(transcript);
        self.put_machine_on_roster_in_txn(txn, (&key, &sign), actor, request)?;
        let finish = self.repin_finish_in_txn(txn, &door, start)?;
        Ok((
            RootRestore {
                usable: finish.usable.iter().map(|key| *key.id()).collect(),
                needs_rehome: finish.needs_rehome,
                withheld: finish.report.withheld,
                narrowed: finish.report.narrowed,
            },
            finish.usable,
        ))
    }
}
