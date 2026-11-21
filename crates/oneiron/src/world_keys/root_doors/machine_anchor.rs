//! The anchor door: a kit's seed marks a machine `Owned(Yours)` under its
//! anchor, for this install's own request or for a new machine's.

use super::*;

impl Vault {
    /// Kit use: marks a machine `Owned(Yours)` under the seed's anchor.
    /// `request` is this install's own (then the door pins the seed's root
    /// and runs the re-wrap sequence, also when the pin stays), or a new
    /// machine's request shown here (then `code` must be the code the new
    /// machine displays, the seed's root must be this install's pin, and the
    /// pin never moves). The appended mark must head the anchor's chain and
    /// be the machine's trusted identity there with the request's keys.
    pub fn anchor_machine(
        &self,
        owner: &AuthenticatedOwner,
        seed: &RecoveryRootSeed,
        request: &MachineEnrolmentRequest,
        code: Option<RequestCode>,
        confirm: Option<KitConfirmation>,
    ) -> Result<AnchoredMachine> {
        if self.is_own_enrolment(request)? {
            return self.anchor_own_machine(owner, seed, request, confirm);
        }
        if code != Some(request.code()) {
            return Err(refused(
                "the request code is not the one the new machine shows",
            ));
        }
        self.with_write_txn(|txn| self.anchor_other_machine_in_txn(txn, owner, seed, request))
    }

    /// Whether `request` is this install's own: its machine id and its
    /// install key.
    pub(in crate::world_keys) fn is_own_enrolment(
        &self,
        request: &MachineEnrolmentRequest,
    ) -> Result<bool> {
        self.load_install_signing_if_minted()?;
        let txn = self.store.env.read_txn()?;
        let machine = crate::identity::read_machine_id_in_txn(self, &txn)?;
        let key = crate::identity::read_machine_signing_key_in_txn(self, &txn)?
            .map(|key| key.verifying_key().to_bytes());
        Ok(machine == Some(request.machine) && key == Some(request.machine_key))
    }

    /// [`Self::anchor_machine`]'s transaction for another machine's request,
    /// whose code the caller checked: the seed's root must be this install's
    /// pin, which never moves.
    pub(in crate::world_keys) fn anchor_other_machine_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        seed: &RecoveryRootSeed,
        request: &MachineEnrolmentRequest,
    ) -> Result<AnchoredMachine> {
        let root = seed.public(&request.vault_id)?;
        let anchor = seed.anchor();
        let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if fold.vault_id != Some(request.vault_id) {
            return Err(invalid_authority());
        }
        if fold.pinned_root.map(|pin| pin.id) != Some(root.id) {
            return Err(refused(
                "anchoring another machine needs the seed's root to be this install's pin",
            ));
        }
        let mark = self.append_anchor_mark_in_txn(txn, &anchor, actor, request)?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        if !anchor_mark_stands(&after, root.anchor_key, mark, request) {
            return Err(refused("the anchor's mark does not stand"));
        }
        Ok(AnchoredMachine {
            machine: after
                .machine(request.machine)
                .cloned()
                .ok_or_else(invalid_authority)?,
            repin: None,
        })
    }

    fn anchor_own_machine(
        &self,
        owner: &AuthenticatedOwner,
        seed: &RecoveryRootSeed,
        request: &MachineEnrolmentRequest,
        confirm: Option<KitConfirmation>,
    ) -> Result<AnchoredMachine> {
        let secret = self.own_anchor_prep(owner, seed, request, confirm)?;
        self.with_write_txn(|txn| {
            self.anchor_own_machine_in_txn(txn, owner, &secret, seed, request, confirm)
        })
    }

    /// An own anchoring's checks before its transaction: the seed door's,
    /// then `request` must name this machine with its own keys.
    pub(in crate::world_keys) fn own_anchor_prep(
        &self,
        owner: &AuthenticatedOwner,
        seed: &RecoveryRootSeed,
        request: &MachineEnrolmentRequest,
        confirm: Option<KitConfirmation>,
    ) -> Result<MachineSecret> {
        let (secret, own) = self.seed_door_prep(owner, seed, confirm)?;
        if own.machine != request.machine
            || own.machine_key != request.machine_key
            || own.encryption_key != request.encryption_key
        {
            return Err(refused("the request names this machine with other keys"));
        }
        Ok(secret)
    }

    /// A seed door's checks in a read snapshot, before this install's machine
    /// identity is minted, then its own request and secret.
    pub(in crate::world_keys) fn seed_door_prep(
        &self,
        owner: &AuthenticatedOwner,
        seed: &RecoveryRootSeed,
        confirm: Option<KitConfirmation>,
    ) -> Result<(MachineSecret, MachineEnrolmentRequest)> {
        self.precheck_root_door(owner, |txn, fold| {
            self.kit_seed_gate_in_txn(txn, fold, seed, confirm)
                .map(drop)
        })?;
        self.own_request()
    }

    /// The own anchoring's transaction, with `secret` from
    /// [`Self::own_anchor_prep`]: the seed's root pinned, published when the
    /// kit-restored seed rule allows, this machine marked, and the re-wraps.
    pub(in crate::world_keys) fn anchor_own_machine_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        secret: &MachineSecret,
        seed: &RecoveryRootSeed,
        request: &MachineEnrolmentRequest,
        confirm: Option<KitConfirmation>,
    ) -> Result<AnchoredMachine> {
        let anchor = seed.anchor();
        let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
        let signing = self.door_signing_key_in_txn(txn, secret.machine)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let (root, publish) = self.kit_seed_gate_in_txn(txn, &fold, seed, confirm)?;
        let pin = PinnedRoot {
            id: root.id,
            anchor_key: root.anchor_key,
        };
        let door = RepinDoor {
            secret,
            signing: &signing,
            new_root: root.id,
            seed: Some(seed),
            restore: false,
        };
        let start = self.repin_start_in_txn(txn, &door)?;
        self.pin_first_in_txn(txn, fold.pinned_root, pin, start.earlier_admitter)?;
        if publish {
            self.publish_owner_root_in_txn(txn, &anchor, root_record(&root, actor))?;
        }
        let mark = self.append_anchor_mark_in_txn(txn, &anchor, actor, request)?;
        self.move_pin_in_txn(txn, fold.pinned_root, pin, start.earlier_admitter)?;
        self.end_wait_in_txn(txn, root.id, None, None)?;
        let mid = self.authority_view_readonly_in_txn(txn)?;
        if !anchor_mark_stands(&mid, root.anchor_key, mark, request) || mid.pinned_root != Some(pin)
        {
            return Err(refused("the anchor's mark does not stand"));
        }
        let finish = self.repin_finish_in_txn(txn, &door, start)?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        Ok(AnchoredMachine {
            machine: after
                .machine(request.machine)
                .cloned()
                .ok_or_else(invalid_authority)?,
            repin: Some(finish.report),
        })
    }
}
