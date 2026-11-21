//! The kit activation door: its checks, which run before the owner's confirm,
//! and its one write transaction, which publishes the kit's root, moves the
//! pin, enrols the kit's authority key R and carries what the earlier R keys
//! approved.

use super::*;
use crate::authority::{ActAuthority, ActSurface, ActivationPredecessor, OwnerProofGround};
use crate::world_keys::{OwnerActImportance, owner_presence_reasons};

/// What [`Vault::activation_prep`] answers: this install's machine secret,
/// its enrolment request, and the predecessor of R's enrolment.
pub(crate) type ActivationPrep = (
    MachineSecret,
    MachineEnrolmentRequest,
    ActivationPredecessor,
);

impl Vault {
    /// Kit issue, phase 2: called after the kit issuer reports the pieces
    /// saved. One write transaction: the root's record, the new anchor's
    /// `Owned(Yours)` mark of this machine and of each carried machine, the
    /// pin, and the re-wraps. It succeeds only if each appended mark heads
    /// the new anchor's chain and is the machine's trusted identity there,
    /// with the same keys; otherwise nothing is published. On a first issue
    /// `carry` is empty; on a re-issue each carried machine is mine under the
    /// old pin, and this machine is marked whenever it is. The activation's
    /// own checks ([`Self::activation_prep`]) come before the confirm, so an
    /// activation they refuse never prompts.
    pub fn activate_owner_root(
        &self,
        owner: &AuthenticatedOwner,
        prepared: PreparedRoot,
        carry: &BTreeSet<EntityId>,
    ) -> Result<ActivatedRoot> {
        let prep = self.activation_prep(owner, &prepared, carry)?;
        let witness = self.owner_presence(
            OwnerActImportance::Important,
            owner_presence_reasons::KIT_ACTIVATION,
        )?;
        let ground = OwnerProofGround::witnessed(&witness);
        let authority = ActAuthority::Owner(owner.clone(), ActSurface::ThisInstall);
        self.activate_owner_root_with(&authority, (prepared, prep), carry, &ground, |_| Ok(()))
            .map(|(activated, ())| activated)
    }

    /// [`Self::activate_owner_root`], with `also` run in its transaction once
    /// the new root stands: a kit's inventory and its vault-key wrap commit
    /// with the root or not at all. `authority` carries the true act surface
    /// for R's enrolment row. `prep` is what [`Self::activation_prep`]
    /// answered for `prepared` and `carry`: the door ran it before its
    /// confirm, so the predecessor loaded before the write txn opens.
    /// `ground` is the ground the activation's owner proofs are signed on.
    pub(crate) fn activate_owner_root_with<T>(
        &self,
        authority: &ActAuthority,
        (prepared, prep): (PreparedRoot, ActivationPrep),
        carry: &BTreeSet<EntityId>,
        ground: &OwnerProofGround,
        also: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<T>,
    ) -> Result<(ActivatedRoot, T)> {
        if matches!(authority, ActAuthority::Agent(_)) {
            return Err(authority_refused(ACTIVATION_OWNER_ONLY));
        }
        let (secret, request, predecessor) = prep;
        self.with_write_txn(|txn| {
            let activated = self.activate_owner_root_in_txn(
                txn,
                authority,
                &secret,
                &request,
                &prepared,
                carry,
                &predecessor,
                ground,
            )?;
            Ok((activated, also(txn)?))
        })
    }

    /// An activation's checks in a read snapshot, then the predecessor of
    /// R's enrolment ([`Vault::load_activation_predecessor`], read only),
    /// both before this install's machine identity is minted, then its own
    /// request and secret. A refusal for want of a predecessor therefore
    /// writes nothing at all (WAYBACK-R4-NO-PREDECESSOR = A).
    pub(in crate::world_keys) fn activation_prep(
        &self,
        owner: &AuthenticatedOwner,
        prepared: &PreparedRoot,
        carry: &BTreeSet<EntityId>,
    ) -> Result<ActivationPrep> {
        self.precheck_root_door(owner, |txn, fold| {
            let me = crate::identity::read_machine_id_in_txn(self, txn)?;
            carried_marks(fold, prepared, carry, me)?;
            // Another owner's R refuses before any mint (REVIEW-9488 round 2 P1 3).
            let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
            let (_, key) = self.kit_activation_signer_in_txn(txn, prepared.seed(), &vault_id)?;
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            self.recovery_authority_enrols_in_txn(txn, fold, actor, &key.authority_key())
                .map(drop)
        })?;
        let predecessor = self.load_activation_predecessor(owner)?;
        let (secret, request) = self.own_request()?;
        Ok((secret, request, predecessor))
    }

    /// [`Self::activate_owner_root`]'s transaction, in the caller's: the
    /// root's record, the marks, the pin and the re-wraps, with `secret` and
    /// `request` this install's own from [`Self::activation_prep`], plus R's
    /// enrolment after the marks and the pin move (WAYBACK-R4-FIRST-KEY = B),
    /// with the owner's earlier R keys revoked just before it
    /// (WAYBACK-SECOND-KIT-OLD-ROOT-KEY = A). `authority` carries the true
    /// act surface for R's row; `predecessor` was loaded before the write
    /// txn opened and signs both. `ground` is the ground the activation's
    /// owner proofs are signed on.
    #[expect(clippy::too_many_arguments)]
    pub(in crate::world_keys) fn activate_owner_root_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        authority: &ActAuthority,
        secret: &MachineSecret,
        request: &MachineEnrolmentRequest,
        prepared: &PreparedRoot,
        carry: &BTreeSet<EntityId>,
        predecessor: &ActivationPredecessor,
        ground: &OwnerProofGround,
    ) -> Result<ActivatedRoot> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(ACTIVATION_OWNER_ONLY)),
        };
        let seed = prepared.seed();
        let anchor = seed.anchor();
        let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
        let signing = self.door_signing_key_in_txn(txn, secret.machine)?;
        let old = self.authority_view_readonly_in_txn(txn)?;
        let (root, mut marks) = carried_marks(&old, prepared, carry, Some(secret.machine))?;
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
        self.pin_first_in_txn(txn, old.pinned_root, pin, start.earlier_admitter)?;
        marks.push(request.clone());
        self.put_anchor_entry_in_txn(txn, prepared.entry().clone())?;
        let mut appended = Vec::new();
        for mark in &marks {
            appended.push(self.append_anchor_mark_in_txn(txn, &anchor, actor, mark)?);
        }
        self.move_pin_in_txn(txn, old.pinned_root, pin, start.earlier_admitter)?;
        self.end_wait_in_txn(txn, root.id, None, None)?;
        let mid = self.authority_view_readonly_in_txn(txn)?;
        let stands = marks
            .iter()
            .zip(&appended)
            .all(|(mark, hash)| anchor_mark_stands(&mid, root.anchor_key, *hash, mark));
        if !stands || mid.pinned_root != Some(pin) {
            return Err(refused("the new root's marks do not stand"));
        }
        let vault_id = mid.vault_id.ok_or_else(invalid_authority)?;
        let (generation, authority_signer) =
            self.kit_activation_signer_in_txn(txn, seed, &vault_id)?;
        let r_key = authority_signer.authority_key();
        let enrol = self.recovery_authority_enrols_in_txn(txn, &mid, actor, &r_key)?;
        // R enrols before the earlier R keys go: the enrolment's carrier,
        // this install, may stand on an approval only an earlier R gave,
        // which goes stale at that R's revocation once older than the
        // stale-roster window (Sol carry F1).
        if enrol {
            self.enrol_recovery_authority_key_in_txn(
                txn,
                authority,
                secret.machine,
                seed,
                predecessor,
                ground,
            )?;
        } else {
            // A live R only a passkey vouched for is confirmed (REVIEW-9488 P1 3).
            self.confirm_recovery_authority_key_in_txn(
                txn,
                authority,
                secret.machine,
                &authority_signer,
                predecessor,
                ground,
            )?;
        }
        // A new kit replaces the old one (WAYBACK-SECOND-KIT-OLD-ROOT-KEY =
        // A), and R carries what the revoked ones approved, chosen before
        // their revocation, so a kit change unpairs no machine
        // (WAYBACK-R-REVOCATION-STALES-R-APPROVALS = A). Then R binds the
        // owner on a self-hosted vault when a revoked R held their binding,
        // as its enrolment would after the revocation, an R enrolled before
        // this act too (REVIEW-9488 round 2 P1 4).
        let carry = self.revoke_earlier_recovery_authority_keys_in_txn(
            txn,
            actor,
            &r_key,
            predecessor,
            ground,
        )?;
        self.carry_recovery_authority_approvals_in_txn(txn, carry, &authority_signer)?;
        self.bind_owner_to_recovery_authority_key_in_txn(txn, actor, r_key, predecessor, ground)?;
        let report = self.repin_finish_in_txn(txn, &door, start)?.report;
        let authority_seed = RecoveryAuthoritySeed::from_guarded(
            RecoveryAuthoritySigner::authority_seed(seed, &vault_id, generation),
        );
        Ok(ActivatedRoot {
            root: root.id,
            keys: report,
            authority_seed,
        })
    }
}
