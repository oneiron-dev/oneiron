//! The owner anchor's appointment of a successor root key (row
//! OWNER-ANCHOR-ROOT-RECOVERY, PLAN v3 section 7; Engine RULINGs 14 Nov
//! 21:01, 21:47 and 22:32): the way out of a roster with no live root key.
//!
//! A handoff fork, a cycle of revocations, a handoff to a key without
//! `ROLE_OWNER` or the revocation of the last root key can leave the roster
//! with no root key. No roster row settles that state, and owner writes stop,
//! since no root key can bind the owner. The owner then runs this door on an
//! install that pins the root of the kit he restored: the root's anchor
//! appoints a fresh successor key of this install, the successor binds him as
//! `human`, and owner writes resume.
//!
//! The door takes the owner's own proof from this install, revalidated in
//! the writer transaction; a proof a transport or a host bound is refused. It
//! needs vault ownership, not an authority binding, so it passes on a
//! rootless vault. The kit's seed passes the kit-restored seed rule
//! ([`Vault::kit_seed_gate_in_txn`]), its root must be stored, and this
//! install must pin it: an awaited root is no pin, and `pin_owner_root` pins
//! or confirms it first. The writer half
//! ([`Vault::appoint_successor_in_txn`]) reads the roster rootless in its
//! transaction, only then makes the successor key, in memory, and signs,
//! appends and checks: a second run checked before the first committed is
//! refused there, before it touches this install's slot. The slot takes the
//! successor's seed as the writer's last step, under the vault's owner
//! signing slot lock, so a refused appointment, and one whose commit fails,
//! leaves the slot's seed as it was (FIX
//! APPOINTMENT-DROPS-SLOT-SEED-BEFORE-ITS-VERDICT), and no other door of
//! this process reads or renews the slot in between (FIX
//! OWNER-SIGNING-SLOT-RENEWAL-OUTSIDE-SLOT-LOCK).
//!
//! Running the door on two installs that cannot see each other's rows signs
//! two appointments beside each other: they burn the anchor, and the owner
//! re-issues the kit. Every row an old roster key signed outside the
//! appointment's ancestry stays sealed; the owner does those acts again.

use std::sync::PoisonError;

use super::{DevicePin, KitConfirmation, OwnerSigningSlot, RecoveryRootSeed, SlotRenewal, refused};
use crate::Vault;
use crate::authority::{
    AuthorityKey, PinnedRoot, RootAppointmentReceipt, read_pin_row_in_txn,
    refuse_unneeded_appointment,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};

/// The proof was carried by a transport credential or a host action: the
/// owner appoints from this install alone. Nothing was written.
const BOUND_PROOF: &str = "a root appointment takes the owner's proof from this install, with no \
                           transport credential or host action bound to it";
/// The kit's root is not in this vault's log. Nothing was written.
const ROOT_NOT_STORED: &str = "the kit's root is not in this vault's log; no appointment names \
                               it";
/// This install does not pin the kit's root. Nothing was written.
const NOT_PINNED: &str = "this install does not pin the kit's root (an awaited root is no pin); \
                          pin or confirm it with pin_owner_root, then appoint";

impl Vault {
    /// The owner's appointment of a successor root key on a vault whose
    /// roster holds no live root key: the anchor of `seed`'s root, which this
    /// install pins, appoints a newly made owner signing key of this install,
    /// and that key binds the owner as `human` in the same transaction. The
    /// receipt comes only once the fold counts both and the roster holds a
    /// root key again. `confirm` is the kit confirmation the kit-restored
    /// seed rule reads, as at the other seed doors.
    ///
    /// # Errors
    /// [`crate::error::SecretError::WorldKeyRefused`] for a bound proof, a
    /// root not stored or not pinned here, a roster that still holds a live
    /// root key, a burned anchor, an ancestry over which the appointment
    /// would be void, or an appointment or binding the fold does not count;
    /// the kit-restored seed rule's refusals; an owner refusal when the proof
    /// is no longer the vault's live owner; the keystore's refusal.
    pub fn appoint_owner_root(
        &self,
        owner: &AuthenticatedOwner,
        seed: &RecoveryRootSeed,
        confirm: Option<KitConfirmation>,
    ) -> Result<RootAppointmentReceipt> {
        self.appoint_owner_root_between(owner, seed, confirm, || {})
    }

    /// [`Self::appoint_owner_root`], with `between` run after the door's
    /// read-only check and before its writer: the gap in which another run
    /// of the door can commit first (the test door
    /// `test_doors::root_appointment::appoint_owner_root_between`).
    pub(crate) fn appoint_owner_root_between(
        &self,
        owner: &AuthenticatedOwner,
        seed: &RecoveryRootSeed,
        confirm: Option<KitConfirmation>,
        between: impl FnOnce(),
    ) -> Result<RootAppointmentReceipt> {
        if !owner.is_unbound() {
            return Err(refused(BOUND_PROOF));
        }
        self.precheck_root_door(owner, |txn, fold| {
            let pin = self.appointment_pin_in_txn(txn, fold, seed, confirm)?;
            refuse_unneeded_appointment(fold, pin.anchor_key)
        })?;
        between();
        let slot = self.device_owner_signing_slot()?;
        // One step with a first PIN's set, entered before the writer and
        // held to its commit (row OCS-OWNER-PIN): no PIN of this process is
        // set between the successor's making and the commit. So the
        // successor never signs beside a set PIN, and a set neither seals
        // the seed the successor replaced nor drops the successor's own. The
        // step is taken first and the writer inside it, as at the enrollment
        // door; the writer takes no step.
        let device_pin = self.device_pin();
        let _step = device_pin.as_deref().map(DevicePin::step);
        // The slot is renewed under the vault's owner signing slot lock,
        // taken inside the step and before the writer, as every door that
        // reads or renews the slot takes it, and held until the slot is put
        // back after a failed commit.
        let _slot_lock = self
            .store
            .owner_signing_slot_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut renewal = None;
        let appointed = self.with_write_txn(|txn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let pin = self.appointment_pin_in_txn(txn, &fold, seed, confirm)?;
            let (receipt, renewed) =
                self.appoint_successor_in_txn(txn, actor, &pin, &seed.anchor(), &slot)?;
            renewal = Some(renewed);
            Ok(receipt)
        });
        if let (Err(_), Some(renewal)) = (&appointed, renewal) {
            self.put_back_unless_appointed(&slot, renewal);
        }
        appointed
    }

    /// The writer renewed the slot and the door failed after it: in the
    /// commit, or in work after a commit that is durable. The slot takes back
    /// its old seed unless this install's roster names the successor, which
    /// only the committed appointment put there. When the roster cannot be
    /// read, the slot keeps the successor's seed: a committed successor whose
    /// seed no install held would leave the roster with a root key nobody
    /// signs with.
    fn put_back_unless_appointed(&self, slot: &OwnerSigningSlot, renewal: SlotRenewal) {
        let successor = AuthorityKey::Ed25519(renewal.successor());
        let appointed = self
            .store
            .env
            .read_txn()
            .map_err(Error::from)
            .and_then(|txn| {
                self.authority_view_readonly_in_txn(&txn)
                    .map(|fold| fold.roster.contains_key(&successor))
            });
        match appointed {
            Ok(true) => {}
            Ok(false) => slot.put_back(renewal),
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "the appointment's roster was not read after its failed write; this install's \
                 owner signing slot keeps the successor's seed"
            ),
        }
    }

    /// The pin a root appointment from `seed` is made under: `seed`'s root
    /// passes the kit-restored seed rule, is stored, and is this install's
    /// pin.
    fn appointment_pin_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &crate::authority::AuthorityFold,
        seed: &RecoveryRootSeed,
        confirm: Option<KitConfirmation>,
    ) -> Result<PinnedRoot> {
        let (root, publish) = self.kit_seed_gate_in_txn(txn, fold, seed, confirm)?;
        if publish {
            return Err(refused(ROOT_NOT_STORED));
        }
        let pin = PinnedRoot {
            id: root.id,
            anchor_key: root.anchor_key,
        };
        if read_pin_row_in_txn(&self.store, txn)?.pin != Some(pin) || fold.pinned_root != Some(pin)
        {
            return Err(refused(NOT_PINNED));
        }
        Ok(pin)
    }
}
