//! The signed half of the owner's world-settings door, and the one judge every
//! egress door asks: may a world be readable on a destination?
//!
//! The owner's door (`policy_model`) revalidates the owner and writes the
//! receipt; this half proves the edit comes from this machine, that the owner
//! marked this machine "yours" and that it holds the world, then signs the
//! edit with the install key. The fold is the judge: an edit it refused never
//! reports success.

use std::collections::BTreeSet;

use ed25519_dalek::Signer;

use crate::error::{Error, Result};
use crate::ports::TombstoneStoreRead;
use crate::registry::ENTITY_TYPE_WORLD;
use crate::{EntityId, TimeRange, Vault};

use super::*;

/// Where an owner's settings edit comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditOrigin {
    /// An in-process call on this machine.
    ThisMachine,
    /// A request from a connected peer. Only this machine edits its worlds:
    /// another machine's possession of a world cannot be proven here.
    Peer(PeerMachine),
}

/// One signed and folded settings edit.
pub(crate) struct WorldPrivacyChange {
    pub(crate) machine: EntityId,
    pub(crate) entry_hash: AuthorityEntryHash,
    pub(crate) previous: EffectiveWorldPrivacy,
    pub(crate) next: EffectiveWorldPrivacy,
    /// For an orphan re-pick, the machines the world's read named, none of
    /// them still the owner's; empty otherwise.
    pub(crate) orphaned_from: BTreeSet<EntityId>,
}

fn refused(reason: &'static str) -> Error {
    Error::Gate(crate::error::GateError::ConsentOwnerNotAuthenticated(
        reason,
    ))
}

impl Vault {
    /// A world's effective settings in this vault's fold.
    pub fn world_privacy(&self, world: EntityId) -> Result<EffectiveWorldPrivacy> {
        let txn = self.store.env.read_txn()?;
        Ok(self
            .authority_view_readonly_in_txn(&txn)?
            .world_privacy(world))
    }

    /// Signs and lands one edit in the caller's transaction. The caller has
    /// revalidated the owner and holds the release lock.
    pub(crate) fn append_world_privacy_edit_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        origin: EditOrigin,
        world: EntityId,
        settings: WorldPrivacy,
    ) -> Result<WorldPrivacyChange> {
        settings.validate()?;
        let machine = crate::identity::read_machine_id_in_txn(self, txn)?
            .ok_or_else(|| refused("this install is not one of the owner's machines"))?;
        match origin {
            EditOrigin::ThisMachine => {}
            EditOrigin::Peer(PeerMachine::Proven(peer)) if peer == machine => {}
            EditOrigin::Peer(_) => {
                return Err(refused(
                    "a world's settings change only on a machine that holds it",
                ));
            }
        }
        if world == crate::claim::base_world_id()
            || self.get_entity_type_in_txn(txn, &world)? != Some(ENTITY_TYPE_WORLD)
        {
            return Err(Error::InvalidConfig(
                "world settings need a stored WORLD row other than base reality".to_owned(),
            ));
        }
        let visibility = TombstoneStoreRead::port_deletion_state(&self.store, txn, &world)?;
        if visibility.deleted || visibility.archived || visibility.stale {
            return Err(Error::InvalidConfig(
                "world settings need a live WORLD row".to_owned(),
            ));
        }
        let key = crate::identity::read_machine_signing_key_in_txn(self, txn)?
            .ok_or_else(|| refused("this install has no machine key"))?;
        let public_key = key.verifying_key().to_bytes();
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if !fold
            .machine(machine)
            .is_some_and(|folded| folded.is_mine() && folded.profile.machine_key == public_key)
        {
            return Err(refused(
                "only a machine the owner marked as theirs edits a world",
            ));
        }
        let standing = fold
            .world_edit_standing(machine, world)
            .ok_or_else(|| refused("this machine does not hold the world"))?;
        if let ReadLocation::OneMachine(target) = settings.read
            && !fold.machine(target).is_some_and(FoldedMachine::is_mine)
        {
            return Err(refused(
                "a one-machine world lives only on the owner's machine",
            ));
        }
        let signer = AuthorityKey::Ed25519(public_key);
        let seq = match fold.append_sequences.get(&signer) {
            None => 1,
            Some(seq) => seq.checked_add(1).ok_or_else(invalid_authority)?,
        };
        let mut parents: BTreeSet<AuthorityEntryHash> = fold.append_heads.clone();
        if let Some(side) = fold.side_heads.get(&world) {
            parents.extend(side.iter().copied());
        }
        let now = self.instant_in_txn(txn)?.secs();
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: fold.vault_id,
            seq,
            parent_hashes: parents.into_iter().collect(),
            op: AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                world,
                owner,
                machine,
                settings,
            }),
            signer: AuthoritySignature {
                suite: AuthoritySignatureSuite::Ed25519,
                public_key: signer,
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: now,
        };
        entry.signer.signature = key.sign(&authority_transcript(&entry)?).to_bytes().to_vec();
        let entry_hash = authority_entry_hash(&entry)?;
        let previous = fold.world_privacy(world);
        let orphaned_from = if standing == WorldEditStanding::RepicksOrphan {
            super::world_privacy::orphaned_from(&previous.read, |id| {
                fold.machine(id).is_some_and(FoldedMachine::is_mine)
            })
        } else {
            BTreeSet::new()
        };
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        if !after
            .worlds
            .get(&world)
            .is_some_and(|folded| folded.live.contains_key(&entry_hash))
        {
            return Err(invalid_authority());
        }
        Ok(WorldPrivacyChange {
            machine,
            entry_hash,
            previous,
            next: after.world_privacy(world),
            orphaned_from,
        })
    }
}

/// One snapshot's world settings and machine standing: fold once, then answer
/// for many worlds and rows.
#[derive(Clone)]
pub struct WorldPrivacyView {
    view: AuthorityView,
}

impl WorldPrivacyView {
    pub fn load_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Self> {
        Ok(Self {
            view: vault.authority_view_readonly_in_txn(txn)?,
        })
    }

    #[must_use]
    pub fn readable_on(&self, world: EntityId, destination: Destination) -> bool {
        self.view.world_readable_on(world, destination)
    }

    /// Every edited world not readable on `destination`: the withheld set.
    #[must_use]
    pub fn withheld_for(&self, destination: Destination) -> BTreeSet<EntityId> {
        self.view.worlds_withheld_from(destination)
    }

    /// Moves with every authority-log write, a remote one included.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.view.generation()
    }
}

/// May `destination` hold `world` readable, in `txn`'s snapshot?
pub fn world_readable_on_machine_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    world: EntityId,
    destination: Destination,
) -> Result<bool> {
    Ok(WorldPrivacyView::load_in(vault, txn)?.readable_on(world, destination))
}

#[cfg(any(test, feature = "test-support"))]
impl Vault {
    /// Keeps `world` on this machine (`keep`) or lets it go everywhere, the
    /// way an owner does: the vault is rooted under the test host, this
    /// install is enrolled as one of the owner's machines, and the edit goes
    /// through the owner's door.
    #[doc(hidden)]
    pub fn keep_world_on_this_machine_for_test(&self, world: EntityId, keep: bool) -> Result<()> {
        let issuer = crate::test_support::test_host_issuer();
        self.ensure_host_root_slip(&issuer)?;
        let person = self
            .ensure_embedded_owner_actor()
            .map_err(|_| Error::InvariantViolation("embedded owner"))?;
        let bound = self
            .authority_fold()?
            .actor_bindings
            .get(&issuer.public_key())
            .is_some_and(|binding| binding.actor_ref == person);
        if !bound {
            self.bind_host_owner_for_test(&issuer, person)?;
        }
        let owner = self.authenticate_owner(
            person,
            &person.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )?;
        let machine = match self.local_machine()? {
            Some(LocalMachine {
                id,
                profile: Some(profile),
            }) if profile.is_mine() => id,
            _ => {
                let vault_id = self
                    .authority_fold()?
                    .vault_id
                    .ok_or_else(invalid_authority)?;
                let request = self.machine_enrolment_request(
                    vault_id,
                    MachineEncryptionKey {
                        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
                        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
                    },
                )?;
                self.enroll_machine(
                    &issuer,
                    &owner,
                    &request,
                    MachineRole::Owned(MachineOwnership::Yours),
                )?
                .profile
                .machine
            }
        };
        let read = if keep {
            ReadLocation::OneMachine(machine)
        } else {
            ReadLocation::Everywhere
        };
        self.set_world_privacy_as(
            &owner,
            EditOrigin::ThisMachine,
            world,
            WorldPrivacy {
                read,
                ..WorldPrivacy::default()
            },
        )?;
        Ok(())
    }
}
