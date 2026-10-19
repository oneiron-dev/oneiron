//! The signed half of the owner's world-settings door, and the one judge every
//! egress door asks: may a world be readable on a destination?
//!
//! The owner's door (`policy_model`) revalidates the owner and writes the
//! receipt; that say-so is the gate, from whichever linked surface it came
//! (owner ruling 10-19: "it doesn't matter where you said yes, if you said
//! so"). This half records it as an [`OwnerAct`] and signs the edit with this
//! install's key, whatever the install's role in the roster, a hosted node
//! included, as long as the one carrier rule admits it
//! ([`super::owner_act_signer_admits`]). It need not hold the world. The fold
//! is the judge: an edit it refused never reports success.

use std::collections::BTreeSet;

use crate::error::{Error, Result};
use crate::ports::TombstoneStoreRead;
use crate::registry::ENTITY_TYPE_WORLD;
use crate::{EntityId, TimeRange, Vault};

use super::*;

/// Where a request to one of the root, kit, restore or custody doors comes
/// from (L04's doors, each with its own rule until its mesh row lands). The
/// world-settings door takes the owner act's [`ActSurface`] instead, which
/// no rule reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditOrigin {
    /// An in-process call on this machine.
    ThisMachine,
    /// A request from a connected peer.
    Peer(PeerMachine),
}

/// Who a settings edit is written as, once its door checked them in the
/// writer: the PERSON whose will it is (a holder of the world's settings
/// right, or for an agent's act the vault owner its Grant carries), who
/// decided (the holder himself, or an agent within its Grant), where (audit
/// only), and the request a holder's yes answers (FIX 4480).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorldEditAuthor {
    pub(crate) owner: EntityId,
    pub(crate) by: ActBy,
    pub(crate) surface: ActSurface,
    pub(crate) answer: Option<EntityId>,
}

impl WorldEditAuthor {
    /// A holder's own say-so, answering nothing.
    pub(crate) const fn holder(owner: EntityId, surface: ActSurface) -> Self {
        Self {
            owner,
            by: ActBy::Owner,
            surface,
            answer: None,
        }
    }
}

/// One signed and folded settings edit.
pub(crate) struct WorldPrivacyChange {
    pub(crate) machine: EntityId,
    pub(crate) entry_hash: AuthorityEntryHash,
    pub(crate) previous: EffectiveWorldPrivacy,
    pub(crate) next: EffectiveWorldPrivacy,
    /// When the world was orphaned before the edit, the machines its read
    /// named, none of them still the owner's; empty otherwise.
    pub(crate) orphaned_from: BTreeSet<EntityId>,
}

/// This install cannot carry the owner's act: it has no machine identity or
/// install key, or the roster holds no live profile of it under that key.
/// Key possession and integrity: an act is signed by the install that
/// carries it, and FIX 2222 keeps every roster key (the host root included)
/// out. Nothing was written.
fn no_carrier() -> Error {
    Error::InvalidConfig(
        "this install has no live machine profile in the vault's roster to carry the owner's \
         world settings; nothing was written"
            .to_owned(),
    )
}

/// The edit would name more rows than one authority entry may: the log's
/// encoding bound (`MAX_PARENTS`), never a possession test. It refuses
/// atomically: no data moves and no share is written (CALLS "mesh
/// world-privacy parent bound").
fn parent_bound(named: usize) -> Error {
    Error::InvalidConfig(format!(
        "this world's settings edit would name {named} parent rows, more than the {MAX_PARENTS} \
         one authority entry names; nothing was written"
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

    /// A world's settings revision in this vault's fold: what a surface shows
    /// the owner, and passes back as the edit's `seen`.
    pub fn world_privacy_revision(&self, world: EntityId) -> Result<PolicyRevision> {
        let txn = self.store.env.read_txn()?;
        Ok(self
            .authority_view_readonly_in_txn(&txn)?
            .world_policy_revision(world))
    }

    /// Signs and lands one edit in the caller's transaction. The caller has
    /// revalidated `author` (a holder, or an agent's Grant) and holds the
    /// release lock. Its surface is where the will was said, for audit only.
    /// `seen` is the settings revision the deciding surface showed: it must be
    /// the world's current one, else the edit is a conflict, never a silent
    /// overwrite; `None` takes the current revision (a caller that showed
    /// none).
    pub(crate) fn append_world_privacy_edit_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        author: WorldEditAuthor,
        world: EntityId,
        settings: WorldPrivacy,
        seen: Option<PolicyRevision>,
    ) -> Result<WorldPrivacyChange> {
        settings.validate()?;
        // Integrity: the settings belong to a stored, live WORLD row other
        // than base reality. Its metadata is enough; no plaintext, key or
        // holding of the world is needed to decide its settings.
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
        let fold = self.authority_view_readonly_in_txn(txn)?;
        // Key possession: this install carries the act with its own install
        // key, under a live profile of any role (mesh contract §3).
        let machine = crate::identity::read_machine_id_in_txn(self, txn)?.ok_or_else(no_carrier)?;
        let key =
            crate::identity::read_machine_signing_key_in_txn(self, txn)?.ok_or_else(no_carrier)?;
        let public_key = key.verifying_key().to_bytes();
        if !owner_act_signer_admits(fold.machine(machine), &fold.roster, &public_key) {
            return Err(no_carrier());
        }
        // Revision integrity (contract §4): the owner decided on what the
        // surface showed him.
        let current = fold.world_policy_revision(world);
        if seen.is_some_and(|seen| seen != current) {
            return Err(Error::ConcurrentWrite(
                "the world's settings changed since they were read",
            ));
        }
        // A recipient limit, the owner's own choice (contract §5): a
        // one-machine world is read only on a machine he marked "yours". It
        // limits where the world goes, never who edits it.
        let target = match settings.read {
            ReadLocation::OneMachine(target) => Some(target),
            ReadLocation::MyMachines | ReadLocation::Everywhere => None,
        };
        if target.is_some_and(|target| fold.trusted_machine(target).is_none()) {
            return Err(Error::InvalidConfig(
                "the owner-selected OneMachine recipient policy requires a live machine marked \
                 Yours"
                    .to_owned(),
            ));
        }
        // A main-log edit (contract §6): it names the main-log heads, its
        // carrier's standing rows, a one-machine target's and the world's live
        // edits, so it supersedes every edit this install folds. It never
        // names a key record, which rides the world's recipient-filtered side
        // branch. A fenced main-log row beneath it is crossed on refold
        // (`refold_world_edits`), as for a grant travel choice.
        let mut parents = fold.append_heads.clone();
        parents.extend(standing_rows(&fold, machine));
        parents.extend(
            target
                .into_iter()
                .flat_map(|target| standing_rows(&fold, target)),
        );
        parents.extend(
            fold.worlds
                .get(&world)
                .into_iter()
                .flat_map(|folded| folded.live.keys().copied()),
        );
        if parents.len() > MAX_PARENTS {
            return Err(parent_bound(parents.len()));
        }
        let signer = AuthorityKey::Ed25519(public_key);
        let seq = next_sequence(&fold, &signer)?;
        let now = self.instant_in_txn(txn)?.secs();
        let act = OwnerAct {
            owner: author.owner,
            by: author.by,
            surface: author.surface,
            act: OwnerActKind::WorldPrivacy,
            target: world,
            seen: current.0,
            answer: author.answer,
        };
        let entry = sign_side_entry(
            &fold,
            &key,
            seq,
            parents,
            AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                world,
                act,
                machine,
                settings,
            }),
            now,
        )?;
        let entry_hash = authority_entry_hash(&entry)?;
        let previous = fold.world_privacy(world);
        let local = fold.local_admitter();
        let orphaned_from =
            super::world_privacy::orphaned_from(&fold.world_local_read(world), |id| {
                super::world_privacy::mine_by_roster(&fold, id, local)
            });
        let at = TimeRange {
            start: now,
            end: now,
        };
        let after = self
            .land_world_edit_in_txn(txn, &[(entry, at, now)], world, &entry_hash)?
            .ok_or_else(invalid_authority)?;
        Ok(WorldPrivacyChange {
            machine,
            entry_hash,
            previous,
            next: after.world_privacy(world),
            orphaned_from,
        })
    }

    /// Lands a world edit and reads the fold back: `None` unless the edit is
    /// live.
    fn land_world_edit_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        rows: &[(AuthorityLogEntry, TimeRange, u64)],
        world: EntityId,
        entry_hash: &AuthorityEntryHash,
    ) -> Result<Option<AuthorityView>> {
        self.put_authority_log_entries_in_txn(txn, rows)?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        let live = after
            .worlds
            .get(&world)
            .is_some_and(|folded| folded.live.contains_key(entry_hash));
        Ok(live.then_some(after))
    }
}

/// One snapshot's world settings and machine standing: fold once, then answer
/// for many worlds and rows.
#[derive(Clone)]
pub struct WorldPrivacyView {
    view: AuthorityView,
}

impl WorldPrivacyView {
    /// Refused under a conflicted vault root: its fold knows no world's
    /// settings, so no door may judge a world portable from it.
    pub fn load_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Self> {
        Self::load_unless_conflicted_in(vault, txn)?.ok_or_else(invalid_authority)
    }

    /// [`Self::load_in`], or `None` under a conflicted vault root, for a
    /// door that names that integrity hold rather than failing on it.
    pub(crate) fn load_unless_conflicted_in(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<Self>> {
        let view = vault.authority_view_readonly_in_txn(txn)?;
        Ok((!view.vault_root_is_conflicted()).then_some(Self { view }))
    }

    #[must_use]
    pub fn readable_on(&self, world: EntityId, destination: Destination) -> bool {
        self.view.world_readable_on(world, destination)
    }

    /// Every edited world not readable on `destination`: the withheld set.
    pub fn withheld_for(&self, destination: Destination) -> Result<BTreeSet<EntityId>> {
        self.view.worlds_withheld_from(destination)
    }

    /// Revalidate a connection's machine proof in this very snapshot, then
    /// apply the world's read setting. Actor identity is never a machine proof.
    pub fn withheld_for_peer(&self, peer: PeerMachine) -> Result<BTreeSet<EntityId>> {
        self.withheld_for(self.destination_for_peer(peer))
    }

    /// The destination a connection's machine proof names in this very
    /// snapshot: its machine while the proof still stands on the key it
    /// proved, else one nobody proved (mesh PR2b). An unanswered install's
    /// proof never stands ([`AuthorityFold::machine_proof_key`]).
    #[must_use]
    pub fn destination_for_peer(&self, peer: PeerMachine) -> Destination {
        match peer {
            PeerMachine::Proven { machine, key }
                if self.view.machine_proof_key(machine) == Some(key) =>
            {
                Destination::Machine(machine)
            }
            _ => Destination::Unknown,
        }
    }

    /// Where `world` may be read, as the owner's recipient choice sets it.
    pub(crate) fn world_read(&self, world: EntityId) -> EffectiveRead {
        self.view.world_privacy(world).read
    }

    /// Whether `machine` is one the owner marked his: the recipient test the
    /// judge reads, never the carrier rule.
    pub(crate) fn marked_mine(&self, machine: EntityId) -> bool {
        self.view.trusted_machine(machine).is_some()
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
        self.keep_world_on_this_machine_under_for_test(
            &crate::test_support::test_host_issuer(),
            world,
            keep,
        )
    }

    /// [`Self::keep_world_on_this_machine_for_test`] on a vault rooted under
    /// `issuer`.
    #[doc(hidden)]
    pub fn keep_world_on_this_machine_under_for_test(
        &self,
        issuer: &HostSlipIssuer,
        world: EntityId,
        keep: bool,
    ) -> Result<()> {
        self.ensure_host_root_slip(issuer)?;
        let person = self
            .ensure_embedded_owner_actor()
            .map_err(|_| Error::InvariantViolation("embedded owner"))?;
        let bound = self
            .authority_fold()?
            .actor_bindings
            .get(&issuer.public_key())
            .is_some_and(|binding| binding.actor_ref == person);
        if !bound {
            self.bind_host_owner_for_test(issuer, person)?;
        }
        let owner = self.authenticate_owner(
            person,
            &person.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )?;
        let machine = match self.local_machine()? {
            Some(LocalMachine { id, mine: true, .. }) => id,
            _ => {
                let vault_id = self
                    .authority_fold()?
                    .vault_id
                    .ok_or_else(invalid_authority)?;
                // A request carries this install's own encryption key (world
                // privacy P6b) and is signed by its machine key (P6c). With no
                // keystore on the handle, a process-memory one holds both for
                // this test handle.
                let none = self
                    .world_keys
                    .keystore
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_none();
                if none {
                    self.install_device_keystore(std::sync::Arc::new(
                        oneiron_keystore::MemoryKeystore::default(),
                    ));
                }
                let request = self
                    .machine_encryption_key(vault_id)
                    .and_then(|own| self.machine_enrolment_request(vault_id, own));
                let request = request?;
                // The install the vault never profiled joins on the explicit
                // self-host bootstrap arm (C4), as pairing's does: the test
                // host's root signs the owner's answer, with no act. A
                // profiled install takes his answer carried by itself.
                let mut txn = self.store.env.write_txn()?;
                let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
                let fold = self.authority_view_readonly_in_txn(&txn)?;
                let yours = MachineRole::Owned(MachineOwnership::Yours);
                if fold.machine(request.machine).is_none() {
                    drop(fold);
                    self.enroll_bootstrap_in_txn(&mut txn, issuer, actor, &request, yours)?;
                    txn.commit()?;
                    #[cfg(feature = "sync")]
                    self.reseal_after_machine_admission()?;
                } else {
                    drop((fold, txn));
                    self.set_machine_role(
                        &owner,
                        ActSurface::ThisInstall,
                        request.machine,
                        yours,
                        None,
                    )?;
                }
                request.machine
            }
        };
        let read = if keep {
            ReadLocation::OneMachine(machine)
        } else {
            ReadLocation::Everywhere
        };
        self.set_world_privacy_as(
            &owner,
            ActSurface::ThisInstall,
            world,
            WorldPrivacy {
                read,
                ..WorldPrivacy::default()
            },
            None,
        )?;
        Ok(())
    }
}
