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
    /// revalidated the owner and holds the release lock. With `earlier`, the
    /// read folded under the admitter this machine was mine under before its
    /// last pin change gives standing as well as the local read (an owner's
    /// re-assertion, world privacy P6b).
    pub(crate) fn append_world_privacy_edit_under_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        origin: EditOrigin,
        world: EntityId,
        settings: WorldPrivacy,
        earlier: Option<&AuthorityFold>,
    ) -> Result<WorldPrivacyChange> {
        settings.validate()?;
        let machine = crate::identity::read_machine_id_in_txn(self, txn)?
            .ok_or_else(|| refused("this install is not one of the owner's machines"))?;
        // A peer stands as this machine only with the key it proved on its
        // connection, which must be this install's own.
        let proven = match origin {
            EditOrigin::ThisMachine => None,
            EditOrigin::Peer(PeerMachine::Proven { machine: peer, key }) if peer == machine => {
                Some(key)
            }
            EditOrigin::Peer(_) => {
                return Err(refused(
                    "a world's settings change only on a machine that holds it",
                ));
            }
        };
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
        if proven.is_some_and(|proven| proven != public_key) {
            return Err(refused(
                "a world's settings change only on a machine that holds it",
            ));
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if !fold
            .trusted_machine(machine)
            .is_some_and(|trusted| trusted.profile.machine_key == public_key)
        {
            return Err(refused(
                "only a machine the owner marked as theirs edits a world",
            ));
        }
        // Standing comes from the read of an admitter whose chain admits this
        // machine: this install's own first, then the earlier one's when the
        // owner re-asserts. The edit names that admitter's chain heads.
        let (standing, admitter, judged) = match fold.world_edit_standing_by(machine, world) {
            Some((standing, admitter)) => (standing, admitter, &*fold),
            None => earlier
                .and_then(|earlier| {
                    earlier
                        .world_edit_standing_by(machine, world)
                        .map(|(standing, admitter)| (standing, admitter, earlier))
                })
                .ok_or_else(|| refused("this machine does not hold the world"))?,
        };
        if let ReadLocation::OneMachine(target) = settings.read
            && fold.trusted_machine(target).is_none()
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
        let now = self.instant_in_txn(txn)?.secs();
        let sign = |seq, parents: BTreeSet<AuthorityEntryHash>, settings| {
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
                    public_key: signer.clone(),
                    signature: vec![0; 64],
                },
                cosigns: Vec::new(),
                ts: now,
            };
            entry.signer.signature = key.sign(&authority_transcript(&entry)?).to_bytes().to_vec();
            Ok::<_, Error>(entry)
        };
        // The edit names only the rows its standing rests on. A machine that
        // holds the world names its own head revision and a one-machine
        // target's: an unrelated main-log head adds no safety, and one a
        // handoff later fences would wedge a replica that refused it (Engine
        // ruling E7 on Wonder P2 round 1, W4). A world readable nowhere before
        // the edit (a conflict, an orphan) names the main-log heads instead:
        // whether its contenders or named machines still stand may rest on
        // any main-log row (a shared key, custody), and an edit stuck on a
        // replica leaves the world unreadable there (Sol P2 round 5, F2, F3).
        let target = match settings.read {
            ReadLocation::OneMachine(target) => Some(target),
            ReadLocation::MyMachines | ReadLocation::Everywhere => None,
        };
        // The edit replaces the live edits it names; a refused edit replaces
        // nothing and is never named. More than one entry may name are
        // replaced a share at a time, each share's edit picking this machine
        // alone, which keeps its standing, and the last edit carries the
        // owner's settings. The first share leads with the edits that pick this
        // machine, so a contender stays one (Wonder P2 round 1, W5). A share
        // reaches a replica before the last edit may, so it only narrows a
        // world this machine holds, or picks the machine the owner moves the
        // world to; a world readable nowhere moves to this machine first, and
        // on in a second edit (Sol P2 round 5, F5).
        let picks_this_machine =
            !matches!(settings.read, ReadLocation::OneMachine(only) if only != machine);
        let mut live = Vec::new();
        let mut authors = BTreeSet::new();
        for hash in fold
            .worlds
            .get(&world)
            .into_iter()
            .flat_map(|folded| folded.live.keys())
        {
            let edit = match stored_authority_row(&self.store, txn, hash)?.map(|row| row.op) {
                Some(AuthorityOp::WorldPrivacy(edit)) => Some(edit),
                _ => None,
            };
            let picks_this = edit
                .as_ref()
                .is_some_and(|edit| edit.settings.read == ReadLocation::OneMachine(machine));
            authors.extend(edit.map(|edit| edit.machine));
            live.push((!picks_this, *hash));
        }
        live.sort_unstable();
        // A holder also names the head revisions of the machines whose live
        // edits its hold reads, while they stay few: whether such an edit
        // counts may rest on a later revision of its machine (Sol P2 round 6,
        // F5). It never falls back to the main-log heads, which would carry an
        // unrelated fenced row into a narrowing of a readable world (Wonder P2
        // round 4, W3); a hold resting on rows none of these carry refuses,
        // and the owner marks this machine again.
        // A machine's rows are the heads of its chains in this install's
        // trust set, where the edit's strength is judged, and in the trust
        // set its standing comes from, where its validity is.
        let local = fold.local_admitter();
        let heads = |id: EntityId| {
            let chain_heads = |judged: &AuthorityFold, admitter: MachineAdmitter| {
                judged
                    .machine(id)
                    .map(|folded| {
                        folded
                            .trust_chains(&admitter)
                            .into_iter()
                            .map(|(_, chain)| chain.entry)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            };
            let mut rows = chain_heads(&fold, local);
            rows.extend(chain_heads(judged, admitter));
            rows
        };
        let standing_rows: BTreeSet<AuthorityEntryHash> = match standing {
            WorldEditStanding::Holds => {
                let mut rows: BTreeSet<_> = std::iter::once(machine)
                    .chain(target)
                    .flat_map(&heads)
                    .collect();
                let authors: BTreeSet<_> = authors.into_iter().flat_map(&heads).collect();
                if rows.union(&authors).count() <= MAX_PARENTS / 2 {
                    rows.extend(authors);
                }
                rows
            }
            WorldEditStanding::Contends | WorldEditStanding::RepicksOrphan => {
                fold.append_heads.clone()
            }
        };
        let author = |standing_rows: &BTreeSet<AuthorityEntryHash>| {
            let mut live = live.iter().map(|(_, hash)| *hash);
            let mut seq = seq;
            let mut entries = Vec::new();
            let mut parents = standing_rows.clone();
            while parents.len() + live.len() > MAX_PARENTS {
                if standing != WorldEditStanding::Holds && !picks_this_machine {
                    return Err(refused(
                        "a world with this many concurrent edits moves to this machine first",
                    ));
                }
                let room = MAX_PARENTS
                    .checked_sub(parents.len())
                    .filter(|room| *room > 0)
                    .ok_or_else(invalid_authority)?;
                parents.extend(live.by_ref().take(room));
                let share = sign(
                    seq,
                    std::mem::replace(&mut parents, standing_rows.clone()),
                    WorldPrivacy {
                        read: ReadLocation::OneMachine(machine),
                        ..settings.clone()
                    },
                )?;
                parents.insert(authority_entry_hash(&share)?);
                seq = seq.checked_add(1).ok_or_else(invalid_authority)?;
                entries.push(share);
            }
            parents.extend(live);
            let entry = sign(seq, parents, settings.clone())?;
            let entry_hash = authority_entry_hash(&entry)?;
            entries.push(entry);
            let at = TimeRange {
                start: now,
                end: now,
            };
            let rows: Vec<_> = entries.into_iter().map(|entry| (entry, at, now)).collect();
            Ok((rows, entry_hash))
        };
        let previous = fold.world_privacy(world);
        let orphaned_from = if standing == WorldEditStanding::RepicksOrphan {
            super::world_privacy::orphaned_from(&judged.world_read_under(world, admitter), |id| {
                super::world_privacy::mine_by_roster(judged, id, admitter)
            })
        } else {
            BTreeSet::new()
        };
        let (rows, entry_hash) = author(&standing_rows)?;
        let after = self
            .land_world_edit_in_txn(txn, &rows, world, &entry_hash)?
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
        let view = vault.authority_view_readonly_in_txn(txn)?;
        if view.vault_root_is_conflicted() {
            return Err(invalid_authority());
        }
        Ok(Self { view })
    }

    #[must_use]
    pub fn readable_on(&self, world: EntityId, destination: Destination) -> bool {
        self.view.world_readable_on(world, destination)
    }

    /// Every edited world not readable on `destination`: the withheld set.
    pub fn withheld_for(&self, destination: Destination) -> Result<BTreeSet<EntityId>> {
        self.view.worlds_withheld_from(destination)
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
                let request = self.machine_enrolment_request(
                    vault_id,
                    MachineEncryptionKey {
                        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
                        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
                    },
                )?;
                self.enroll_machine(
                    issuer,
                    &owner,
                    &request,
                    MachineRole::Owned(MachineOwnership::Yours),
                )?;
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
