//! The one re-wrap sequence (contract §4). Every door that marks this
//! install's own machine or changes its pin runs it in its one write
//! transaction: `activate_owner_root`, `pin_owner_root`, `restore_world_keys`,
//! and `anchor_machine` on this install's own request.
//!
//! 1. Before the door's marks and pin, it opens each key this machine can
//!    open: from a counted wrap to it, or from a record this machine signed
//!    itself, whatever the pin, checked against that record's commitment.
//! 2. The door appends its marks and writes the pin. The sequence refolds and
//!    opens each further key from a counted wrap to the new root with the
//!    door's seed. A key this machine will not read under the new pin is
//!    first wrapped, on the old pin's standing rows, to the new root and to
//!    this machine, so a later door here opens it from its own record.
//! 3. It lists the worlds this install holds whose settings the pin change
//!    made differ. It edits none: only the owner re-asserts a world.
//! 4. It wraps each key this machine may still read to the new root and to
//!    every machine mine under the new pin that may read the world.
//! 5. It refolds and puts each key it reached in exactly one list.
//!
//! A key is reached when this machine holds a counted wrap of it, a record
//! of its own wrapping it to itself, or (with the door's seed) a counted
//! wrap of it to the new root. A reached key that is conflicted, or whose
//! every envelope fails to open, is reported with that reason, never
//! dropped. A key whose world's live edits outgrow one record is withheld
//! as `FrontierWide` and the door goes on: one wide world never stops a
//! pin move or a kit restore.
//!
//! A world deleted here less than 90 days ago (`DELETED_WORLD_KEEP_SECS`) is
//! reached like a live one, so the new kit still restores it from the bundles
//! that hold it (the Engine's call, 10-18). An erased world, or one deleted
//! longer ago, is never opened.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;

use super::pads::{WorldKeyPad, deleted_world_keys_kept_in_txn, pad_in_txn};
use super::{
    MachineSecret, RecoveryRootSeed, SequenceCounter, WorldKey, WorldKeyBinding, WorldKeyId,
    WrapRecipient, open_counted, open_world_key, recipients,
};
use crate::authority::{
    AuthorityFold, AuthorityView, Destination, EffectiveRead, EffectiveWorldPrivacy,
    MachineAdmitter, PinnedRoot, RecoveryRootId, WorldKeyWrapsRecord, invalid_authority,
    own_world_key_records_in_txn, read_pin_and_earlier_in_txn,
};
use crate::error::Result;
use crate::{EntityId, Vault};

/// Why a pin door left a key without a new wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Withheld {
    /// This machine is not mine under the new pin.
    NotMine,
    /// The local read excludes this machine: conflicted, nowhere, or one
    /// other machine.
    NotReadable,
    /// The WORLD row is unknown or erased here, or was deleted more than 90
    /// days ago: never opened.
    NotLive,
    /// The world now reads everywhere: no wrap counts for it, so its older
    /// keys keep only the wraps they already have.
    NotPrivate,
    /// The key's counted records name other bytes or another owner for its
    /// id, or bytes other than the ones this machine opened: it is never
    /// current, never opened, and gets no new wrap.
    Conflicted,
    /// Every envelope this door could open the key from failed: a corrupt
    /// wrap, or one sealed to another key. A well-signed record can carry
    /// one, since the fold never sees inside an envelope.
    Unopenable,
    /// The world's live settings edits outgrew one key record, so this door
    /// gave the key no new wrap, and raised the world's OF-520 question. The
    /// key keeps the wraps it had (a kit's root wrap among them): once one
    /// machine merges the world's settings, a re-run of the door wraps it
    /// where this machine still reads the world.
    FrontierWide,
    /// Only machines removed here signed the key's counted records, or the
    /// new pin removes one of the signers it stood on under the old pin, and
    /// this machine signed none: no door here wraps it again, since that
    /// record would make it current. A kit restore lists it as usable instead
    /// (the Engine's Q2 on Astra #1422c; Astra #1422d F2).
    SignerRemoved,
}

/// A world this install holds whose settings the pin change made differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NarrowedWorld {
    pub world: EntityId,
    pub earlier: EffectiveWorldPrivacy,
    pub now: EffectiveWorldPrivacy,
    /// The earlier frontier's signers; `true` is mine under the new pin.
    pub earlier_signers: Vec<(EntityId, bool)>,
}

/// What a pin door did to the keys this machine reached.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepinReport {
    pub rewrapped: Vec<WorldKeyId>,
    pub withheld: Vec<(WorldKeyId, Withheld)>,
    pub narrowed: Vec<NarrowedWorld>,
    /// The root `pin_owner_root` left a second step for: it is not stored
    /// here yet, so the pin stayed, or this machine is not mine under it yet,
    /// its marks still held. `owner_root_view` reports when it has arrived;
    /// pinning again then finishes (Astra #1422e F1, r23).
    pub awaiting: Option<RecoveryRootId>,
}

/// The door the sequence runs for.
pub(crate) struct RepinDoor<'a> {
    pub(crate) secret: &'a MachineSecret,
    pub(crate) signing: &'a SigningKey,
    /// The root the new pin names.
    pub(crate) new_root: RecoveryRootId,
    /// The seed the door holds, which opens counted wraps to the new root.
    pub(crate) seed: Option<&'a RecoveryRootSeed>,
    /// A kit restore lists a world kept on another machine as needing a
    /// re-home, never as withheld.
    pub(crate) restore: bool,
}

/// A key the sequence reached.
struct Reached {
    key: Reach,
    owner: EntityId,
}

/// What became of a reached key.
enum Reach {
    Opened(WorldKey),
    /// Its world is not live here, nor deleted within 90 days: never opened.
    NotLive,
    /// Conflicted where it was reached: never opened.
    Conflicted,
    /// Every envelope tried failed.
    Unopenable,
}

impl Reach {
    fn opened(&self) -> Option<&WorldKey> {
        match self {
            Self::Opened(key) => Some(key),
            Self::NotLive | Self::Conflicted | Self::Unopenable => None,
        }
    }
}

/// Step 1's result, taken before the door's marks and pin.
pub(crate) struct RepinStart {
    old: AuthorityView,
    reached: BTreeMap<WorldKeyId, Reached>,
    /// The keys this machine signed a record of itself, each with the
    /// commitment and owner that record named.
    own_keys: BTreeSet<(WorldKeyId, [u8; 32], EntityId)>,
    /// Each held world's earlier settings and the earlier frontier's signers.
    earlier: BTreeMap<EntityId, (EffectiveWorldPrivacy, Vec<EntityId>)>,
    /// The admitter the pin singleton keeps as `earlier` once the pin moves.
    pub(crate) earlier_admitter: Option<MachineAdmitter>,
}

/// Step 5's result.
pub(crate) struct RepinFinish {
    pub(crate) report: RepinReport,
    /// A kit restore's keys of worlds kept on another machine.
    pub(crate) needs_rehome: Vec<WorldKeyId>,
    /// A kit restore's keys this machine may read, for the session ring
    /// once the door commits.
    pub(crate) usable: Vec<WorldKey>,
}

impl Vault {
    /// Step 1, before the door's marks and pin.
    pub(crate) fn repin_start_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        door: &RepinDoor<'_>,
    ) -> Result<RepinStart> {
        let me = door.secret.machine;
        let my_key = door.signing.verifying_key().to_bytes();
        let now = self.instant_in_txn(txn)?.secs();
        let old = self.authority_view_readonly_in_txn(txn)?;
        let (_, kept) = read_pin_and_earlier_in_txn(&self.store, txn)?;
        let old_mine = old
            .trusted_machine(me)
            .is_some_and(|trusted| trusted.profile.machine_key == my_key);
        let old_admitter = old.pinned_root.map_or(MachineAdmitter::Roster, |pin| {
            MachineAdmitter::Anchor(pin.anchor_key)
        });
        let earlier_admitter = if old_mine { Some(old_admitter) } else { kept };
        // The earlier settings: the local ones, or the earlier admitter's
        // read when this machine was not mine under the old pin. With no
        // earlier admitter, the local settings before the door.
        let earlier_view = match kept {
            Some(admitter) if !old_mine => {
                self.authority_view_under_admitter_in_txn(txn, &old, admitter)?
            }
            _ => old.clone(),
        };
        // Only a live world is listed for re-assertion: a deleted one's
        // settings take no edit, and its keys are rewrapped below as they are.
        let mut earlier = BTreeMap::new();
        for (world, folded) in &earlier_view.worlds {
            if self.world_row_live_in_txn(txn, *world)? {
                earlier.insert(
                    *world,
                    (
                        earlier_view.world_privacy(*world),
                        folded.live.values().copied().collect(),
                    ),
                );
            }
        }
        let to_me = WrapRecipient::Machine(me);
        let mut own = own_world_key_records_in_txn(&self.store, txn, &old, me, my_key)?;
        let own_keys = own
            .iter()
            .map(|(_, record)| (record.key, record.commitment, record.owner))
            .collect();
        own.retain(|(_, record)| record.wraps.iter().any(|(to, _)| *to == to_me));
        let mut reached = BTreeMap::new();
        for key in old.all_world_keys() {
            let mine = key.wraps.contains_key(&to_me);
            let signed = own.iter().any(|(_, record)| record.key == key.id);
            if !mine && !signed {
                continue;
            }
            let reach = if !self.world_keys_reached_in_txn(txn, key.id.world, now)? {
                Reach::NotLive
            } else if key.conflicted {
                Reach::Conflicted
            } else {
                match pad_in_txn(&self.store, txn, &key.id)? {
                    Some(pad) => open_counted(&old, key, to_me, &door.secret.secret, &pad)
                        .or_else(|| {
                            open_own(&old, &own, key.id, Some(key.commitment), door.secret, &pad)
                        })
                        .map_or(Reach::Unopenable, Reach::Opened),
                    None => Reach::Unopenable,
                }
            };
            reached.insert(
                key.id,
                Reached {
                    key: reach,
                    owner: key.owner,
                },
            );
        }
        // Keys this machine wrapped itself that count nowhere here.
        for (_, record) in &own {
            if old.world_key(&record.key).is_some() || reached.contains_key(&record.key) {
                continue;
            }
            let reach = if self.world_keys_reached_in_txn(txn, record.key.world, now)? {
                pad_in_txn(&self.store, txn, &record.key)?
                    .and_then(|pad| open_own(&old, &own, record.key, None, door.secret, &pad))
                    .map_or(Reach::Unopenable, Reach::Opened)
            } else {
                Reach::NotLive
            };
            reached.insert(
                record.key,
                Reached {
                    key: reach,
                    owner: record.owner,
                },
            );
        }
        Ok(RepinStart {
            old,
            reached,
            own_keys,
            earlier,
            earlier_admitter,
        })
    }

    /// Steps 2-5, after the door appended its marks and wrote the pin.
    pub(crate) fn repin_finish_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        door: &RepinDoor<'_>,
        mut start: RepinStart,
    ) -> Result<RepinFinish> {
        let me = door.secret.machine;
        let my_key = door.signing.verifying_key().to_bytes();
        let now = self.instant_in_txn(txn)?.secs();
        let mid = self.authority_view_readonly_in_txn(txn)?;
        let root = self
            .root_recipient_in_txn(txn, &mid, door.new_root)?
            .ok_or_else(invalid_authority)?;
        let to_root = WrapRecipient::RecoveryRoot(door.new_root);
        let mine = |fold: &AuthorityFold| {
            fold.trusted_machine(me)
                .is_some_and(|trusted| trusted.profile.machine_key == my_key)
        };
        // Step 1's pre-wraps count under the old pin, so only a machine mine
        // there makes them, and only for the keys it reached there: a key the
        // seed opens already has its root wrap.
        let pre_wrap: BTreeSet<WorldKeyId> = if mine(&start.old) {
            start.reached.keys().copied().collect()
        } else {
            BTreeSet::new()
        };
        // Every key with a counted wrap to the new root is reached, so a
        // restore lists each one: a key step 1 could not open gets its turn
        // with the seed.
        if let Some(seed) = door.seed {
            let recovery = seed.recovery_secret()?;
            for key in mid.all_world_keys() {
                let retry = start
                    .reached
                    .get(&key.id)
                    .is_none_or(|reached| matches!(reached.key, Reach::Unopenable));
                if !retry || !key.wraps.contains_key(&to_root) {
                    continue;
                }
                let reach = if !self.world_keys_reached_in_txn(txn, key.id.world, now)? {
                    Reach::NotLive
                } else if key.conflicted {
                    Reach::Conflicted
                } else {
                    pad_in_txn(&self.store, txn, &key.id)?
                        .and_then(|pad| open_counted(&mid, key, to_root, &recovery, &pad))
                        .map_or(Reach::Unopenable, Reach::Opened)
                };
                start.reached.insert(
                    key.id,
                    Reached {
                        key: reach,
                        owner: key.owner,
                    },
                );
            }
        }
        let reads = |fold: &AuthorityFold, world: EntityId| {
            mine(fold)
                && fold.world_privacy(world).read != EffectiveRead::Everywhere
                && fold.world_readable_on(world, Destination::Machine(me))
        };
        // A key gets a record here only if it stands under the new pin, or
        // stood under the old one and the new pin removes none of its
        // signers, or this machine signed a record of these very bytes
        // itself: this door's record would make it current (the Engine's Q2
        // on Astra #1422c). So a key whose signers the new pin leaves out
        // keeps its wraps, and the old trust set's silence never overrides a
        // removal in the new one (Astra #1422d F2). A record of one id,
        // this machine's own or a standing one, vouches for no other bytes
        // under it, such as those a seed retry or the old pin opens (Astra
        // #1422e F2, #1422f F1). Such a key is still opened, and a kit
        // restore keeps it usable.
        let stands = |id: &WorldKeyId, key: &WorldKey, owner: EntityId| {
            let stands_in = |fold: &AuthorityFold| {
                fold.world_key(id).is_some_and(|held| {
                    fold.world_key_stands(held) && !other_bytes(held, key, owner)
                })
            };
            let none_removed = || {
                [&start.old, &mid]
                    .into_iter()
                    .filter_map(|fold| fold.world_key(id))
                    .flat_map(|key| key.signers.iter())
                    .all(|machine| mid.signer_stands(*machine))
            };
            start.own_keys.contains(&(*id, key.commitment(), owner))
                || stands_in(&mid)
                || (stands_in(&start.old) && none_removed())
        };
        let my_public = door.secret.secret.public_key().clone();
        let mut seq = SequenceCounter::new();
        // Keys whose world outgrew one record, in the pre-wrap and in the
        // wrap step: withheld unless already wrapped, and the door goes on
        // (Engine, 2026-10-15).
        let mut pre_wide = BTreeSet::new();
        let mut wide = BTreeSet::new();
        // A key this machine will not read under the new pin is wrapped
        // first on the old pin's rows, to the new root and to itself.
        for (id, reached) in &start.reached {
            let Some(key) = reached.key.opened() else {
                continue;
            };
            if !pre_wrap.contains(id)
                || !stands(id, key, reached.owner)
                || mid.world_privacy(id.world).read == EffectiveRead::Everywhere
                || reads(&mid, id.world)
            {
                continue;
            }
            let records = match self.append_world_key_wraps_in_txn(
                txn,
                &start.old,
                door.signing,
                me,
                key,
                reached.owner,
                &[
                    (to_root, root.key.clone()),
                    (WrapRecipient::Machine(me), my_public.clone()),
                ],
                &mut seq,
            )? {
                Ok(records) => records,
                // The same two wraps on bounded parents, so a later door
                // here still opens the key from its own record.
                Err(_) => {
                    pre_wide.insert(*id);
                    vec![self.append_bridge_wrap_in_txn(
                        txn,
                        &start.old,
                        door.signing,
                        me,
                        key,
                        reached.owner,
                        Some(&root),
                        &my_public,
                        &mut seq,
                    )?]
                }
            };
            let after = self.authority_view_readonly_in_txn(txn)?;
            if !records
                .iter()
                .all(|hash| after.valid_entries.contains(hash))
            {
                return Err(invalid_authority());
            }
        }
        let narrowed = start
            .earlier
            .iter()
            .filter_map(|(world, (before, signers))| {
                let now = mid.world_privacy(*world);
                (now != *before).then(|| NarrowedWorld {
                    world: *world,
                    earlier: before.clone(),
                    now,
                    earlier_signers: signers
                        .iter()
                        .map(|signer| (*signer, mid.trusted_machine(*signer).is_some()))
                        .collect(),
                })
            })
            .collect();
        let mut appended = Vec::new();
        for (id, reached) in &start.reached {
            let Some(key) = reached.key.opened() else {
                continue;
            };
            if !reads(&mid, id.world) || !stands(id, key, reached.owner) {
                continue;
            }
            let counted = mid.world_key(id);
            if counted.is_some_and(|held| other_bytes(held, key, reached.owner)) {
                continue;
            }
            let missing: Vec<_> = recipients(&mid, id.world, Some(root.clone()))
                .into_iter()
                .filter(|(to, _)| !counted.is_some_and(|held| held.wraps.contains_key(to)))
                .collect();
            match self.append_world_key_wraps_in_txn(
                txn,
                &mid,
                door.signing,
                me,
                key,
                reached.owner,
                &missing,
                &mut seq,
            )? {
                Ok(records) => appended.extend(records),
                // The root's and this machine's wraps go in a bridge record,
                // which may not count; the other readers wait for a merge.
                Err(_) => {
                    wide.insert(*id);
                    let own = WrapRecipient::Machine(me);
                    if missing.iter().any(|(to, _)| *to == to_root || *to == own) {
                        self.append_bridge_wrap_in_txn(
                            txn,
                            &mid,
                            door.signing,
                            me,
                            key,
                            reached.owner,
                            Some(&root),
                            &my_public,
                            &mut seq,
                        )?;
                    }
                }
            }
        }
        self.require_counted_in_txn(txn, &appended)?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        let mut finish = RepinFinish {
            report: RepinReport {
                narrowed,
                ..RepinReport::default()
            },
            needs_rehome: Vec::new(),
            usable: Vec::new(),
        };
        for (id, reached) in start.reached {
            let read = after.world_privacy(id.world).read;
            let held = after.world_key(&id);
            let key = match reached.key {
                Reach::NotLive => Err(Withheld::NotLive),
                Reach::Conflicted => Err(Withheld::Conflicted),
                Reach::Unopenable => Err(Withheld::Unopenable),
                Reach::Opened(_) if read == EffectiveRead::Everywhere => Err(Withheld::NotPrivate),
                // The counted key under this id must be the bytes this
                // machine opened, or its wraps say nothing about them.
                Reach::Opened(key)
                    if held.is_some_and(|held| other_bytes(held, &key, reached.owner)) =>
                {
                    Err(Withheld::Conflicted)
                }
                Reach::Opened(_) if pre_wide.contains(&id) => Err(Withheld::FrontierWide),
                Reach::Opened(_) if !mine(&after) => Err(Withheld::NotMine),
                Reach::Opened(_) if !reads(&after, id.world) => {
                    if door.restore
                        && matches!(read, EffectiveRead::OneMachine(other) if other != me)
                    {
                        finish.needs_rehome.push(id);
                        continue;
                    }
                    Err(Withheld::NotReadable)
                }
                Reach::Opened(key) => Ok(key),
            };
            let key = match key {
                Ok(key) => key,
                Err(reason) => {
                    finish.report.withheld.push((id, reason));
                    continue;
                }
            };
            if !stands(&id, &key, reached.owner) {
                if door.restore {
                    finish.usable.push(key);
                } else {
                    finish.report.withheld.push((id, Withheld::SignerRemoved));
                }
                continue;
            }
            let wrapped = held.is_some_and(|held| {
                held.wraps.contains_key(&to_root)
                    && held.wraps.contains_key(&WrapRecipient::Machine(me))
            });
            // A key whose root and own wraps already count is rewrapped,
            // even when another reader's wrap had to wait (Astra S2-R2
            // A2-F5); its question is raised.
            if !wrapped {
                if wide.contains(&id) {
                    finish.report.withheld.push((id, Withheld::FrontierWide));
                    continue;
                }
                return Err(invalid_authority());
            }
            finish.report.rewrapped.push(id);
            if door.restore {
                finish.usable.push(key);
            }
        }
        Ok(finish)
    }

    /// Whether a pin door reaches `world`'s keys: its WORLD row is live here,
    /// or the world was deleted less than 90 days before `now` and not erased,
    /// so the new kit still restores it from the bundles that hold it.
    fn world_keys_reached_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        world: EntityId,
        now: u64,
    ) -> Result<bool> {
        Ok(self.world_row_live_in_txn(txn, world)?
            || deleted_world_keys_kept_in_txn(&self.store, txn, world, now)?)
    }

    /// This vault's own log folded under `admitter`'s trust, for the read
    /// an earlier admitter gives (`read_X`).
    pub(crate) fn authority_view_under_admitter_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        admitter: MachineAdmitter,
    ) -> Result<AuthorityView> {
        let pin = match admitter {
            MachineAdmitter::Roster => None,
            MachineAdmitter::Anchor(anchor_key) => fold
                .root_anchors()
                .get(&anchor_key)
                .and_then(|ids| ids.first())
                .map(|id| PinnedRoot {
                    id: *id,
                    anchor_key,
                }),
        };
        self.authority_view_under_pin_in_txn(txn, pin)
    }
}

/// The fold's key under this id is conflicted, or names bytes or an owner
/// other than the key this machine opened.
fn other_bytes(held: &crate::authority::FoldedWorldKey, key: &WorldKey, owner: EntityId) -> bool {
    held.conflicted || held.commitment != key.commitment() || held.owner != owner
}

/// Opens `id` with its `pad` from a record this machine signed itself, checked
/// against that record's commitment, and against `commitment` when the fold holds
/// the key.
fn open_own(
    fold: &AuthorityFold,
    own: &[(crate::authority::AuthorityEntryHash, WorldKeyWrapsRecord)],
    id: WorldKeyId,
    commitment: Option<[u8; 32]>,
    secret: &MachineSecret,
    pad: &WorldKeyPad,
) -> Option<WorldKey> {
    let vault_id = fold.vault_id?;
    let me = WrapRecipient::Machine(secret.machine);
    own.iter()
        .map(|(_, record)| record)
        .filter(|record| {
            record.key == id && commitment.is_none_or(|held| held == record.commitment)
        })
        .find_map(|record| {
            let (_, bytes) = record.wraps.iter().find(|(to, _)| *to == me)?;
            let envelope = oneiron_crypto::Envelope::parse(bytes).ok()?;
            let binding = WorldKeyBinding {
                vault_id,
                key: id,
                owner: record.owner,
                policy: record.policy,
                commitment: record.commitment,
            };
            open_world_key(&binding, me, &secret.secret, &envelope, pad).ok()
        })
}
