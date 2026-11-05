//! Folds the owner's namings of a device key's successor (FIX 11135, Engine
//! 11-06 06:58 = A), and signs one from the owner's door on the install he
//! names.
//!
//! The successions keep the shared owner-choice register
//! ([`super::owner_choice`]) under their own revision domain, one frontier
//! per predecessor (client id, device key): a succession supersedes exactly
//! that predecessor's live successions its parents carry, and concurrent
//! different successions conflict. While a predecessor's successions
//! conflict, or its newest is one this install does not count at full
//! strength, it has no successor here: no install completes its receipts.
//! Successions are main-log entries, so every machine the owner admits folds
//! them.
//!
//! The register names who completes a predecessor's erase receipts, nothing
//! else: each receipt is still verified under the key that signed it, and
//! the completion is the successor's own, under its own key.

use std::collections::{BTreeMap, BTreeSet};

use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::{TimeRange, Vault};

use super::machine_standing::InstallCounted;
use super::owner_choice::{
    FoldedOwnerChoice, OwnerChoiceOp, OwnerChoiceState, folded_owner_choices, owner_choice_landing,
};
use super::*;

/// What one succession chooses: the machine that completes the predecessor's
/// receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct DeviceSuccessionChoice {
    /// The successor machine.
    pub(crate) successor: EntityId,
}

/// Every predecessor's successions in one fold state, each keyed by its
/// succession target.
pub(super) type DeviceSuccessionChoiceState = OwnerChoiceState<DeviceSuccessionChoice>;

/// One predecessor's folded successions, as this install counts them.
pub(crate) type FoldedPredecessorSuccession = FoldedOwnerChoice<DeviceSuccessionChoice>;

/// Every predecessor's folded successions.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct FoldedDeviceSuccessions {
    /// Each predecessor's successions, keyed by its succession target
    /// ([`device_succession_target`] of its client id and device key); a
    /// predecessor the owner never named has no entry.
    pub(crate) predecessors: BTreeMap<EntityId, FoldedPredecessorSuccession>,
}

impl FoldedDeviceSuccessions {
    /// Whether no succession of any predecessor folded: a projection an image
    /// need not carry.
    pub(super) fn is_empty(&self) -> bool {
        self.predecessors.is_empty()
    }

    /// Whether any predecessor's live succession rests on how this install
    /// counts machines.
    pub(super) fn rests_on_counting(&self) -> bool {
        self.predecessors
            .values()
            .any(|folded| !folded.live.is_empty())
    }

    /// The succession revision of the predecessor whose succession target is
    /// `target`: what a succession of it names as `seen`, zero while it has
    /// no live succession.
    pub(crate) fn revision(&self, target: EntityId) -> [u8; 32] {
        self.predecessors.get(&target).map_or([0; 32], |folded| {
            folded.revision(DEVICE_SUCCESSION_REVISION_CONTEXT)
        })
    }

    /// The successor of the predecessor whose succession target is `target`,
    /// as this install counts its successions: the succession in force while
    /// it is itself live and unconflicted, else none.
    pub(crate) fn successor(&self, target: EntityId) -> Option<EntityId> {
        let folded = self.predecessors.get(&target)?;
        if !folded.conflict.is_empty() {
            return None;
        }
        let head = folded.in_force.as_ref()?;
        if !folded.live.contains_key(&head.act) {
            return None;
        }
        head.choice.map(|choice| choice.successor)
    }

    /// The live successions `machine` carried, for its next profile
    /// revision's acknowledged set ([`super::world_privacy::live_edits_by`]).
    pub(super) fn live_choices_by(
        &self,
        machine: EntityId,
    ) -> impl Iterator<Item = AuthorityEntryHash> + '_ {
        self.predecessors
            .values()
            .flat_map(move |folded| super::owner_choice::live_choices_by(folded, machine))
    }
}

/// The `DeviceSuccession` transition ([`owner_choice_landing`]), under the
/// succession's own revision domain, on its predecessor's frontier.
pub(super) fn apply_device_succession(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    succession: &DeviceSuccession,
    hash: AuthorityEntryHash,
    counting: (Option<&PinnedRoot>, InstallCounted<'_>),
    restriction_only: bool,
) -> std::result::Result<(), AuthorityFoldIssue> {
    let choice = DeviceSuccessionChoice {
        successor: succession.successor,
    };
    let op = OwnerChoiceOp {
        act: &succession.act,
        machine: succession.machine,
        choice: Some(&choice),
        context: DEVICE_SUCCESSION_REVISION_CONTEXT,
    };
    let landing = owner_choice_landing(
        state,
        &state.device_succession,
        entry,
        op,
        hash,
        counting,
        restriction_only,
    )?;
    state.device_succession.land(landing);
    Ok(())
}

/// The fold's view of every predecessor's successions, under this install's
/// pin and holds.
pub(super) fn folded_device_successions(
    state: &FoldState,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
) -> FoldedDeviceSuccessions {
    FoldedDeviceSuccessions {
        predecessors: folded_owner_choices(state, &state.device_succession, pin, counted),
    }
}

impl AuthorityFold {
    /// The machine the owner named to complete the receipts of the device
    /// key `device_key` under client id `client`, as this install counts his
    /// successions (FIX 11135). Conflicting vault roots, or any live
    /// succession of that predecessor this install holds back, leave it with
    /// none.
    pub(crate) fn device_successor(
        &self,
        client: u64,
        device_key: &[u8; 32],
    ) -> Result<Option<EntityId>> {
        if self.vault_root_is_conflicted() {
            return Ok(None);
        }
        let target = device_succession_target(client, device_key)?;
        if self
            .device_successions
            .predecessors
            .get(&target)
            .is_some_and(|folded| {
                folded
                    .live
                    .keys()
                    .any(|act| self.install.held_back.contains(act))
            })
        {
            return Ok(None);
        }
        Ok(self.device_successions.successor(target))
    }
}

/// This install cannot carry the owner's succession: it has no machine
/// identity or install key, or no live profile of it stands under that key.
/// No roster key, the host root included, carries an owner act (FIX 2222).
const NO_CARRIER: &str = "this install has no live machine profile in the vault's roster to carry \
                          the owner's device succession";
/// The predecessor named is this install's own current device key.
const SELF_SUCCESSION: &str = "the device key named is this install's own";
/// The succession would name more rows than one authority entry may: the
/// log's encoding bound, never a possession test.
const TOO_MANY_HEADS: &str = "the authority log has more concurrent heads than one device succession may name; nothing was \
     written";

impl Vault {
    /// The owner names the device key `device_key` under client id `client`
    /// as the predecessor of this install, from `surface` (FIX 11135, Engine
    /// 06:58 = A): this install then completes the erase receipts that key
    /// attested, each verified under that key, the completion under its own.
    /// The successor is this install's own machine, read in the same
    /// transaction; nothing the caller names stands in for it. The
    /// succession supersedes the predecessor's live successions and lands
    /// live and counted here before it commits.
    ///
    /// # Errors
    /// A refusal when the proof is no longer the live owner, when this
    /// install cannot carry the act, or when `device_key` under `client` is
    /// this install's own; history this vault lacks; a succession that does
    /// not land.
    pub fn name_device_predecessor_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        client: u64,
        device_key: [u8; 32],
    ) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_in_txn(self, &txn)?;
        let own = (
            crate::store::install_identity::read_client_id_in_txn(self, &txn)?,
            crate::store::install_identity::read_device_verifying_key_in_txn(self, &txn)?,
        );
        if own == (Some(client), Some(device_key)) {
            return Err(authority_refused(SELF_SUCCESSION));
        }
        let before = self.authority_view_readonly_in_txn(&txn)?;
        let machine = crate::identity::read_machine_id_in_txn(self, &txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let key = crate::identity::read_machine_signing_key_in_txn(self, &txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let public_key = key.verifying_key().to_bytes();
        let signer = AuthorityKey::Ed25519(public_key);
        let target = device_succession_target(client, &device_key)?;
        if !super::owner_act_signer_admits(before.machine(machine), &before.roster, &public_key) {
            return Err(authority_refused(NO_CARRIER));
        }
        let seen = before.device_successions.revision(target);
        // FIX 7908: join a frontier wider than one entry names.
        let joiner = FrontierSigner::Install(machine, &key);
        let joined =
            self.prepare_authority_frontier_in_txn(&mut txn, &before, joiner, MAX_PARENTS)?;
        let fold = joined.as_ref().unwrap_or(&before);
        let seq = next_sequence(fold, &signer)?;
        let parents = fold.append_heads.clone();
        if parents.len() > MAX_PARENTS {
            return Err(Error::InvalidConfig(TOO_MANY_HEADS.to_owned()));
        }
        let act = OwnerAct::by_owner(actor, OwnerActKind::DeviceSuccession, target, surface, seen);
        let now = self.instant_in_txn(&txn)?.secs();
        let entry = sign_side_entry(
            fold,
            &key,
            seq,
            parents,
            AuthorityOp::DeviceSuccession(DeviceSuccession {
                act,
                machine,
                client,
                device_key,
                successor: machine,
            }),
            now,
        )?;
        let hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(&mut txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(&txn)?;
        let live = after
            .device_successions
            .predecessors
            .get(&target)
            .is_some_and(|folded| folded.live.contains_key(&hash));
        if !live || after.install.held_back.contains(&hash) {
            return Err(invalid_authority());
        }
        let appended = after
            .valid_entries
            .difference(&before.valid_entries)
            .map(authority_log_entity_id_from_hash)
            .collect::<Result<BTreeSet<EntityId>>>()?;
        // The succession and its joins reach every loaded window through the
        // live mirror, and a crash before it loses none (FIX 7957).
        #[cfg(feature = "sync")]
        self.mark_pending_mirrors_in_txn(&mut txn, &appended)?;
        txn.commit()?;
        #[cfg(feature = "sync")]
        self.note_committed_rows(appended);
        #[cfg(not(feature = "sync"))]
        drop(appended);
        Ok(())
    }
}
