//! Folds the owner's signed cuts of a repository's origin authority (FIX
//! 15740, Engine 11-06 02:54 A2; ARCH-0068: "Refs are SINGLE-WRITER PER
//! REPO", "Cutover = an authority epoch"), and signs them in the transaction
//! of each owner cut.
//!
//! The cuts keep the shared owner-choice register ([`super::owner_choice`])
//! under their own revision domain, one frontier per repository portable id:
//! a cut supersedes exactly that repository's live cuts its parents carry,
//! and concurrent different cuts conflict. A cut opens an epoch above every
//! live cut it supersedes, so no later cut rolls the epoch back. While the
//! repository's cuts conflict, or its newest cut is one this install does not
//! count at full strength, its writer is unresolved here: no carried manifest
//! is proven against it, and it never reads as a repository nobody cut.
//! Cuts are main-log entries, so every machine the owner admits folds them.
//!
//! The register records what the owner cut, never a publication lease: the
//! host's own authority row still decides its pushes, mirrors and permits.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::{TimeRange, Vault};

use super::machine_standing::InstallCounted;
use super::owner_choice::{
    FoldedOwnerChoice, OwnerChoiceOp, OwnerChoiceState, folded_owner_choices, owner_choice_landing,
};
use super::*;

/// What one cut chooses: the epoch it opens and the one machine that writes
/// the repository's refs at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct OriginCutChoice {
    /// The authority epoch the cut opens, never zero.
    pub(crate) epoch: u64,
    /// The refs writer at `epoch`.
    pub(crate) writer: EntityId,
}

/// Every repository's cuts in one fold state, each keyed by its portable id.
pub(super) type OriginCutChoiceState = OwnerChoiceState<OriginCutChoice>;

/// One repository's folded cuts, as this install counts them.
pub(crate) type FoldedRepoOriginCut = FoldedOwnerChoice<OriginCutChoice>;

/// Every repository's folded cuts.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct FoldedOriginCuts {
    /// Each repository's cuts, keyed by its cut target ([`origin_cut_target`]
    /// of its portable id); a repository the owner never cut has no entry.
    pub(crate) repos: BTreeMap<EntityId, FoldedRepoOriginCut>,
}

/// A repository's origin authority as this install counts the owner's cuts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OriginCutStanding {
    /// No live cut names the repository: the owner never cut it.
    NoCut,
    /// The newest cut counts here, unconflicted: its epoch and writer.
    InForce(OriginCutChoice),
    /// Live cuts conflict, or the newest is one this install does not count
    /// at full strength: no writer is proven here until a cut that saw them
    /// all lands.
    Unresolved,
}

impl FoldedOriginCuts {
    /// Whether no cut of any repository folded: a projection an image need
    /// not carry.
    pub(super) fn is_empty(&self) -> bool {
        self.repos.is_empty()
    }

    /// Whether any repository's live cut rests on how this install counts
    /// machines.
    pub(super) fn rests_on_counting(&self) -> bool {
        self.repos.values().any(|folded| !folded.live.is_empty())
    }

    /// The cut revision of the repository whose cut target is `repo`: what a
    /// cut of it names as `seen`, zero while it has no live cut.
    pub(crate) fn revision(&self, repo: EntityId) -> [u8; 32] {
        self.repos.get(&repo).map_or([0; 32], |folded| {
            folded.revision(ORIGIN_CUT_REVISION_CONTEXT)
        })
    }

    /// The highest epoch a live cut of the repository whose cut target is
    /// `repo` opens, zero for none: the next cut of it opens an epoch above
    /// this one.
    pub(crate) fn live_epoch(&self, repo: EntityId) -> u64 {
        self.repos
            .get(&repo)
            .into_iter()
            .flat_map(|folded| folded.live.values())
            .filter_map(|head| head.choice.map(|choice| choice.epoch))
            .max()
            .unwrap_or(0)
    }

    /// The origin authority of the repository whose cut target is `repo`, as
    /// this install counts its cuts. The cut in force stands only while it is
    /// itself live and unconflicted: a newer cut this install does not count
    /// leaves the repository unresolved, so the writer it replaced never
    /// stands again.
    pub(crate) fn standing(&self, repo: EntityId) -> OriginCutStanding {
        let Some(folded) = self
            .repos
            .get(&repo)
            .filter(|folded| !folded.live.is_empty())
        else {
            return OriginCutStanding::NoCut;
        };
        if !folded.conflict.is_empty() {
            return OriginCutStanding::Unresolved;
        }
        match &folded.in_force {
            Some(head) if folded.live.contains_key(&head.act) => head
                .choice
                .map_or(OriginCutStanding::Unresolved, OriginCutStanding::InForce),
            _ => OriginCutStanding::Unresolved,
        }
    }

    /// The live cuts `machine` carried, for its next profile revision's
    /// acknowledged set ([`super::world_privacy::live_edits_by`]).
    pub(super) fn live_choices_by(
        &self,
        machine: EntityId,
    ) -> impl Iterator<Item = AuthorityEntryHash> + '_ {
        self.repos
            .values()
            .flat_map(move |folded| super::owner_choice::live_choices_by(folded, machine))
    }
}

/// The `OriginCut` transition ([`owner_choice_landing`]), under the cut's
/// own revision domain, on its repository's frontier. A cut that opens no
/// epoch above every live cut it supersedes is invalid.
pub(super) fn apply_origin_cut(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    cut: &OriginCut,
    hash: AuthorityEntryHash,
    counting: (Option<&PinnedRoot>, InstallCounted<'_>),
    restriction_only: bool,
) -> std::result::Result<(), AuthorityFoldIssue> {
    if state
        .origin_cut
        .live_values(cut.act.target)
        .any(|live| live.epoch >= cut.epoch)
    {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let choice = OriginCutChoice {
        epoch: cut.epoch,
        writer: cut.writer,
    };
    let op = OwnerChoiceOp {
        act: &cut.act,
        machine: cut.machine,
        choice: Some(&choice),
        context: ORIGIN_CUT_REVISION_CONTEXT,
    };
    let landing = owner_choice_landing(
        state,
        &state.origin_cut,
        entry,
        op,
        hash,
        counting,
        restriction_only,
    )?;
    state.origin_cut.land(landing);
    Ok(())
}

/// The fold's view of every repository's cuts, under this install's pin and
/// holds.
pub(super) fn folded_origin_cuts(
    state: &FoldState,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
) -> FoldedOriginCuts {
    FoldedOriginCuts {
        repos: folded_owner_choices(state, &state.origin_cut, pin, counted),
    }
}

impl AuthorityFold {
    /// The origin authority the owner's cuts give the repository `repo`
    /// (portable id) in this fold, as this install counts them (FIX 15740).
    /// Conflicting vault roots, or any live cut of the repo this install
    /// holds back (a concurrent one among them), leave it unresolved.
    pub(crate) fn origin_cut_standing(&self, repo: &[u8; 32]) -> Result<OriginCutStanding> {
        if self.vault_root_is_conflicted() {
            return Ok(OriginCutStanding::Unresolved);
        }
        let target = origin_cut_target(repo)?;
        if self.origin_cuts.repos.get(&target).is_some_and(|folded| {
            folded
                .live
                .keys()
                .any(|act| self.install.held_back.contains(act))
        }) {
            return Ok(OriginCutStanding::Unresolved);
        }
        Ok(self.origin_cuts.standing(target))
    }
}

/// This install cannot carry the owner's cut: it has no machine identity or
/// install key, or no live profile of it stands under that key. No roster
/// key, the host root included, carries an owner act (FIX 2222).
const NO_CARRIER: &str = "this install has no live machine profile in the vault's roster to carry \
                          the owner's origin cut";
/// The cut would name more rows than one authority entry may: the log's
/// encoding bound, never a possession test.
const TOO_MANY_HEADS: &str = "the authority log has more concurrent heads than one origin cut may name; nothing was \
     written";

impl Vault {
    /// The highest epoch a live cut of any of `repos` (portable ids) opens in
    /// `txn`'s snapshot, zero for none: an owner cut of a repository they
    /// stand for opens an epoch above it (FIX 15740).
    pub(crate) fn origin_cut_epoch_floor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        repos: &[[u8; 32]],
    ) -> Result<u64> {
        if repos.is_empty() {
            return Ok(0);
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let mut floor = 0_u64;
        for repo in repos {
            floor = floor.max(fold.origin_cuts.live_epoch(origin_cut_target(repo)?));
        }
        Ok(floor)
    }

    /// Signs and appends the owner's cut of each of `repos` (portable ids):
    /// epoch `epoch`, refs writer `writer`, as `actor`, the owner the cutting
    /// door revalidated in `txn`, from `surface`. `txn` is the transaction
    /// that installs the host's own authority row, so the cuts and the row
    /// commit together or not at all (FIX 15740). Each cut supersedes its
    /// repository's live cuts, and each must land live and counted here
    /// before the caller commits. Returns the id of every authority log row
    /// it appended, each frontier join it needed among them, for the
    /// caller's transaction to hand to the live mirror.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] for an install that
    /// cannot carry the act; history this vault lacks; a cut that does not
    /// land.
    pub(crate) fn sign_origin_cuts_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        surface: ActSurface,
        repos: &[[u8; 32]],
        (epoch, writer): (u64, EntityId),
    ) -> Result<BTreeSet<EntityId>> {
        if repos.is_empty() {
            return Ok(BTreeSet::new());
        }
        let before = self.authority_view_readonly_in_txn(txn)?;
        let machine = crate::identity::read_machine_id_in_txn(self, txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let key = crate::identity::read_machine_signing_key_in_txn(self, txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let public_key = key.verifying_key().to_bytes();
        let signer = AuthorityKey::Ed25519(public_key);
        let mut acts = Vec::with_capacity(repos.len());
        for repo in repos {
            let target = origin_cut_target(repo)?;
            let fold = self.authority_view_readonly_in_txn(txn)?;
            if !super::owner_act_signer_admits(fold.machine(machine), &fold.roster, &public_key) {
                return Err(authority_refused(NO_CARRIER));
            }
            let seen = fold.origin_cuts.revision(target);
            // FIX 7908: join a frontier wider than one entry names.
            let joiner = FrontierSigner::Install(machine, &key);
            let fold = self
                .prepare_authority_frontier_in_txn(txn, &fold, joiner, MAX_PARENTS)?
                .unwrap_or(fold);
            let seq = next_sequence(&fold, &signer)?;
            let parents = fold.append_heads.clone();
            if parents.len() > MAX_PARENTS {
                return Err(Error::InvalidConfig(TOO_MANY_HEADS.to_owned()));
            }
            let act = OwnerAct::by_owner(actor, OwnerActKind::OriginCut, target, surface, seen);
            let now = self.instant_in_txn(txn)?.secs();
            let entry = sign_side_entry(
                &fold,
                &key,
                seq,
                parents,
                AuthorityOp::OriginCut(OriginCut {
                    act,
                    machine,
                    repo: *repo,
                    epoch,
                    writer,
                }),
                now,
            )?;
            acts.push((target, authority_entry_hash(&entry)?));
            let at = TimeRange {
                start: now,
                end: now,
            };
            self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        }
        let after = self.authority_view_readonly_in_txn(txn)?;
        for (repo, act) in acts {
            let live = after
                .origin_cuts
                .repos
                .get(&repo)
                .is_some_and(|folded| folded.live.contains_key(&act));
            if !live || after.install.held_back.contains(&act) {
                return Err(invalid_authority());
            }
        }
        after
            .valid_entries
            .difference(&before.valid_entries)
            .map(authority_log_entity_id_from_hash)
            .collect()
    }
}
