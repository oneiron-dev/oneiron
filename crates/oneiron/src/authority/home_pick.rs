//! Folds the owner's signed picks of his vault's home node (DOOR-101 PR2a;
//! ARCH-0026: "The owner picks the home node in settings; the always-on
//! machine is the default"), and the owner's door that signs one.
//!
//! The picks keep the shared owner-choice register ([`super::owner_choice`])
//! under the home pick's own revision domain, beside the checkpoint root
//! policy's: a pick supersedes exactly the live picks its parents carry,
//! concurrent different picks conflict, and while they do the last
//! unconflicted pick stays recorded and the owner's surface reads the
//! conflict. A clear (no pick) hands the vault back to the default election
//! order. A pick this install does not count at full strength counts as not
//! made. Picks are main-log entries, so every machine the owner admits folds
//! them.
//!
//! The register records what the owner picked, never whether the node is a
//! candidate here: a pick of a node this machine does not know, or one not
//! eligible now, is recorded all the same, and only the election
//! (`dreamer_runner::home`) passes over it. The election also passes over the
//! pick while picks conflict. No job, lease or budget moves with a pick.

use crate::error::{Error, Result};
use crate::store::Store;
use crate::{HostingPrivacyPosture, TimeRange, Vault};

use super::machine_standing::InstallCounted;
use super::owner_choice::{
    FoldedOwnerChoice, OwnerChoiceHead, OwnerChoiceOp, OwnerChoiceState, folded_owner_choice,
    owner_choice_landing,
};
use super::*;

/// The vault's home picks in one fold state.
pub(super) type HomePickChoiceState = OwnerChoiceState<u64>;

/// One pick as a surface shows it: the node, `None` for a clear.
pub(crate) type HomePickHead = OwnerChoiceHead<u64>;

/// The vault's folded home picks, as this install counts them.
pub(crate) type FoldedHomePick = FoldedOwnerChoice<u64>;

/// The home pick is the owner's: no Grant action names it, so an agent's act
/// never makes it. Authority; nothing was written.
const OWNER_ONLY: &str = "the home node pick is the owner's; no Grant action names it";
/// This install cannot carry the owner's pick: it has no machine identity or
/// install key, or no live profile of it stands under that key. No roster
/// key, the host root included, carries an owner act (FIX 2222).
const NO_CARRIER: &str = "this install has no live machine profile in the vault's roster to carry \
                          the owner's home node pick";
/// The pick would name more rows than one authority entry may: the log's
/// encoding bound, never a possession test.
const TOO_MANY_HEADS: &str =
    "the authority log has more concurrent heads than one home node pick may name; nothing was \
     written";
/// The supplied `seen` is not the vault's current pick revision.
const STALE: &str = "the home node pick changed since it was read";

/// The `HomeNodePick` transition ([`owner_choice_landing`]), under the home
/// pick's revision domain.
pub(super) fn apply_home_pick(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    pick: &HomeNodePick,
    hash: AuthorityEntryHash,
    counting: (Option<&PinnedRoot>, InstallCounted<'_>),
    restriction_only: bool,
) -> std::result::Result<(), AuthorityFoldIssue> {
    let op = OwnerChoiceOp {
        act: &pick.act,
        machine: pick.machine,
        choice: pick.node_id.as_ref(),
        context: HOME_PICK_REVISION_CONTEXT,
    };
    let landing = owner_choice_landing(
        state,
        &state.home_pick,
        entry,
        op,
        hash,
        counting,
        restriction_only,
    )?;
    state.home_pick.land(landing);
    Ok(())
}

/// The fold's view of the vault's picks, under this install's pin and holds.
pub(super) fn folded_home_pick(
    state: &FoldState,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
) -> FoldedHomePick {
    folded_owner_choice(state, &state.home_pick, pin, counted)
}

/// The vault's home picks as the owner's surface shows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HomePickState {
    /// The revision a pick names as `seen`: the digest of the live picks,
    /// zero when none.
    pub(crate) revision: [u8; 32],
    /// The last unconflicted pick: the newest one every live pick descends
    /// from; `None` while no pick counts.
    pub(crate) in_force: Option<HomePickHead>,
    /// Every live pick.
    pub(crate) heads: Vec<HomePickHead>,
    /// The live picks in conflict, empty when none: the election passes over
    /// the pick until a pick that saw them all supersedes them.
    pub(crate) conflict: Vec<HomePickHead>,
}

impl HomePickState {
    fn of(folded: &FoldedHomePick) -> Self {
        Self {
            revision: folded.revision(HOME_PICK_REVISION_CONTEXT),
            in_force: folded.in_force.clone(),
            heads: folded.live.values().cloned().collect(),
            conflict: folded.conflict.clone(),
        }
    }

    /// The node the last unconflicted pick names; `None` for no pick or a
    /// clear. Recorded, not elected.
    pub(crate) fn pick(&self) -> Option<u64> {
        self.in_force.as_ref().and_then(|head| head.choice)
    }

    /// The node the election ranks: none while picks conflict.
    pub(crate) fn election_pick(&self) -> Option<u64> {
        if self.conflict.is_empty() {
            self.pick()
        } else {
            None
        }
    }
}

/// The vault's home picks in `txn`'s snapshot. History the vault lacks
/// refuses as the fold does, and conflicting vault roots refuse: neither
/// reads as no pick. An unrooted log has none.
pub(crate) fn home_pick_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<HomePickState> {
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    if fold.vault_root_is_conflicted() {
        return Err(invalid_authority());
    }
    Ok(HomePickState::of(&fold.home_pick))
}

/// The vault's home picks as an election in `txn` reads them; `None` when
/// this snapshot cannot read them (history the vault lacks, or conflicting
/// vault roots), so the election leaves the designation as it stands.
pub(crate) fn election_home_pick_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<HomePickState>> {
    match authority_view_readonly_for_store_in_txn(store, posture, txn) {
        Ok(fold) if fold.vault_root_is_conflicted() => Ok(None),
        Ok(fold) => Ok(Some(HomePickState::of(&fold.home_pick))),
        Err(error) if super::readonly_fold::is_history_incomplete(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

/// One signed and folded home pick, and this install's home after its own
/// re-election.
pub(crate) struct HomePickReceipt {
    /// The pick's authority entry hash.
    pub(crate) act: AuthorityEntryHash,
    /// The vault's picks with it landed.
    pub(crate) state: HomePickState,
    /// This install's MACRO home designation once the pick re-elected it.
    pub(crate) home: Option<crate::dreamer_runner::DreamerHomeNodeDesignation>,
}

impl Vault {
    /// The owner picks the node that runs his vault's MACRO consolidation
    /// (`node_id`), or clears his pick (`None`) so the default election
    /// order holds again, as `authority`, from any linked surface on any
    /// host. `seen` is the revision the deciding surface showed him
    /// ([`HomePickState::revision`]); `None` takes the current one.
    ///
    /// A pick of a node this install does not know, or one not eligible now,
    /// is recorded all the same; only the election passes over it. The pick
    /// names the main-log heads alone, whose fold carries this install's
    /// standing rows and every live pick (FIX 4987), so it supersedes all of
    /// them, and lands atomically or not at all. Its landing re-elects this install's home in the same
    /// transaction; the commit then wakes the watchers.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] for an agent's act or
    /// an install that cannot carry it; [`Error::ConcurrentWrite`] when
    /// `seen` is not the current revision; an owner refusal when the proof is
    /// no longer the vault's live owner.
    pub(crate) fn set_home_pick_as(
        &self,
        authority: &ActAuthority,
        node_id: Option<u64>,
        seen: Option<[u8; 32]>,
    ) -> Result<HomePickReceipt> {
        let (owner, surface) = match authority {
            ActAuthority::Owner(owner, surface) => (owner, *surface),
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        // Revision integrity (mesh contract §4): the owner picked on what the
        // surface showed him.
        let current = fold.home_pick.revision(HOME_PICK_REVISION_CONTEXT);
        if seen.is_some_and(|seen| seen != current) {
            return Err(Error::ConcurrentWrite(STALE));
        }
        let machine = crate::identity::read_machine_id_in_txn(self, &txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let key = crate::identity::read_machine_signing_key_in_txn(self, &txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let public_key = key.verifying_key().to_bytes();
        if !super::owner_act_signer_admits(fold.machine(machine), &fold.roster, &public_key) {
            return Err(authority_refused(NO_CARRIER));
        }
        let signer = AuthorityKey::Ed25519(public_key);
        let seq = next_sequence(&fold, &signer)?;
        let parents = fold.append_heads.clone();
        if parents.len() > MAX_PARENTS {
            return Err(Error::InvalidConfig(TOO_MANY_HEADS.to_owned()));
        }
        let act = OwnerAct::by_owner(
            actor,
            OwnerActKind::HomeNodePick,
            home_pick_target(&vault_id)?,
            surface,
            current,
        );
        let now = self.instant_in_txn(&txn)?.secs();
        let entry = sign_side_entry(
            &fold,
            &key,
            seq,
            parents,
            AuthorityOp::HomeNodePick(HomeNodePick {
                act,
                machine,
                node_id,
            }),
            now,
        )?;
        let act = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(&mut txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(&txn)?;
        if !after.home_pick.live.contains_key(&act) || after.install.held_back.contains(&act) {
            return Err(invalid_authority());
        }
        let state = HomePickState::of(&after.home_pick);
        let home = crate::dreamer_runner::DreamerRunnerStore::new(self)
            .home_node_designation_in_txn(&txn)?;
        txn.commit()?;
        // The landing re-elected this install's home in its transaction; the
        // topology route and the deadline lane re-read it now.
        self.store.notify_proactivity_changes();
        Ok(HomePickReceipt { act, state, home })
    }
}
