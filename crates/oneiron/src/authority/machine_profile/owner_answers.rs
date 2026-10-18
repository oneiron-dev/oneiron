//! The owner's machine answers (mesh PR1b): a profile revision that carries
//! his act ([`OwnerAct`]), signed by the install key of the machine that
//! served him (its carrier), and the one provenance predicate every fold
//! reads it through.
//!
//! The owner's ruling (10-19): "Linking together machines is like a
//! computronium mesh. It doesn't matter where you said yes, if you said so."
//! So an answer stands on its admitted act, carried by any live linked
//! machine ([`super::super::owner_act_signer_admits`]), before and after the
//! owner anchor and whatever this install pins. Custody stays truthful beside
//! it: the carrier's key is labelled [`SignerClass::Carrier`], never owner
//! held, and an unproved host-root `Owned` answer still refuses.
//!
//! Precedence is causal (C5): an act that saw a target's heads, an older
//! anchor-era head included, supersedes them, in every arrival order and
//! under any pin. Concurrent different answers conflict; no timestamp,
//! numeric or lexicographic winner ever grants "yours".

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::entity_id::EntityId;

use super::apply::{refused_revision, roster_chain};
use super::merge::add_removal;
use super::*;
use crate::authority::machine_standing::{InstallCounted, Mark, Standing, StandingView};

/// What makes an act-backed revision the owner's: its admitted act's
/// carrier, the install key that signed it, the carrier's live signing
/// chains at the act's parents (its removal race, FIX 2998), and every
/// revision of the target the act's parents held (what it supersedes).
/// Typed provenance beside custody: it never relabels the signer's custody,
/// and the custody graph never reads it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(in crate::authority) struct ActProof {
    pub(in crate::authority) carrier: EntityId,
    pub(in crate::authority) key: [u8; 32],
    pub(in crate::authority) marks: BTreeMap<MachineAdmitter, Mark>,
    pub(in crate::authority) saw: Arc<BTreeSet<AuthorityEntryHash>>,
}

impl FoldedMachine {
    /// This machine's revision as a deciding surface shows the owner (C5):
    /// the digest of its live chains' heads, the roster's and every
    /// anchor's, zero for none. The writer compares an answer's `seen` with
    /// it; replicas derive what an answer supersedes from its parents.
    #[must_use]
    pub fn answer_revision(&self) -> [u8; 32] {
        machine_answer_revision(self.chains().map(|(_, chain)| chain.entry))
    }
}

impl MachineRevision {
    /// The machine that carried the owner's act this revision stands on, if
    /// it is an owner answer that still stands here.
    #[must_use]
    pub fn carrier(&self) -> Option<EntityId> {
        self.act.as_ref().map(|proof| proof.carrier)
    }
}

/// An act-bearing profile's transition, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster
/// consent check, as a grant travel choice's is. Its signer is the carrier's
/// install key alone; the roster rule never applies to it.
///
/// It requires no cosign, the carrier admitted by the one carrier rule in
/// the act's parent state, pin-free, with no root-key exception (FIX 2222:
/// the host root acts as nobody; C4: an unprofiled target never carries its
/// own answer), the act's owner live there, and the carrier's next sequence.
/// The act's target is the profile's machine (its shape check). What the
/// answer supersedes is every revision of the target its parent state
/// holds, derived here, never read off the surface's `seen`, which the
/// writer compared (C5): so a replica judges it without any surface's view,
/// and a stranger anchor's row a replica may not store is never a parent.
/// The target's own checks stay: its key no authority, its row no actor, its
/// proof its own, its revision above its roster chain. A carrier this install
/// does not count lands the answer restriction only, as a revision past its
/// floor does.
pub(in crate::authority) fn apply_owner_answer(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    profile: &MachineProfile,
    hash: AuthorityEntryHash,
    (pin, counted): (Option<&PinnedRoot>, InstallCounted<'_>),
    restriction_only: bool,
) -> std::result::Result<(), AuthorityFoldIssue> {
    let (Some(carrier), Some(act)) = (profile.carrier, profile.act) else {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    };
    if !entry.cosigns.is_empty() {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let signer = entry.signer_key();
    let AuthorityKey::Ed25519(key) = signer else {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    };
    let key = *key;
    if state
        .seqs
        .get(signer)
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    let standing = Standing::new(state, pin, counted);
    let roster = StandingView::Under(MachineAdmitter::Roster);
    if !standing.admits_owner_act_signer(carrier, &key, roster) {
        return Err(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    let not_counted_here = !standing.admits_owner_act_signer(carrier, &key, StandingView::Install);
    let marks = standing.live_signing_chains(carrier, signer);
    drop(standing);
    if !super::super::owner_act::owner_live_at(state, act.owner) {
        return Err(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    let target = state.machines.get(&profile.machine);
    // Key possession: a machine carrying its own answer signs with the key
    // the answer names; it never proves a new key for itself.
    if carrier == profile.machine && profile.machine_key != key {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let saw: Arc<BTreeSet<_>> = Arc::new(
        target
            .into_iter()
            .flat_map(BTreeMap::values)
            .flat_map(|chain| chain.revisions.keys().copied())
            .collect(),
    );
    let chain = roster_chain(state, profile.machine);
    let head = chain.map(|chain| &chain.head);
    if refused_revision(state, profile, head) {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let folded = MachineRevision {
        profile: profile.clone(),
        conflicted: false,
        removed: profile.role == MachineRole::Removed || head.is_some_and(|folded| folded.removed),
        stale: false,
        admitter_unsettled: false,
        floor_held: false,
        signer: signer.clone(),
        signer_class: SignerClass::Carrier,
        entry: hash,
        act: Some(Arc::new(ActProof {
            carrier,
            key,
            marks,
            saw,
        })),
    };
    let revisions = crate::authority::machine_standing::with_revision(
        chain,
        &folded,
        true,
        restriction_only || not_counted_here,
    );
    let chains = state.machines.entry(profile.machine).or_default();
    let prior = chains.remove(&MachineAdmitter::Roster);
    let mut owner_held_removals = prior
        .as_ref()
        .map(|chain| chain.owner_held_removals.clone())
        .unwrap_or_default();
    if profile.role == MachineRole::Removed {
        add_removal(&mut owner_held_removals, signer, &folded);
    }
    // The approved chain: the owner-held roster revisions and the admitted
    // answers alike, so a custodian's later demote never reaches it.
    let owner_held = Some(MachineRevision {
        removed: folded.removed
            || prior
                .as_ref()
                .and_then(|chain| chain.owner_held.as_ref())
                .is_some_and(|held| held.removed),
        ..folded.clone()
    });
    chains.insert(
        MachineAdmitter::Roster,
        MachineChain {
            head: folded,
            owner_held,
            owner_held_removals,
            revisions,
        },
    );
    state
        .machine_keys
        .entry(profile.machine_key)
        .or_default()
        .insert(KeyClaim {
            machine: profile.machine,
            admitter: MachineAdmitter::Roster,
            owner_held: None,
            act_carrier: Some(carrier),
        });
    Ok(())
}

/// Whether an admitted answer still stands in `state`: its carrier is still
/// admitted under the key that signed it, or every chain that admitted it at
/// the act's parents and no longer does lost it only by revisions that saw
/// the act (FIX 2998's removal race, mesh contract §4). Read off the raw
/// chains, so judging one machine never folds another's answers. A role
/// change between linked roles takes nothing away: only a removal or a new
/// key does.
pub(in crate::authority) fn act_stands(
    state: &FoldState,
    proof: &ActProof,
    act: &AuthorityEntryHash,
) -> bool {
    let Some(chains) = state.machines.get(&proof.carrier) else {
        return false;
    };
    let names_key = |chain: &MachineChain| {
        !chain.head.removed && !chain.head.conflicted && chain.head.profile.machine_key == proof.key
    };
    if chains.values().all(|chain| !chain.head.removed) && chains.values().any(names_key) {
        return true;
    }
    let mut reasons = false;
    for (admitter, mark) in &proof.marks {
        let Some(chain) = chains.get(admitter) else {
            return false;
        };
        if names_key(chain) {
            continue;
        }
        reasons = true;
        let mut takers = chain
            .revisions
            .iter()
            .filter(|(hash, revision)| {
                !mark.prior.contains(*hash)
                    && (revision.profile().role == MachineRole::Removed
                        || revision.profile().machine_key != proof.key)
            })
            .peekable();
        let saw = takers.peek().is_some()
            && takers.all(|(_, revision)| revision.profile().seen_world_edits.contains(act));
        if chain.head.conflicted || !saw {
            return false;
        }
    }
    reasons
}

/// The heads of `T(X)` that count for the owner's answer: each chain an
/// admitted answer among them saw is superseded (C5), in every arrival order
/// and under any pin. `None` when an admitted answer and another head still
/// standing say different things: concurrent different answers conflict,
/// and nothing picks a winner that grants "yours".
pub(in crate::authority) fn effective_chains<'a>(
    chains: Vec<(MachineAdmitter, &'a MachineRevision)>,
) -> Option<Vec<(MachineAdmitter, &'a MachineRevision)>> {
    let superseded: BTreeSet<AuthorityEntryHash> = chains
        .iter()
        .filter_map(|(_, chain)| chain.act.as_ref())
        .flat_map(|proof| proof.saw.iter().copied())
        .collect();
    let standing: Vec<_> = chains
        .into_iter()
        .filter(|(_, chain)| !superseded.contains(&chain.entry))
        .collect();
    let answered = standing.iter().any(|(_, chain)| chain.act.is_some());
    let disagree = standing
        .iter()
        .any(|(_, chain)| chain.profile.says_mine() != standing[0].1.profile.says_mine());
    (!(answered && disagree)).then_some(standing)
}

/// Whether a chain's merged head is an owner answer that another answer in
/// the chain contests: one that says otherwise and that neither saw. The
/// merge marks such a head conflicted whatever the numeric revisions say,
/// until a later answer that saw both settles it.
pub(in crate::authority) fn answer_contested(
    head: &MachineRevision,
    revisions: &BTreeMap<AuthorityEntryHash, Arc<crate::authority::machine_standing::Revision>>,
) -> bool {
    if head.act.is_none() {
        return false;
    }
    let Some(own) = revisions.get(&head.entry) else {
        return false;
    };
    revisions.iter().any(|(hash, other)| {
        *hash != head.entry
            && other.profile().act.is_some()
            && other.profile().role != head.profile.role
            && !own.past().contains(hash)
            && !other.past().contains(&head.entry)
    })
}

/// What makes a roster mark accepted, as the stale-roster renewal, both
/// resumed folds and the checkpoint image's safety index read it: a roster
/// key the owner held as it signed, judged again against custody on the
/// merged history, or an admitted owner answer, which rests on its carrier's
/// act and no roster key, so custody never reaches it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(in crate::authority) enum MarkProof {
    OwnerHeld(AuthorityKey),
    Act { carrier: EntityId },
}

impl MarkProof {
    /// The proof a chain head stands on, if it is a mark at all.
    pub(in crate::authority) fn of(head: &MachineRevision) -> Option<Self> {
        match (&head.act, head.signer_class) {
            (Some(proof), _) => Some(Self::Act {
                carrier: proof.carrier,
            }),
            (None, SignerClass::OwnerHeld) => Some(Self::OwnerHeld(head.signer.clone())),
            (None, _) => None,
        }
    }

    /// The one predicate: an owner-held signer outside the host's custody on
    /// `merged`, or an admitted answer.
    pub(in crate::authority) fn accepted(&self, merged: &FoldState) -> bool {
        match self {
            Self::OwnerHeld(signer) => !(merged.hosted && in_host_custody(merged, signer)),
            Self::Act { .. } => true,
        }
    }
}

/// The live answers `machine` carried, for its next profile revision's
/// acknowledged set beside its world edits and grant travel choices
/// ([`crate::authority::world_privacy::live_edits_by`]).
pub(in crate::authority) fn live_answers_by(
    fold: &AuthorityFold,
    machine: EntityId,
) -> impl Iterator<Item = AuthorityEntryHash> + '_ {
    fold.machines
        .values()
        .flat_map(|folded| folded.roster.iter().chain(&folded.roster_trusted))
        .filter(move |revision| revision.carrier() == Some(machine))
        .map(|revision| revision.entry)
}
