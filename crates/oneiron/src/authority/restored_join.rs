//! A machine born of a restore joins the vault (row
//! RESTORED-COPIES-ENROL-EACH-OTHER; Setting DESIGN pass 15e "Joined", RULING
//! SETTING-UNTANGLE = A; scope RULING RESTORED-COPIES-JOIN-SCOPE = A).
//!
//! A restore that drops its image's machine identity on a vault the owner
//! roots, and an archived vault's activation, make a new machine whose
//! enrolment names its origin ([`MachineProfile::restored_from`], signed in
//! the machine's own proof). Such a machine is not yet a machine of the
//! vault. Its act-free revisions (the root's bootstrap, an anchor's mark) are
//! judged as the profile transitions judge them and then HELD here: no chain
//! and no key claim of it stands, so it carries no act, witnesses nothing,
//! proves no peer, and its say-so answers nothing. Two copies of one image
//! therefore never join each other: neither stands as a live machine to sign
//! for the other.
//!
//! An accepted entry joins every held enrolment its parents' state holds,
//! which is every held enrolment among its ancestors, when its signer is the
//! install key of a live machine there (the one carrier rule in the roster
//! view, pin-free: [`super::owner_act_signer_admits`]). Each joined
//! enrolment's chain and key claim stand from that entry on. A machine that
//! never restored is joined. A revision carried under the owner's act needs
//! a live carrier, which only a joined machine is, so it stands as before,
//! and joins what it finds held of its target first: pairing a restored
//! install from a joined machine is the door's way in, and the bootstrap
//! arm refuses one (`machine_answers::RESTORED_NOT_JOINED`). The owner's
//! own word that no other machine is left is the second way in (DESIGN
//! 15e): one [`RestoredMachineJoin`] row, signed alone by a key the vault
//! trusts as the owner's ([`apply_owner_join`]), joins the one enrolment it
//! names. Its door (`Vault::join_restored_install`) files this install's
//! enrolment and that row in one transaction; it is the only door that
//! writes a held enrolment.
//!
//! A machine's origin is fixed by its first revision: a later revision of it
//! that names another image, or none, is refused (`origin_differs`), so the
//! mark is never dropped under a fresh proof. A revision without the field
//! (every one written before it) reads as a machine that never restored and
//! keeps its verdict.
//!
//! Cost per entry: one pass over the enrolments the parents hold (none on a
//! vault no restore marked), and, while one waits, one key-claim lookup and
//! one carrier check on the signer.

use std::collections::{BTreeMap, BTreeSet};

use super::machine_standing::{InstallCounted, Standing, StandingView};
use super::*;
use crate::entity_id::EntityId;

/// One enrolment of a machine born of a restore, as the fold holds it: the
/// chain its revision would have stood, the key claims it would have made,
/// and the entry that joined it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct RestoredEnrolment {
    pub(super) machine: EntityId,
    pub(super) admitter: MachineAdmitter,
    pub(super) chain: MachineChain,
    pub(super) machine_key: [u8; 32],
    pub(super) claims: BTreeSet<KeyClaim>,
    /// The entry that joined it, `None` while it waits.
    pub(super) joined_by: Option<AuthorityEntryHash>,
}

/// A restored machine's enrolment as [`AuthorityFold`] shows it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RestoredEnrolmentStanding {
    /// The MACHINE row the enrolment names.
    pub machine: EntityId,
    /// The image it names as its origin.
    pub restored_from: [u8; 32],
    /// The entry that joined it; `None` while it waits for a joined
    /// machine's entry (or the owner's act) to join it.
    pub joined_by: Option<AuthorityEntryHash>,
    /// The held revision itself: its keys, role and number, which a joined
    /// machine's answer for the machine revises and must keep.
    pub profile: MachineProfile,
    /// The scope that signed it: the roster, or one owner root's anchor.
    pub admitter: MachineAdmitter,
}

/// Every enrolment `state` holds, as the fold shows it.
pub(super) fn listed(state: &FoldState) -> BTreeMap<AuthorityEntryHash, RestoredEnrolmentStanding> {
    state
        .restored_enrolments
        .iter()
        .map(|(hash, enrolment)| {
            let standing = RestoredEnrolmentStanding {
                machine: enrolment.machine,
                restored_from: enrolment
                    .chain
                    .head
                    .profile
                    .restored_from
                    .unwrap_or_default(),
                joined_by: enrolment.joined_by,
                profile: enrolment.chain.head.profile.clone(),
                admitter: enrolment.admitter,
            };
            (*hash, standing)
        })
        .collect()
}

/// Two branches' enrolments: a union by entry, where one that either branch
/// joined is joined, by the entry that sorts first when both did.
pub(super) fn merge(
    merged: &mut BTreeMap<AuthorityEntryHash, RestoredEnrolment>,
    right: &BTreeMap<AuthorityEntryHash, RestoredEnrolment>,
) {
    for (hash, enrolment) in right {
        match merged.get_mut(hash) {
            Some(kept) => {
                kept.joined_by = match (kept.joined_by, enrolment.joined_by) {
                    (Some(left), Some(right)) => Some(left.min(right)),
                    (left, right) => left.or(right),
                };
            }
            None => {
                merged.insert(*hash, enrolment.clone());
            }
        }
    }
}

/// Whether `machine` has joined in `state`: some chain of it stands there.
fn joined(state: &FoldState, machine: EntityId) -> bool {
    state
        .machines
        .get(&machine)
        .is_some_and(|chains| !chains.is_empty())
}

/// The enrolments `state` holds for `machine` that wait to join.
fn waiting(state: &FoldState, machine: EntityId) -> Vec<RestoredEnrolment> {
    state
        .restored_enrolments
        .values()
        .filter(|enrolment| enrolment.machine == machine && enrolment.joined_by.is_none())
        .cloned()
        .collect()
}

/// A revision whose origin is not its machine's: some revision of the
/// machine its parents hold, on any admitter's chain or any enrolment held
/// for it, names another image or none. Judged on the revision's parents,
/// over every revision each chain holds, not only its head, so a head a
/// merge marked for disagreeing origins ([`origins_disagree`]) is never
/// revised clean.
pub(super) fn origin_differs(state: &FoldState, profile: &MachineProfile) -> bool {
    let chains = state
        .machines
        .get(&profile.machine)
        .into_iter()
        .flat_map(BTreeMap::values);
    let held = state
        .restored_enrolments
        .values()
        .filter(|enrolment| enrolment.machine == profile.machine)
        .map(|enrolment| &enrolment.chain);
    chains
        .chain(held)
        .flat_map(|chain| {
            std::iter::once(chain.head.profile.restored_from)
                .chain(
                    chain
                        .owner_held
                        .iter()
                        .map(|head| head.profile.restored_from),
                )
                .chain(
                    chain
                        .revisions
                        .values()
                        .map(|revision| revision.profile().restored_from),
                )
        })
        .any(|origin| origin != profile.restored_from)
}

/// Whether two revisions one chain holds name different origins: branches
/// that disagree on the image a machine was born of leave it conflicted,
/// whatever their revision numbers (REVIEW-9509 round 2 P1).
pub(super) fn origins_disagree(
    revisions: &oneiron_persistent_collections::PersistentMap<
        AuthorityEntryHash,
        std::sync::Arc<super::machine_standing::Revision>,
    >,
) -> bool {
    let mut origins = revisions
        .values()
        .map(|revision| revision.profile().restored_from);
    origins
        .next()
        .is_some_and(|first| origins.any(|origin| origin != first))
}

/// One revision of `profile`'s machine through its transition `fold`, which
/// writes `state`'s machine chains and key claims as it does for any machine.
/// A joined machine's revision, and one of a machine that never restored and
/// waits for nothing, folds as before. Otherwise the revision is judged on
/// the chains the machine's waiting enrolments would stand (so it must
/// revise them and keep their origin). A `carried` one (the owner's act,
/// carried by a live machine, so its entry joins them: [`witnessed`]) then
/// stands on them. An act-free one is held: its chain and key claims go into
/// `restored_enrolments` under its entry, and nothing of the machine stands.
///
/// A machine that has not joined never carries an answer for itself: no
/// chain of it stands on the parents, so the carrier rule refuses it there,
/// and the held chains this lays under a carried revision must not make it a
/// carrier of its own (REVIEW-9509/9510 P1). The carrier rule reads only the
/// carrier's own chains, so for any other carrier the verdict is the parents'.
/// Nor do they speak for whether the answer needs the owner's proof: `fold`
/// gets the parents as they were, before anything was laid under, and judges
/// that on them (REVIEW-9509 round 2 P1); `None` when nothing was.
pub(super) fn fold_revision(
    state: &mut FoldState,
    profile: &MachineProfile,
    hash: AuthorityEntryHash,
    carried: bool,
    fold: impl FnOnce(&mut FoldState, Option<&FoldState>) -> std::result::Result<(), AuthorityFoldIssue>,
) -> std::result::Result<(), AuthorityFoldIssue> {
    let machine = profile.machine;
    if joined(state, machine) {
        return fold(state, None);
    }
    if carried && profile.carrier == Some(machine) {
        return Err(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    let waiting = waiting(state, machine);
    if waiting.is_empty() && (carried || profile.restored_from.is_none()) {
        return fold(state, None);
    }
    let parents = carried.then(|| state.clone());
    for enrolment in &waiting {
        super::machine_profile::merge_machine_chain(
            state,
            machine,
            enrolment.admitter,
            &enrolment.chain,
        );
    }
    if carried {
        return fold(state, parents.as_ref());
    }
    let result = fold(state, None);
    let chains = state.machines.remove(&machine).unwrap_or_default();
    let mut claims = BTreeSet::new();
    if let Some(named) = state.machine_keys.get_mut(&profile.machine_key) {
        let (theirs, others): (BTreeSet<_>, BTreeSet<_>) = std::mem::take(named)
            .into_iter()
            .partition(|claim| claim.machine == machine);
        *named = others.into();
        claims = theirs;
        if named.is_empty() {
            state.machine_keys.remove(&profile.machine_key);
        }
    }
    result?;
    let (admitter, chain) = chains
        .into_iter()
        .find(|(_, chain)| chain.head.entry == hash)
        .ok_or(AuthorityFoldIssue::InvalidEntry(hash))?;
    state.restored_enrolments.insert(
        hash,
        RestoredEnrolment {
            machine,
            admitter,
            chain,
            machine_key: profile.machine_key,
            claims,
            joined_by: None,
        },
    );
    Ok(())
}

/// The waiting enrolments `entry` joins, judged on its parents' merged
/// `state`: every one held there, when its signer is the install key of a
/// machine the one carrier rule admits there in the roster view. None when
/// nothing waits, at the cost of one test. Whether `entry` itself is accepted
/// is its own transition's verdict; [`join`] runs only on one that is.
pub(super) fn witnessed(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    standing: (Option<&PinnedRoot>, InstallCounted<'_>),
) -> Vec<AuthorityEntryHash> {
    if state
        .restored_enrolments
        .values()
        .all(|enrolment| enrolment.joined_by.is_some())
    {
        return Vec::new();
    }
    let AuthorityKey::Ed25519(key) = entry.signer_key() else {
        return Vec::new();
    };
    let Some(claims) = state.machine_keys.get(key) else {
        return Vec::new();
    };
    let (pin, counted) = standing;
    let view = Standing::new(state, pin, counted);
    let roster = StandingView::Under(MachineAdmitter::Roster);
    if !claims
        .iter()
        .any(|claim| view.admits_owner_act_signer(claim.machine, key, roster))
    {
        return Vec::new();
    }
    state
        .restored_enrolments
        .iter()
        .filter(|(_, enrolment)| enrolment.joined_by.is_none())
        .map(|(hash, _)| *hash)
        .collect()
}

/// The owner's word that no other machine is left (DESIGN 15e, the second
/// way in): `record`, which `entry`'s primary signer signs alone, joins the
/// one enrolment it names, judged on its parents' `state`. The signer is a
/// key `state` takes as the owner's proof
/// ([`super::owner_proof::gives_owner_proof`]): the recovery credential that
/// opened the image proves nobody's will, so a key of his says it. The act's
/// owner is live there ([`super::owner_act::owner_live_at`]), and the
/// enrolment is one `state` holds for the act's target under the act's
/// owner, of a machine no chain or held enrolment there removes, and the
/// signer's sequence is above the one `state` holds for it. An enrolment an
/// entry joined already keeps that entry; the act then changes nothing.
pub(super) fn apply_owner_join(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    record: &RestoredMachineJoin,
    hash: AuthorityEntryHash,
) -> std::result::Result<(), AuthorityFoldIssue> {
    // The signer's sequence moves forward here as everywhere: a join never
    // rewinds it below what its parents hold (REVIEW-9510/9511 P1).
    if state
        .seqs
        .get(entry.signer_key())
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    let target = record.act.target;
    // The enrolment is held for the act's target and names the act's owner:
    // a join under another owner id never admits his machine (REVIEW-9510
    // round 2 P1 :305).
    let held = state
        .restored_enrolments
        .get(&record.enrolment)
        .is_some_and(|enrolment| {
            enrolment.machine == target && enrolment.chain.head.profile.owner == record.act.owner
        });
    // A removal is terminal: once the parents hold one of the target, on a
    // chain that stands or one still held, no join brings it back
    // (REVIEW-9510 round 2 P1 :312).
    let removed = state
        .machines
        .get(&target)
        .is_some_and(|chains| chains.values().any(|chain| chain.head.removed))
        || state
            .restored_enrolments
            .values()
            .any(|enrolment| enrolment.machine == target && enrolment.chain.head.removed);
    if !held
        || removed
        || !super::owner_proof::gives_owner_proof(state, entry.signer_key())
        || !super::owner_act::owner_live_at(state, record.act.owner)
    {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    join(state, &[record.enrolment], hash);
    Ok(())
}

/// Joins the `witnessed` enrolments in `state`, the state after the entry
/// `by`: each one's chain and key claims stand from there on, merged as any
/// branch's chain merges.
pub(super) fn join(
    state: &mut FoldState,
    witnessed: &[AuthorityEntryHash],
    by: AuthorityEntryHash,
) {
    for hash in witnessed {
        let Some(enrolment) = state.restored_enrolments.get_mut(hash) else {
            continue;
        };
        if enrolment.joined_by.is_some() {
            continue;
        }
        enrolment.joined_by = Some(by);
        let enrolment = enrolment.clone();
        super::machine_profile::merge_machine_chain(
            state,
            enrolment.machine,
            enrolment.admitter,
            &enrolment.chain,
        );
        state
            .machine_keys
            .entry(enrolment.machine_key)
            .or_default()
            .extend(enrolment.claims);
    }
}

impl AuthorityFold {
    /// Every enrolment of a machine born of a restore, by entry, and the
    /// entry that joined it, `None` while it waits (row
    /// RESTORED-COPIES-ENROL-EACH-OTHER).
    #[must_use]
    pub fn restored_enrolments(&self) -> &BTreeMap<AuthorityEntryHash, RestoredEnrolmentStanding> {
        &self.restored_enrolments
    }

    /// The enrolment of `machine` that waits to join, when the machine was
    /// born of a restore and no chain of it stands yet: the entry a joined
    /// machine's entry must descend from, or the owner's act must name.
    #[must_use]
    pub fn unjoined_restored_enrolment(&self, machine: EntityId) -> Option<AuthorityEntryHash> {
        if self.machine(machine).is_some() {
            return None;
        }
        self.restored_enrolments
            .iter()
            .find(|(_, enrolment)| enrolment.machine == machine && enrolment.joined_by.is_none())
            .map(|(hash, _)| *hash)
    }

    /// The enrolments of `machine` that wait to join under a scope this
    /// install counts: the roster's, and its pinned anchor's, as
    /// [`FoldedMachine::standing_heads`] reads a machine. The mark of an
    /// anchor this install does not pin numbers no pairing and refuses none
    /// (REVIEW-9509 round 2 P1).
    pub fn counted_waiting_enrolments(
        &self,
        machine: EntityId,
    ) -> impl Iterator<Item = (&AuthorityEntryHash, &RestoredEnrolmentStanding)> + '_ {
        let pinned = self
            .pinned_root
            .as_ref()
            .map(|pin| MachineAdmitter::Anchor(pin.anchor_key));
        self.restored_enrolments.iter().filter(move |(_, held)| {
            held.machine == machine
                && held.joined_by.is_none()
                && (held.admitter == MachineAdmitter::Roster || Some(held.admitter) == pinned)
        })
    }
}
