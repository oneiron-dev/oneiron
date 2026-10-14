//! Folds `MachineProfile` entries into each physical machine's standing.
//!
//! A machine's standing is the owner's answer at the pairing ceremony. It
//! merges across branches as actor bindings do: a higher revision supersedes,
//! divergent profiles at one revision poison the machine, and a removal on any
//! branch is terminal. Liveness is derived, never stored, so the facts that
//! poison a machine (a shared key, a second key for one machine, an actor
//! binding to its row) apply in every arrival order.
//!
//! Revisions form one chain per admitter and supersede only their own chain:
//! the roster's, and one per owner anchor. Inside the roster's chain the
//! revisions a key the owner holds signed form a chain of their own, so a
//! custodian's later demote, removal or conflicting revision never reaches
//! it. Which chains this install trusts is local: the accepted roster
//! revisions, plus the pinned anchor's chain (world privacy P6b, contract §4).
//! Poison applies within one admitter's chains for admission, and across the
//! trusted chains for trust; an untrusted admitter's poison never touches a
//! trusted chain, and its keys never speak for the machine.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::*;

/// Who admitted a chain of a machine's revisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MachineAdmitter {
    /// The vault's roster, under the owner-held rule for an owned mark.
    Roster,
    /// One valid owner root's anchor key (Ed25519).
    Anchor([u8; 32]),
}

/// Whose authority signed a revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignerClass {
    /// A key the owner holds.
    OwnerHeld,
    /// A cloud root, or a key in the host's custody on a hosted vault: it
    /// registers, demotes or removes, and never answers for the owner.
    Custodial,
}

/// The root this install pins: only its anchor's chain is trusted here, and
/// only while the fold holds the root as valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedRoot {
    pub id: RecoveryRootId,
    pub anchor_key: [u8; 32],
}

/// The winning revision of one admitter's chain for one machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineRevision {
    pub profile: MachineProfile,
    /// Divergent profiles at one revision, a machine key claimed by two
    /// machines, a machine whose revisions named two keys, or a row that is
    /// also an actor: never live.
    pub conflicted: bool,
    /// A `Removed` revision folded in this chain on some branch. Terminal.
    pub removed: bool,
    /// The winning revision rests on a roster key revoked since, past the
    /// stale-roster window, and no key still on the roster signed it again:
    /// not live on this install.
    pub stale: bool,
    /// The roster has no settled root: a handoff conflict retired its root
    /// and installed no successor. A roster revision is not live until the
    /// conflict settles, when the standing is judged again.
    pub admitter_unsettled: bool,
    /// The key that signed the revision, and its class. A roster key's class
    /// is judged again on the merged history: a key found to be in the host's
    /// custody on any branch the fold holds stops its owned revision standing.
    pub signer: AuthorityKey,
    pub signer_class: SignerClass,
    /// The authority-log entry that carried the revision.
    pub entry: AuthorityEntryHash,
}

/// One machine's folded standing: a chain per admitter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldedMachine {
    /// The roster's chain: every revision a roster key signed.
    pub roster: Option<MachineRevision>,
    /// The roster revisions a key P1 accepts for an owned mark signed (owner
    /// held, and not in the host's custody on a hosted fold, judged on the
    /// merged history), merged as a chain of their own. Custody that reaches
    /// its head's signer later leaves only the accepted removals; it never
    /// falls back to an older owned revision.
    pub roster_trusted: Option<MachineRevision>,
    /// Each owner anchor's chain, by anchor key.
    pub anchored: BTreeMap<[u8; 32], MachineRevision>,
    /// For each key a chain here names, the trust scopes in which another
    /// machine claims it: `Roster` for an accepted roster revision.
    shared: BTreeMap<[u8; 32], BTreeSet<MachineAdmitter>>,
}

/// The identity a trusted chain gives a machine: the keys that may sign as
/// it and be wrapped to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedMachine<'a> {
    pub chain: MachineAdmitter,
    pub profile: &'a MachineProfile,
}

/// One admitter's revisions of one machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MachineChain {
    pub(super) head: MachineRevision,
    /// The roster's chain only: the highest revision an owner-held key
    /// signed. Its removal is judged again from `owner_held_removals`.
    pub(super) owner_held: Option<MachineRevision>,
    /// The roster's chain only: each owner-held signer's removal, so one
    /// stands while its own signer stays accepted, whatever custody later
    /// finds of the key that signed the head.
    pub(super) owner_held_removals: BTreeMap<AuthorityKey, MachineRevision>,
}

/// One install key a revision named, and under whose authority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct KeyClaim {
    pub(super) machine: EntityId,
    pub(super) admitter: MachineAdmitter,
    /// The roster key that signed it, when that key was owner-held as the
    /// revision folded. Custody is judged again on the merged history.
    pub(super) owner_held: Option<AuthorityKey>,
}

impl MachineRevision {
    /// Of two entries carrying one revision, the smaller entry speaks for it.
    fn min_by_entry(self, other: &Self) -> Self {
        if other.entry < self.entry {
            other.clone()
        } else {
            self
        }
    }

    /// An owned revision stands only when a key the owner holds signed it.
    #[must_use]
    pub fn is_live(&self) -> bool {
        !self.conflicted
            && !self.removed
            && !self.stale
            && !self.admitter_unsettled
            && (self.signer_class == SignerClass::OwnerHeld
                || !matches!(self.profile.role, MachineRole::Owned(_)))
    }

    /// Live, and the owner's explicit `Yours`.
    #[must_use]
    pub fn says_yours(&self) -> bool {
        self.is_live() && self.profile.says_mine()
    }
}

impl FoldedMachine {
    /// One admitter's chain.
    #[must_use]
    pub fn chain(&self, admitter: &MachineAdmitter) -> Option<&MachineRevision> {
        match admitter {
            MachineAdmitter::Roster => self.roster.as_ref(),
            MachineAdmitter::Anchor(key) => self.anchored.get(key),
        }
    }

    /// Every admitter's chain: the roster's, then each anchor's.
    pub fn chains(&self) -> impl Iterator<Item = (MachineAdmitter, &MachineRevision)> {
        self.roster
            .iter()
            .map(|chain| (MachineAdmitter::Roster, chain))
            .chain(
                self.anchored
                    .iter()
                    .map(|(key, chain)| (MachineAdmitter::Anchor(*key), chain)),
            )
    }

    /// Chain `admitter` is live (not removed, not conflicted) and says
    /// `Owned(Yours)`.
    #[must_use]
    pub fn admits(&self, admitter: &MachineAdmitter) -> bool {
        self.chain(admitter)
            .is_some_and(MachineRevision::says_yours)
    }

    /// Some single chain admits it. Pin-free: it authorizes nothing.
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        self.chains().any(|(_, chain)| chain.says_yours())
    }

    /// The identity under `T(admitter)`: the accepted roster revisions, plus
    /// that anchor's chain. `None` unless one of those chains admits the
    /// machine, none is removed or conflicted, every live one carries the same
    /// machine key and encryption key, and no other machine claims a key
    /// within them. A stale chain never vetoes a live one's keys (Sol code-R3
    /// S3-F3). Pin-free.
    #[must_use]
    pub fn trusted_under(&self, admitter: &MachineAdmitter) -> Option<TrustedMachine<'_>> {
        let anchor = match admitter {
            MachineAdmitter::Roster => None,
            MachineAdmitter::Anchor(key) => self.anchored.get(key).map(|chain| (*admitter, chain)),
        };
        let chains: Vec<_> = self
            .roster_trusted
            .iter()
            .map(|chain| (MachineAdmitter::Roster, chain))
            .chain(anchor)
            .collect();
        let mut live = chains
            .iter()
            .map(|(_, chain)| *chain)
            .filter(|chain| chain.is_live());
        let disagree = live.next().is_some_and(|first| {
            live.any(|chain| {
                chain.profile.machine_key != first.profile.machine_key
                    || chain.profile.encryption_key != first.profile.encryption_key
            })
        });
        let blocked = disagree
            || chains.iter().any(|(_, chain)| {
                chain.removed
                    || chain.conflicted
                    || self
                        .shared
                        .get(&chain.profile.machine_key)
                        .is_some_and(|scopes| {
                            scopes.contains(&MachineAdmitter::Roster) || scopes.contains(admitter)
                        })
            });
        if blocked {
            return None;
        }
        chains
            .into_iter()
            .rev()
            .find(|(_, chain)| chain.says_yours())
            .map(|(chain, revision)| TrustedMachine {
                chain,
                profile: &revision.profile,
            })
    }

    /// The trusted identity under this install's pin: `trusted_under` the
    /// pinned anchor, or the roster alone with no pin. The caller passes a
    /// pin only while the fold holds its root ([`AuthorityFold::pinned_root`]).
    #[must_use]
    pub fn trusted(&self, pin: Option<&PinnedRoot>) -> Option<TrustedMachine<'_>> {
        self.trusted_under(&pin.map_or(MachineAdmitter::Roster, |pin| {
            MachineAdmitter::Anchor(pin.anchor_key)
        }))
    }

    /// Mine under this install's pin.
    #[must_use]
    pub fn is_mine(&self, pin: Option<&PinnedRoot>) -> bool {
        self.trusted(pin).is_some()
    }

    /// Some chain here, trusted or not, names `machine_key`.
    #[must_use]
    pub fn names_key(&self, machine_key: &[u8; 32]) -> bool {
        self.roster
            .iter()
            .chain(&self.roster_trusted)
            .chain(self.anchored.values())
            .any(|chain| &chain.profile.machine_key == machine_key)
    }
}

impl AuthorityFold {
    /// Every valid root's anchor key, with each root id that anchor signed.
    /// Full root records live only in the stored entries.
    #[must_use]
    pub fn root_anchors(&self) -> &BTreeMap<[u8; 32], BTreeSet<RecoveryRootId>> {
        &self.root_anchors
    }

    /// The folded standing of one MACHINE row, if any admitter profiled it.
    #[must_use]
    pub fn machine(&self, machine: EntityId) -> Option<&FoldedMachine> {
        self.machines.get(&machine)
    }

    /// One machine's trusted identity under this install's pin.
    #[must_use]
    pub fn trusted_machine(&self, machine: EntityId) -> Option<TrustedMachine<'_>> {
        self.machines
            .get(&machine)?
            .trusted(self.pinned_root.as_ref())
    }

    /// The machine key a connection proves to stand as `machine` here: its
    /// trusted identity's under this install's pin, else its live roster
    /// revision's (a node the owner never called theirs, so never mine). A
    /// key only an untrusted chain names never speaks for the machine.
    #[must_use]
    pub fn machine_proof_key(&self, machine: EntityId) -> Option<[u8; 32]> {
        let folded = self.machines.get(&machine)?;
        match folded.trusted(self.pinned_root.as_ref()) {
            Some(trusted) => Some(trusted.profile.machine_key),
            None => folded
                .roster
                .as_ref()
                .filter(|roster| roster.is_live())
                .map(|roster| roster.profile.machine_key),
        }
    }
}

/// One fold transition, signed by an owner roster key, for a machine that is
/// not an actor and whose key is not authority. Only an owner-held key answers
/// "yours", "work/school" or "rented": a cloud or custodial root, which the
/// hosted posture lets consent, can register its own node or demote and remove
/// a machine, but never vouch for a machine as the owner's. Neither can the
/// host's own root on a hosted vault, whatever its role labels say.
pub(super) fn apply_machine_profile(
    state: &mut FoldState,
    signer: &AuthorityKey,
    profile: &MachineProfile,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> std::result::Result<(), AuthorityFoldIssue> {
    let Some(device) = state
        .roster
        .get(signer)
        .filter(|device| device.roles & ROLE_OWNER != 0)
    else {
        return Err(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    };
    let signer_class = if folded_device_can_authority_consent(device)
        && !custodial_host_root(state, signer, context)
    {
        SignerClass::OwnerHeld
    } else {
        SignerClass::Custodial
    };
    let admitted = match profile.role {
        MachineRole::Owned(_) => signer_class == SignerClass::OwnerHeld,
        MachineRole::HostedNode | MachineRole::ExecutionNode | MachineRole::Removed => {
            context.device_can_consent(device)
        }
    };
    if !admitted {
        return Err(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    let head = roster_chain(state, profile.machine).map(|chain| &chain.head);
    if refused_revision(state, profile, head) {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let folded = MachineRevision {
        profile: profile.clone(),
        conflicted: false,
        removed: profile.role == MachineRole::Removed || head.is_some_and(|folded| folded.removed),
        stale: false,
        admitter_unsettled: false,
        signer: signer.clone(),
        signer_class,
        entry: hash,
    };
    let chains = state.machines.entry(profile.machine).or_default();
    let prior = chains.remove(&MachineAdmitter::Roster);
    // The owner-held chain keeps only its own removals: a custodian's
    // removal stays in the roster's chain and never reaches it.
    let mut owner_held_removals = prior
        .as_ref()
        .map(|chain| chain.owner_held_removals.clone())
        .unwrap_or_default();
    if signer_class == SignerClass::OwnerHeld && profile.role == MachineRole::Removed {
        add_removal(&mut owner_held_removals, signer, &folded);
    }
    let owner_held = match prior {
        _ if signer_class == SignerClass::OwnerHeld => Some(MachineRevision {
            removed: profile.role == MachineRole::Removed
                || prior
                    .as_ref()
                    .and_then(|chain| chain.owner_held.as_ref())
                    .is_some_and(|held| held.removed),
            ..folded.clone()
        }),
        Some(chain) => chain.owner_held,
        None => None,
    };
    chains.insert(
        MachineAdmitter::Roster,
        MachineChain {
            head: folded,
            owner_held,
            owner_held_removals,
        },
    );
    state
        .machine_keys
        .entry(profile.machine_key)
        .or_default()
        .insert(KeyClaim {
            machine: profile.machine,
            admitter: MachineAdmitter::Roster,
            owner_held: (signer_class == SignerClass::OwnerHeld).then(|| signer.clone()),
        });
    Ok(())
}

/// One revision in a valid root's anchor chain of a machine (E2(b)): an owned
/// mark or a removal, never a hosted or execution node. It supersedes only
/// that anchor's chain; the roster's chain and every other anchor's stay as
/// they are. No install key and no host cosign vouches here.
pub(super) fn apply_anchor_profile(
    state: &mut FoldState,
    anchor: [u8; 32],
    profile: &MachineProfile,
    hash: AuthorityEntryHash,
) -> std::result::Result<(), AuthorityFoldIssue> {
    if !matches!(profile.role, MachineRole::Owned(_) | MachineRole::Removed) {
        return Err(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    let admitter = MachineAdmitter::Anchor(anchor);
    let head = state
        .machines
        .get(&profile.machine)
        .and_then(|chains| chains.get(&admitter))
        .map(|chain| &chain.head);
    if refused_revision(state, profile, head) {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let folded = MachineRevision {
        profile: profile.clone(),
        conflicted: false,
        removed: profile.role == MachineRole::Removed || head.is_some_and(|folded| folded.removed),
        stale: false,
        admitter_unsettled: false,
        signer: AuthorityKey::Ed25519(anchor),
        signer_class: SignerClass::OwnerHeld,
        entry: hash,
    };
    state.machines.entry(profile.machine).or_default().insert(
        admitter,
        MachineChain {
            head: folded,
            owner_held: None,
            owner_held_removals: BTreeMap::new(),
        },
    );
    state
        .machine_keys
        .entry(profile.machine_key)
        .or_default()
        .insert(KeyClaim {
            machine: profile.machine,
            admitter,
            owner_held: None,
        });
    Ok(())
}

/// A revision no chain takes: a key that is authority, a row that is an
/// actor's, a proof the machine did not sign, or no higher than its chain.
fn refused_revision(
    state: &FoldState,
    profile: &MachineProfile,
    head: Option<&MachineRevision>,
) -> bool {
    key_is_authority(state, &profile.machine_key)
        || machine_is_actor(state, profile.machine)
        || !profile.proof_verifies(&state.vault_id)
        || head.is_some_and(|folded| profile.revision <= folded.profile.revision)
}

/// A key in the host's custody on a hosted vault, where the host's root is
/// the provider's key and not the owner's: that root, or any key it admitted
/// directly or through another custodial key. Judged from provenance and the
/// vault's posture, so a key labelled owner-held still counts.
fn custodial_host_root(state: &FoldState, signer: &AuthorityKey, context: FoldContext<'_>) -> bool {
    context.hosted && in_host_custody(state, signer)
}

/// Whether `key`, or any key up its admitters, is marked as the host's.
pub(super) fn in_host_custody(state: &FoldState, key: &AuthorityKey) -> bool {
    let mut seen = BTreeSet::new();
    let mut pending = vec![key];
    while let Some(next) = pending.pop() {
        if state.host_custody_keys.contains(next) {
            return true;
        }
        if seen.insert(next) {
            pending.extend(state.key_admitters.get(next).into_iter().flatten());
        }
    }
    false
}

fn roster_chain(state: &FoldState, machine: EntityId) -> Option<&MachineChain> {
    state.machines.get(&machine)?.get(&MachineAdmitter::Roster)
}

/// An install key that is also a roster key or an actor's key is no machine's.
fn key_is_authority(state: &FoldState, machine_key: &[u8; 32]) -> bool {
    let key = AuthorityKey::Ed25519(*machine_key);
    state.roster.contains_key(&key) || state.actor_bindings.contains_key(&key)
}

/// A row any accepted binding ever named, on any branch, is an actor's.
fn machine_is_actor(state: &FoldState, machine: EntityId) -> bool {
    state.actor_rows.contains(&machine)
}

/// Higher revision wins; divergent content at one revision is poison carried
/// by the byte-wise smaller profile, so the merge is the same in every order.
/// A strictly higher revision clears that poison, as it does for actor
/// bindings; a removal never clears.
pub(super) fn merge_machine(left: &MachineRevision, right: &MachineRevision) -> MachineRevision {
    let mut merged = match left.profile.revision.cmp(&right.profile.revision) {
        Ordering::Greater => left.clone(),
        Ordering::Less => right.clone(),
        Ordering::Equal if left.profile == right.profile => MachineRevision {
            conflicted: left.conflicted || right.conflicted,
            ..left.clone().min_by_entry(right)
        },
        Ordering::Equal if left.profile < right.profile => MachineRevision {
            conflicted: true,
            ..left.clone()
        },
        Ordering::Equal => MachineRevision {
            conflicted: true,
            ..right.clone()
        },
    };
    merged.removed = left.removed || right.removed;
    merged
}

fn merge_chain(left: &MachineChain, right: &MachineChain) -> MachineChain {
    let mut owner_held_removals = left.owner_held_removals.clone();
    for (signer, removal) in &right.owner_held_removals {
        add_removal(&mut owner_held_removals, signer, removal);
    }
    MachineChain {
        head: merge_machine(&left.head, &right.head),
        owner_held: match (&left.owner_held, &right.owner_held) {
            (Some(left), Some(right)) => Some(merge_machine(left, right)),
            (one, other) => one.clone().or_else(|| other.clone()),
        },
        owner_held_removals,
    }
}

/// Records `signer`'s removal, merged with any it signed before.
fn add_removal(
    removals: &mut BTreeMap<AuthorityKey, MachineRevision>,
    signer: &AuthorityKey,
    removal: &MachineRevision,
) {
    let merged = match removals.get(signer) {
        Some(earlier) => merge_machine(earlier, removal),
        None => removal.clone(),
    };
    removals.insert(signer.clone(), merged);
}

fn join_chains(
    into: &mut BTreeMap<MachineAdmitter, MachineChain>,
    chains: &BTreeMap<MachineAdmitter, MachineChain>,
) {
    for (admitter, chain) in chains {
        match into.get_mut(admitter) {
            Some(existing) => *existing = merge_chain(existing, chain),
            None => {
                into.insert(*admitter, chain.clone());
            }
        }
    }
}

/// Joins one machine's chain from another state into `state`.
pub(super) fn merge_machine_chain(
    state: &mut FoldState,
    machine: EntityId,
    admitter: MachineAdmitter,
    chain: &MachineChain,
) {
    join_chains(
        state.machines.entry(machine).or_default(),
        &BTreeMap::from([(admitter, chain.clone())]),
    );
}

pub(super) fn merge_machine_maps(
    merged: &mut BTreeMap<EntityId, BTreeMap<MachineAdmitter, MachineChain>>,
    keys: &mut BTreeMap<[u8; 32], BTreeSet<KeyClaim>>,
    right: &FoldState,
) {
    for (machine, chains) in &right.machines {
        join_chains(merged.entry(*machine).or_default(), chains);
    }
    for (key, claims) in &right.machine_keys {
        keys.entry(*key).or_default().extend(claims.iter().cloned());
    }
}

/// Which claims one chain's poison is judged against.
#[derive(Clone, Copy)]
enum ClaimScope<'a> {
    /// Every roster revision: admission under the roster.
    Roster,
    /// The roster revisions a key P1 accepts signed: the trusted roster chain.
    Accepted,
    /// One anchor's revisions.
    Anchor(&'a [u8; 32]),
}

/// The fold's key claims, indexed once for the public view.
struct ClaimIndex<'s> {
    state: &'s FoldState,
    by_machine: BTreeMap<EntityId, Vec<(&'s [u8; 32], &'s KeyClaim)>>,
    custodial: std::cell::RefCell<BTreeMap<AuthorityKey, bool>>,
}

impl<'s> ClaimIndex<'s> {
    fn new(state: &'s FoldState) -> Self {
        let mut by_machine: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for (key, claims) in &state.machine_keys {
            for claim in claims {
                by_machine
                    .entry(claim.machine)
                    .or_default()
                    .push((key, claim));
            }
        }
        Self {
            state,
            by_machine,
            custodial: std::cell::RefCell::default(),
        }
    }

    /// A roster key the owner held as it signed, and that custody on the
    /// merged history has not reached since.
    fn accepted(&self, signer: &AuthorityKey) -> bool {
        let state = self.state;
        !*self
            .custodial
            .borrow_mut()
            .entry(signer.clone())
            .or_insert_with(|| state.hosted && in_host_custody(state, signer))
    }

    fn in_scope(&self, claim: &KeyClaim, scope: ClaimScope<'_>) -> bool {
        match scope {
            ClaimScope::Roster => claim.admitter == MachineAdmitter::Roster,
            ClaimScope::Accepted => {
                claim.admitter == MachineAdmitter::Roster
                    && claim
                        .owner_held
                        .as_ref()
                        .is_some_and(|signer| self.accepted(signer))
            }
            ClaimScope::Anchor(key) => claim.admitter == MachineAdmitter::Anchor(*key),
        }
    }

    /// The roster revisions a key P1 accepts signed, judged on the merged
    /// history: the owner-held head while its signer stays accepted, removed
    /// once any accepted signer removed the machine. A custodian's removal
    /// never counts, and an accepted one outlives a head whose signer custody
    /// reached since (Sol code-R1 S1-F5).
    fn accepted_roster(&self, chain: &MachineChain) -> Option<MachineRevision> {
        let removal = chain
            .owner_held_removals
            .iter()
            .filter(|(signer, _)| self.accepted(signer))
            .map(|(_, removal)| removal.clone())
            .reduce(|left, right| merge_machine(&left, &right));
        match chain
            .owner_held
            .clone()
            .filter(|held| self.accepted(&held.signer))
        {
            Some(held) => Some(MachineRevision {
                removed: removal.is_some(),
                ..held
            }),
            None => removal,
        }
    }

    /// P1's poison within one scope: the machine named another key there,
    /// another machine claims its key there, or its key or row is authority.
    fn poisoned(&self, id: EntityId, key: &[u8; 32], scope: ClaimScope<'_>) -> bool {
        let rekeyed = self.by_machine.get(&id).is_some_and(|claims| {
            claims
                .iter()
                .any(|(claimed, claim)| *claimed != key && self.in_scope(claim, scope))
        });
        let shared = self.state.machine_keys.get(key).is_some_and(|claims| {
            claims
                .iter()
                .any(|claim| claim.machine != id && self.in_scope(claim, scope))
        });
        rekeyed || shared || key_is_authority(self.state, key) || machine_is_actor(self.state, id)
    }

    /// The trust scopes in which another machine claims `key`.
    fn shared_scopes(&self, id: EntityId, key: &[u8; 32]) -> BTreeSet<MachineAdmitter> {
        self.state
            .machine_keys
            .get(key)
            .into_iter()
            .flatten()
            .filter(|claim| claim.machine != id)
            .filter_map(|claim| match claim.admitter {
                MachineAdmitter::Roster => self
                    .in_scope(claim, ClaimScope::Accepted)
                    .then_some(MachineAdmitter::Roster),
                anchor @ MachineAdmitter::Anchor(_) => Some(anchor),
            })
            .collect()
    }

    /// One machine's public standing, with the derived poison applied per
    /// chain. Custody is judged on the merged history, so a mark signed before
    /// its signer's custody reached that branch counts no more than one
    /// signed after. Every reader of a machine's standing goes through this.
    fn folded(
        &self,
        id: EntityId,
        chains: &BTreeMap<MachineAdmitter, MachineChain>,
        roster_unsettled: bool,
    ) -> FoldedMachine {
        let state = self.state;
        let roster = chains.get(&MachineAdmitter::Roster);
        let roster_head = roster.map(|chain| {
            let mut head = chain.head.clone();
            if state.hosted && in_host_custody(state, &head.signer) {
                head.signer_class = SignerClass::Custodial;
            }
            head.conflicted |= self.poisoned(id, &head.profile.machine_key, ClaimScope::Roster);
            head.admitter_unsettled = roster_unsettled;
            head
        });
        let roster_trusted =
            roster
                .and_then(|chain| self.accepted_roster(chain))
                .map(|mut held| {
                    held.conflicted |=
                        self.poisoned(id, &held.profile.machine_key, ClaimScope::Accepted);
                    held.admitter_unsettled = roster_unsettled;
                    held
                });
        let anchored: BTreeMap<_, _> = chains
            .iter()
            .filter_map(|(admitter, chain)| match admitter {
                MachineAdmitter::Anchor(key) => {
                    let mut head = chain.head.clone();
                    head.conflicted |=
                        self.poisoned(id, &head.profile.machine_key, ClaimScope::Anchor(key));
                    Some((*key, head))
                }
                MachineAdmitter::Roster => None,
            })
            .collect();
        let shared = roster_trusted
            .iter()
            .chain(anchored.values())
            .map(|chain| chain.profile.machine_key)
            .map(|key| (key, self.shared_scopes(id, &key)))
            .filter(|(_, scopes)| !scopes.is_empty())
            .collect();
        FoldedMachine {
            roster: roster_head,
            roster_trusted,
            anchored,
            shared,
        }
    }
}

/// The fold's public view: each machine with the derived poison applied per
/// chain, and no roster standing while the roster has no settled root.
pub(super) fn folded_machines(
    state: &FoldState,
    roster_unsettled: bool,
) -> BTreeMap<EntityId, FoldedMachine> {
    let index = ClaimIndex::new(state);
    state
        .machines
        .iter()
        .map(|(id, chains)| (*id, index.folded(*id, chains, roster_unsettled)))
        .collect()
}
