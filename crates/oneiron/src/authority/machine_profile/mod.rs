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
//! the roster's, and one per owner anchor. The owner's answers carried by a
//! linked machine's install key under his act join the roster's chain
//! ([`owner_answers`], mesh PR1b). Inside the roster's chain the approved
//! revisions, those a key the owner holds signed and the admitted answers,
//! form a chain of their own, so a custodian's later demote, removal or
//! conflicting revision never reaches it. An admitted answer that saw a
//! chain's head supersedes it causally, an anchor's included. Which chains this install trusts is local: the accepted roster
//! revisions, plus the pinned anchor's chain (world privacy P6b, contract §4).
//! Poison applies within one admitter's chains for admission, and across the
//! trusted chains for trust; an untrusted admitter's poison never touches a
//! trusted chain, and its keys never speak for the machine.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::entity_id::EntityId;

use super::machine_standing::Revision;
use super::*;

/// Who admitted a chain of a machine's revisions.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum MachineAdmitter {
    /// The vault's roster, under the owner-held rule for an owned mark.
    Roster,
    /// One valid owner root's anchor key (Ed25519).
    Anchor([u8; 32]),
}

/// Whose authority signed a revision.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum SignerClass {
    /// A key the owner holds.
    OwnerHeld,
    /// A cloud root, or a key in the host's custody on a hosted vault: it
    /// registers, demotes or removes, and never answers for the owner.
    Custodial,
    /// A linked machine's install key carrying the owner's act (mesh PR1b):
    /// the act answers for the owner, never the key, and the label says
    /// nothing of who holds the key. A revision it signed stands only while
    /// its act does.
    Carrier,
}

/// The root this install pins: only its anchor's chain is trusted here, and
/// only while the fold holds the root as valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PinnedRoot {
    pub id: RecoveryRootId,
    pub anchor_key: [u8; 32],
}

/// The winning revision of one admitter's chain for one machine.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    /// This install holds the chain: its head reached this install past its
    /// signer's sequence floor, or the fold with no vouch does not count the
    /// chain under that head (Astra #1430, `install_fold::NoVouch`). A held
    /// chain is not live here and grants nothing, but its restriction still
    /// lands and its keys still count against the other chains' (the
    /// Engine's held-chain ruling on the P2 port). Always false in the
    /// roster view.
    pub floor_held: bool,
    /// The key that signed the revision, and its class. A roster key's class
    /// is judged again on the merged history: a key found to be in the host's
    /// custody on any branch the fold holds stops its owned revision standing.
    pub signer: AuthorityKey,
    pub signer_class: SignerClass,
    /// The authority-log entry that carried the revision.
    pub entry: AuthorityEntryHash,
    /// The admitted owner act an owner answer stands on, while it stands
    /// here ([`owner_answers::act_stands`]); `None` for a roster or anchor
    /// revision, and for an answer whose carrier lost the removal race.
    pub(in crate::authority) act: Option<Arc<ActProof>>,
}

/// One machine's folded standing: a chain per admitter.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    pub(super) shared: BTreeMap<[u8; 32], BTreeSet<MachineAdmitter>>,
}

/// The identity a trusted chain gives a machine: the keys that may sign as
/// it and be wrapped to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedMachine<'a> {
    pub chain: MachineAdmitter,
    pub profile: &'a MachineProfile,
}

/// One admitter's revisions of one machine.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct MachineChain {
    pub(super) head: MachineRevision,
    /// The roster's chain only: the highest approved revision, one an
    /// owner-held key signed or an admitted owner answer. Its removal is
    /// judged again from `owner_held_removals`.
    pub(super) owner_held: Option<MachineRevision>,
    /// The roster's chain only: each approving signer's removal (an
    /// owner-held roster key's, or a carrier's install key's), so one stands
    /// while its own signer stays accepted, whatever custody later finds of
    /// the key that signed the head.
    pub(super) owner_held_removals: BTreeMap<AuthorityKey, MachineRevision>,
    /// Every revision of the machine in this chain that this history holds.
    /// The race rule reads the whole set, so no merge order or grouping
    /// changes it.
    pub(super) revisions: BTreeMap<AuthorityEntryHash, Arc<Revision>>,
}

/// One install key a revision named, and under whose authority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub(super) struct KeyClaim {
    pub(super) machine: EntityId,
    pub(super) admitter: MachineAdmitter,
    /// The roster key that signed it, when that key was owner-held as the
    /// revision folded. Custody is judged again on the merged history.
    pub(super) owner_held: Option<AuthorityKey>,
    /// The carrier whose admitted owner act claimed it, beside custody and
    /// never in its place: an answer's claim counts in the approved chain's
    /// scope whatever custody finds.
    pub(super) act_carrier: Option<EntityId>,
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

    /// An owned revision stands only when a key the owner holds signed it,
    /// or as an admitted owner answer; a carrier's revision stands only
    /// while its act does. A custodial key registers its node or demotes,
    /// and never answers "yours", "work/school" or "rented" (truthful
    /// custody, FIX 2222).
    #[must_use]
    pub fn is_live(&self) -> bool {
        let approved = match self.signer_class {
            SignerClass::OwnerHeld => true,
            SignerClass::Custodial => !matches!(self.profile.role, MachineRole::Owned(_)),
            SignerClass::Carrier => self.act.is_some(),
        };
        !self.conflicted
            && !self.removed
            && !self.stale
            && !self.admitter_unsettled
            && !self.floor_held
            && approved
    }

    /// Live, and the owner's explicit `Yours`.
    #[must_use]
    pub fn says_yours(&self) -> bool {
        self.is_live() && self.profile.says_mine()
    }

    /// Live but for this install's hold: its keys count against every other
    /// trusted chain's, so a held rotation never leaves the old key standing
    /// through another chain. A stale chain never vetoes (Sol code-R3 S3-F3).
    fn keyed(&self) -> bool {
        Self {
            floor_held: false,
            ..self.clone()
        }
        .is_live()
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
    /// machine, none is removed or conflicted, every live or held one carries
    /// the same machine key and encryption key, and no other machine claims a
    /// key within them. A stale chain never vetoes a live one's keys (Sol
    /// code-R3 S3-F3); a held chain admits nothing, but its removal, conflict
    /// and keys still block. Pin-free; the install view's holds are in the
    /// chains.
    ///
    /// An admitted owner answer that saw another chain's head supersedes it,
    /// an older anchor-era "yours" included, under any pin and in any
    /// arrival order; an answer and a head it never saw that say otherwise
    /// conflict (mesh PR1b C5). Shared-key poison and a terminal removal
    /// still veto every chain.
    #[must_use]
    pub fn trusted_under(&self, admitter: &MachineAdmitter) -> Option<TrustedMachine<'_>> {
        let chains = self.trust_chains(admitter);
        if self.keys_unsettled(admitter, &chains)
            || chains
                .iter()
                .any(|(_, chain)| chain.removed || chain.conflicted)
        {
            return None;
        }
        owner_answers::effective_chains(chains)?
            .into_iter()
            .rev()
            .find(|(_, chain)| chain.says_yours())
            .map(|(chain, revision)| TrustedMachine {
                chain,
                profile: &revision.profile,
            })
    }

    /// The head of the chain `admitter` gives `T(admitter)`: the accepted
    /// roster revisions, or that anchor's chain.
    #[must_use]
    pub(super) fn trust_head(&self, admitter: &MachineAdmitter) -> Option<&MachineRevision> {
        match admitter {
            MachineAdmitter::Roster => self.roster_trusted.as_ref(),
            MachineAdmitter::Anchor(key) => self.anchored.get(key),
        }
    }

    /// This install holds `admitter`'s chains here: they admit nothing, but
    /// their restriction and keys still count.
    pub(super) fn hold(&mut self, admitter: &MachineAdmitter) {
        for chain in self.chains_mut(admitter) {
            chain.floor_held = true;
        }
    }

    /// `admitter`'s chains went stale here: not live, and never a veto.
    pub(super) fn go_stale(&mut self, admitter: &MachineAdmitter) {
        for chain in self.chains_mut(admitter) {
            chain.stale = true;
        }
    }

    fn chains_mut(&mut self, admitter: &MachineAdmitter) -> Vec<&mut MachineRevision> {
        match admitter {
            MachineAdmitter::Roster => [self.roster.as_mut(), self.roster_trusted.as_mut()]
                .into_iter()
                .flatten()
                .collect(),
            MachineAdmitter::Anchor(key) => self.anchored.get_mut(key).into_iter().collect(),
        }
    }

    /// The chains of `T(admitter)` here: the accepted roster revisions, then
    /// that anchor's chain.
    pub(super) fn trust_chains(
        &self,
        admitter: &MachineAdmitter,
    ) -> Vec<(MachineAdmitter, &MachineRevision)> {
        let anchor = match admitter {
            MachineAdmitter::Roster => None,
            MachineAdmitter::Anchor(key) => self.anchored.get(key).map(|chain| (*admitter, chain)),
        };
        self.roster_trusted
            .iter()
            .map(|chain| (MachineAdmitter::Roster, chain))
            .chain(anchor)
            .collect()
    }

    /// Two live or held chains of `T(admitter)` name other keys, or another
    /// machine claims a key one of them names within it: never mine there,
    /// and no edit's race passes there.
    pub(super) fn keys_unsettled(
        &self,
        admitter: &MachineAdmitter,
        chains: &[(MachineAdmitter, &MachineRevision)],
    ) -> bool {
        let mut keyed = chains
            .iter()
            .map(|(_, chain)| *chain)
            .filter(|chain| chain.keyed());
        let disagree = keyed.next().is_some_and(|first| {
            keyed.any(|chain| {
                chain.profile.machine_key != first.profile.machine_key
                    || chain.profile.encryption_key != first.profile.encryption_key
            })
        });
        disagree
            || chains.iter().any(|(_, chain)| {
                self.shared
                    .get(&chain.profile.machine_key)
                    .is_some_and(|scopes| {
                        scopes.contains(&MachineAdmitter::Roster) || scopes.contains(admitter)
                    })
            })
    }

    /// The roster view of this public standing: no chain stale, unsettled or
    /// held, as every install reads the log. Validity and who may carry an
    /// owner act are judged on it; this install's projections only weaken.
    #[must_use]
    pub(super) fn roster_view(&self) -> Self {
        let clear = |chain: &MachineRevision| MachineRevision {
            stale: false,
            admitter_unsettled: false,
            floor_held: false,
            ..chain.clone()
        };
        Self {
            roster: self.roster.as_ref().map(clear),
            roster_trusted: self.roster_trusted.as_ref().map(clear),
            anchored: self
                .anchored
                .iter()
                .map(|(key, chain)| (*key, clear(chain)))
                .collect(),
            shared: self.shared.clone(),
        }
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

    /// The machine mine under this install's pin whose trusted identity
    /// signs with `machine_key`.
    #[must_use]
    pub fn mine_machine_by_key(&self, machine_key: &[u8; 32]) -> Option<EntityId> {
        self.machines.keys().copied().find(|machine| {
            self.trusted_machine(*machine)
                .is_some_and(|trusted| &trusted.profile.machine_key == machine_key)
        })
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

mod apply;
mod merge;
mod owner_answers;

pub(super) use apply::{
    apply_anchor_profile, apply_machine_profile, in_host_custody, key_is_authority,
    machine_is_actor,
};
pub(super) use merge::{merge_machine, merge_machine_chain, merge_machine_maps};
pub(super) use owner_answers::{
    ActProof, MarkProof, act_stands, answer_contested, answer_revision_of, apply_owner_answer,
    live_answers_by,
};
