//! What a derivation batch holds, and who commits it.

use std::collections::BTreeSet;

use crate::EntityId;
use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::selection::StrengthSignals;
use crate::error::{Error, Result};
use crate::write_envelope::{SourceLineage, WriteActor};

/// Who commits a derivation batch, as the engine stamps it: the actor of the
/// caller's credential, the run the batch belongs to, and that run's
/// recorded lineage. The verbs (6.7d) build it from the live-run attachment
/// and an engine job from its attempt; a caller never supplies it.
#[derive(Debug, Clone)]
pub struct DerivationStamp {
    /// The committing actor.
    pub actor: WriteActor,
    /// The run the batch belongs to, as recorded; `None` for an engine job
    /// with no run.
    pub run: Option<String>,
    /// The attempt the batch runs in, when it runs in one: an archive's
    /// snapshot and tombstone name it.
    pub attempt: Option<AttemptId>,
    /// The source classes the run's inputs carried. Every derived claim is
    /// `Generated`; this adds what it was derived from.
    pub lineage: SourceLineage,
}

/// A row a derivation item names: one already stored, or one an earlier item
/// of the same batch lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemRef {
    /// A stored row, by id.
    Stored(EntityId),
    /// The row an earlier item of the batch lands, by that item's local name.
    Local(String),
}

/// A claim an agent derived.
#[derive(Debug, Clone)]
pub struct DerivedClaim {
    /// The item's name inside its batch: unique there, and what later items
    /// name it by.
    pub local: String,
    /// The claim's predicate.
    pub predicate: String,
    /// What the claim is about.
    pub subject: ItemRef,
    /// The claim's value.
    pub value: serde_json::Value,
    /// Its confidence, in `[0, 1]`.
    pub confidence: f32,
    /// The rows it was derived from. The derivation floor (GATE-12) needs at
    /// least one of them to be live evidence.
    pub evidence: Vec<ItemRef>,
}

/// Evidence an agent derived (kind 2): rows it reads that support a stored
/// claim it reads.
#[derive(Debug, Clone)]
pub struct DerivedEvidence {
    /// The item's name inside its batch.
    pub local: String,
    /// The claim the evidence supports.
    pub head: ItemRef,
    /// The supporting rows: TURNs, cited whole, or admissible claims.
    pub sources: Vec<ItemRef>,
}

/// A supersession an agent derived: the claim `new` replaces the claim
/// `old`, which the agent's grant reaches.
#[derive(Debug, Clone)]
pub struct DerivedSupersede {
    /// The item's name inside its batch.
    pub local: String,
    /// The claim that stands.
    pub new: ItemRef,
    /// The claim it replaces.
    pub old: ItemRef,
}

/// An agent's answer to one open conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivedSettlement {
    /// This member stands; each other live member is superseded by it.
    Keep(ItemRef),
    /// Every member stays active: the pair is held and its gap is known.
    HoldBoth,
    /// The marker named no real contradiction.
    Dismiss,
}

/// A settlement an agent derived for the open conflict `marker`.
#[derive(Debug, Clone)]
pub struct DerivedSettle {
    /// The item's name inside its batch.
    pub local: String,
    /// The open conflict's marker.
    pub marker: ItemRef,
    /// The answer.
    pub settlement: DerivedSettlement,
}

/// An archive an agent derived: its own weak claim `claim`, with the
/// strength it scored.
#[derive(Debug, Clone)]
pub struct DerivedArchive {
    /// The item's name inside its batch.
    pub local: String,
    /// The claim to archive.
    pub claim: ItemRef,
    /// The strength signals the agent scored it by.
    pub signals: StrengthSignals,
    /// Its score: below the owner's strength policy row, or refused.
    pub score: f64,
}

/// A SameAs between two claims an agent derived (kind 4): it lands as the
/// link's proposed coreference status claim; the edge is applied only where
/// the owner's standing nightly-link grant already lets this actor apply
/// one.
#[derive(Debug, Clone)]
pub struct DerivedSameAs {
    /// The item's name inside its batch.
    pub local: String,
    /// One claim.
    pub source: ItemRef,
    /// The claim it is the same as.
    pub target: ItemRef,
}

/// An identity-topology judgment an agent derived (kind 4): a merge, split,
/// facet or distinct assertion under the agent's own live `topology_seal`
/// Grant. It lands as a parked proposal, or, when `apply` asks and the
/// Grant allows it, as an applied event.
#[derive(Debug, Clone)]
pub struct DerivedTopology {
    /// The item's name inside its batch.
    pub local: String,
    /// The judgment.
    pub op: crate::identity_topology::IdentityTopologyOp,
    /// The agent's own `topology_seal` Grant.
    pub grant: EntityId,
    /// Whether the judgment asks to take effect now rather than wait as a
    /// proposal.
    pub apply: bool,
}

/// One `about` line of a person: the sensitivity band it is written for and
/// its one plain line of text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedAboutLine {
    /// The band, 0 (public) to 3 (restricted). The line stands on the facts
    /// at or below it.
    pub band: u8,
    /// The line.
    pub text: String,
}

/// A person's `about` lines an agent derived (kind 5): one line for each
/// band that has facts at or below it, written from the facts whose digest
/// `written_from` names.
#[derive(Debug, Clone)]
pub struct DerivedPersonAbout {
    /// The item's name inside its batch.
    pub local: String,
    /// The PERSON.
    pub person: ItemRef,
    /// The digest of the facts the lines were written from, as the agent's
    /// read reads them ([`crate::Vault::person_about_facts`]).
    pub written_from: [u8; 32],
    /// The lines, lowest band first.
    pub lines: Vec<DerivedAboutLine>,
}

/// A PsychProfile snapshot an agent derived (kind 5), stored at the profile
/// address of its subject, `facet` and `world`.
#[derive(Debug, Clone)]
pub struct DerivedPsychProfile {
    /// The item's name inside its batch.
    pub local: String,
    /// The facet of the profile's address.
    pub facet: Option<EntityId>,
    /// The world of the profile's address.
    pub world: Option<EntityId>,
    /// The snapshot: every source revision with the exact words it was read
    /// from, each from a record the agent reads.
    pub profile: crate::psych_profile::PsychProfile,
}

/// One derived item. Each kind is one arm with a stager of its own.
#[derive(Debug, Clone)]
pub enum DerivationItem {
    /// A `Generated` claim (kind 1).
    Claim(DerivedClaim),
    /// Evidence for a stored claim (kind 2).
    Evidence(DerivedEvidence),
    /// A supersession (kind 3).
    Supersede(DerivedSupersede),
    /// A conflict settlement (kind 3).
    Settle(DerivedSettle),
    /// A SameAs between two claims (kind 4).
    SameAs(DerivedSameAs),
    /// An identity-topology judgment (kind 4).
    Topology(DerivedTopology),
    /// A person's `about` lines (kind 5).
    PersonAbout(DerivedPersonAbout),
    /// A PsychProfile snapshot (kind 5).
    PsychProfile(DerivedPsychProfile),
    /// A reversible archive (kind 6).
    Archive(DerivedArchive),
}

impl DerivationItem {
    /// The item's name inside its batch.
    pub fn local(&self) -> &str {
        match self {
            Self::Claim(claim) => &claim.local,
            Self::Evidence(evidence) => &evidence.local,
            Self::Supersede(supersede) => &supersede.local,
            Self::Settle(settle) => &settle.local,
            Self::SameAs(same_as) => &same_as.local,
            Self::Topology(topology) => &topology.local,
            Self::PersonAbout(about) => &about.local,
            Self::PsychProfile(profile) => &profile.local,
            Self::Archive(archive) => &archive.local,
        }
    }

    /// The kind's name, as the batch record and the receipts name it.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Claim(_) => "claim",
            Self::Evidence(_) => "evidence",
            Self::Supersede(_) => "supersede",
            Self::Settle(_) => "settle",
            Self::SameAs(_) => "same_as",
            Self::Topology(_) => "topology",
            Self::PersonAbout(_) => "person_about",
            Self::PsychProfile(_) => "psych_profile",
            Self::Archive(_) => "archive",
        }
    }

    /// Every row the item names.
    pub(super) fn refs(&self) -> Vec<&ItemRef> {
        match self {
            Self::Claim(claim) => std::iter::once(&claim.subject)
                .chain(claim.evidence.iter())
                .collect(),
            Self::Evidence(evidence) => std::iter::once(&evidence.head)
                .chain(evidence.sources.iter())
                .collect(),
            Self::Supersede(supersede) => vec![&supersede.new, &supersede.old],
            Self::Settle(settle) => match &settle.settlement {
                DerivedSettlement::Keep(kept) => vec![&settle.marker, kept],
                DerivedSettlement::HoldBoth | DerivedSettlement::Dismiss => vec![&settle.marker],
            },
            Self::SameAs(same_as) => vec![&same_as.source, &same_as.target],
            Self::Topology(_) => Vec::new(),
            Self::PersonAbout(about) => vec![&about.person],
            Self::PsychProfile(_) => Vec::new(),
            Self::Archive(archive) => vec![&archive.claim],
        }
    }
}

/// The items one commit lands, in order: an item names only rows stored
/// before the batch or landed by an item before it.
#[derive(Debug, Clone)]
pub struct DerivationBatch {
    /// The items, in the order they stage.
    pub items: Vec<DerivationItem>,
}

/// The most items one batch holds.
pub const MAX_BATCH_ITEMS: usize = 256;

impl DerivationBatch {
    /// Checks the batch's shape: at least one item and no more than
    /// [`MAX_BATCH_ITEMS`], every local name non-empty and unique, and every
    /// local reference naming an earlier item.
    ///
    /// # Errors
    ///
    /// A malformed batch, which aborts the whole commit.
    pub(super) fn validate(&self) -> Result<()> {
        if self.items.is_empty() {
            return Err(malformed("a derivation batch holds at least one item"));
        }
        if self.items.len() > MAX_BATCH_ITEMS {
            return Err(malformed("a derivation batch holds at most 256 items"));
        }
        let mut earlier: BTreeSet<&str> = BTreeSet::new();
        for item in &self.items {
            let local = item.local();
            if local.trim().is_empty() {
                return Err(malformed("every derivation item has a local name"));
            }
            for named in item.refs() {
                if let ItemRef::Local(name) = named
                    && !earlier.contains(name.as_str())
                {
                    return Err(malformed(
                        "a derivation item names only rows of items before it",
                    ));
                }
            }
            if !earlier.insert(local) {
                return Err(malformed(
                    "each derivation item's local name is unique in its batch",
                ));
            }
        }
        Ok(())
    }
}

fn malformed(why: &'static str) -> Error {
    Error::InvalidClaimBody(why)
}
