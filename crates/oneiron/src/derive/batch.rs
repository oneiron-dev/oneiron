//! What a derivation batch holds, and who commits it.

use std::collections::BTreeSet;

use crate::EntityId;
use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::selection::StrengthSignals;
use crate::error::{Error, Result};
use crate::model_decision::MAX_DECISION_STATE_BYTES;
use crate::snapshot_read::{EVIDENCE_SPANS_MAX_RANGES, EvidenceRange};
use crate::verbs::{CandidateOperand, PinnedClaim};
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
/// of the same batch creates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemRef {
    /// A stored row, by id.
    Stored(EntityId),
    /// The row an earlier item of the batch creates, by that item's local
    /// name.
    Local(String),
}

/// One cited TURN's byte ranges over its text as the committing actor reads it.
#[derive(Debug, Clone)]
pub struct DerivedEvidenceSpans {
    /// The cited TURN, as stored.
    pub source: EntityId,
    /// Byte ranges over the TURN's text as the committing actor reads it
    /// through `vault.evidence.spans`.
    pub ranges: Vec<EvidenceRange>,
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
    /// Byte ranges over a cited TURN's text as the committing actor reads it
    /// through `vault.evidence.spans`, at the version the batch's `sources`
    /// pins; a TURN with no entry is cited whole.
    pub spans: Vec<DerivedEvidenceSpans>,
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
    /// Byte ranges over a cited TURN's text as the committing actor reads it
    /// through `vault.evidence.spans`, at the version the batch's `sources`
    /// pins; a TURN with no entry is cited whole.
    pub spans: Vec<DerivedEvidenceSpans>,
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

/// One member of a conflict an extraction job opens: the candidate exactly
/// as a bound Resolution read of `ai.verdict` takes it, with the confidence
/// and the prospective query hints a kept alternative lands with. Neither
/// enters the candidate's id.
#[derive(Debug, Clone)]
pub struct DerivedConflictMember {
    /// The candidate, exactly the operand the Resolution read takes.
    pub operand: CandidateOperand,
    /// Its confidence, in `[0, 1]`.
    pub confidence: f32,
    /// The prospective query hints a kept alternative lands with.
    pub prospective_queries: Vec<String>,
}

/// A conflict an extraction job opens: the set a bound Resolution read of
/// `ai.verdict` names, opened instead of asked. A later Settle item of the
/// batch names the marker by this item's local name.
#[derive(Debug, Clone)]
pub struct DerivedConflict {
    /// The item's name inside its batch.
    pub local: String,
    /// The conflict's candidates, 1..n.
    pub members: Vec<DerivedConflictMember>,
    /// The stored heads the set stands against, each with the version the
    /// job read: what the Resolution read names as `priors`.
    pub heads: Vec<PinnedClaim>,
    /// As the pack's `set_members`: the candidate indexes of the one set to
    /// open, when the members form more than one.
    pub set_members: Option<Vec<usize>>,
}

/// A candidate an extraction job lands: one extraction candidate that
/// replaces nothing.
#[derive(Debug, Clone)]
pub struct DerivedCandidate {
    /// The item's name inside its batch.
    pub local: String,
    /// The candidate, exactly the operand the verdict takes, with the
    /// confidence and hints it lands with.
    pub member: DerivedConflictMember,
}

/// The job's decision for a conflict set: `skip` replaces the set's prior
/// head with the set's one member and no verdict, `merge` lands one merged
/// claim from the whole set, `accumulate` lands every member beside the
/// heads.
#[derive(Debug, Clone)]
pub enum DerivedResolutionOutcome {
    /// The set's one member replaces the set's prior head with no verdict.
    Skip,
    /// One merged claim from the whole set, with the kept member's index
    /// into the members and the merged value's bytes.
    Merge {
        /// The kept member's index into the members, when the job names one.
        kept: Option<usize>,
        /// The merged value's bytes, never null.
        value: serde_json::Value,
    },
    /// Every member lands as a plain write beside the heads.
    Accumulate,
}

/// A conflict resolution an extraction job stages: the Conflict item's set
/// shape with the job's decision for that set.
#[derive(Debug, Clone)]
pub struct DerivedConflictResolution {
    /// The item's name inside its batch.
    pub local: String,
    /// The conflict's candidates, 1..n.
    pub members: Vec<DerivedConflictMember>,
    /// The stored heads the set stands against, each with the version the
    /// job read: what the Resolution read names as `priors`.
    pub heads: Vec<PinnedClaim>,
    /// As the pack's `set_members`: the candidate indexes of the one set to
    /// resolve, when the members form more than one.
    pub set_members: Option<Vec<usize>>,
    /// The job's decision for the set.
    pub outcome: DerivedResolutionOutcome,
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
    /// The stored observation row's pin, as the reader
    /// `vault.consolidation.strength.observations.page` served it.
    pub observation_pin: String,
    /// The effective strength policy's pin, as the same reader served it.
    pub policy_pin: String,
    /// The effective scoring config's pin, as the same reader served it.
    pub config_pin: String,
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
    /// A conflict an extraction job opens: the set a bound Resolution read
    /// of `ai.verdict` names, opened instead of asked.
    Conflict(DerivedConflict),
    /// A candidate an extraction job lands: one extraction candidate that
    /// replaces nothing.
    Candidate(DerivedCandidate),
    /// A conflict resolution an extraction job stages: the Conflict item's
    /// set shape with the job's decision for that set.
    ConflictResolution(DerivedConflictResolution),
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
            Self::Conflict(conflict) => &conflict.local,
            Self::Candidate(candidate) => &candidate.local,
            Self::ConflictResolution(resolution) => &resolution.local,
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
            Self::Conflict(_) => "conflict",
            Self::Candidate(_) => "candidate",
            Self::ConflictResolution(_) => "conflict_resolution",
        }
    }

    /// Whether the item's first landed row is one the item itself creates:
    /// a claim, a settlement's answer, a link's status claim, a topology
    /// event, a conflict's marker, a candidate's claim. Only such an item
    /// can be named by a later item: a later Settle item names a conflict's
    /// marker by the Conflict
    /// item's local name. Every other kind lands on a row that stood before
    /// it (a supersession's replacement, an archived claim, a PERSON) or may
    /// replay one (an evidence record, a profile at its address), and a name
    /// for such a row would cite it with no version and no read of its own.
    pub(super) const fn creates_row(&self) -> bool {
        matches!(
            self,
            Self::Claim(_)
                | Self::Settle(_)
                | Self::SameAs(_)
                | Self::Topology(_)
                | Self::Conflict(_)
                | Self::Candidate(_)
                | Self::ConflictResolution(_)
        )
    }

    /// The rows the item cites as its sources: a claim's evidence and an
    /// evidence item's sources. A stored one needs its version in the batch.
    fn cited(&self) -> &[ItemRef] {
        match self {
            Self::Claim(claim) => &claim.evidence,
            Self::Evidence(evidence) => &evidence.sources,
            // A conflict item holds no `ItemRef`: its pins are checked by
            // its stager through the extraction read, never by
            // `derive/sources.rs`.
            Self::Conflict(_) | Self::Candidate(_) | Self::ConflictResolution(_) => &[],
            _ => &[],
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
            // A conflict item holds no `ItemRef`: its pins are checked by
            // its stager through the extraction read, never by
            // `derive/sources.rs`. A candidate item's versions are inside
            // its operand, likewise, as are a resolution item's.
            Self::Conflict(_) | Self::Candidate(_) | Self::ConflictResolution(_) => Vec::new(),
        }
    }
}

/// The items one commit lands, in order: an item names only rows stored
/// before the batch or landed by an item before it.
#[derive(Debug, Clone)]
pub struct DerivationBatch {
    /// The items, in the order they stage.
    pub items: Vec<DerivationItem>,
    /// The version of every stored source the items cite (a claim's evidence,
    /// an evidence item's sources), as the caller's read served it
    /// ([`crate::snapshot_read`]). The commit rechecks each in its write: a
    /// source that moved or is withheld since aborts the whole batch.
    pub sources: Vec<crate::snapshot_read::SourceVersion>,
}

/// The most items one batch holds.
pub const MAX_BATCH_ITEMS: usize = 256;

impl DerivationBatch {
    /// Checks the batch's shape: at least one item and no more than
    /// [`MAX_BATCH_ITEMS`], every local name non-empty and unique, every
    /// local reference naming an earlier item that creates a row
    /// ([`DerivationItem::creates_row`]), at most one `about` item for a
    /// person, a version for every stored source cited, well-formed span
    /// locators on claim and evidence items, well-formed conflict items:
    /// at least one member, bounded collections, every member confidence
    /// finite and in `[0, 1]`, and prospective query hints the lexical
    /// normaliser admits, well-formed candidate items: the member
    /// checks with the evidence bound, and well-formed resolution items:
    /// the conflict checks with a merge's kept member and value.
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
        let mut nameable: BTreeSet<&str> = BTreeSet::new();
        let mut about_persons: Vec<&ItemRef> = Vec::new();
        for item in &self.items {
            let local = item.local();
            if local.trim().is_empty() {
                return Err(malformed("every derivation item has a local name"));
            }
            for named in item.refs() {
                if let ItemRef::Local(name) = named
                    && !nameable.contains(name.as_str())
                {
                    return Err(malformed(
                        "a derivation item names only rows that items before it create",
                    ));
                }
            }
            if !earlier.insert(local) {
                return Err(malformed(
                    "each derivation item's local name is unique in its batch",
                ));
            }
            if item.creates_row() {
                nameable.insert(local);
            }
            // A person's `about` row keeps one before-image, so a second
            // `about` item for the same person would leave a revert of the
            // batch at the first item's lines, not at the lines before it.
            if let DerivationItem::PersonAbout(about) = item {
                if about_persons.contains(&&about.person) {
                    return Err(malformed(
                        "a derivation batch holds one about item for a person",
                    ));
                }
                about_persons.push(&about.person);
            }
            for cited in item.cited() {
                if let ItemRef::Stored(id) = cited
                    && !self.sources.iter().any(|version| version.entity == *id)
                {
                    return Err(malformed(
                        "every stored source a derivation item cites names its version",
                    ));
                }
            }
            match item {
                DerivationItem::Claim(claim) => validate_spans(&claim.evidence, &claim.spans)?,
                DerivationItem::Evidence(evidence) => {
                    validate_spans(&evidence.sources, &evidence.spans)?;
                }
                DerivationItem::Conflict(conflict) => validate_conflict(conflict)?,
                DerivationItem::Candidate(candidate) => validate_candidate(candidate)?,
                DerivationItem::ConflictResolution(resolution) => {
                    validate_conflict_resolution(resolution)?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn malformed(why: &'static str) -> Error {
    Error::InvalidClaimBody(why)
}

/// Checks one conflict item's shape: at least one member, at most
/// [`MAX_DECISION_STATE_BYTES`] members, heads, `set_members` entries and
/// TURN evidence entries of one member, every member confidence finite and
/// in `[0, 1]`, and prospective query hints the lexical normaliser admits.
/// Every other fault of an operand (ids, grammar, pins, the set, the
/// selector) is judged by the extraction read when the item stages, and
/// refuses the item, not the batch.
fn validate_conflict(item: &DerivedConflict) -> Result<()> {
    validate_conflict_shape(
        &item.members,
        item.heads.len(),
        item.set_members.as_ref().map_or(0, Vec::len),
        "a conflict item holds at least one member",
        "a conflict collection exceeds the native decision state bound",
        "a conflict member's confidence is a number from 0 to 1",
    )
}

/// Checks one resolution item's shape: the Conflict item's checks with a
/// merge's kept member and value. A merge needs a value that is not null;
/// a kept member indexes the members. Every other fault is judged when the
/// item stages, and refuses the item, not the batch.
fn validate_conflict_resolution(item: &DerivedConflictResolution) -> Result<()> {
    validate_conflict_shape(
        &item.members,
        item.heads.len(),
        item.set_members.as_ref().map_or(0, Vec::len),
        "a conflict resolution item holds at least one member",
        "a conflict resolution collection exceeds the native decision state bound",
        "a conflict resolution member's confidence is a number from 0 to 1",
    )?;
    if let DerivedResolutionOutcome::Merge { kept, value } = &item.outcome {
        if value.is_null() {
            return Err(malformed("a merge needs a value that is not null"));
        }
        if kept.is_some_and(|kept| kept >= item.members.len()) {
            return Err(malformed("a kept member indexes the members"));
        }
    }
    Ok(())
}

/// Checks the Conflict item's shape shared with resolutions: at least one
/// member, bounded collections and evidence, and each member's confidence
/// and hints.
fn validate_conflict_shape(
    members: &[DerivedConflictMember],
    heads_len: usize,
    set_members_len: usize,
    empty: &'static str,
    bound: &'static str,
    confidence: &'static str,
) -> Result<()> {
    if members.is_empty() {
        return Err(malformed(empty));
    }
    let bounded = [members.len(), heads_len, set_members_len];
    if bounded
        .iter()
        .any(|length| *length > MAX_DECISION_STATE_BYTES)
        || members
            .iter()
            .any(|member| member.operand.evidence.len() > MAX_DECISION_STATE_BYTES)
    {
        return Err(malformed(bound));
    }
    for member in members {
        validate_conflict_member(member, confidence)?;
    }
    Ok(())
}

/// Checks one candidate item's shape: its member's confidence and hints,
/// as a conflict member's, with at most [`MAX_DECISION_STATE_BYTES`] TURN
/// evidence entries. Every other fault of the operand is judged by the
/// extraction read when the item stages, and refuses the item, not the
/// batch.
fn validate_candidate(item: &DerivedCandidate) -> Result<()> {
    if item.member.operand.evidence.len() > MAX_DECISION_STATE_BYTES {
        return Err(malformed(
            "a candidate collection exceeds the native decision state bound",
        ));
    }
    validate_conflict_member(
        &item.member,
        "a candidate member's confidence is a number from 0 to 1",
    )
}

/// Checks one conflict-shaped member: its confidence finite and in
/// `[0, 1]` (else `confidence_message`), and prospective query hints the
/// lexical normaliser admits. The conflict and candidate shape checks
/// share this one rule.
fn validate_conflict_member(
    member: &DerivedConflictMember,
    confidence_message: &'static str,
) -> Result<()> {
    if !member.confidence.is_finite() || !(0.0..=1.0).contains(&member.confidence) {
        return Err(malformed(confidence_message));
    }
    let hints: Vec<&str> = member
        .prospective_queries
        .iter()
        .map(String::as_str)
        .collect();
    crate::claim::normalize_lexical_query_hints(&hints)?;
    Ok(())
}

/// Checks one claim or evidence item's span locators against the stored rows
/// it cites: each entry names a cited stored row once, with one to
/// [`EVIDENCE_SPANS_MAX_RANGES`] ranges, each with `start < end`.
fn validate_spans(cited: &[ItemRef], spans: &[DerivedEvidenceSpans]) -> Result<()> {
    let mut seen: BTreeSet<EntityId> = BTreeSet::new();
    for entry in spans {
        if !seen.insert(entry.source) {
            return Err(malformed("each spans entry names its source once"));
        }
        if entry.ranges.is_empty() || entry.ranges.len() > EVIDENCE_SPANS_MAX_RANGES {
            return Err(malformed("each spans entry names one to sixty-four ranges"));
        }
        if entry.ranges.iter().any(|range| range.start >= range.end) {
            return Err(malformed("a spans range needs start < end"));
        }
        let cites = cited
            .iter()
            .any(|named| matches!(named, ItemRef::Stored(id) if *id == entry.source));
        if !cites {
            return Err(malformed(
                "each spans entry names a stored source the item cites",
            ));
        }
    }
    Ok(())
}
