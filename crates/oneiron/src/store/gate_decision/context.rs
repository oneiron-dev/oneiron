//! What a Gate decision was made about, the loop it came from and the ruled
//! analysis of the input it judged (FIX 7499, 7500, 7801). The decision's
//! original writer captures it before its one append; nothing writes it
//! later, and no door reads it to decide a write. An empty part means the
//! writer had nothing proven to put there.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::federation::Scope;

use super::types::{GateDecisionId, GateDecisionRecord};

/// The context one decision's writer captured with it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateDecisionContext {
    /// The read context of each record the decision is about. A bundle has
    /// one per member, and a reader sees the decision only when it is
    /// admitted to every one.
    pub read: Vec<GateDecisionReadContext>,
    /// The loop decisions this one comes from, each proven by its writer.
    pub links: Vec<GateLoopLink>,
    /// The ruled risk analysis of the input the decision judged, when its
    /// writer judged one.
    pub analysis: Option<GateDecisionAnalysis>,
}

/// The read context of one record a decision is about: never a captured
/// Grant or a list of readers. A reader is judged against it under its own
/// live authority each time it reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateDecisionReadContext {
    /// The record itself: a claim candidate's id, landed or not, or a loop
    /// decision's target.
    pub record: Option<EntityId>,
    /// The live rows the record is about: a claim's subject or both ends of
    /// its edge, a loop's target. A reader reads each of them now.
    pub about: Vec<EntityId>,
    /// The record's own read position, kept for a record that may never
    /// have landed. `None` when the record's position is its `about` rows'.
    pub position: Option<GateReadPosition>,
}

/// A record's own read position, as its write stamped it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReadPosition {
    /// The record's entity type.
    pub entity_type: u8,
    /// Its six-axis record Scope for the read verb.
    pub scope: Scope,
    /// A claim's own read selectors beside its Scope.
    pub claim: Option<GateClaimReadSelectors>,
}

/// What a claim's read selectors judge beside its Scope, kept bit for bit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateClaimReadSelectors {
    /// The relationship the claim is scoped to.
    pub relationship: Option<EntityId>,
    /// Whether its scope marks it private.
    pub private: bool,
    /// Its opaque scope selector, as MessagePack.
    pub scope: Option<Vec<u8>>,
    /// Its confidence, as the bits of the finite `f32` it was written with.
    pub confidence_bits: u32,
    /// Its salience, the same way.
    pub salience_bits: Option<u32>,
    /// Its staleness marker.
    pub stale: bool,
}

/// One proven link from a decision to the loop it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateLoopLink {
    /// Which part of the loop the decision is.
    pub family: GateLoopFamily,
    /// The loop that produced it.
    pub source: GateLoopSource,
    /// The loop's run, when its writer knew it.
    pub run: Option<String>,
    /// The loop's attempt, when its writer knew it.
    pub attempt: Option<[u8; 16]>,
    /// The decision that admitted the loop.
    pub origin: GateLoopOrigin,
}

/// Which part of a loop a decision is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateLoopFamily {
    /// The loop's run admitted or refused.
    Admission,
    /// The loop's action, or the answer to it.
    Action,
}

/// The loop a decision came from: the producer, never the person who
/// answers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateLoopSource {
    /// The vault's Dreamer.
    Dreamer,
    /// The Coach.
    Coach,
    /// A resident's own dreaming or free time.
    Resident,
    /// A turn-woken program.
    TurnProgram,
}

/// The decision that admitted a loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateLoopOrigin {
    /// This decision is the admission itself.
    SelfDecision,
    /// An earlier decision in the ledger.
    Decision(GateDecisionId),
    /// The loop is proven by its run or attempt; the decision that admitted
    /// it was not resolved where this one was written.
    Unresolved,
}

/// The ruled risk vector (ARCH-0040 `dr:SK07`): each axis's result and what
/// its rules covered. Closed tokens only, never the bytes matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateDecisionAnalysis {
    /// The rule set that computed it.
    pub rules: String,
    /// A path to a credential or secret store.
    pub sensitive_path: GateRiskAxis,
    /// A secret-shaped argument or value.
    pub secret_argument: GateRiskAxis,
    /// A command of a destructive class.
    pub dangerous_command: GateRiskAxis,
}

/// One risk axis's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRiskAxis {
    /// What the rules found.
    pub state: GateRiskState,
    /// How much of the axis's surface they read.
    pub coverage: GateAnalysisCoverage,
    /// The rules that matched, each once.
    pub matched: Vec<String>,
}

/// What an axis's rules found. `NoHit` says the whole surface was read by
/// the stated rules, not that the input is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateRiskState {
    /// A rule matched.
    Hit,
    /// No rule matched over what was read.
    NoHit,
    /// The input has no surface this axis reads.
    NotApplicable,
    /// The surface could not be read.
    NotAnalysed,
}

/// How much of an axis's surface its rules read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateAnalysisCoverage {
    /// All of it.
    Complete,
    /// Some of it: part of the surface was not in a form the rules read.
    Partial,
    /// None of it.
    None,
}

impl GateDecisionContext {
    /// Whether the writer captured nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.read.is_empty() && self.links.is_empty() && self.analysis.is_none()
    }

    /// The read context and links `original` carries, for a decision that
    /// answers it: each link now names `original` as its origin where it was
    /// the admission itself. No analysis is carried, since this decision
    /// judged no fresh input.
    #[must_use]
    pub fn answering(original: &GateDecisionRecord) -> Self {
        Self {
            read: original.context.read.clone(),
            links: original
                .context
                .links
                .iter()
                .map(|link| link.answered_by(original.decision_id))
                .collect(),
            analysis: None,
        }
    }

    /// [`Self::answering`] over every decision in `originals`, each read
    /// context and link once, in order.
    #[must_use]
    pub fn answering_all(originals: &[GateDecisionRecord]) -> Self {
        let mut context = Self::default();
        for original in originals {
            let answered = Self::answering(original);
            for read in answered.read {
                if !context.read.contains(&read) {
                    context.read.push(read);
                }
            }
            for link in answered.links {
                if !context.links.contains(&link) {
                    context.links.push(link);
                }
            }
        }
        context
    }

    /// Whether any part names `id`: a read context's record, an `about` row,
    /// its relationship, or its scope selector's bytes.
    pub(super) fn names(&self, id: &EntityId) -> bool {
        self.read.iter().any(|read| read.names(id))
    }

    /// Takes every read context that names `id` out, whole: no scope is made
    /// up in its place. Links and analysis name no entity and stay.
    pub(super) fn scrub(&mut self, id: &EntityId) -> bool {
        let before = self.read.len();
        self.read.retain(|read| !read.names(id));
        self.read.len() != before
    }
}

impl GateDecisionReadContext {
    /// The read context of a record whose position is its `about` rows'.
    /// `None` when it names no row, so nothing would prove its scope.
    #[must_use]
    pub fn about(record: Option<EntityId>, about: Vec<EntityId>) -> Option<Self> {
        (!about.is_empty()).then_some(Self {
            record,
            about,
            position: None,
        })
    }

    fn names(&self, id: &EntityId) -> bool {
        self.record == Some(*id)
            || self.about.contains(id)
            || self.position.as_ref().is_some_and(|position| {
                position.claim.as_ref().is_some_and(|claim| {
                    claim.relationship == Some(*id)
                        || claim.scope.as_deref().is_some_and(|bytes| {
                            contains(bytes, id.as_bytes())
                                || contains(bytes, id.to_hex().as_bytes())
                        })
                })
            })
    }
}

impl GateLoopLink {
    /// This link as a decision answering `original` carries it.
    fn answered_by(&self, original: GateDecisionId) -> Self {
        Self {
            origin: match self.origin {
                GateLoopOrigin::SelfDecision => GateLoopOrigin::Decision(original),
                origin => origin,
            },
            ..self.clone()
        }
    }
}

impl GateDecisionRecord {
    /// Whether this decision names `actor`: as the actor it judged, or in
    /// the context its writer copied.
    pub(super) fn names_actor(&self, actor: &EntityId) -> bool {
        self.actor_ref.as_deref() == Some(actor.to_hex().as_str()) || self.context.names(actor)
    }

    /// Takes `actor` out of this decision: its actor ref and each read
    /// context that names it. Whether anything changed.
    pub(super) fn scrub_actor(&mut self, actor: &EntityId) -> bool {
        let mut changed = false;
        if self.actor_ref.as_deref() == Some(actor.to_hex().as_str()) {
            self.actor_ref = None;
            changed = true;
        }
        self.context.scrub(actor) || changed
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
