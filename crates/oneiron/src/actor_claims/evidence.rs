//! Typed evidence inlets for the `actor.*` write door.

use rmpv::Value;

use crate::claim::ClaimSource;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::invalid;
use super::rows::ACTOR_CLAIM_MAX_CITED_EVIDENCE;

const KEY_LANE: &str = "lane";
pub(super) const KEY_RECEIPTS: &str = "receipts";
const KEY_SESSION: &str = "session";
const KEY_TURNS: &str = "turns";
pub(super) const KEY_AT: &str = "at";
const LANE_TASK: &str = "task";
const LANE_CHAT: &str = "chat";
const LANE_AMENDMENT: &str = "amendment";
// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------
/// Which inlet observed the fact, and what it observed.
///
/// This is not a label: the writer derives the claim's `src` lineage and its
/// evidence payload from this value, so an inlet cannot claim a trail it does
/// not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ActorClaimLane {
    /// RS1 pack-receipt ids the routed judgment rested on.
    Task { receipts: Vec<String> },
    /// The sitting and the turns it distilled from.
    Chat {
        session: EntityId,
        turns: Vec<EntityId>,
    },
    /// Receipt ids whose ARCH-0056 amendment Δ a judgment rested on (ED-03).
    ///
    /// A third lane rather than a reuse of [`Self::Task`] because the two cite
    /// different ledgers: a task row cites an attempt PACK receipt, an
    /// amendment row cites the receipt ED-01 measured a Δ against, and
    /// grounding one against the other's index would answer "no such receipt"
    /// for a citation that is plainly readable.
    Amendment { receipts: Vec<String> },
}
/// The trace a row rests on, plus when it was observed.
///
/// Constructed through the two lane constructors — there is no "no evidence"
/// shape, because a row with nothing to cite is the thing the doctrine header
/// exists to refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorClaimEvidence {
    pub(super) lane: ActorClaimLane,
    pub(super) at: u64,
}
impl ActorClaimEvidence {
    /// TASK-lane evidence: the pack receipts the judgment cited.
    pub fn task(receipts: Vec<String>, at: u64) -> Result<Self> {
        if receipts.is_empty() {
            return Err(invalid("a task-lane actor row must cite a receipt"));
        }
        if receipts.len() > ACTOR_CLAIM_MAX_CITED_EVIDENCE {
            return Err(invalid("actor row cites more evidence than the bound"));
        }
        Ok(Self {
            lane: ActorClaimLane::Task { receipts },
            at,
        })
    }

    /// AMENDMENT-lane evidence: the receipts whose Δs the judgment rested on
    /// (ED-03, ARCH-0056 §5).
    pub fn amendment(receipts: Vec<String>, at: u64) -> Result<Self> {
        if receipts.is_empty() {
            return Err(invalid("an amendment-lane actor row must cite a receipt"));
        }
        if receipts.len() > ACTOR_CLAIM_MAX_CITED_EVIDENCE {
            return Err(invalid("actor row cites more evidence than the bound"));
        }
        Ok(Self {
            lane: ActorClaimLane::Amendment { receipts },
            at,
        })
    }

    /// CHAT-lane evidence: the sitting and the turns distilled from it.
    pub fn chat(session: EntityId, turns: Vec<EntityId>, at: u64) -> Result<Self> {
        if turns.is_empty() {
            return Err(invalid("a chat-lane actor row must cite a turn"));
        }
        if turns.len() > ACTOR_CLAIM_MAX_CITED_EVIDENCE {
            return Err(invalid("actor row cites more evidence than the bound"));
        }
        Ok(Self {
            lane: ActorClaimLane::Chat { session, turns },
            at,
        })
    }

    /// The evidence meet this lane earns — see the module header's lineage
    /// note. Derived here and nowhere else, so it cannot be passed in.
    pub(super) const fn lineage(&self) -> ClaimSource {
        match self.lane {
            // Attempt receipts ARE tool output; a row resting on them says so.
            // An amendment Δ is the same class of fact: the engine MEASURED two
            // bodies it holds, so the row rests on machine output rather than on
            // anything a model wrote.
            ActorClaimLane::Task { .. } | ActorClaimLane::Amendment { .. } => {
                ClaimSource::ToolOutput
            }
            // A distilled note is model-written prose over turns.
            ActorClaimLane::Chat { .. } => ClaimSource::Generated,
        }
    }

    /// The evidence payload the writer stores on the row.
    ///
    /// Crate-visible so a projector can ask whether the head already standing
    /// IS the row it was about to write — the comparison that keeps a replay
    /// from minting a fresh claim entity per pass (ED-03).
    pub(crate) fn to_value(&self) -> Value {
        let mut entries = vec![(Value::from(KEY_AT), Value::from(self.at))];
        match &self.lane {
            ActorClaimLane::Task { receipts } => {
                entries.push((Value::from(KEY_LANE), Value::from(LANE_TASK)));
                entries.push((
                    Value::from(KEY_RECEIPTS),
                    Value::Array(receipts.iter().map(|r| Value::from(r.as_str())).collect()),
                ));
            }
            ActorClaimLane::Amendment { receipts } => {
                entries.push((Value::from(KEY_LANE), Value::from(LANE_AMENDMENT)));
                entries.push((
                    Value::from(KEY_RECEIPTS),
                    Value::Array(receipts.iter().map(|r| Value::from(r.as_str())).collect()),
                ));
            }
            ActorClaimLane::Chat { session, turns } => {
                entries.push((Value::from(KEY_LANE), Value::from(LANE_CHAT)));
                entries.push((
                    Value::from(KEY_SESSION),
                    Value::Binary(session.as_bytes().to_vec()),
                ));
                entries.push((
                    Value::from(KEY_TURNS),
                    Value::Array(
                        turns
                            .iter()
                            .map(|id| Value::Binary(id.as_bytes().to_vec()))
                            .collect(),
                    ),
                ));
            }
        }
        Value::Map(entries)
    }
}
