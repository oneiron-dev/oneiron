//! Recorded principal standing and refusal vocabulary.

use oneiron_base::edge::EdgeActorClass;
use oneiron_contracts::entity_id::EntityId;

/// A recorded principal that stood in one snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrincipalStanding {
    pub principal: EntityId,
    pub class: EdgeActorClass,
    /// The one live Grant that lists the work's verb, for an agent; `None`
    /// for a person.
    pub grant: Option<EntityId>,
}

/// Why a recorded principal does not stand, for a caller that refuses and
/// names the reason (FIX 7511).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoStanding {
    /// Every case [`principal_standing_in_txn`] answers `None` for but the
    /// one below.
    NotStanding,
    /// On a shared vault, a Grant stood for the agent's verb by the Grant
    /// rule ([`AgentGrantStanding::stands_for`]) but its authenticated pact
    /// membership is gone, and no other Grant stands.
    PactStandingLapsed,
}

/// The typed reason a refusing caller names for [`NoStanding::PactStandingLapsed`]
/// (CALLS `FIX 7511 lapse refusal`, accepted by the Engine 10-21 21:2x); its
/// code leads the text.
pub const PACT_STANDING_LAPSED: &str = "pact_standing_lapsed: on this shared vault the \
     agent's Grant for the verb stands only while its pact membership does, and that membership \
     has lapsed";
