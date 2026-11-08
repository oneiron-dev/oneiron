//! How a calibration pair's answer was returned: its route and the routing policy revision
//! its receipt pins, both read from the receipt alone (route-conditioned calibration).

use crate::model_decision::{DecisionRung, HostRuleRef};
use serde::{Deserialize, Serialize};

/// How the answer a calibration pair carries was returned, read from its receipt's clock and
/// ask alone, never guessed. No route selects one answer among several candidates: no caller
/// does (a choice wider than a provider's option bound is read again among its chunk winners,
/// one read, not a pick by score).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DecisionRoute {
    /// The rule rung answered.
    Rule,
    /// A model rung answered and needed no more thinking: the first measurement that answered
    /// stood. A rung that abstained before it measured nothing.
    Direct { rung: DecisionRung },
    /// More thinking ran (a stronger rung, or a required second measurement), and `rung`
    /// answered.
    SteppedUp { rung: DecisionRung },
    /// More thinking was wanted and gave no answer: it did not start, or the deadline cut it.
    /// The answer `rung` read before it stood.
    StepUnfinished { rung: DecisionRung },
    /// The decision went up to the person rung and the role it went to answered, a person or
    /// the agent bound to that role. A person's changed answer pairs the prior it changed on
    /// this route.
    Person,
    /// The receipt names no route: it carries no decision clock (an answer made off it), or its
    /// clock names no rung whose answer stands and no ask answered it.
    Unrouted,
}

/// The routing policy revision a receipt pins: the band row the ladder weighed the first
/// answer against, the think-more and ask-a-person rows in force, and the rule row whose
/// answer stood.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoutingPolicy {
    /// Zero denotes the seed band in shadow; learned bands pin their version.
    pub band_version: u32,
    /// The think-more row's version, when the call asked the paired question under one.
    pub think_row: Option<u32>,
    /// The ask-a-person row's version, when the dial reached the person under one.
    pub person_row: Option<u32>,
    /// The rule row whose answer stands, as id@revision, when one does.
    pub rule: Option<HostRuleRef>,
}
