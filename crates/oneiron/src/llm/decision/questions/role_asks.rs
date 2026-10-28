//! A question unit's person ask (OF-506; ARCH-0076 role ladder): a graph or
//! artifact answer whose dial reaches the person asks the next authorised
//! role, under the caller's ceiling, ending at the vault's owners. The model
//! only requests the escalation; the caller binds the route, and the work the
//! ask decides is the unit's, so each unit keeps its own ask.

use crate::llm::decision::DecisionQuestion;
use crate::{EntityId, Result};

const QUESTION_UNIT_ASK_DOMAIN: &[u8] = b"oneiron:question-unit-ask:v1";

/// The work one unit's ask decides: `question`'s version, asked for
/// `principal`, over `unit` at its `source` version. Two units, or one unit
/// at two versions, keep apart asks; the same unit at the same version asked
/// again on a refresh is the same open ask, so its recorded route and the
/// role it reached carry over.
pub fn question_unit_correlation(
    question: &DecisionQuestion,
    principal: EntityId,
    unit: &[u8],
    source: &[u8; 32],
) -> Result<EntityId> {
    EntityId::derive(
        QUESTION_UNIT_ASK_DOMAIN,
        &[
            question.id.as_bytes(),
            &question.version.to_le_bytes(),
            principal.as_bytes(),
            unit,
            source,
        ],
    )
}
