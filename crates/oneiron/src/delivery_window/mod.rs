//! Delivery-window policy claims and evaluator for OF-327 O3.
//!
//! The `delivery_window.*` family is deliberately interrupt-only: async writes
//! stay deliverable, while interrupt-class verbs are held or reshaped.

mod claims;
mod context;
mod evaluate;
mod types;
mod validate;
mod window;

pub use self::claims::DeliveryWindowPolicyClaim;
pub use self::context::DeliveryWindowEvaluationContext;
pub use self::evaluate::DeliveryWindowEvaluator;
pub use self::types::{
    DELIVERY_WINDOW_CLAIM_PREDICATES, DELIVERY_WINDOW_SCHEMA_VERSION,
    DeliveryWindowApnsInterruptionLevel, DeliveryWindowAppliesTo, DeliveryWindowContextCondition,
    DeliveryWindowDecision, DeliveryWindowLadderRung, DeliveryWindowMatch,
    DeliveryWindowResolution, DeliveryWindowResolvedLevel, DeliveryWindowVerbClass,
    MISSING_LOCAL_MINUTE_REASON, PREDICATE_DELIVERY_WINDOW_CHANNEL,
    PREDICATE_DELIVERY_WINDOW_CONTEXT, PREDICATE_DELIVERY_WINDOW_QUIET,
};
pub use self::validate::is_delivery_window_claim_predicate;
pub(crate) use self::validate::validate_delivery_window_claim_structure;
pub use self::window::DeliveryWindowTimeWindow;

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::types::*;
#[cfg(test)]
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use rmpv::Value;
