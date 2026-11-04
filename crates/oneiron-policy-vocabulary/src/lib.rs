//! Policy-model vocabulary of the oneiron engine: the output contract a
//! policy document asks the model for, the substrate owner's pattern rules,
//! and the DEC-0005 goal limits. The `oneiron` crate keeps classification,
//! decisions and relays, and reaches these modules at their old
//! `policy_model::{contract, pattern, goal_limits}` paths.

pub mod policy_model;

// The paths the moved modules name: `crate::error::{Error, Result}` and
// `crate::EntityId`, the same items as `oneiron`'s root re-exports.
pub(crate) use oneiron_base::error;
pub(crate) use oneiron_contracts::entity_id::EntityId;
