//! The refusal dial (OF-533) an agent definition stores: one position from
//! none to full, and the agent's explicit setting per domain.

use serde::{Deserialize, Serialize};

#[cfg(doc)]
use crate::agent_def::VaultKind;

#[doc(hidden)]
pub use oneiron_verb_wire::store::agent_refusal::{
    REFUSAL_DIAL_KEYS, RefusalDial, RefusalDomain, RefusalLevel,
};
