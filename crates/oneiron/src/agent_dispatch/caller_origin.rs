//! The caller origin a dispatch keeps (FIX 4973). This records how the root
//! reached admission; it never changes authority or where execution reads.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::error::Result;
use crate::settings::CallerLocality;

use super::AgentDispatcher;

#[doc(hidden)]
pub use oneiron_verb_wire::agent_dispatch::caller_origin::CallerOrigin;

impl AgentDispatcher<'_> {
    /// A real parent wins even when its frozen value is Unknown. A missing
    /// or non-dispatch parent supplies no provenance, never the child's
    /// host stamp. Existing admission checks remain responsible for parents.
    pub(super) fn inherited_caller_origin_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        parent: Option<AttemptId>,
        stamped: Option<CallerOrigin>,
    ) -> Result<CallerOrigin> {
        match parent {
            None => Ok(stamped.unwrap_or(CallerOrigin::Unknown)),
            Some(parent) => Ok(self
                .parent_dispatch_input_in_txn(txn, parent)?
                .map_or(CallerOrigin::Unknown, |input| input.caller_origin)),
        }
    }
}
