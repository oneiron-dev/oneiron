//! The caller origin a dispatch keeps (FIX 4973). This records how the root
//! reached admission; it never changes authority or where execution reads.

use crate::attempt_queue::AttemptId;
use crate::error::Result;

use super::AgentDispatcher;

/// Root-admission provenance, inherited unchanged by children. The host
/// supplies connection locality from the actual transport, not guest input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CallerOrigin {
    Connection {
        locality: CallerLocality,
    },
    NativeHost,
    /// A new root for which no producer supplied an origin fact.
    Unknown,
}

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
