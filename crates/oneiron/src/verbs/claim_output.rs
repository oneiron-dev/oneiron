//! Move native claim-review payloads through the core SDK result boundary.

use serde_json::Value;

use crate::memory::{ClaimProposalReview, MemoryResult};

use super::encode;

pub(super) fn review(mut output: ClaimProposalReview) -> MemoryResult<Value> {
    let value = output.claim.value.take();
    let scope = output.claim.scope.take();
    let mut encoded = encode(output)?;
    encoded["claim"]["value"] = value;
    if let Some(scope) = scope {
        encoded["claim"]["scope"] = scope;
    }
    Ok(encoded)
}
