//! Move native pending-proposal summaries through the core SDK result boundary.

use serde_json::Value;

use super::encode;
use crate::edit_settle::PendingProposalView;
use crate::memory::MemoryResult;

pub(super) fn view(mut output: PendingProposalView) -> MemoryResult<Value> {
    let summary = output.summary.take();
    let mut encoded = encode(output)?;
    encoded["summary"] = summary;
    Ok(encoded)
}

pub(super) fn list(mut output: Vec<PendingProposalView>) -> MemoryResult<Value> {
    let summaries: Vec<_> = output.iter_mut().map(|view| view.summary.take()).collect();
    let mut encoded = encode(output)?;
    for (index, summary) in summaries.into_iter().enumerate() {
        encoded[index]["summary"] = summary;
    }
    Ok(encoded)
}
