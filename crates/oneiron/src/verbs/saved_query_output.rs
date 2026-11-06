//! Preserve saved-query operands and judge rubrics through core SDK encoding.

use serde_json::Value;

use crate::campaign::surface::{
    SavedQueryFilterSpec, SavedQueryMatcherSpec, SavedQueryReadResult, SavedQueryRecordView,
};
use crate::memory::MemoryResult;

use super::encode;

pub(super) fn record(mut output: SavedQueryRecordView) -> MemoryResult<Value> {
    let mut payloads = Vec::new();
    drain_record(&mut output, "", &mut payloads);
    Ok(restore(encode(output)?, payloads))
}

pub(super) fn read(mut output: SavedQueryReadResult) -> MemoryResult<Value> {
    let mut payloads = Vec::new();
    if let Some(record) = output.record.as_mut() {
        drain_record(record, "/record", &mut payloads);
    }
    Ok(restore(encode(output)?, payloads))
}

fn drain_record(
    record: &mut SavedQueryRecordView,
    base: &str,
    payloads: &mut Vec<(String, Value)>,
) {
    drain_filter(
        &mut record.definition.filter,
        format!("{base}/definition/filter"),
        payloads,
    );
    match &mut record.definition.matcher {
        SavedQueryMatcherSpec::Hard { expression } => drain_filter(
            expression,
            format!("{base}/definition/matcher/expression"),
            payloads,
        ),
        SavedQueryMatcherSpec::LlmJudge { rubric, .. } => {
            payloads.push((format!("{base}/definition/matcher/rubric"), rubric.take()))
        }
        SavedQueryMatcherSpec::SemanticThreshold { .. } => {}
    }
}

fn drain_filter(
    filter: &mut SavedQueryFilterSpec,
    path: String,
    payloads: &mut Vec<(String, Value)>,
) {
    let mut pending = vec![(filter, path)];
    while let Some((filter, path)) = pending.pop() {
        match filter {
            SavedQueryFilterSpec::All { terms } | SavedQueryFilterSpec::Any { terms } => {
                for (index, term) in terms.iter_mut().enumerate().rev() {
                    pending.push((term, format!("{path}/terms/{index}")));
                }
            }
            SavedQueryFilterSpec::Not { term } => {
                pending.push((term.as_mut(), format!("{path}/term")));
            }
            SavedQueryFilterSpec::Claim { value, .. } => {
                payloads.push((format!("{path}/value"), value.take()));
            }
            SavedQueryFilterSpec::TaskOwner { .. } | SavedQueryFilterSpec::EdgeExists { .. } => {}
        }
    }
}

fn restore(mut encoded: Value, payloads: Vec<(String, Value)>) -> Value {
    for (path, payload) in payloads {
        // These defaulted fields are always emitted by the native serde derives.
        *encoded
            .pointer_mut(&path)
            .expect("saved-query serialization retains its payload fields") = payload;
    }
    encoded
}
