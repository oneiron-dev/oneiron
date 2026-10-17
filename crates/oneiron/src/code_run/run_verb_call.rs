//! The four memory run rows as typed calls, outside the sandbox (OF-181).
//!
//! `vault.search`, `vault.claims.put`, `vault.claims.supersede` and
//! `vault.edges.put` decode pure input and run on ordinary storage, so the
//! app's action registry serves them beside a code run. Each arm is the
//! component bridge's own conversion, with its defaults: a search's limit of
//! 20 and a claim's run clock.

use super::{
    JS_SAFE_INTEGER, MemoryClaimInput, MemoryEdgeInput, MemorySearchInput, MemorySupersedeInput,
    MemoryTimeRange, SelfCall, SelfMemoryPutClaimCall, SelfMemoryPutEdgeCall, SelfMemorySearchCall,
    SelfMemorySupersedeClaimCall,
};
use crate::task_verb::sdk::RunVerb;
use crate::{ClaimCandidate, ClaimSubject, EdgeKind, EntityId, Error, Result, TimeRange};
use serde_json::Value;

/// The memory run rows, which need no live run.
pub(crate) const MEMORY_RUN_VERBS: [RunVerb; 4] = [
    RunVerb::VaultSearch,
    RunVerb::VaultClaimsPut,
    RunVerb::VaultClaimsSupersede,
    RunVerb::VaultEdgesPut,
];

/// The typed call a memory run row makes, `now` in unix seconds. Any other
/// run row needs its caller's live run, so it has none here.
pub(crate) fn memory_run_call(verb: RunVerb, input: Value, now: u64) -> Result<Option<SelfCall>> {
    Ok(Some(match verb {
        RunVerb::VaultSearch => {
            let args: MemorySearchInput = decode(input)?;
            SelfCall::MemorySearch(SelfMemorySearchCall::new(
                args.query,
                args.limit.map_or(20, |limit| limit as usize),
            ))
        }
        RunVerb::VaultClaimsPut => {
            let args: MemoryClaimInput = decode(input)?;
            let confidence = args.confidence.map(js_f32).transpose()?;
            let occurred = args.occurred.unwrap_or(MemoryTimeRange {
                start: now,
                end: now,
            });
            let (start, end) = (js_time(occurred.start)?, js_time(occurred.end)?);
            if start > end {
                return Err(failure("invalid claim time range"));
            }
            let candidate = ClaimCandidate::new(
                args.predicate,
                ClaimSubject::Entity(EntityId::from_hex(&args.subject)?),
                json_value(args.value),
                confidence.unwrap_or(1.0),
            );
            SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
                EntityId::from_hex(&args.id)?,
                candidate,
                TimeRange { start, end },
                args.learned_at.map_or(Ok(now), js_time)?,
            ))
        }
        RunVerb::VaultClaimsSupersede => {
            let args: MemorySupersedeInput = decode(input)?;
            SelfCall::MemorySupersedeClaim(SelfMemorySupersedeClaimCall::new(
                EntityId::from_hex(&args.new_id)?,
                EntityId::from_hex(&args.old_id)?,
                js_time(args.now)?,
            ))
        }
        RunVerb::VaultEdgesPut => {
            let args: MemoryEdgeInput = decode(input)?;
            let weight = args.weight.map(js_f32).transpose()?;
            let kind =
                EdgeKind::from_name(&args.kind).ok_or_else(|| failure("invalid edge kind"))?;
            let weight = weight
                .or_else(|| kind.default_weight())
                .ok_or_else(|| failure("edge weight required"))?;
            SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                EntityId::from_hex(&args.src)?,
                kind,
                EntityId::from_hex(&args.tgt)?,
                weight,
            ))
        }
        _ => return Ok(None),
    }))
}

fn failure(detail: &str) -> Error {
    Error::InvalidConfig(detail.to_owned())
}

fn decode<T: serde::de::DeserializeOwned>(input: Value) -> Result<T> {
    serde_json::from_value(input).map_err(|_| failure("invalid typed component arguments"))
}

/// A caller's integer for a time field, inside JavaScript's safe range.
fn js_time(value: u64) -> Result<u64> {
    if value > JS_SAFE_INTEGER {
        return Err(failure("invalid guest integer"));
    }
    Ok(value)
}

/// A caller's number for an `f32` field. A number past `f32`'s range is
/// refused, not rounded to its edge or to infinity.
fn js_f32(value: f64) -> Result<f32> {
    if !value.is_finite() || value.abs() > f64::from(f32::MAX) {
        return Err(failure("invalid guest number"));
    }
    Ok(value as f32)
}

fn json_value(value: Value) -> rmpv::Value {
    match value {
        Value::Null => rmpv::Value::Nil,
        Value::Bool(v) => rmpv::Value::Boolean(v),
        Value::Number(v) => {
            if let Some(v) = v.as_u64() {
                rmpv::Value::from(v)
            } else if let Some(v) = v.as_i64() {
                rmpv::Value::from(v)
            } else {
                rmpv::Value::F64(v.as_f64().unwrap_or_default())
            }
        }
        Value::String(v) => rmpv::Value::from(v),
        Value::Array(v) => rmpv::Value::Array(v.into_iter().map(json_value).collect()),
        Value::Object(v) => rmpv::Value::Map(
            v.into_iter()
                .map(|(k, v)| (rmpv::Value::from(k), json_value(v)))
                .collect(),
        ),
    }
}
