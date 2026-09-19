//! WS names and typed dispatch project the engine table.
use super::AppError;
use oneiron::memory::Memory;
use oneiron::memory::verb_table::{FacadeRequest, FacadeVerb};
use serde_json::Value;

pub(super) fn verb(method: &str) -> Option<FacadeVerb> {
    FacadeVerb::parse_sdk(method).or_else(|| FacadeVerb::parse_wire(method))
}
#[cfg(test)]
pub(super) fn read_method(method: &str) -> bool {
    verb(method).is_some_and(|verb| verb.scope() == oneiron::memory::verb_table::FacadeScope::Read)
}

pub(super) struct Read(FacadeRequest);
impl Read {
    pub(super) fn parse(method: &str, value: Value) -> Result<Self, AppError> {
        let verb = verb(method)
            .ok_or_else(|| AppError::bad_request("unknown facade RPC", Some("method")))?;
        Ok(Self(verb.request(value)?))
    }
    pub(super) fn run(self, memory: &Memory<'_>) -> Result<Value, AppError> {
        Ok(self.0.run(memory)?.body()?)
    }
}

pub(super) fn facade_limit(requested: Option<usize>, default: usize) -> Result<usize, AppError> {
    let limit = requested.unwrap_or(default);
    if limit == 0 || limit > crate::api::CORE_MAX_LIST_LIMIT {
        return Err(AppError::new(
            oneiron::memory::MEMORY_CODE_BAD_REQUEST,
            format!(
                "limit must be between 1 and {}",
                crate::api::CORE_MAX_LIST_LIMIT
            ),
            ["Request a smaller page and paginate."],
        ));
    }
    Ok(limit)
}
