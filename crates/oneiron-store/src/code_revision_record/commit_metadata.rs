//! Message and file modes are canonical revision data, not export input;
//! authorship is erasable attribution beside them (FIX 6258).
use crate::code_commit_metadata::CodeCommitMetadata;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;
use std::collections::BTreeMap;
pub fn invalid() -> Error {
    Error::InvalidClaimBody("invalid canonical code commit metadata")
}
fn modes_value(meta: &CodeCommitMetadata) -> Value {
    Value::Array(
        meta.file_modes
            .iter()
            .map(|(id, mode)| Value::Array(vec![Value::Binary(id.to_vec()), Value::from(*mode)]))
            .collect(),
    )
}
pub fn to_value(meta: Option<&CodeCommitMetadata>) -> Value {
    meta.map_or(Value::Nil, |m| {
        Value::Array(vec![
            m.author.map_or(Value::Nil, |author| {
                Value::Binary(author.as_bytes().to_vec())
            }),
            Value::from(m.message.clone()),
            modes_value(m),
        ])
    })
}
/// The content the revision fold binds: the message and the modes, never
/// the erasable author or whether one is named (FIX 6258).
pub fn integrity_value(meta: &CodeCommitMetadata) -> Value {
    Value::Array(vec![Value::from(meta.message.clone()), modes_value(meta)])
}
