//! Authorship, message and file modes are canonical revision data, not export input.
use crate::code_commit_metadata::CodeCommitMetadata;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;
use std::collections::BTreeMap;
pub fn invalid() -> Error {
    Error::InvalidClaimBody("invalid canonical code commit metadata")
}
pub fn to_value(meta: Option<&CodeCommitMetadata>) -> Value {
    meta.map_or(Value::Nil, |m| {
        Value::Array(vec![
            m.author.map_or(Value::Nil, |author| {
                Value::Binary(author.as_bytes().to_vec())
            }),
            Value::from(m.message.clone()),
            Value::Array(
                m.file_modes
                    .iter()
                    .map(|(id, mode)| {
                        Value::Array(vec![Value::Binary(id.to_vec()), Value::from(*mode)])
                    })
                    .collect(),
            ),
        ])
    })
}
