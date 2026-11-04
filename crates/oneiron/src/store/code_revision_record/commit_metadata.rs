//! Authorship, message and file modes are canonical revision data, not export input.
use crate::store::code_commit_metadata::CodeCommitMetadata;
use crate::{EntityId, Error, Result};
use rmpv::Value;
use std::collections::BTreeMap;
fn invalid() -> Error {
    Error::InvalidClaimBody("invalid canonical code commit metadata")
}
pub(crate) fn validate(revision: &super::CodeRevision) -> Result<()> {
    let Some(meta) = &revision.commit_metadata else {
        return Ok(());
    };
    if meta.message.len() > 64 * 1024
        || meta.message.contains('\0')
        || crate::store::repo_provenance_trailer::parse_repo_provenance_trailer(&meta.message)?
            .is_some()
        || meta.file_modes.iter().any(|(id, mode)| {
            !revision.file_frontiers.contains_key(id)
                || !matches!(*mode, 0o100644 | 0o100755 | 0o120000)
        })
    {
        return Err(invalid());
    }

    Ok(())
}
pub(crate) fn to_value(meta: Option<&CodeCommitMetadata>) -> Value {
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
pub(crate) fn from_value(value: &Value) -> Result<Option<CodeCommitMetadata>> {
    if value.is_nil() {
        return Ok(None);
    }
    let fields = value
        .as_array()
        .filter(|f| f.len() == 3)
        .ok_or_else(invalid)?;
    let author = if fields[0].is_nil() {
        None
    } else {
        Some(super::codec::entity_value(&fields[0], "author")?)
    };
    let message = fields[1].as_str().ok_or_else(invalid)?.to_owned();
    let mut file_modes = BTreeMap::new();
    for pair in fields[2].as_array().ok_or_else(invalid)? {
        let pair = pair
            .as_array()
            .filter(|f| f.len() == 2)
            .ok_or_else(invalid)?;
        let Value::Binary(id) = &pair[0] else {
            return Err(invalid());
        };
        let id: [u8; 32] = id.as_slice().try_into().map_err(|_| invalid())?;
        let mode = u32::try_from(pair[1].as_u64().ok_or_else(invalid)?).map_err(|_| invalid())?;
        if file_modes.insert(id, mode).is_some() {
            return Err(invalid());
        }
    }
    Ok(Some(CodeCommitMetadata {
        author,
        message,
        file_modes,
    }))
}
