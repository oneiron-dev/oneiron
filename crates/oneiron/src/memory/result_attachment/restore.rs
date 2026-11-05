use std::collections::{BTreeMap, BTreeSet};

use super::{MessageResultAttachment, handle_digest};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_MESSAGE;

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// Retires only MESSAGE attachments whose body custody was explicitly retired.
/// Entity headers, row keys and unrelated MessagePack values stay unchanged.
pub(crate) fn retire_message_results_in_rows(
    databases: &mut BTreeMap<String, Rows>,
    digests: &BTreeSet<[u8; 32]>,
) -> Result<()> {
    if digests.is_empty() {
        return Ok(());
    }
    let Some(entities) = databases.get_mut("entities") else {
        return Ok(());
    };
    for (_, value) in entities {
        retire_message_result_in_row(value, digests)?;
    }
    Ok(())
}

pub(crate) fn retire_message_result_in_row(
    value: &mut Vec<u8>,
    digests: &BTreeSet<[u8; 32]>,
) -> Result<()> {
    if digests.is_empty() {
        return Ok(());
    }
    let corrupt = || Error::CorruptedIndex("checkpoint message result attachment");
    if value.len() <= ENTITY_METADATA_HEADER_LEN || value[0] != ENTITY_TYPE_MESSAGE {
        return Ok(());
    }
    let mut body = rmpv::decode::read_value(&mut &value[ENTITY_METADATA_HEADER_LEN..])
        .map_err(|_| corrupt())?;
    let Some(result) = field_mut(&mut body, "metadata")
        .and_then(|metadata| field_mut(metadata, super::MESSAGE_RESULT_METADATA_KEY))
    else {
        return Ok(());
    };
    let result_json: serde_json::Value =
        rmpv::ext::from_value(result.clone()).map_err(|_| corrupt())?;
    let mut attachment: MessageResultAttachment =
        serde_json::from_value(result_json).map_err(|_| corrupt())?;
    if attachment.invalid_reason().is_some() {
        return Err(corrupt());
    }
    let digest = handle_digest(&attachment.handle).ok_or_else(corrupt)?;
    if !digests.contains(&digest) {
        return Ok(());
    }
    attachment.retire_content();
    let result_json = serde_json::to_value(attachment).map_err(|_| corrupt())?;
    *result = rmpv::ext::to_value(result_json).map_err(|_| corrupt())?;
    let mut rewritten = value[..ENTITY_METADATA_HEADER_LEN].to_vec();
    rmpv::encode::write_value(&mut rewritten, &body).map_err(|_| corrupt())?;
    *value = rewritten;
    Ok(())
}

fn field_mut<'a>(value: &'a mut rmpv::Value, name: &str) -> Option<&'a mut rmpv::Value> {
    let rmpv::Value::Map(fields) = value else {
        return None;
    };
    fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
}
