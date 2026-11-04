//! Strict decoding of parent-verified citation locators on attachments.

use rmpv::Value;

use super::super::support::invalid_consolidation;
use super::super::turn_text::MessageSpan;
use super::super::watermark::entity_ref_from_value;
use super::LOCATOR_MESSAGES_KEY;
use super::VerifiedLocator;
use crate::error::Result;

fn decode_offset(value: &Value) -> Result<usize> {
    usize::try_from(
        value
            .as_u64()
            .ok_or_else(|| invalid_consolidation("invalid locator offset"))?,
    )
    .map_err(|_| invalid_consolidation("locator offset overflow"))
}

fn decode_message_spans(value: &Value) -> Result<Vec<MessageSpan>> {
    let Value::Array(rows) = value else {
        return Err(invalid_consolidation("locator messages must be an array"));
    };
    if rows.is_empty() {
        return Err(invalid_consolidation("locator messages are empty"));
    }
    rows.iter()
        .map(|row| {
            let Value::Map(fields) = row else {
                return Err(invalid_consolidation("locator message must be a map"));
            };
            let (mut message, mut span, mut revision, mut frontier) = (None, None, None, None);
            for (key, value) in fields {
                match (key.as_str(), value) {
                    (Some("message"), value) if message.is_none() => {
                        message = Some(
                            entity_ref_from_value(value)
                                .ok_or_else(|| invalid_consolidation("invalid locator message"))?,
                        );
                    }
                    (Some("span"), Value::Array(pair)) if span.is_none() => {
                        let [start, end] = pair.as_slice() else {
                            return Err(invalid_consolidation("invalid locator message span"));
                        };
                        span = Some((decode_offset(start)?, decode_offset(end)?));
                    }
                    (Some("revision"), Value::Binary(bytes)) if revision.is_none() => {
                        revision = Some(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                            invalid_consolidation("locator message revision must have 32 bytes")
                        })?);
                    }
                    (Some("frontier"), Value::Binary(bytes)) if frontier.is_none() => {
                        frontier = Some(bytes.clone());
                    }
                    _ => {
                        return Err(invalid_consolidation(
                            "unknown, duplicate or mistyped locator message key",
                        ));
                    }
                }
            }
            let (start, end) =
                span.ok_or_else(|| invalid_consolidation("missing locator message span"))?;
            if start >= end {
                return Err(invalid_consolidation("empty locator message span"));
            }
            Ok(MessageSpan {
                message: message.ok_or_else(|| invalid_consolidation("missing locator message"))?,
                start,
                end,
                revision: revision
                    .ok_or_else(|| invalid_consolidation("missing locator message revision"))?,
                frontier,
            })
        })
        .collect()
}

/// [`decode_verified_citations`] without the MESSAGE slices.
pub(crate) fn decode_verified_locators(
    evidence: &Value,
) -> Result<Vec<(super::super::SwarmEvidenceRef, [u8; 32])>> {
    Ok(decode_verified_citations(evidence)?
        .into_iter()
        .map(|(locator, hash, _)| (locator, hash))
        .collect())
}

/// Strictly decodes the parent-verified locator set on an attachment. The
/// ordinary evidence-envelope decoder ignores this additive key for readers.
pub(crate) fn decode_verified_citations(evidence: &Value) -> Result<Vec<VerifiedLocator>> {
    let Value::Map(fields) = evidence else {
        return Err(invalid_consolidation("verified evidence must be a map"));
    };
    let Value::Array(items) = fields
        .iter()
        .find(|(key, _)| key.as_str() == Some("locators"))
        .map(|(_, value)| value)
        .ok_or_else(|| invalid_consolidation("attachment locators are missing"))?
    else {
        return Err(invalid_consolidation(
            "attachment locators must be an array",
        ));
    };
    if items.is_empty() {
        return Err(invalid_consolidation("attachment locators are empty"));
    }
    items
        .iter()
        .map(|row| {
            let Value::Map(fields) = row else {
                return Err(invalid_consolidation("attachment locator must be a map"));
            };
            let mut source_id = None;
            let mut claim_id = None;
            let mut byte_range = None;
            let mut hash = None;
            let mut messages = None;
            for (key, value) in fields {
                match key.as_str() {
                    Some("source_id") if source_id.is_none() => {
                        source_id = Some(
                            entity_ref_from_value(value)
                                .ok_or_else(|| invalid_consolidation("invalid locator source"))?,
                        );
                    }
                    Some("claim_id") if claim_id.is_none() => {
                        claim_id = Some(
                            entity_ref_from_value(value)
                                .ok_or_else(|| invalid_consolidation("invalid locator claim"))?,
                        );
                    }
                    Some("byte_range") if byte_range.is_none() => {
                        let Value::Array(pair) = value else {
                            return Err(invalid_consolidation("invalid locator range"));
                        };
                        let [start, end] = pair.as_slice() else {
                            return Err(invalid_consolidation("invalid locator range"));
                        };
                        byte_range = Some((
                            usize::try_from(
                                start.as_u64().ok_or_else(|| {
                                    invalid_consolidation("invalid locator start")
                                })?,
                            )
                            .map_err(|_| invalid_consolidation("locator start overflow"))?,
                            usize::try_from(
                                end.as_u64()
                                    .ok_or_else(|| invalid_consolidation("invalid locator end"))?,
                            )
                            .map_err(|_| invalid_consolidation("locator end overflow"))?,
                        ));
                    }
                    Some(LOCATOR_MESSAGES_KEY) if messages.is_none() => {
                        messages = Some(decode_message_spans(value)?);
                    }
                    Some("content_hash") if hash.is_none() => {
                        let Value::Binary(bytes) = value else {
                            return Err(invalid_consolidation("invalid locator hash"));
                        };
                        hash = Some(bytes.as_slice().try_into().map_err(|_| {
                            invalid_consolidation("locator hash must have 32 bytes")
                        })?);
                    }
                    _ => return Err(invalid_consolidation("unknown or duplicate locator key")),
                }
            }
            Ok((
                super::super::SwarmEvidenceRef {
                    source_id: source_id
                        .ok_or_else(|| invalid_consolidation("missing locator source"))?,
                    claim_id,
                    byte_range,
                },
                hash.ok_or_else(|| invalid_consolidation("missing locator hash"))?,
                messages.unwrap_or_default(),
            ))
        })
        .collect()
}
