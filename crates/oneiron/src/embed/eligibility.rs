//! Which stored records are embedded, and what the embedder receives for each.

use super::PendingEmbeddingPayload;

/// The payload the embedding worker sends for a stored record, or `None` when
/// the record is not embedded at all.
///
/// One rule for every door that queues or leases embedding work — the
/// embedding-space swap, cold attach and the worker — so no door queues work
/// the worker can only fail on:
/// - a CLAIM whose body decodes, except a lexical query hint: that record is
///   lexical-only by construction, the write door never marks it and the
///   vector door refuses it;
/// - an epoch SUMMARY, strictly decoded. An ordinary SUMMARY shares the type
///   byte and is not one;
/// - and of those, only a text with something in it. Whitespace and control
///   characters alone leave nothing to embed, and no provider can return a
///   truthful vector for them.
pub(crate) fn embeddable_payload(entity_type: u8, body: &[u8]) -> Option<PendingEmbeddingPayload> {
    match entity_type {
        crate::registry::ENTITY_TYPE_CLAIM => {
            let claim = crate::claim::decode_claim_body(body, true).ok()?;
            (claim.predicate != crate::claim::PREDICATE_LEXICAL_QUERY_HINT
                && has_content(&super::claim_text(&claim)))
            .then(|| PendingEmbeddingPayload::ClaimBody(body.to_vec()))
        }
        crate::registry::ENTITY_TYPE_SUMMARY => {
            let text = crate::compaction::decode_epoch_summary_body(body)
                .ok()?
                .text;
            has_content(&text).then_some(PendingEmbeddingPayload::SummaryText(text))
        }
        _ => None,
    }
}

/// What idle publication embeds for a text revision, or `None` when it has
/// nothing to embed and publishes with no vector.
///
/// A CLAIM by the rule above, so a claim never gets a vector at idle that the
/// worker would not give it. Any other record as its text fields joined by
/// newlines, all of them: one field with something in it — a title beside an
/// empty body — is enough.
pub(crate) fn indexed_payload(
    entity_type: u8,
    body: &[u8],
    fields: &[(String, String)],
) -> Option<PendingEmbeddingPayload> {
    if entity_type == crate::registry::ENTITY_TYPE_CLAIM {
        return embeddable_payload(entity_type, body);
    }
    let text = fields
        .iter()
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    has_content(&text).then_some(PendingEmbeddingPayload::SummaryText(text))
}

fn has_content(text: &str) -> bool {
    text.chars().any(|c| !c.is_whitespace() && !c.is_control())
}
