//! A nightly topic (ARCH-0026 Nightly, "an entity or a topic"; Engine
//! ruling L2-04-TOPIC): the words of a Name span that bound no entity. A
//! span's thing is the entity its reading bound; a Name span that bound none
//! still names something, its topic (`SieveSpan::entity`: "unresolved spans
//! remain topics"). Spans whose words are equal in lower case, with their
//! whitespace collapsed, name one topic, so the unbound TURNs about one
//! unknown name meet in one thing whichever conversation they are in.
//!
//! The words are read as the sieve read them, through the Dreamer's own
//! gate: a span whose source the Dreamer may no longer read, or whose text
//! is no longer the version its offsets index, names no topic. A Date span
//! names none. A TURN that names no topic stays in the structural topic.

use std::collections::{BTreeMap, BTreeSet};

use crate::dreamer_consolidation::ConsolidationPartitionPlan;
use crate::dreamer_wake::sieve::{SieveSpan, SpanKind, span_words_in_txn};
use crate::{EntityId, Result, Vault};

const TOPIC_DOMAIN: &[u8] = b"oneiron:dreamer-nightly-topic:v1";

/// One topic: BLAKE3 of its folded words.
pub(in crate::dreamer_wake::nightly) type TopicKey = [u8; 32];

/// The topic each spent Name span of a planned TURN names, by span id, when
/// the span bound no entity, read at the planning snapshot.
pub(in crate::dreamer_wake::nightly) fn topics_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    partitions: &[ConsolidationPartitionPlan],
    spans: &[SieveSpan],
) -> Result<BTreeMap<[u8; 32], TopicKey>> {
    let planned: BTreeSet<EntityId> = partitions
        .iter()
        .flat_map(|partition| &partition.turns)
        .map(|turn| turn.turn_id)
        .collect();
    let mut topics = BTreeMap::new();
    for span in spans.iter().filter(|span| {
        span.owed.is_empty()
            && span.entity.is_none()
            && span.kind == SpanKind::Name
            && planned.contains(&span.turn)
    }) {
        if let Some(words) = span_words_in_txn(vault, txn, span)?
            && let Some(topic) = topic_of(&words)
        {
            topics.insert(span.id, topic);
        }
    }
    Ok(topics)
}

/// The topic `words` name: their lower case, whitespace collapsed; none for
/// words that are only whitespace.
fn topic_of(words: &str) -> Option<TopicKey> {
    let folded = words
        .split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ");
    if folded.is_empty() {
        return None;
    }
    Some(
        *blake3::Hasher::new()
            .update(TOPIC_DOMAIN)
            .update(folded.as_bytes())
            .finalize()
            .as_bytes(),
    )
}
