//! The nightly plan's things, for integration tests (census L2-04): witnessed
//! TURNs whose sieve spans are spent, grouped as the night's plan groups
//! them, read in one snapshot.

use crate::dreamer_wake::sieve::{RuleClass, SieveSpan, SpanBand, SpanKind, SpanOrigin};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

/// What a spent span reads as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpentSpanKind {
    Name,
    Date,
}

/// One spent span: `words`, first found inside `text`, the words of the
/// visible MESSAGE `message` of `turn`; bound to `entity`, or to none.
/// `score` orders the queue, highest first.
#[derive(Debug, Clone, Copy)]
pub struct SpentSpan<'a> {
    pub turn: EntityId,
    pub message: EntityId,
    pub text: &'a str,
    pub words: &'a str,
    pub kind: SpentSpanKind,
    pub entity: Option<EntityId>,
    pub score: u32,
}

/// One planned thing: the entity it is bound to, and each child's TURNs,
/// each with the slice line it is read on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedThing {
    pub entity: Option<EntityId>,
    pub children: Vec<Vec<(EntityId, u32)>>,
}

/// Witnesses `words`, spoken by a fresh PERSON, as one visible user MESSAGE
/// into a fresh TURN of `conversation` at `occurred_at`; `(turn, message)`.
///
/// # Errors
///
/// The witness door's.
pub fn witness_turn(
    vault: &Vault,
    conversation: EntityId,
    words: &str,
    occurred_at: u64,
) -> Result<(EntityId, EntityId)> {
    super::consolidation::witness_user_turn(vault, conversation, words, None, occurred_at)
}

/// The things the night's plan makes of `spans`, each spent (it owes no
/// rung), with no partition limit.
///
/// # Errors
///
/// A span whose words are not in its text, or the plan's reads.
pub fn planned_things(vault: &Vault, spans: &[SpentSpan<'_>]) -> Result<Vec<PlannedThing>> {
    let mut queue = spans.iter().map(sieve_span).collect::<Result<Vec<_>>>()?;
    // The queue readout: highest score first.
    queue.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.id.cmp(&right.id))
    });
    let txn = vault.store.env.read_txn()?;
    let things = crate::dreamer_wake::nightly::planned_thing_lines_in_txn(vault, &txn, &queue)?;
    Ok(things
        .into_iter()
        .map(|(entity, children)| PlannedThing { entity, children })
        .collect())
}

/// `spent` as the sieve queues a span whose rungs are all answered.
fn sieve_span(spent: &SpentSpan<'_>) -> Result<SieveSpan> {
    let start = spent.text.find(spent.words).ok_or_else(|| {
        Error::InvalidConfig(format!("`{}` is not in the span's text", spent.words))
    })?;
    let end = start + spent.words.len();
    let (kind, class) = match spent.kind {
        SpentSpanKind::Name => (SpanKind::Name, RuleClass::Name),
        SpentSpanKind::Date => (SpanKind::Date, RuleClass::AbsoluteDate),
    };
    let id = *blake3::Hasher::new()
        .update(b"oneiron:test-door:nightly-span:v1")
        .update(spent.turn.as_bytes())
        .update(spent.message.as_bytes())
        .update(&(start as u64).to_le_bytes())
        .finalize()
        .as_bytes();
    // The digest the sieve versions a chunk's text by.
    let source_digest = *blake3::Hasher::new()
        .update(b"oneiron:dreamer-sieve:chunk:v1")
        .update(spent.text.as_bytes())
        .finalize()
        .as_bytes();
    Ok(SieveSpan {
        id,
        turn: spent.turn,
        source: spent.message,
        start: start as u64,
        end: end as u64,
        kind,
        entity: spent.entity,
        novel: Some(spent.entity.is_none()),
        origin: SpanOrigin::Rule { rules: 1, class },
        source_digest,
        policy_digest: [0; 32],
        confidence: 100,
        score: spent.score,
        band: SpanBand::Sure,
        owed: Vec::new(),
        queued_at: 0,
    })
}
