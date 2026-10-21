//! The sieve's half of its follower session (FIX 7510): what the follower
//! captures of a TURN the sieve reads, the owed novelty spans it answers,
//! and the queue update a reading makes, in the caller's transaction so a
//! batch of readings, its result and the follower's cursor commit together.

use std::collections::BTreeSet;

use crate::claim::ScopedReadActorKey;
use crate::error::{Error, Result};
use crate::llm::Scope;
use crate::llm::decision::EvidenceVersion;
use crate::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON, ENTITY_TYPE_PLACE};
use crate::{EntityId, Vault};

use super::recipes::queue_key;
use super::{QUEUE, SPANS, SieveRung, SieveSpan, SpanBand, SpanKind, SpanOrigin, chunks};

/// One chunk of a TURN as the follower freezes it: its source, the digest
/// that versions it and its words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CapturedChunk {
    pub(crate) source: EntityId,
    pub(crate) digest: [u8; 32],
    pub(crate) text: String,
}

/// A model's reading of one span: what the queue entry takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SpanReading {
    pub(crate) kind: SpanKind,
    pub(crate) entity: Option<EntityId>,
    pub(crate) novel: bool,
    pub(crate) confidence: u8,
}

/// The chunks of `turn` the Dreamer may read now, as the sieve reads them,
/// or `None` for a turn the sieve does not read (gone, imported, a role
/// GATE-10 keeps out). A MESSAGE the Dreamer may not read gives no chunk.
pub(crate) fn capture_turn_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<Vec<CapturedChunk>>> {
    if !super::sieved_turn_in_txn(vault, txn, turn)? {
        return Ok(None);
    }
    let Some(read) = chunks::turn_chunks_in_txn(vault, txn, turn)? else {
        return Ok(None);
    };
    Ok(Some(
        read.chunks
            .into_iter()
            .map(|chunk| CapturedChunk {
                source: chunk.source,
                digest: chunk.digest,
                text: chunk.text,
            })
            .collect(),
    ))
}

/// The words `span`'s offsets index, read as the sieve read them: `None`
/// when the chunk no longer reads, or no longer reads at the span's digest.
pub(crate) fn span_chunk_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    span: &SieveSpan,
) -> Result<Option<String>> {
    let Some(text) = chunks::chunk_text_in_txn(vault, txn, &span.turn, &span.source)? else {
        return Ok(None);
    };
    Ok((chunk_digest(&text) == span.source_digest).then_some(text))
}

/// BLAKE3 of a chunk's words, as the sieve versions a span's source.
fn chunk_digest(text: &str) -> [u8; 32] {
    *blake3::Hasher::new()
        .update(b"oneiron:dreamer-sieve:chunk:v1")
        .update(text.as_bytes())
        .finalize()
        .as_bytes()
}

/// The Dreamer's own scoped read, as a rung reads its evidence.
fn dreamer_read_key() -> Result<ScopedReadActorKey> {
    let actor = crate::WriteActor::new(
        crate::dreamer_runner::authority::dreamer_actor_id()?,
        crate::EdgeActorClass::System,
    );
    ScopedReadActorKey::with_actor_class(
        actor.entity_ref().to_hex(),
        actor.actor_class().gate_actor_class(),
    )
    .ok_or(Error::InvalidConfig("sieve read actor".into()))
}

/// The version a scope pins a document at: its live content's hash.
fn version_of(raw: &[u8]) -> String {
    format!(
        "blake3:{}",
        crate::entity_id::bytes_to_hex_lower(
            &crate::dreamer_consolidation::swarm_evidence_content_hash(
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]
            )
        )
    )
}

/// Each of `ids` pinned at its live version under the Dreamer's read, in
/// order; `None` when the Dreamer may not read one of them now.
pub(crate) fn pins_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ids: &[EntityId],
) -> Result<Option<Vec<(EntityId, String)>>> {
    let read = vault.scoped_read(dreamer_read_key()?);
    let mut pins = Vec::with_capacity(ids.len());
    for id in ids {
        let Some(raw) = read.entity_raw_live_in(txn, id)? else {
            return Ok(None);
        };
        pins.push((*id, version_of(&raw)));
    }
    Ok(Some(pins))
}

/// A span's turn and source pinned into `scope`, then its entity
/// candidates: each known PERSON, ORG or PLACE whose identity key is the
/// span's `quote`, and a saved tag's links, each the Dreamer may read, in
/// id order and pinned too. `None` when the turn or the source does not
/// read now. A rung's evidence and the follower's question read alike.
pub(crate) fn candidates_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    span: &SieveSpan,
    quote: &str,
    scope: &mut Scope,
) -> Result<Option<Vec<EntityId>>> {
    candidates_pinned_in_txn(vault, txn, span, quote, scope, &mut Vec::new())
}

/// [`candidates_in_txn`], also pinning each body it read as an evidence
/// version, as a rung's typed decisions cite them (OF-498a).
pub(crate) fn candidates_pinned_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    span: &SieveSpan,
    quote: &str,
    scope: &mut Scope,
    versions: &mut Vec<EvidenceVersion>,
) -> Result<Option<Vec<EntityId>>> {
    let read = vault.scoped_read(dreamer_read_key()?);
    for id in BTreeSet::from([span.turn, span.source]) {
        let Some(raw) = read.entity_raw_live_in(txn, &id)? else {
            return Ok(None);
        };
        super::recipes::pin_version(scope, versions, id, &raw);
    }
    let mut ids = BTreeSet::new();
    for kind in [ENTITY_TYPE_PERSON, ENTITY_TYPE_ORG, ENTITY_TYPE_PLACE] {
        ids.extend(vault.lookup_identity_key_in_txn(txn, kind, quote)?);
    }
    if let SpanOrigin::SavedTag { envelope, index } = span.origin {
        if let Some(tags) = crate::tagging::readable_view_in_txn(&vault.store, txn, &span.turn)?
            && super::read::envelope_digest(&tags.envelope) == envelope
            && let Some(mention) = usize::try_from(index)
                .ok()
                .and_then(|index| tags.mentions.get(index))
        {
            ids.extend(mention.link.entities());
        }
    }
    let mut entities = Vec::new();
    for id in ids {
        if let Some(raw) = read.entity_raw_live_in(txn, &id)? {
            super::recipes::pin_version(scope, versions, id, &raw);
            entities.push(id);
        }
    }
    Ok(Some(entities))
}

/// Every queued span that still owes the novelty rung, in queue order, and
/// whether the Dreamer may read its turn and its source now.
pub(crate) fn owed_novelty_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(SieveSpan, bool)>> {
    let mut owed = Vec::new();
    for row in QUEUE.iter_from(&vault.store, txn, &[])? {
        let (_, span) = row?;
        if span.owed.contains(&SieveRung::Novelty) {
            owed.push(span);
        }
    }
    let pairs = owed
        .iter()
        .map(|span| (span.turn, span.source))
        .collect::<Vec<_>>();
    let admission = chunks::admissions_in_txn(vault, txn, &pairs)?;
    Ok(owed
        .into_iter()
        .zip(admission)
        .map(|(span, admission)| (span, admission == chunks::Admission::Readable))
        .collect())
}

/// Whether any queued span still owes the novelty rung, read or not.
pub(crate) fn novelty_owed_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    for row in QUEUE.iter_from(&vault.store, txn, &[])? {
        if row?.1.owed.contains(&SieveRung::Novelty) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `span` is still queued as it was asked, and the Dreamer may read
/// its turn and its source now.
pub(crate) fn still_queued_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    span: &SieveSpan,
) -> Result<bool> {
    Ok(
        QUEUE.get(&vault.store, txn, &queue_key(span))?.as_ref() == Some(span)
            && chunks::admissions_in_txn(vault, txn, &[(span.turn, span.source)])?
                == [chunks::Admission::Readable],
    )
}

/// A follower's novelty reading of `span`, in the caller's transaction: an
/// uncertain reading still owes typing, and so does a span whose rule
/// reading owed it already.
pub(crate) fn apply_follower_reading_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    span: &SieveSpan,
    reading: SpanReading,
) -> Result<()> {
    let policy = super::policy::policy_in_txn(vault, txn)?;
    let typing_owed = span.owed.contains(&SieveRung::Typing)
        || (reading.confidence >= policy.uncertain_low
            && reading.confidence < policy.uncertain_high);
    apply_reading_in_txn(vault, txn, span, reading, typing_owed)
}

/// The interest queue's update for a model `reading` of `span`, in the
/// caller's transaction: its kind, entity, novelty, confidence, band and
/// score, the rung it still owes, and its place by the new score. A span
/// read as not novel keeps its place at score zero; nothing drops.
pub(crate) fn apply_reading_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    span: &SieveSpan,
    reading: SpanReading,
    typing_owed: bool,
) -> Result<()> {
    let policy = super::policy::policy_in_txn(vault, txn)?;
    let mut updated = span.clone();
    updated.kind = reading.kind;
    updated.entity = reading.entity;
    updated.novel = Some(reading.novel);
    updated.confidence = reading.confidence;
    updated.band = if reading.confidence < policy.uncertain_low {
        SpanBand::Low
    } else if reading.confidence < policy.uncertain_high {
        SpanBand::Uncertain
    } else {
        SpanBand::Sure
    };
    updated.score = match reading.kind {
        SpanKind::Date => policy.date_interest,
        SpanKind::Name => policy.name_interest,
    }
    .saturating_mul(u32::from(reading.confidence));
    if !reading.novel {
        updated.score = 0;
    }
    updated.policy_digest = policy.digest()?;
    updated.owed = if typing_owed {
        vec![SieveRung::Typing]
    } else {
        Vec::new()
    };
    super::recipes::spend_in_txn(&vault.store, txn, span)?;
    let key = queue_key(&updated);
    QUEUE.put(&vault.store, txn, &key, &updated)?;
    SPANS.put(&vault.store, txn, &(updated.turn, key), &())?;
    Ok(())
}
