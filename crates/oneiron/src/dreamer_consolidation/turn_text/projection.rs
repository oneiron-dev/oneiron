//! The exact projection a consolidation branch read of one witnessed TURN
//! (FIX 5755), and a retained citation bound again over it (FIX 6150).
//!
//! A range a round cited over a witnessed TURN's text is measured over the
//! words of the MESSAGEs that text joined, in the order the branch read them.
//! A retained alternative keeps that projection content-free: the ordered
//! MESSAGE ids, nothing of their words. When the TURN as the Dreamer reads
//! it now no longer binds such a citation, a Keep binds it again over the
//! MESSAGEs it cites alone, read as the Dreamer in the caller's snapshot
//! under the same gates, bindings and finality a branch reads by, each at
//! the revision and slice the citation named, joined as the projection
//! joined them, and held to the citation's own hash. A MESSAGE it does not
//! cite no longer refuses it. One it cites that is gone, withheld, rebound,
//! hidden, unfinished, edited or of another speaker refuses; it never reads
//! fewer words, and never other words at the old offsets.

use super::{
    MESSAGES_NOT_RESIDENT, MessageSpan, SourceRow, TurnText, decode_message, message_reader, peers,
};
use crate::claim::ScopedRead;
use crate::dreamer_consolidation::provenance::VerifiedLocator;
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::dreamer_consolidation::swarm_evidence_content_hash;
use crate::dreamer_consolidation::watermark::decode_turn_body;
use crate::dreamer_runner::{DreamerTurnRole, dreamer_turn_role};
use crate::edge::EdgeKind;
use crate::gate::{WITNESS_AUTHOR_COMPANION, WITNESS_AUTHOR_SYSTEM, WITNESS_AUTHOR_USER};
use crate::ports::EdgeDirection;
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::{EntityId, Error, Result};

impl TurnText {
    /// The MESSAGEs this text joins, in projection order: what a retained
    /// alternative keeps of it, content-free. None for inline text.
    pub(in crate::dreamer_consolidation) fn projection(&self) -> Vec<EntityId> {
        self.layout.iter().map(|(id, _, _)| *id).collect()
    }
}

fn changed() -> Error {
    invalid_consolidation("the projection a retained citation was read from changed")
}

/// What every cited MESSAGE of one TURN is held to: the TURN, its one
/// conversation, its own speaker's author bucket, and whether it was
/// imported.
struct Frame {
    turn: EntityId,
    conversation: EntityId,
    bucket: &'static str,
    imported: bool,
}

/// The TURN `turn_body` holds as a witnessed TURN still reads: its words not
/// withdrawn, joined from MESSAGEs, of a user or assistant speaker, every
/// tagged MESSAGE resident, under one conversation.
fn frame_in(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    turn_body: &[u8],
) -> Result<Frame> {
    let vault = read.vault();
    if !crate::ports::body_readable_in_txn(
        &vault.store,
        txn,
        turn,
        turn_body,
        crate::ports::BodyStale::Withdrawn,
    )? {
        return Err(changed());
    }
    let facts = decode_turn_body(turn_body);
    if facts.text.is_some() {
        return Err(changed());
    }
    let bucket = match dreamer_turn_role(
        facts.speaker.as_deref(),
        &vault.config.assistant_display_names,
    ) {
        DreamerTurnRole::User => WITNESS_AUTHOR_USER,
        DreamerTurnRole::Assistant => WITNESS_AUTHOR_COMPANION,
        _ => return Err(changed()),
    };
    if crate::tagging::tagged_messages_absent_in_txn(&vault.store, txn, turn)? {
        return Err(invalid_consolidation(MESSAGES_NOT_RESIDENT));
    }
    let parents = peers(
        vault,
        txn,
        turn,
        EdgeDirection::Out,
        EdgeKind::ChildOf,
        None,
    )?;
    let [conversation] = parents.as_slice() else {
        return Err(invalid_consolidation(
            "witnessed turn has no single conversation",
        ));
    };
    Ok(Frame {
        turn: *turn,
        conversation: *conversation,
        bucket,
        imported: facts.imported,
    })
}

/// The words of the MESSAGE `span` cites, `row` as the Dreamer read it in
/// `txn`: still live, readable, bound to the TURN, its conversation and its
/// byline, of the TURN's own speaker, visible, final and not words another
/// speaker said in an import, at the exact revision (and document frontier)
/// the citation read.
fn cited_words_in(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    frame: &Frame,
    span: &MessageSpan,
    row: Option<SourceRow>,
) -> Result<String> {
    let vault = read.vault();
    let id = &span.message;
    let Some((entity_type, _, body)) = row else {
        return Err(invalid_consolidation(
            "witnessed turn message is not readable",
        ));
    };
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, id)?.is_live() {
        return Err(changed());
    }
    let message = decode_message(&body)
        .ok_or_else(|| invalid_consolidation("witnessed message body is malformed"))?;
    let out = |kind| peers(vault, txn, id, EdgeDirection::Out, kind, None);
    let bylines = usize::from(message.author != WITNESS_AUTHOR_SYSTEM && !frame.imported);
    if entity_type != ENTITY_TYPE_MESSAGE
        || out(EdgeKind::PartOf)? != [frame.turn]
        || out(EdgeKind::BelongsTo)? != [frame.conversation]
        || out(EdgeKind::AuthoredBy)?.len() != bylines
    {
        return Err(invalid_consolidation(
            "witnessed turn message binding changed",
        ));
    }
    let words = !crate::memory::message_completion_in_txn(vault, txn, id)?.incomplete;
    #[cfg(feature = "sync")]
    let frontier = crate::entity_doc::source_frontier_in_txn(&vault.store, txn, id)?;
    #[cfg(not(feature = "sync"))]
    let frontier = None;
    if message.author != frame.bucket
        || !message.is_visible
        || !words
        || (frame.imported && message.not_the_owners)
        || swarm_evidence_content_hash(&body) != span.revision
        || frontier != span.frontier
    {
        return Err(changed());
    }
    Ok(message.content)
}

/// Binds `cited`, a stored range over the witnessed TURN `turn_body` holds,
/// again over the MESSAGEs it cites alone (FIX 6150): each read as `read` in
/// `txn` and held as [`cited_words_in`] holds it, each slice the citation
/// named taken from its own words, and the slices joined as `projection`,
/// the MESSAGEs its branch read in order, joined them. MESSAGEs between two
/// slices held no words then, so only their joins lie between; a range may
/// also open or close on joins beside its outer MESSAGEs. Refuses unless
/// those bytes hash to the citation's own hash.
pub(in crate::dreamer_consolidation) fn rebind_cited_in(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    turn_body: &[u8],
    projection: &[EntityId],
    cited: &VerifiedLocator,
) -> Result<()> {
    let (reference, hash, spans) = cited;
    let (Some((start, end)), Some(first)) = (reference.byte_range, spans.first()) else {
        return Err(changed());
    };
    let frame = frame_in(read, txn, &reference.source_id, turn_body)?;
    let ids: Vec<EntityId> = spans.iter().map(|span| span.message).collect();
    let rows = message_reader(read)?.get_entities_parts_in_txn(txn, &ids)?;
    let mut quoted = Vec::new();
    let mut first_at = 0;
    // The last slice's place in the projection, and whether it ran to the
    // end of its MESSAGE's words.
    let mut last: Option<(usize, bool)> = None;
    for (span, row) in spans.iter().zip(rows) {
        let content = cited_words_in(read, txn, &frame, span, row)?;
        let words = content
            .as_bytes()
            .get(span.start..span.end)
            .filter(|words| !words.is_empty())
            .ok_or_else(changed)?;
        let at = projection
            .iter()
            .position(|id| *id == span.message)
            .ok_or_else(changed)?;
        match last {
            None => first_at = at,
            Some((previous, to_end)) => {
                if at <= previous || !to_end || span.start != 0 {
                    return Err(changed());
                }
                quoted.resize(quoted.len() + (at - previous), b'\n');
            }
        }
        quoted.extend_from_slice(words);
        last = Some((at, span.end == content.len()));
    }
    let Some((last_at, to_end)) = last else {
        return Err(changed());
    };
    // Joins the range may open on, before its first MESSAGE, or close on,
    // after its last.
    let before = if first.start == 0 { first_at } else { 0 };
    let after = if to_end {
        projection.len() - 1 - last_at
    } else {
        0
    };
    let joins = end
        .checked_sub(start)
        .and_then(|len| len.checked_sub(quoted.len()))
        .ok_or_else(changed)?;
    for opening in joins.saturating_sub(after)..=joins.min(before) {
        let mut bytes = vec![b'\n'; opening];
        bytes.extend_from_slice(&quoted);
        bytes.resize(bytes.len() + (joins - opening), b'\n');
        if swarm_evidence_content_hash(&bytes) == *hash {
            return Ok(());
        }
    }
    Err(changed())
}
