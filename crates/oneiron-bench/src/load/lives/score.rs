//! Context accuracy with no model (ASK L9-36-ACCURACY = C, its first column):
//! whether a system's top-k returned text holds the gold answer span, and the
//! rank of the first returned item that holds a gold evidence turn. The same
//! rule scores every system, on whatever text that system returns.

use super::corpus::{Life, Question};

/// Lower case with every whitespace run made one space.
pub(super) fn normal(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Why a question is asked but not scored, or `None` when it is scored: a
/// scored question has a checked answer span (`support: string`) and is not
/// `unanswerable`.
pub(super) fn unscored_reason(question: &Question) -> Option<&'static str> {
    if question.kind == "unanswerable" {
        Some("unanswerable")
    } else if question.support.as_deref() != Some("string") {
        Some("unchecked_support")
    } else if question
        .answer_span
        .as_deref()
        .is_none_or(|span| span.trim().is_empty())
    {
        // A checked answer that spans several turns has no single span.
        Some("no_answer_span")
    } else {
        None
    }
}

/// One returned text, normalised; `truncated` when the system cut it short
/// (Oneiron caps an item's text at 500 characters and ends it with `…`).
struct Piece {
    text: String,
    truncated: bool,
}

fn piece(text: &str) -> Piece {
    let trimmed = text.trim_end();
    match trimmed.strip_suffix('…') {
        Some(cut) => Piece {
            text: normal(cut),
            truncated: true,
        },
        None => Piece {
            text: normal(trimmed),
            truncated: false,
        },
    }
}

/// Whether a returned piece holds an evidence turn: it contains the turn's
/// whole text, or it was cut short and its text (32 characters or more) lies
/// inside the turn's.
fn holds(piece: &Piece, turn: &str) -> bool {
    piece.text.contains(turn)
        || (piece.truncated && piece.text.chars().count() >= 32 && turn.contains(&piece.text))
}

/// A scored row's two values.
pub(super) struct Scored {
    pub(super) answer_in_context: bool,
    /// 1-based rank of the first item holding a gold evidence turn.
    pub(super) evidence_rank: Option<usize>,
    /// The evidence turn that item holds.
    pub(super) evidence_turn: Option<String>,
}

/// Scores the returned `items` (each item's texts, in rank order) against
/// `question` of `life`.
pub(super) fn score(life: &Life, question: &Question, items: &[Vec<String>]) -> Scored {
    let pieces = items
        .iter()
        .map(|texts| texts.iter().map(|t| piece(t)).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let span = normal(question.answer_span.as_deref().unwrap_or(""));
    let answer_in_context =
        !span.is_empty() && pieces.iter().flatten().any(|p| p.text.contains(&span));
    let evidence = question
        .evidence
        .iter()
        .filter_map(|id| life.evidence_text(id))
        .map(|(id, text)| (id.to_owned(), normal(text)))
        .collect::<Vec<_>>();
    let found = pieces.iter().enumerate().find_map(|(rank, item)| {
        evidence
            .iter()
            .find(|(_, turn)| !turn.is_empty() && item.iter().any(|p| holds(p, turn)))
            .map(|(id, _)| (rank + 1, id.clone()))
    });
    Scored {
        answer_in_context,
        evidence_rank: found.as_ref().map(|(rank, _)| *rank),
        evidence_turn: found.map(|(_, id)| id),
    }
}

/// 16 hex of blake3 over the returned texts, so two runs' answers compare.
pub(super) fn texts_digest(items: &[Vec<String>]) -> String {
    let mut hasher = blake3::Hasher::new();
    for texts in items {
        for text in texts {
            hasher.update(text.as_bytes());
            hasher.update(b"\x1f");
        }
        hasher.update(b"\x1e");
    }
    hasher.finalize().to_hex()[..16].to_owned()
}
