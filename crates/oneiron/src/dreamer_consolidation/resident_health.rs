//! A resident's own health cards as its dreaming's input (OF-490, FIX
//! 1145/1146): the cards whose subject is the resident, read through the
//! public card query, oldest touch first past its dreaming's cursor. A card
//! is mutable (a repeat merges into it, a person settles it), so the cursor
//! is the time it was last touched with its handle: a card touched again
//! after a dreaming read it is read again, with what changed. A card holds
//! refs and numbers, never a diary body, and the facts read here are only
//! those.

use crate::dreamer_runner::maintenance::agent_health::AgentHealthCard;
use crate::{EntityId, Vault};

/// One card's facts, keyed by the `(time last touched, handle)` cursor a
/// dreaming that reads it moves to.
pub(super) type HealthCardLine = ((u64, String), String);

/// The time `card` was last touched: opened, updated or settled.
fn touched_at(card: &AgentHealthCard) -> u64 {
    card.updated_at
        .max(card.opened_at)
        .max(card.outcome_at.unwrap_or(0))
}

/// The facts one card says about its resident, on one line.
fn card_line(card: &AgentHealthCard, at: u64) -> String {
    let mut line = format!(
        "- {at} {} {:?}: measured {} against dial {} over {}..{}, {:?} confidence, {} evidence, outcome {:?}",
        card.signal.as_str(),
        card.tone,
        card.measured,
        card.dial,
        card.window_from,
        card.window_to,
        card.confidence,
        card.evidence.len(),
        card.outcome,
    );
    if let Some(task) = card.task {
        line.push_str(&format!(" task {}", task.to_hex()));
    }
    if card.agent_blocked {
        line.push_str(", you said you were stuck");
    }
    line.push_str(&format!(" ({})", card.card_ref()));
    line
}

/// The health cards about `resident` touched past `(after, after_id)`,
/// oldest touch first, ties by handle. A card query that does not read
/// leaves the dreaming as it was: it reads no card and its cursor stays.
pub(super) fn health_card_lines(
    vault: &Vault,
    resident: EntityId,
    after: u64,
    after_id: &str,
) -> Vec<HealthCardLine> {
    let cards = match vault.agent_health_cards_between(after, u64::MAX) {
        Ok(cards) => cards,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                resident = %resident.to_hex(),
                "a resident's health cards did not read; it dreams without them"
            );
            return Vec::new();
        }
    };
    let mut lines: Vec<HealthCardLine> = cards
        .iter()
        .filter(|card| card.subject == resident)
        .map(|card| {
            let at = touched_at(card);
            ((at, card.card_ref()), card_line(card, at))
        })
        .filter(|((at, id), _)| (*at, id.as_str()) > (after, after_id))
        .collect();
    lines.sort_by(|left, right| left.0.cmp(&right.0));
    lines
}
