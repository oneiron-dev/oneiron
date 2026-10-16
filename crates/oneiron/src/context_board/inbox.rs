//! INBOX, the seventh core section (ARCH-0067, AGM-3): who is talking to me
//! and what still needs me. Its rows are this agent's slice of the ARCH-0063
//! inbox lens, in the lens's impact order. It stores nothing and hides when
//! nothing is addressed to the agent.
use super::frame::{BoardFrameError, BoardSection, SectionPolicy, ShedRank};
use super::one_line_token;
use crate::agent_inbox_lens::{AgentInboxItemKind, AgentInboxLensItem};
use crate::entity_id::EntityId;

/// INBOX for `actor`, or `None` when its slice is empty. One row per item:
/// the item handle, its kind, impact, the actor's own identity that carries
/// it, the thread, and how many identities share that thread. Rows hold
/// refs only; foreign message text never renders here.
pub fn assemble_inbox_section(
    actor: EntityId,
    items: &[AgentInboxLensItem],
) -> Result<Option<BoardSection>, BoardFrameError> {
    if items.is_empty() {
        return Ok(None);
    }
    let rows = items
        .iter()
        .map(|item| {
            let kind = match item.kind {
                AgentInboxItemKind::Conversation => "conversation",
                AgentInboxItemKind::ApprovalRequired => "waiting",
                AgentInboxItemKind::CoordinationUpdate => "update",
            };
            let via = item
                .participants
                .iter()
                .find(|participant| participant.actor_ref == actor)
                .map_or(item.identity_ref, |participant| participant.identity_ref);
            let mut row = format!(
                "{} {kind} impact={} via={}",
                one_line_token(&item.item_id),
                item.impact.0,
                via.to_hex()
            );
            if let Some(thread) = item
                .thread_ref
                .as_deref()
                .filter(|thread| !item.item_id.ends_with(thread))
            {
                row.push_str(&format!(" thread={}", one_line_token(thread)));
            }
            if item.participants.len() > 1 {
                row.push_str(&format!(" identities={}", item.participants.len()));
            }
            row
        })
        .collect();
    BoardSection::new(
        "INBOX",
        Vec::new(),
        rows,
        vec![format!("count: {}", items.len())],
        SectionPolicy {
            pinned: false,
            shed_rank: Some(ShedRank::TasksToCounts),
        },
    )
    .map(Some)
}
