//! INBOX, the seventh core section (ARCH-0067, AGM-3): who is talking to me
//! and what still needs me. Its rows are this agent's slice of the ARCH-0063
//! inbox lens, in the lens's impact order. It stores nothing and hides when
//! nothing is addressed to the agent.
use super::frame::{BoardFrameError, BoardSection, SectionPolicy, ShedRank};
use super::one_line_token;
use super::people::PeopleView;
use crate::agent_inbox_lens::{AgentInboxItemKind, AgentInboxLensItem};
use crate::entity_id::EntityId;

/// INBOX for `actor`, or `None` when its slice is empty. One row per item:
/// the item handle, its kind, impact, the actor's own identity that carries
/// it, the thread, how many identities share that thread, and the other
/// persons on it, named by handle (PEOPLE, ARCH-0067). A concern row (OF-568)
/// names the agent it is about, its signal and tone, and sits with the other
/// concerns on that agent. Rows hold refs only; foreign message text never
/// renders here.
pub fn assemble_inbox_section(
    actor: EntityId,
    items: &[AgentInboxLensItem],
    people: &PeopleView<'_>,
) -> Result<Option<BoardSection>, BoardFrameError> {
    if items.is_empty() {
        return Ok(None);
    }
    // Concerns group per agent: each after the last row on the same subject.
    let mut ordered: Vec<&AgentInboxLensItem> = Vec::with_capacity(items.len());
    for item in items {
        let group = item.concern.and_then(|concern| {
            ordered.iter().rposition(|row| {
                row.concern
                    .is_some_and(|other| other.subject == concern.subject)
            })
        });
        match group {
            Some(at) => ordered.insert(at + 1, item),
            None => ordered.push(item),
        }
    }
    let rows = ordered
        .into_iter()
        .map(|item| {
            let kind = match item.kind {
                AgentInboxItemKind::Conversation => "conversation",
                AgentInboxItemKind::ApprovalRequired => "waiting",
                AgentInboxItemKind::CoordinationUpdate => "update",
                AgentInboxItemKind::Concern => "concern",
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
            if let Some(concern) = item.concern {
                row.push_str(&format!(
                    " about={} signal={} tone={}",
                    people.label(concern.subject),
                    concern.signal.as_str(),
                    concern.tone.as_str()
                ));
            } else if item.participants.len() > 1 {
                row.push_str(&format!(" identities={}", item.participants.len()));
            }
            let mut others = Vec::new();
            for participant in &item.participants {
                if participant.actor_ref != actor && !others.contains(&participant.actor_ref) {
                    others.push(participant.actor_ref);
                }
            }
            if !others.is_empty() {
                row.push_str(&format!(
                    " with={}",
                    others
                        .into_iter()
                        .map(|other| people.label(other))
                        .collect::<Vec<_>>()
                        .join(",")
                ));
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
