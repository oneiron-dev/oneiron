//! Where an agent-health card is delivered (ARCH-0063 concern cards): the
//! inbox rows its readers see. An open card goes to its recipients. A card
//! that copies to the owner keeps reaching each live owner among them after
//! its leader or spawner settles it (FIX 8709; ARCH-0063: "It goes there even
//! when the project leader acts on it"), until that owner's own outcome
//! receipt covers the card's current evidence. A render or a read is no
//! receipt, and a leader's or spawner's receipt never covers an owner. New
//! evidence reopens the card and no receipt covers it yet; a late label adds
//! no evidence, so it uncovers nothing.

use std::collections::HashSet;

use super::{AgentHealthCard, AgentHealthOutcome, CARD_REF_PREFIX, CARDS, card_ref};
use crate::agent_inbox_lens::{
    AgentInboxConcern, AgentInboxItemKind, AgentInboxLensItem, AgentInboxParticipant, InboxImpact,
};
use crate::{EntityId, Result, Vault};

/// The cards as inbox rows: kind Concern, under "Waiting on you", one row
/// per card, each naming the agent it is about so a renderer groups them per
/// agent. Never folded into a thread. An open card's row goes to its
/// recipients; a settled card's, when it copies to the owner, to the owners
/// it still waits on ([`pending_owners`]), with the same row. The live owners
/// are read once, in the cards' snapshot, and only when a settled copy needs
/// them: a census that fails is logged and leaves the settled cards out.
pub(crate) fn agent_health_inbox_items(vault: &Vault) -> Result<Vec<AgentInboxLensItem>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut census: Option<Vec<EntityId>> = None;
    let mut items = Vec::new();
    for (key, card) in CARDS.scan(&vault.store, &rtxn)? {
        let readers = if card.outcome == AgentHealthOutcome::Open {
            card.recipients.clone()
        } else if card.owner_copy {
            let owners = census.get_or_insert_with(|| {
                crate::policy_model::owners_in_txn(vault, &rtxn).unwrap_or_else(|error| {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "agent-health owner notices not read; settled cards left out"
                    );
                    Vec::new()
                })
            });
            pending_owners(&card, owners)
        } else {
            continue;
        };
        if readers.is_empty() {
            continue;
        }
        let participants = readers
            .into_iter()
            .map(|reader| AgentInboxParticipant {
                identity_ref: Some(reader),
                actor_ref: reader,
            })
            .collect();
        let card_ref = card_ref(&key);
        items.push(AgentInboxLensItem {
            item_id: format!("concern:{}", &card_ref[CARD_REF_PREFIX.len()..]),
            kind: AgentInboxItemKind::Concern,
            thread_ref: None,
            identity_ref: Some(card.subject),
            actor_ref: card.subject,
            facet_ref: None,
            participants,
            impact: InboxImpact(card.tone.impact()),
            occurred_at: card.window_to,
            receipt_ref: card.diagnostics.last().map(EntityId::to_hex),
            payload_ref: Some(card_ref),
            concern: Some(AgentInboxConcern {
                subject: card.subject,
                signal: card.signal,
                tone: card.tone,
            }),
            diary_review: None,
            sender: None,
            widening: None,
        });
    }
    Ok(items)
}

/// The owners `card`'s notice still waits on: each recipient who is one of
/// the live vault `owners` and has set no outcome of its own, as an owner,
/// over the card's evidence as it stands now.
fn pending_owners(card: &AgentHealthCard, owners: &[EntityId]) -> Vec<EntityId> {
    card.recipients
        .iter()
        .copied()
        .filter(|recipient| owners.contains(recipient) && !acknowledged(card, *recipient))
        .collect()
}

/// Whether `owner` set an outcome on `card`, as an owner, whose receipt
/// holds every evidence id the card holds now.
fn acknowledged(card: &AgentHealthCard, owner: EntityId) -> bool {
    card.review_outcomes
        .iter()
        .filter(|receipt| receipt.by == owner && receipt.by_owner)
        .any(|receipt| {
            let held: HashSet<&EntityId> = receipt.evidence.iter().collect();
            card.evidence.iter().all(|id| held.contains(id))
        })
}
