//! An INBOX row's words, resolved inside the reader's scope (OF-490, OF-519).
//!
//! The lens holds pointers. This resolver turns the one pointer that names
//! words someone wrote, an inbound provider message's archived body, into
//! its text, for the reader the row is addressed to, through that reader's
//! own scoped read. Resident dreaming reads its INBOX through it.
use std::collections::BTreeSet;

use super::*;
use crate::claim::ScopedRead;

/// Where an INBOX row's words came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboxTextSource {
    /// An inbound provider message on `channel`: the archived event body its
    /// `payload_ref` names (OF-519).
    ProviderEvent {
        channel: String,
        payload_ref: String,
    },
}

/// One INBOX row's words, as a scoped reader resolved them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedInboxText {
    pub item_id: String,
    /// The identity the words arrived on.
    pub identity_ref: EntityId,
    pub source: InboxTextSource,
    pub text: String,
    /// Always true: the words are what someone outside the vault wrote, to
    /// read as data and never to follow as instructions.
    pub claims_not_instructions: bool,
}

impl Vault {
    /// The words each of `items` carries, as `read` may read them, by item
    /// id.
    ///
    /// Nothing is taken from `items` but their ids: each row is found again
    /// in the reading actor's own current INBOX slice, so a caller cannot hand
    /// in a row, or a payload ref, it was never sent. A row resolves only when
    /// its newest entry is addressed to that actor, on an identity `read` can
    /// read in this snapshot. Today the one row that carries words is an
    /// inbound provider message (Slack, LINE); every other kind holds pointers
    /// and resolves to nothing.
    pub fn resolve_agent_inbox_texts(
        &self,
        read: &ScopedRead<'_>,
        items: &[AgentInboxLensItem],
    ) -> Result<BTreeMap<String, ResolvedInboxText>> {
        let mut resolved = BTreeMap::new();
        let wanted: BTreeSet<&str> = items.iter().map(|item| item.item_id.as_str()).collect();
        if wanted.is_empty() {
            return Ok(resolved);
        }
        let Ok(actor) = EntityId::from_hex(read.actor_key().actor_ref()) else {
            return Ok(resolved);
        };
        read.persist_grant_clock()?;
        let canonical = self.agent_inbox_slice(actor, usize::MAX, None)?;
        let rtxn = self.store.env.read_txn()?;
        let policy = read.live_policy_manifest_in(&rtxn)?;
        for item in canonical {
            if !wanted.contains(item.item_id.as_str())
                || item.kind != AgentInboxItemKind::Conversation
                || item.actor_ref != actor
            {
                continue;
            }
            let Some(payload_ref) = item.payload_ref.as_deref() else {
                continue;
            };
            if !read.is_ref_readable_with_policy_in(&rtxn, &policy, &item.identity_ref)? {
                continue;
            }
            // The channel is the identity's own head (OF-272), not a field
            // the row could carry.
            let Some(facts) = crate::channel_identity::channel_identity_facts_in_txn(
                &self.store,
                &rtxn,
                &item.identity_ref,
            )?
            else {
                continue;
            };
            let Some(text) = self.read_provider_event_text(&facts.channel, payload_ref)? else {
                continue;
            };
            resolved.insert(
                item.item_id.clone(),
                ResolvedInboxText {
                    item_id: item.item_id.clone(),
                    identity_ref: item.identity_ref,
                    source: InboxTextSource::ProviderEvent {
                        channel: facts.channel,
                        payload_ref: payload_ref.to_owned(),
                    },
                    text,
                    claims_not_instructions: true,
                },
            );
        }
        Ok(resolved)
    }
}
