//! CONV-09 reaction facade verbs (OF-372, ONE-1991).
//!
//! Thin [`Memory`] verbs over the engine reaction door: toggle, grouped
//! pills with `with=reactions`-style listing signals, and the agent inbox.
//! Native routes (not bypasses): every verb rides `Vault::react` /
//! `grouped_reaction_pills` / `reactions_since` / `reactions_outbound`.

use crate::conversation::reaction::{
    GROUPED_PILLS_MAX_MESSAGES, ReactInput, ReactOutcome, ReactionExternalId, ReactionGrouping,
    ReactionSignal, ReactionsOutbound,
};
use crate::edge::EdgeActorClass;
use crate::memory::{Memory, MemoryError, MemoryResult};
use serde::{Deserialize, Serialize};

use super::support::resolve_entity_ref;

/// Toggle input for one reaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactToMessageInput {
    /// MESSAGE ref (hex or short ref) inside a conversation.
    pub message_ref: String,
    /// Reactor PERSON ref; `None` ⇒ the bound facade actor.
    pub by_ref: Option<String>,
    /// Glyph: non-empty, at most 64 Unicode scalar values.
    pub glyph: String,
    /// Occurrence timestamp (Unix seconds).
    pub at: u64,
    /// Mirrored provenance; `None` ⇒ first-party.
    pub ext: Option<ReactionExternalId>,
}

/// Receipt for one reaction toggle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionReceipt {
    /// `put` for a fresh record, `revoked` for a tombstone toggle.
    pub state: String,
    /// 32-hex id of the affected reaction record.
    pub reaction_id: String,
    /// Short-id ref when one is assigned, else the hex id.
    pub reaction_ref: String,
}

impl Memory<'_> {
    /// Toggles one reaction for `(message, by, glyph)`.
    ///
    /// React-as-self: `by` defaults to the bound actor and any other `by`
    /// is refused — the door stamps `by` from the verified actor, never from
    /// caller bytes. Agents are persons: an agent-class PERSON reacts through
    /// the same verb with its own bound actor.
    pub fn react_to_message(&self, input: ReactToMessageInput) -> MemoryResult<ReactionReceipt> {
        self.verified_actor_class()?;
        if self.actor_class != EdgeActorClass::Human && self.actor_class != EdgeActorClass::Agent {
            return Err(MemoryError::new(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "only human and agent actors react",
                &["Bind a human or agent actor key to react."],
            ));
        }
        let message = resolve_entity_ref(self.vault, &input.message_ref)?;
        let by = match &input.by_ref {
            Some(reference) => resolve_entity_ref(self.vault, reference)?,
            None => self.actor,
        };
        if by != self.actor {
            return Err(MemoryError::new(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "reaction by must be the bound actor",
                &["React as yourself; pass no by_ref or your own ref."],
            ));
        }
        let request = ReactInput {
            message,
            by,
            glyph: input.glyph,
            at: input.at,
            ext: input.ext,
        };
        let (outcome, publish) = self.with_verified_actor_write_txn(|txn| {
            self.vault
                .react_in_txn(txn, &self.actor, &request, crate::unix_seconds_now())
                .map_err(MemoryError::from)
        })?;
        if let Some((id, learned_at, tombstone)) = publish {
            self.vault
                .publish_reaction_revocation(&id, learned_at, &tombstone)
                .map_err(MemoryError::from)?;
        }
        let reaction_ref = self.short_ref_or_hex(&outcome.reaction_id)?;
        Ok(ReactionReceipt {
            state: match outcome.state {
                crate::conversation::reaction::ReactionState::Put => "put".to_owned(),
                crate::conversation::reaction::ReactionState::Revoked => "revoked".to_owned(),
            },
            reaction_id: outcome.reaction_id.to_hex(),
            reaction_ref,
        })
    }

    /// Grouped pills across messages in one batched read (zero follow-ups).
    pub fn reaction_pills(
        &self,
        message_refs: &[String],
        viewer_ref: Option<String>,
    ) -> MemoryResult<Vec<ReactionGrouping>> {
        if message_refs.len() > GROUPED_PILLS_MAX_MESSAGES {
            return Err(MemoryError::bad_request(
                "grouped pills accept at most 50 messages",
            ));
        }
        let mut messages = Vec::with_capacity(message_refs.len());
        for reference in message_refs {
            messages.push(resolve_entity_ref(self.vault, reference)?);
        }
        let viewer = match viewer_ref {
            Some(reference) => resolve_entity_ref(self.vault, &reference)?,
            None => self.actor,
        };
        if viewer != self.actor {
            return Err(MemoryError::new(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "reaction viewer must be the bound actor",
                &[],
            ));
        }
        self.vault
            .grouped_reaction_pills(&messages, &viewer)
            .map_err(MemoryError::from)
    }

    /// Agent signal: reactions on `person`'s messages at/after `since`.
    pub fn reactions_since(
        &self,
        person_ref: Option<String>,
        since: u64,
    ) -> MemoryResult<Vec<ReactionSignal>> {
        let person = match person_ref {
            Some(reference) => resolve_entity_ref(self.vault, &reference)?,
            None => self.actor,
        };
        if person != self.actor {
            return Err(MemoryError::new(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "reaction inbox belongs to the bound actor",
                &[],
            ));
        }
        self.vault
            .reactions_since(&person, since)
            .map_err(MemoryError::from)
    }

    /// Room outbound posture for reactions: `mirrored | first_party_only`.
    pub fn reactions_outbound(&self, conversation_ref: &str) -> MemoryResult<ReactionsOutbound> {
        let conversation = resolve_entity_ref(self.vault, conversation_ref)?;
        self.vault
            .reactions_outbound(&conversation)
            .map_err(MemoryError::from)
    }

    /// Ingests one mirrored surface reaction idempotently on `ext`.
    ///
    /// The mirrored path into [`Self::react_to_message`]: same record shape
    /// with `ext`, same toggle law, duplicate delivery a no-op. `by` is the
    /// mirrored reactor PERSON (which must exist); the bound actor is the
    /// ingesting identity and need not equal `by`.
    pub fn ingest_mirrored_reaction(
        &self,
        message_ref: &str,
        by_ref: &str,
        glyph: &str,
        at: u64,
        ext: ReactionExternalId,
    ) -> MemoryResult<ReactionReceipt> {
        self.verified_actor_class()?;
        if self.actor_class != EdgeActorClass::System {
            return Err(MemoryError::new(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "mirrored ingestion requires a system adapter actor",
                &[],
            ));
        }
        let message = resolve_entity_ref(self.vault, message_ref)?;
        let by = resolve_entity_ref(self.vault, by_ref)?;
        let outcome: ReactOutcome = self
            .vault
            .react(
                &by,
                ReactInput {
                    message,
                    by,
                    glyph: glyph.to_owned(),
                    at,
                    ext: Some(ext),
                },
            )
            .map_err(MemoryError::from)?;
        let reaction_ref = self.short_ref_or_hex(&outcome.reaction_id)?;
        Ok(ReactionReceipt {
            state: match outcome.state {
                crate::conversation::reaction::ReactionState::Put => "put".to_owned(),
                crate::conversation::reaction::ReactionState::Revoked => "revoked".to_owned(),
            },
            reaction_id: outcome.reaction_id.to_hex(),
            reaction_ref,
        })
    }
}
