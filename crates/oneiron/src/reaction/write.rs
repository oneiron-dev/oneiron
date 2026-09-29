//! First-party reaction writes on the (message, person, glyph) chain, and the
//! claim write both first-party and mirrored reactions share.
use super::chain::{StoredReaction, chain_in};
use super::value::{PREDICATE_CONVERSATION_REACTION, ReactionValue};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::conversation::{AudienceCache, room_for_record_in, room_person_write_allowed};
use crate::conversation_dag::{actor_in_txn, require_type};
use crate::edge::EdgeActorClass;
use crate::error::{Error, RecordError, Result};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{
    ClaimCandidate, EntityId, TimeRange, Vault, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

/// A standalone reaction is weak evidence: it is findable by a direct query
/// but never outranks an ordinary memory of equal relevance.
pub(crate) const REACTION_STANDALONE_WEIGHT: f32 = 0.1;
/// Salience stamped on each reaction claim.
const REACTION_SALIENCE: f32 = 0.1;
/// Message text copied into a reaction's lexical document.
const INDEXED_EXCERPT_CHARS: usize = 280;
/// Tolerated provider clock skew for a reaction's occurrence time (seconds).
const OCCURRENCE_SKEW: u64 = 300;

pub(super) fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

pub(super) fn denied() -> Error {
    Error::Record(RecordError::ConversationDenied)
}

/// A reaction put by the reacting person (a human or an agent PERSON).
#[derive(Debug, Clone)]
pub struct ReactionInput {
    pub message: EntityId,
    pub by: EntityId,
    pub glyph: String,
    pub occurred_at: u64,
    pub actor: WriteActor,
}

/// The observable effect of a reaction request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReactionState {
    Put,
    Revoked,
    Replayed,
}

impl ReactionState {
    /// The agent-facing event name of this effect.
    #[must_use]
    pub const fn event(self) -> &'static str {
        match self {
            Self::Put => "reaction.put",
            Self::Revoked => "reaction.revoked",
            Self::Replayed => "reaction.replayed",
        }
    }
}

/// The reaction claim a request resolved to, and what happened to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReactionChange {
    pub id: EntityId,
    pub state: ReactionState,
}

/// The room of a live MESSAGE or TURN a reaction may target.
pub(super) fn target_room_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
) -> Result<EntityId> {
    match live_entity_row_in_txn(&vault.store, txn, &record)? {
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_MESSAGE | ENTITY_TYPE_TURN,
            ..
        } => {}
        _ => return Err(invalid("reaction target is not a live conversation record")),
    }
    if vault.archive_tombstone_in_txn(txn, &record)?.is_some() {
        return Err(invalid("reaction target is not a live conversation record"));
    }
    room_for_record_in(vault, txn, record)?.ok_or_else(|| invalid("reaction target has no room"))
}

/// The reacting PERSON must be live and may still write in the room.
pub(super) fn require_reactor_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    by: EntityId,
) -> Result<()> {
    require_type(&vault.store, txn, &by, ENTITY_TYPE_PERSON)?;
    if !room_person_write_allowed(&vault.store, txn, room, by)? {
        return Err(denied());
    }
    Ok(())
}

pub(super) fn require_occurrence(vault: &Vault, occurred_at: u64) -> Result<u64> {
    let now = vault.store.clock.now_recorded_at();
    if occurred_at > now.saturating_add(OCCURRENCE_SKEW) {
        return Err(invalid("reaction occurrence is in the future"));
    }
    Ok(now)
}

fn first_party_envelope(actor: WriteActor) -> Result<WriteEnvelope> {
    let source = match actor.actor_class() {
        EdgeActorClass::Human => ClaimSource::UserStated,
        EdgeActorClass::Agent | EdgeActorClass::System => ClaimSource::Observed,
    };
    Ok(WriteEnvelope::new(
        actor,
        source,
        WriteProvenance::new(Value::Map(vec![(
            Value::from("kind"),
            Value::from("conversation_reaction"),
        )]))?,
        ClaimApprovalStatus::Auto,
    ))
}

/// The lexical document of a reaction: its glyph, the reactor's name and an
/// excerpt of the reacted record, so a direct question can reach it.
fn indexed_text(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    message: EntityId,
    value: &ReactionValue,
) -> Result<String> {
    let mut text = value.glyph.clone();
    if let Some(name) = super::read::person_name_in(vault, txn, value.by)? {
        text.push(' ');
        text.push_str(&name);
    }
    if let Some(excerpt) = super::read::record_text_in(vault, txn, message)? {
        text.push(' ');
        text.extend(excerpt.chars().take(INDEXED_EXCERPT_CHARS));
    }
    Ok(text)
}

/// Writes one reaction claim about `message` and proves its reactor is in the
/// room audience at the reaction's own time, in the caller's transaction. A
/// MACHINE envelope is signed with the signer the host retained for it.
pub(super) fn write_reaction_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    message: EntityId,
    value: &ReactionValue,
    mut envelope: WriteEnvelope,
    learned_at: u64,
) -> Result<EntityId> {
    value.validate()?;
    let id = vault.store.clock.entity_id()?;
    let candidate = ClaimCandidate::new(
        PREDICATE_CONVERSATION_REACTION,
        ClaimSubject::Entity(message),
        value.to_value(),
        1.0,
    )
    .with_salience(REACTION_SALIENCE);
    vault.sign_retained_machine_claim_in_txn(txn, &id, &candidate, &mut envelope)?;
    let text = indexed_text(vault, txn, message, value)?;
    vault
        .batch_in()
        .claim_candidate(
            &id,
            candidate,
            &envelope,
            TimeRange {
                start: value.occurred_at,
                end: value.occurred_at,
            },
            learned_at,
        )
        .text(&id, &[("val", text.as_str())])
        .apply(txn)?;
    // One audience rule governs writes and reads: the reactor must be able to
    // read the message and be in the room at the reaction's occurrence time.
    if !AudienceCache::default().readable(vault, txn, id, &[value.by])? {
        return Err(denied());
    }
    Ok(id)
}

/// Retracts one live reaction claim; a MACHINE-born claim's close is signed by
/// the MACHINE that wrote it.
pub(super) fn retract_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &StoredReaction,
    now: u64,
) -> Result<()> {
    vault.retract_claim_in_txn_as(txn, &row.id, now.max(row.value.occurred_at), row.writer())?;
    Ok(())
}

impl Vault {
    /// Puts a first-party reaction. A repeat put of a live (message, person,
    /// glyph) reaction is idempotent; a put after a remove is a new claim in
    /// the same chain.
    pub fn react(&self, input: ReactionInput) -> Result<ReactionChange> {
        let value = ReactionValue {
            glyph: input.glyph,
            occurred_at: input.occurred_at,
            by: input.by,
            external_id: None,
        };
        value.validate()?;
        self.with_write_txn(|txn| {
            actor_in_txn(&self.store, txn, input.actor)?;
            if input.actor.entity_ref() != input.by {
                return Err(invalid("reactor is not the write actor"));
            }
            let room = target_room_in(self, txn, input.message)?;
            require_reactor_in(self, txn, room, input.by)?;
            let now = require_occurrence(self, value.occurred_at)?;
            if let Some(live) = chain_in(self, txn, input.message, input.by, &value.glyph)?
                .into_iter()
                .rev()
                .find(StoredReaction::live)
            {
                return Ok(ReactionChange {
                    id: live.id,
                    state: ReactionState::Replayed,
                });
            }
            let envelope = first_party_envelope(input.actor)?;
            let id = write_reaction_in_txn(self, txn, input.message, &value, envelope, now)?;
            super::outbound::enqueue_in_txn(self, txn, id, room, false)?;
            Ok(ReactionChange {
                id,
                state: ReactionState::Put,
            })
        })
    }

    /// Removes the person's live reaction: its claim is retracted and stays
    /// readable in the chain's history. Removing nothing is idempotent.
    pub fn remove_reaction(
        &self,
        message: EntityId,
        by: EntityId,
        glyph: &str,
        actor: WriteActor,
    ) -> Result<ReactionChange> {
        self.with_write_txn(|txn| {
            actor_in_txn(&self.store, txn, actor)?;
            if actor.entity_ref() != by {
                return Err(invalid("reactor is not the write actor"));
            }
            let room = target_room_in(self, txn, message)?;
            require_reactor_in(self, txn, room, by)?;
            let chain = chain_in(self, txn, message, by, glyph)?;
            let Some(live) = chain.iter().rev().find(|row| row.live()) else {
                let last = chain
                    .last()
                    .ok_or_else(|| invalid("no reaction to remove"))?;
                return Ok(ReactionChange {
                    id: last.id,
                    state: ReactionState::Replayed,
                });
            };
            let id = live.id;
            let now = self.store.clock.now_recorded_at();
            // Offline peers can each have put the same reaction; the remove
            // retracts every live claim of the tuple, so none survives it.
            for row in chain.iter().filter(|row| row.live()) {
                retract_in_txn(self, txn, row, now)?;
                if row.first_party() {
                    super::outbound::enqueue_in_txn(self, txn, row.id, room, true)?;
                }
            }
            Ok(ReactionChange {
                id,
                state: ReactionState::Revoked,
            })
        })
    }
}
