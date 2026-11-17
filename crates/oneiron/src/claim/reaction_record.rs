//! The `conversation.reaction` value and its provider-echo binding value.
use crate::EntityId;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY;
use crate::write_envelope::claim_body::{ClaimBody, ClaimSubject};
use rmpv::Value;

/// One live reaction per (message, person, glyph); the chain is that tuple.
pub const PREDICATE_CONVERSATION_REACTION: &str = "conversation.reaction";
/// Binds a provider echo of a first-party reaction to its original claim.
/// Metadata about a reaction claim, never a second reaction.
pub const PREDICATE_CONVERSATION_REACTION_ECHO: &str = "conversation.reaction.echo";

const KEY_GLYPH: &str = "glyph";
const KEY_OCCURRED_AT: &str = "occurredAt";
const KEY_BY: &str = "by";
const KEY_EXTERNAL_ID: &str = "externalId";
#[doc(hidden)]
use oneiron_records::claim::reaction_record::{
    KEY_CONNECTOR, KEY_ID, MAX_CONNECTOR_BYTES, MAX_EXTERNAL_ID_BYTES, exact_map, find, invalid,
    string,
};

const MAX_GLYPH_SCALARS: usize = 64;
pub(crate) fn is_reaction_claim_predicate(predicate: &str) -> bool {
    predicate == PREDICATE_CONVERSATION_REACTION
        || predicate == PREDICATE_CONVERSATION_REACTION_ECHO
}

/// A connector's stable provider generation for one add. A remove and a later
/// re-add carry distinct ids; a delivery id is not a generation.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct ReactionExternalId {
    pub connector: String,
    pub id: String,
}

impl ReactionExternalId {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.connector.trim().is_empty()
            || self.id.trim().is_empty()
            || self.connector.len() > MAX_CONNECTOR_BYTES
            || self.id.len() > MAX_EXTERNAL_ID_BYTES
        {
            return Err(invalid("reaction external id"));
        }
        Ok(())
    }

    pub(crate) fn to_value(&self) -> Value {
        Value::Map(vec![
            (
                Value::from(KEY_CONNECTOR),
                Value::from(self.connector.as_str()),
            ),
            (Value::from(KEY_ID), Value::from(self.id.as_str())),
        ])
    }

    fn from_value(value: &Value) -> Result<Self> {
        let entries = exact_map(value, &[KEY_CONNECTOR, KEY_ID], &[])?;
        let external = Self {
            connector: string(&entries, KEY_CONNECTOR)?.to_owned(),
            id: string(&entries, KEY_ID)?.to_owned(),
        };
        external.validate()?;
        Ok(external)
    }
}

/// The value of one `conversation.reaction` claim. `by` is the reacting
/// PERSON: the envelope actor of a first-party write, or the person a signed
/// connector MACHINE observed reacting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionValue {
    pub glyph: String,
    pub occurred_at: u64,
    pub by: EntityId,
    pub external_id: Option<ReactionExternalId>,
}

impl ReactionValue {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_glyph(&self.glyph)?;
        if let Some(external) = &self.external_id {
            external.validate()?;
        }
        Ok(())
    }

    pub(crate) fn to_value(&self) -> Value {
        let mut entries = vec![
            (Value::from(KEY_GLYPH), Value::from(self.glyph.as_str())),
            (Value::from(KEY_OCCURRED_AT), Value::from(self.occurred_at)),
            (
                Value::from(KEY_BY),
                Value::Binary(self.by.as_bytes().to_vec()),
            ),
        ];
        if let Some(external) = &self.external_id {
            entries.push((Value::from(KEY_EXTERNAL_ID), external.to_value()));
        }
        Value::Map(entries)
    }

    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let entries = exact_map(
            value,
            &[KEY_GLYPH, KEY_OCCURRED_AT, KEY_BY],
            &[KEY_EXTERNAL_ID],
        )?;
        let occurred_at = find(&entries, KEY_OCCURRED_AT)
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("reaction occurredAt"))?;
        let by = match find(&entries, KEY_BY) {
            Some(Value::Binary(bytes)) => EntityId::from_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| invalid("reaction by"))?,
            )
            .map_err(|_| invalid("reaction by"))?,
            _ => return Err(invalid("reaction by")),
        };
        let external_id = find(&entries, KEY_EXTERNAL_ID)
            .map(ReactionExternalId::from_value)
            .transpose()?;
        let value = Self {
            glyph: string(&entries, KEY_GLYPH)?.to_owned(),
            occurred_at,
            by,
            external_id,
        };
        value.validate()?;
        Ok(value)
    }
}

fn validate_glyph(glyph: &str) -> Result<()> {
    let scalars = glyph.chars().count();
    if scalars == 0 || scalars > MAX_GLYPH_SCALARS || glyph.chars().any(char::is_control) {
        return Err(invalid("reaction glyph must have 1..=64 printable scalars"));
    }
    Ok(())
}

fn evidence_entry<'a>(body: &'a ClaimBody, key: &str) -> Option<&'a Value> {
    let Some(Value::Map(entries)) = body.evidence.as_ref() else {
        return None;
    };
    entries
        .iter()
        .find(|(candidate, _)| candidate.as_str() == Some(key))
        .map(|(_, value)| value)
}

/// Whether the claim's stamped writer is a signed MACHINE (a connector mirror)
/// rather than the reacting person. The door that verifies MACHINE proofs
/// (#1183) runs for every claim carrying one.
pub(crate) fn machine_written(body: &ClaimBody) -> bool {
    evidence_entry(body, WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY)
        .and_then(Value::as_u64)
        .is_some_and(|class| class == EdgeActorClass::System as u64)
        && evidence_entry(body, KEY_MACHINE_SIGNATURE).is_some()
}

/// Structural rule for the reaction family, run on every claim write door,
/// replicated rows included: a first-party reaction is authored by the person
/// it names, and only a signed MACHINE may attest someone else's reaction.
pub(crate) fn validate_reaction_claim_structure(body: &ClaimBody) -> Result<()> {
    let ClaimSubject::Entity(_) = body.subject else {
        return Err(invalid("reaction subject must be an entity"));
    };
    let author =
        crate::claim::claim_author(body).ok_or_else(|| invalid("reaction claim has no author"))?;
    // The one MACHINE that may attest another person's reaction.
    let mirrored = machine_written(body) && author == conversation_mirror_actor_id()?;
    if machine_written(body) && !mirrored {
        return Err(invalid("only the conversation mirror attests a reaction"));
    }
    if body.predicate == PREDICATE_CONVERSATION_REACTION_ECHO {
        ReactionExternalId::from_value(&body.value)?;
        if !mirrored {
            return Err(invalid(
                "reaction echo must be written by the conversation mirror",
            ));
        }
        return Ok(());
    }
    let value = ReactionValue::from_value(&body.value)?;
    if value.by != author && !mirrored {
        return Err(invalid("reaction author must be the reacting person"));
    }
    Ok(())
}

pub(crate) fn decode_reaction(body: &ClaimBody) -> Option<ReactionValue> {
    (body.predicate == PREDICATE_CONVERSATION_REACTION)
        .then(|| ReactionValue::from_value(&body.value).ok())
        .flatten()
}

pub(crate) fn decode_echo(body: &ClaimBody) -> Option<ReactionExternalId> {
    (body.predicate == PREDICATE_CONVERSATION_REACTION_ECHO)
        .then(|| ReactionExternalId::from_value(&body.value).ok())
        .flatten()
}

/// The person a `conversation.reaction` claim names as its reactor: the `by`
/// of its value, read alone so a value the strict decode refuses still names
/// it, or else its writer stamp. Any other claim names none.
pub(crate) fn named_reactor(body: &ClaimBody) -> Option<EntityId> {
    if body.predicate != PREDICATE_CONVERSATION_REACTION {
        return None;
    }
    let by = match &body.value {
        Value::Map(entries) => entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(KEY_BY))
            .and_then(|(_, value)| match value {
                Value::Binary(bytes) => {
                    EntityId::from_bytes(bytes.as_slice().try_into().ok()?).ok()
                }
                _ => None,
            }),
        _ => None,
    };
    by.or_else(|| crate::claim::claim_author(body))
}

/// A reaction claim as a reader who may not read its reactor gets it: every
/// binary under `by` in its value, and under the writer stamp and the machine
/// signature in its evidence, reads as nil. A mirrored reaction's signature
/// covers the whole body, `by` included (`machine_claim_transcript`), so a
/// reader holding candidate ids could test each one against it. The predicate,
/// subject, glyph and time stay, so it still reads as the reaction it counts as
/// (Engine ANSWER REACTION-CLAIM-VALUE-REACTOR-ID = A, 17 Nov 07:32). The keys
/// stay and keep their shape: every JSON door already projects a binary as
/// null, so a context pack's snapshot recheck still matches the served row to
/// the fields it hydrated, and the evidence still reads as a stamped body
/// (`ClaimBody::evidence_ref_slots` keys on the writer stamp being present).
pub(crate) fn withhold_reactor(body: &mut ClaimBody) {
    fn nil_binaries(value: &mut Value) {
        match value {
            Value::Binary(_) => *value = Value::Nil,
            Value::Array(parts) => parts.iter_mut().for_each(nil_binaries),
            Value::Map(entries) => entries
                .iter_mut()
                .for_each(|(_, value)| nil_binaries(value)),
            _ => {}
        }
    }
    let nil_under = |entries: &mut [(Value, Value)], named: &[&str]| {
        for (key, value) in entries.iter_mut() {
            if key.as_str().is_some_and(|key| named.contains(&key)) {
                nil_binaries(value);
            }
        }
    };
    if let Value::Map(entries) = &mut body.value {
        nil_under(entries, &[KEY_BY]);
    }
    if let Some(Value::Map(entries)) = &mut body.evidence {
        nil_under(
            entries,
            &[
                crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY,
                KEY_MACHINE_SIGNATURE,
            ],
        );
    }
}

/// The evidence key a signed MACHINE's write proof rides under.
const KEY_MACHINE_SIGNATURE: &str = "machine_signature";

use crate::entity_id::derived_domains::CONVERSATION_MIRROR_ACTOR;

/// The engine's conversation-mirror write actor: one deterministic MACHINE.
pub fn conversation_mirror_actor_id() -> Result<EntityId> {
    EntityId::derive(CONVERSATION_MIRROR_ACTOR, &[])
}
