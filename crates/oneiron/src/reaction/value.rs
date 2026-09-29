//! The `conversation.reaction` value and its provider-echo binding value.
use crate::EntityId;
use crate::claim::{ClaimBody, ClaimSubject};
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY;
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
const KEY_CONNECTOR: &str = "connector";
const KEY_ID: &str = "id";
const MAX_GLYPH_SCALARS: usize = 64;
const MAX_CONNECTOR_BYTES: usize = 256;
const MAX_EXTERNAL_ID_BYTES: usize = 1024;

fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

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

fn exact_map<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<Vec<(&'a str, &'a Value)>> {
    let Value::Map(entries) = value else {
        return Err(invalid("reaction value must be a map"));
    };
    let mut seen = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let key = key
            .as_str()
            .filter(|key| required.contains(key) || optional.contains(key))
            .ok_or_else(|| invalid("reaction value key"))?;
        if seen.iter().any(|(prior, _)| *prior == key) {
            return Err(invalid("duplicate reaction value key"));
        }
        seen.push((key, value));
    }
    if required
        .iter()
        .any(|key| !seen.iter().any(|(seen, _)| seen == key))
    {
        return Err(invalid("missing reaction value key"));
    }
    Ok(seen)
}

fn find<'a>(entries: &[(&str, &'a Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, value)| *value)
}

fn string<'a>(entries: &[(&str, &'a Value)], key: &str) -> Result<&'a str> {
    find(entries, key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("reaction value string"))
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
        && evidence_entry(body, "machine_signature").is_some()
}

/// Structural rule for the reaction family, run on every claim write door,
/// replicated rows included: a first-party reaction is authored by the person
/// it names, and only a signed MACHINE may attest someone else's reaction.
pub(crate) fn validate_reaction_claim_structure(body: &ClaimBody) -> Result<()> {
    let ClaimSubject::Entity(_) = body.subject else {
        return Err(invalid("reaction subject must be an entity"));
    };
    let author =
        crate::memory::claim_author(body).ok_or_else(|| invalid("reaction claim has no author"))?;
    if body.predicate == PREDICATE_CONVERSATION_REACTION_ECHO {
        ReactionExternalId::from_value(&body.value)?;
        if !machine_written(body) {
            return Err(invalid("reaction echo must be written by a signed machine"));
        }
        return Ok(());
    }
    let value = ReactionValue::from_value(&body.value)?;
    if value.by != author && !machine_written(body) {
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
