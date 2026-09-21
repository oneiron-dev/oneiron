//! Typed actor evidence references for credential-safe archive serialization.
//! These are byte identities only, never imported projector or routing authority.
use super::{
    evidence::ActorClaimEvidence,
    validate::{skill_fit_scope_skill, validate_actor_claim_structure},
};
use crate::{claim::ClaimBody, entity_id::EntityId};
use rmpv::Value;

#[derive(Default)]
pub(crate) struct ActorArchiveReferences {
    pub(crate) skill: Option<EntityId>,
    pub(crate) chat: Option<(EntityId, Vec<EntityId>)>,
}

pub(crate) fn actor_archive_references(body: &ClaimBody) -> Option<ActorArchiveReferences> {
    if !super::is_actor_claim_predicate(&body.predicate)
        || validate_actor_claim_structure(body).is_err()
    {
        return None;
    }
    let mut refs = ActorArchiveReferences {
        skill: skill_fit_scope_skill(body.scope.as_ref()),
        chat: None,
    };
    let Some(Value::Map(entries)) = body.evidence.as_ref() else {
        return Some(refs);
    };
    let field = |name: &str| {
        entries
            .iter()
            .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
    };
    if field("lane").and_then(Value::as_str) != Some("chat") {
        return Some(refs);
    }
    let decode_id = |value: &Value| {
        let Value::Binary(bytes) = value else {
            return None;
        };
        EntityId::from_bytes(bytes.as_slice().try_into().ok()?).ok()
    };
    let session = decode_id(field("session")?)?;
    let at = field("at")?.as_u64()?;
    let Value::Array(turns) = field("turns")? else {
        return None;
    };
    let turns: Vec<_> = turns.iter().map(decode_id).collect::<Option<_>>()?;
    let canonical = ActorClaimEvidence::chat(session, turns.clone(), at)
        .ok()?
        .to_value();
    // The exact native evidence codec is required, not a field-name exemption.
    // Duplicate keys, extensions and opaque lookalikes still null normally.
    if Some(&canonical) == body.evidence.as_ref() {
        refs.chat = Some((session, turns));
    }
    Some(refs)
}
