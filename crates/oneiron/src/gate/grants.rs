use rmpv::Value;

use crate::claim::{ClaimBody, ScopedReadActorKey};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_ACCESS_GRANT;
use crate::store::Store;

use super::constants::{
    EXTERNAL_EFFECT_EFFECTOR_LONG_PREFIX, EXTERNAL_EFFECT_EFFECTOR_PREFIX,
    EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY, EXTERNAL_EFFECT_SCOPE_CHANNEL_REF_CAMEL_KEY,
    EXTERNAL_EFFECT_SCOPE_CHANNEL_REF_KEY, EXTERNAL_EFFECT_SCOPE_POLICY_RISK_CAMEL_KEY,
    EXTERNAL_EFFECT_SCOPE_POLICY_RISK_KEY, EXTERNAL_EFFECT_SCOPE_VERB_KEY,
    EXTERNAL_EFFECT_WILDCARD, SCOPED_READ_EFFECTOR_CORE_READ, SCOPED_READ_EFFECTOR_ONEIRON_READ,
};
use super::input::{ExternalEffectGateContext, ExternalEffectPolicyRisk, GateActor};
use super::resolution::{PolicyManifestResolution, type_index_entity_id};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PolicyScopedGrant {
    pub(crate) actor_class: Option<String>,
    pub(crate) actor_ref: Option<String>,
    pub(crate) effector: String,
    pub(crate) scope: Option<Value>,
    pub(crate) budget: Option<Value>,
    pub(crate) receipt_required: bool,
}

pub(crate) fn scoped_read_claim_allowed(
    policy: &PolicyManifestResolution,
    actor_key: &ScopedReadActorKey,
    body: &ClaimBody,
    claim_facets: &[EntityId],
) -> bool {
    let diagnostics = policy.diagnostics();
    if diagnostics.loaded_manifest_forces_fail_closed() {
        return false;
    }
    if diagnostics.manifest_count == 0 {
        return true;
    }
    if policy.is_fail_closed() {
        return false;
    }

    let mut saw_core_read_grant = false;
    for grant in policy
        .scoped_grants()
        .iter()
        .filter(|grant| scoped_read_grant_has_read_effector(grant))
    {
        saw_core_read_grant = true;
        if grant.receipt_required {
            continue;
        }
        if grant.budget.is_some() {
            continue;
        }
        if !scoped_read_actor_matches(grant, actor_key) {
            continue;
        }
        if scoped_read_scope_matches_claim(grant.scope.as_ref(), body, claim_facets) {
            return true;
        }
    }

    !saw_core_read_grant
}

pub(super) fn scoped_read_grant_has_read_effector(grant: &PolicyScopedGrant) -> bool {
    grant.effector.trim() == SCOPED_READ_EFFECTOR_CORE_READ
        || grant.effector.trim() == SCOPED_READ_EFFECTOR_ONEIRON_READ
}

fn scoped_read_actor_matches(grant: &PolicyScopedGrant, actor_key: &ScopedReadActorKey) -> bool {
    if let Some(actor_ref) = grant.actor_ref.as_deref()
        && actor_ref != actor_key.actor_ref()
    {
        return false;
    }
    if let Some(actor_class) = grant.actor_class.as_deref()
        && Some(actor_class) != actor_key.actor_class()
    {
        return false;
    }
    true
}

fn scoped_read_scope_matches_claim(
    scope: Option<&Value>,
    body: &ClaimBody,
    claim_facets: &[EntityId],
) -> bool {
    let Some(scope) = scope else {
        return true;
    };
    match scope {
        Value::Nil => true,
        Value::Map(entries) if entries.is_empty() => true,
        Value::Map(entries) => {
            for (key, value) in entries {
                let Some(key) = key.as_str() else {
                    return false;
                };
                let matches = match key {
                    "world" | "world_ref" | "worldRef" => {
                        scoped_read_world_matches_claim(value, body.world)
                    }
                    "claim_scope" | "claimScope" | "scope" => {
                        scoped_read_claim_scope_matches(value, body.scope.as_ref())
                    }
                    "facet" | "facet_ref" | "facetRef" => {
                        scoped_read_claim_facet_matches(value, body.scope.as_ref(), claim_facets)
                    }
                    _ => false,
                };
                if !matches {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}

fn scoped_read_world_matches_claim(value: &Value, claim_world: Option<EntityId>) -> bool {
    if matches!(value, Value::Nil) {
        return claim_world.is_none();
    }
    if value.as_str().is_some_and(|text| text == "base") {
        return claim_world.is_none();
    }
    let Some(grant_world) = scoped_read_entity_id_from_value(value) else {
        return false;
    };
    match claim_world {
        None => true,
        Some(claim_world) => claim_world == grant_world,
    }
}

fn scoped_read_claim_scope_matches(value: &Value, claim_scope: Option<&Value>) -> bool {
    match (value, claim_scope) {
        (Value::Nil, None) => true,
        (_, Some(claim_scope)) => claim_scope == value,
        _ => false,
    }
}

fn scoped_read_claim_scope_field_matches(
    value: &Value,
    claim_scope: Option<&Value>,
    field_names: &[&str],
) -> bool {
    let Some(Value::Map(entries)) = claim_scope else {
        return false;
    };
    entries.iter().any(|(key, candidate)| {
        key.as_str().is_some_and(|key| field_names.contains(&key)) && candidate == value
    })
}

fn scoped_read_claim_facet_matches(
    value: &Value,
    claim_scope: Option<&Value>,
    claim_facets: &[EntityId],
) -> bool {
    if !claim_facets.is_empty() {
        let Some(grant_facet) = scoped_read_entity_id_from_value(value) else {
            return false;
        };
        return claim_facets.contains(&grant_facet);
    }

    scoped_read_claim_scope_field_matches(value, claim_scope, &["facet", "facet_ref", "facetRef"])
}

pub(super) fn scoped_read_entity_id_from_value(value: &Value) -> Option<EntityId> {
    match value {
        Value::Binary(bytes) => {
            let bytes: [u8; ENTITY_ID_LEN] = bytes.as_slice().try_into().ok()?;
            EntityId::from_bytes(bytes).ok()
        }
        _ => EntityId::from_hex(value.as_str()?).ok(),
    }
}

pub(super) fn external_effect_grant_matches(
    grant: &PolicyScopedGrant,
    actor: &GateActor,
    effect: &ExternalEffectGateContext,
) -> bool {
    external_effect_actor_matches(grant, actor)
        && external_effect_effector_matches(grant.effector.trim(), effect.verb.trim())
        && external_effect_scope_matches(grant.scope.as_ref(), effect)
}

fn external_effect_actor_matches(grant: &PolicyScopedGrant, actor: &GateActor) -> bool {
    if let Some(actor_class) = grant.actor_class.as_deref()
        && actor_class != actor.actor_class.trim()
    {
        return false;
    }
    if let Some(actor_ref) = grant.actor_ref.as_deref()
        && Some(actor_ref) != actor.actor_ref.as_deref()
    {
        return false;
    }
    true
}

fn external_effect_effector_matches(effector: &str, verb: &str) -> bool {
    if effector == EXTERNAL_EFFECT_WILDCARD {
        return true;
    }
    if let Some(candidate) = effector.strip_prefix(EXTERNAL_EFFECT_EFFECTOR_PREFIX) {
        return candidate == EXTERNAL_EFFECT_WILDCARD || candidate == verb;
    }
    if let Some(candidate) = effector.strip_prefix(EXTERNAL_EFFECT_EFFECTOR_LONG_PREFIX) {
        return candidate == EXTERNAL_EFFECT_WILDCARD || candidate == verb;
    }
    effector == verb
}

fn external_effect_scope_matches(
    scope: Option<&Value>,
    effect: &ExternalEffectGateContext,
) -> bool {
    let Some(scope) = scope else {
        return true;
    };
    match scope {
        Value::Nil => true,
        Value::Map(entries) if entries.is_empty() => true,
        Value::Map(entries) => entries.iter().all(|(key, value)| {
            let Some(key) = key.as_str() else {
                return false;
            };
            match key {
                EXTERNAL_EFFECT_SCOPE_VERB_KEY => {
                    external_effect_scope_text_matches(value, effect.verb.trim())
                }
                EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY
                | EXTERNAL_EFFECT_SCOPE_CHANNEL_REF_KEY
                | EXTERNAL_EFFECT_SCOPE_CHANNEL_REF_CAMEL_KEY => {
                    external_effect_scope_text_matches(value, effect.channel.trim())
                }
                EXTERNAL_EFFECT_SCOPE_POLICY_RISK_KEY
                | EXTERNAL_EFFECT_SCOPE_POLICY_RISK_CAMEL_KEY => {
                    external_effect_scope_policy_risk_matches(value, effect.policy_risk)
                }
                _ => false,
            }
        }),
        _ => false,
    }
}

fn external_effect_scope_text_matches(value: &Value, expected: &str) -> bool {
    match value {
        Value::Array(values) => values
            .iter()
            .any(|value| external_effect_scope_text_matches(value, expected)),
        _ => value
            .as_str()
            .is_some_and(|value| value == EXTERNAL_EFFECT_WILDCARD || value == expected),
    }
}

fn external_effect_scope_policy_risk_matches(
    value: &Value,
    policy_risk: ExternalEffectPolicyRisk,
) -> bool {
    match value {
        Value::Array(values) => values
            .iter()
            .any(|value| external_effect_scope_policy_risk_matches(value, policy_risk)),
        Value::Boolean(true) => policy_risk == ExternalEffectPolicyRisk::HoldToProposal,
        Value::Boolean(false) => policy_risk == ExternalEffectPolicyRisk::Normal,
        _ => value.as_str().is_some_and(|value| {
            value == EXTERNAL_EFFECT_WILDCARD || value == policy_risk.as_str()
        }),
    }
}

pub(crate) fn companion_profile_access_grant(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    principal_ref: &EntityId,
    person_ref: &EntityId,
    persona_ref: &EntityId,
) -> Result<Option<EntityId>> {
    for index_entry in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_ACCESS_GRANT])?
    {
        let (key, _) = index_entry?;
        let Some(id) = type_index_entity_id(&key, ENTITY_TYPE_ACCESS_GRANT) else {
            return Err(Error::CorruptedIndex("access grant type index key"));
        };
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            return Err(Error::CorruptedIndex("access grant entity row"));
        };
        let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
            return Err(Error::CorruptedIndex("access grant entity header"));
        };
        if header.entity_type != ENTITY_TYPE_ACCESS_GRANT {
            return Err(Error::CorruptedIndex("access grant entity type"));
        }

        let grant = match crate::access_grant::decode_access_grant_body(
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        ) {
            Ok(grant) => grant,
            Err(_) => {
                return Err(Error::CorruptedIndex("access grant body"));
            }
        };
        if grant.allows_companion_profile_read(principal_ref, person_ref, persona_ref) {
            return Ok(Some(id));
        }
    }

    Ok(None)
}
