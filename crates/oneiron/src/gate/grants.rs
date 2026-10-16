use crate::ports::EntityStoreRead;
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
use super::resolution::PolicyManifestResolution;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PolicyScopedGrant {
    pub(crate) actor_class: Option<String>,
    pub(crate) actor_ref: Option<String>,
    pub(crate) effector: String,
    /// Purpose-specific selectors; these can only narrow `authority_scope`.
    pub(crate) scope: Option<Value>,
    pub(crate) authority_scope: crate::federation::Scope,
    pub(crate) budget: Option<Value>,
    pub(crate) receipt_required: bool,
}

pub(crate) fn scoped_read_claim_allowed(
    policy: &PolicyManifestResolution,
    actor_key: &ScopedReadActorKey,
    body: &ClaimBody,
    claim_facets: &[EntityId],
) -> bool {
    scoped_read_claim_allowed_with_scope(
        policy,
        actor_key,
        body,
        claim_facets,
        actor_key.authority_scope(),
    )
}

/// What a key holding a proof of `explicit_scope` reads under `policy`, as
/// `scoped_read_claim_allowed` asks of the proof a key carries. The key's
/// own proof, if any, is not read, and no proof is built.
pub(crate) fn scoped_read_claim_allowed_with_scope(
    policy: &PolicyManifestResolution,
    actor_key: &ScopedReadActorKey,
    body: &ClaimBody,
    claim_facets: &[EntityId],
    explicit_scope: Option<&crate::federation::Scope>,
) -> bool {
    // This derived-data restriction narrows even a default-open vault. The
    // question's principal is a reader boundary, never a grant by itself.
    if let Some(Value::Map(scope)) = &body.scope {
        let mut readers = scope
            .iter()
            .filter(|(key, _)| key.as_str() == Some("typed_question_principal"));
        if let Some((_, reader)) = readers.next()
            && (readers.next().is_some() || reader.as_str() != Some(actor_key.actor_ref()))
        {
            return false;
        }
    }
    // The owner's own Grant is un-narrowed: no manifest row, and no manifest
    // failure, narrows the person on their own vault (ARCH-0057, DEC-0005).
    if actor_key.vault_owner_ref().is_some() {
        return true;
    }
    let diagnostics = policy.diagnostics();
    if diagnostics.loaded_manifest_forces_fail_closed() {
        return false;
    }
    if policy.is_fail_closed() {
        return false;
    }

    if explicit_scope.is_some_and(|scope| {
        !scope.admits(
            "read",
            &body.record_scope("read"),
            &crate::federation::Scope::top(),
        )
    }) {
        return false;
    }
    let mut saw_core_read_grant = false;
    for grant in policy
        .scoped_grants()
        .iter()
        .filter(|grant| scoped_read_grant_has_read_effector(grant))
    {
        if !scoped_read_actor_matches(grant, actor_key) {
            continue;
        }
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
        if grant.authority_scope.admits(
            "read",
            &body.record_scope("read"),
            &crate::federation::Scope::top(),
        ) && scoped_read_scope_matches_claim(grant.scope.as_ref(), body, claim_facets)
        {
            return true;
        }
    }

    explicit_scope.is_some() && !saw_core_read_grant
}

/// Scope authorization for positively stamped non-claim rows. Legacy selectors
/// not expressible from a record position cannot authorize a raw record read.
pub(crate) fn scoped_read_record_allowed(
    policy: &PolicyManifestResolution,
    actor: &ScopedReadActorKey,
    record: &crate::federation::Scope,
) -> bool {
    if actor.vault_owner_ref().is_some() {
        return true;
    }
    if policy.diagnostics().loaded_manifest_forces_fail_closed() || policy.is_fail_closed() {
        return false;
    }
    let proof = actor.authority_scope();
    if proof.is_some_and(|scope| !scope.admits("read", record, &crate::federation::Scope::top())) {
        return false;
    }
    let mut matched = false;
    for grant in policy.scoped_grants().iter().filter(|grant| {
        scoped_read_grant_has_read_effector(grant) && scoped_read_actor_matches(grant, actor)
    }) {
        matched = true;
        if grant.receipt_required || grant.budget.is_some() {
            continue;
        }
        let position_only = match grant.scope.as_ref() {
            None | Some(Value::Nil) => true,
            Some(Value::Map(entries)) => entries.iter().all(|(key, _)| {
                matches!(
                    key.as_str(),
                    Some(
                        "world"
                            | "world_ref"
                            | "worldRef"
                            | "scopeProjectId"
                            | "entity_types"
                            | "max_sensitivity_band"
                    )
                )
            }),
            _ => false,
        };
        if position_only
            && crate::federation::scope_codec::legacy_read_scope(grant.scope.as_ref()).is_some_and(
                |selectors| selectors.admits("read", record, &crate::federation::Scope::top()),
            )
            && grant
                .authority_scope
                .admits("read", record, &crate::federation::Scope::top())
        {
            return true;
        }
    }
    proof.is_some() && !matched
}

pub(super) fn scoped_read_grant_has_read_effector(grant: &PolicyScopedGrant) -> bool {
    grant.effector.trim() == SCOPED_READ_EFFECTOR_CORE_READ
        || grant.effector.trim() == SCOPED_READ_EFFECTOR_ONEIRON_READ
}

pub(super) fn scoped_read_actor_matches(
    grant: &PolicyScopedGrant,
    actor_key: &ScopedReadActorKey,
) -> bool {
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

/// One legacy read selector against one claim (OF-453 "one Scope"). The
/// position axes a selector can name (world, kinds, sensitivity band,
/// project) decode once into a Scope ([`legacy_read_scope`]) and are judged
/// by `Scope::admits` against the claim's own record Scope, exactly as the
/// non-claim record door judges them. What is not a position stays its own
/// conjunct: the opaque claim-scope match, facet placement (FACET-READ is
/// outside `Scope::admits`), and the retrieval quality floor (staleness,
/// confidence, salience). An unknown or malformed selector admits nothing.
///
/// [`legacy_read_scope`]: crate::federation::scope_codec::legacy_read_scope
fn scoped_read_scope_matches_claim(
    scope: Option<&Value>,
    body: &ClaimBody,
    claim_facets: &[EntityId],
) -> bool {
    let Some(selectors) = scoped_read_position_selectors(scope) else {
        return false;
    };
    if !selectors.admits(
        "read",
        &body.record_scope("read"),
        &crate::federation::Scope::top(),
    ) {
        return false;
    }
    let Some(Value::Map(entries)) = scope else {
        return true;
    };
    let floor_keys = entries.iter().any(|(key, _)| {
        matches!(
            key.as_str(),
            Some(
                "entity_types"
                    | "max_sensitivity_band"
                    | "include_stale"
                    | "min_confidence"
                    | "min_salience"
            )
        )
    });
    // The quality floor rides any retrieval key, as it always has: kinds and
    // band are the Scope's above, staleness, confidence and salience are not.
    if floor_keys
        && !super::retrieval_filter::RetrievalPolicyFloor::from_scope(scope).is_some_and(|floor| {
            !floor.deny_all
                && (floor.include_stale || !body.stale)
                && body.confidence >= floor.min_confidence
                && body.salience.unwrap_or(0.0) >= floor.min_salience
        })
    {
        return false;
    }
    entries.iter().all(|(key, value)| match key.as_str() {
        Some("claim_scope" | "claimScope" | "scope") => {
            scoped_read_claim_scope_matches(value, body.scope.as_ref())
        }
        Some("facet" | "facet_ref" | "facetRef") => {
            scoped_read_claim_facet_matches(value, body.scope.as_ref(), claim_facets)
        }
        // Position axes were judged by the Scope above; quality by its floor.
        _ => true,
    })
}

/// The position Scope a legacy read selector names, or `None` when it names
/// one ambiguously (two world keys) or carries a key no door knows.
fn scoped_read_position_selectors(scope: Option<&Value>) -> Option<crate::federation::Scope> {
    if let Some(Value::Map(entries)) = scope
        && entries
            .iter()
            .filter(|(key, _)| matches!(key.as_str(), Some("world" | "world_ref" | "worldRef")))
            .count()
            > 1
    {
        return None;
    }
    crate::federation::scope_codec::legacy_read_scope(scope)
}

/// Whether `grant` reads claims in `world` (`None` is base reality), as
/// [`scoped_read_claim_allowed`] judges a claim's world: its canonical Scope
/// admits a read of some record there (the read verb, the world, and no
/// axis left at bottom, which no record narrows), retrieval's floor for it
/// under the reader's `credential` leaves some entity type its selectors,
/// its bands and the credential's share (a TASK-only grant does), and a
/// world selector, if it carries one, names that world. A
/// selector on another axis leaves the world readable; one this matcher does
/// not know admits no claim, so no world. A grant that needs a receipt or a
/// budget reads none.
pub(crate) fn scoped_read_grant_reads_world(
    grant: &PolicyScopedGrant,
    world: Option<EntityId>,
    credential: Option<&crate::federation::Scope>,
) -> bool {
    if grant.receipt_required || grant.budget.is_some() {
        return false;
    }
    let scope = &grant.authority_scope;
    let id = crate::federation::ScopeId(world.unwrap_or_else(crate::claim::base_world_id));
    if !scope.verbs.contains(&"read".to_owned())
        || !scope.worlds.contains(&id)
        || scope.audience.is_bottom()
        || !super::retrieval_filter::scoped_read_grant_reads_some_type(grant, credential)
    {
        return false;
    }
    // The selector's own world axis, from the same decode the claim matcher
    // judges with; a selector on another axis leaves every world open.
    scoped_read_position_selectors(grant.scope.as_ref())
        .is_some_and(|selectors| selectors.worlds.contains(&id))
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
    // This adapter has no positively stamped record position. A bounded
    // resource grant cannot be widened by treating missing context as a match.
    grant.authority_scope.admits(
        "effect",
        &crate::federation::scope_codec::effect_preset(),
        &crate::federation::Scope::top(),
    ) && external_effect_actor_matches(grant, actor)
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
    facet_ref: Option<&EntityId>,
    now: u64,
) -> Result<Option<EntityId>> {
    for index_entry in store.port_entity_ids_by_type(txn, ENTITY_TYPE_ACCESS_GRANT, None)? {
        let id = index_entry?;
        let Some(raw) = store.port_entity_record(txn, &id)?.map(|row| row.encode()) else {
            return Err(Error::CorruptedIndex("access grant entity row"));
        };
        let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
            return Err(Error::CorruptedIndex("access grant entity header"));
        };
        if header.entity_type != ENTITY_TYPE_ACCESS_GRANT {
            return Err(Error::CorruptedIndex("access grant entity type"));
        }
        // Authority is a live grant row: a deleted one grants nothing, even
        // while an unapplied delete leaves its body stored. Its shell is
        // skipped here; a stored body is checked last, once it matches.
        let live = || -> Result<bool> {
            Ok(crate::vault::live_entity_row_in_txn(store, txn, &id)?.is_live())
        };
        if raw.len() == crate::batch::ENTITY_METADATA_HEADER_LEN && !live()? {
            continue;
        }

        let grant = match crate::access_grant::decode_access_grant_body(
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        ) {
            Ok(grant) => grant,
            Err(_) => {
                return Err(Error::CorruptedIndex("access grant body"));
            }
        };
        if grant.allows_companion_profile_read(principal_ref, person_ref, facet_ref, now) && live()?
        {
            return Ok(Some(id));
        }
    }

    Ok(None)
}
