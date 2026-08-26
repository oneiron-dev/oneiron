use rmpv::Value;

use crate::claim::ClaimSource;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::provenance::PREDICATE_EDGE_PROVENANCE;

use super::constants::{
    ACTOR_CEILING_KEY, ACTOR_CLASS_KEY, ACTOR_REF_KEY, AXIS_CRITICALITY_KEY, AXIS_SENSITIVITY_KEY,
    LOCAL_WRITE_ACTOR_CLASS, POLICY_ACTOR_CEILINGS_KEY, POLICY_DEFAULTS_KEY,
    POLICY_MIN_ENGINE_VERSION_KEY, POLICY_ON_BUDGET_EXHAUSTED_KEY, POLICY_OWNER_POLICY_ENABLED_KEY,
    POLICY_OWNER_POLICY_ROWS_KEY, POLICY_PACK_ID_KEY, POLICY_PACK_VERSION_KEY, POLICY_RULES_KEY,
    POLICY_SCHEMA_VERSION, POLICY_SCHEMA_VERSION_KEY, POLICY_SIGNATURES_KEY,
    POLICY_SOURCE_TRUST_KEY, RULE_AXES_KEY, RULE_EXACT_KEY, RULE_PREFIX_KEY, SIGNATURE_ALG_KEY,
    SIGNATURE_KEY_ID_KEY, SIGNATURE_SIG_KEY, SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY,
    SOURCE_TRUST_RECEIPTED_KEY, SOURCE_TRUST_WARNED_KEY,
};
use super::definition_ceiling::first_party_eiri_connector_actor_ref;

const DEFAULT_POLICY_MANIFEST_ID: [u8; ENTITY_ID_LEN] = [0xD7; ENTITY_ID_LEN];
pub(crate) const DEFAULT_POLICY_MANIFEST_TIMESTAMP: u64 = 0;

pub(crate) fn default_policy_manifest_id() -> Result<EntityId> {
    EntityId::from_bytes(DEFAULT_POLICY_MANIFEST_ID)
        .map_err(|_| Error::InvariantViolation("invalid default policy manifest id"))
}

pub(crate) fn default_policy_manifest() -> Vec<u8> {
    let first_party_eiri_actor_ref = first_party_eiri_connector_actor_ref();
    let manifest = Value::Map(vec![
        (
            Value::from(POLICY_SCHEMA_VERSION_KEY),
            Value::from(POLICY_SCHEMA_VERSION),
        ),
        (
            Value::from(POLICY_PACK_ID_KEY),
            Value::from("oneiron-default-policy"),
        ),
        (Value::from(POLICY_PACK_VERSION_KEY), Value::from("v1")),
        (
            Value::from(POLICY_MIN_ENGINE_VERSION_KEY),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from(POLICY_DEFAULTS_KEY),
            Value::Map(vec![
                (Value::from(AXIS_CRITICALITY_KEY), Value::from("critical")),
                (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
            ]),
        ),
        (
            Value::from(POLICY_RULES_KEY),
            Value::Array(vec![
                Value::Map(vec![
                    (Value::from(RULE_PREFIX_KEY), Value::from("profile.")),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from(crate::commitment::PREDICATE_COMMITMENT_RECORD),
                    ),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (Value::from(RULE_PREFIX_KEY), Value::from("calendar.")),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (Value::from(RULE_PREFIX_KEY), Value::from("booking.")),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (Value::from(RULE_PREFIX_KEY), Value::from("affect.vad")),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from(crate::skill_hub::PREDICATE_SKILL_SCAN_VERDICT),
                    ),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from(crate::skill_hub::PREDICATE_SKILL_HUB_PROVENANCE),
                    ),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from(crate::skill_hub::PREDICATE_SKILL_HUB_UPDATE_PROPOSAL),
                    ),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from(crate::provider_confidence::PREDICATE_ACTOR_CONFIDENCE_PRIOR),
                    ),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from(crate::provider_confidence::PREDICATE_PROVIDER_ENRICHMENT),
                    ),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from(PREDICATE_EDGE_PROVENANCE),
                    ),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
            ]),
        ),
        (
            Value::from(POLICY_ACTOR_CEILINGS_KEY),
            Value::Array(vec![
                Value::Map(vec![
                    (
                        Value::from(ACTOR_CLASS_KEY),
                        Value::from(LOCAL_WRITE_ACTOR_CLASS),
                    ),
                    (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
                ]),
                Value::Map(vec![
                    (Value::from(ACTOR_CLASS_KEY), Value::from("human")),
                    (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
                ]),
                Value::Map(vec![
                    (Value::from(ACTOR_CLASS_KEY), Value::from("agent")),
                    (
                        Value::from(ACTOR_REF_KEY),
                        Value::from(first_party_eiri_actor_ref),
                    ),
                    (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
                ]),
            ]),
        ),
        (
            Value::from(POLICY_SOURCE_TRUST_KEY),
            Value::Map(vec![(
                Value::from(ClaimSource::ToolOutput.as_str()),
                Value::Map(vec![
                    (
                        Value::from(SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY),
                        Value::from(0_u64),
                    ),
                    (
                        Value::from(SOURCE_TRUST_RECEIPTED_KEY),
                        Value::Boolean(true),
                    ),
                    (Value::from(SOURCE_TRUST_WARNED_KEY), Value::Boolean(true)),
                ]),
            )]),
        ),
        (
            Value::from(POLICY_ON_BUDGET_EXHAUSTED_KEY),
            Value::from("suspend"),
        ),
        // The owner policy plane ships OFF with zero rows: a fresh vault
        // classifies nothing and calls no safeguard model until its owner
        // opts in and writes their own rows.
        (
            Value::from(POLICY_OWNER_POLICY_ENABLED_KEY),
            Value::Boolean(false),
        ),
        (
            Value::from(POLICY_OWNER_POLICY_ROWS_KEY),
            Value::Array(Vec::new()),
        ),
        (
            Value::from(POLICY_SIGNATURES_KEY),
            Value::Array(vec![Value::Map(vec![
                (Value::from(SIGNATURE_ALG_KEY), Value::from("ed25519")),
                (Value::from(SIGNATURE_KEY_ID_KEY), Value::from("owner")),
                (
                    Value::from(SIGNATURE_SIG_KEY),
                    Value::from("first-party-eiri-auto"),
                ),
            ])]),
        ),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest).expect("encode default policy manifest");
    data
}
