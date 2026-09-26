//! Stored-row proof for versioned policy Scope, migration, and fail-closed reads/effects.

use super::*;
use crate::batch::{BatchOp, apply_ops};
use crate::claim::ScopedReadActorKey;
use crate::error::Result;
use crate::federation::Scope;
use crate::gate::{
    ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateOutcome,
    GateProvenanceHandles, PolicyManifestResolution, default_policy_manifest,
    default_policy_manifest_id, evaluate_external_effect_policy, resolve_policy_manifest,
};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST};
use crate::test_util::{entity, put_policy_manifest_bytes};
use crate::{TimeRange, Vault, VaultConfig};

const AT: TimeRange = TimeRange { start: 1, end: 1 };

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).expect("fixture encode");
    bytes
}

fn manifest(version: &str, grants: Vec<Value>) -> Vec<u8> {
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut default_policy_manifest().as_slice())
            .expect("default policy")
    else {
        panic!("map");
    };
    for (key, value) in &mut entries {
        if key.as_str() == Some(POLICY_SCHEMA_VERSION_KEY) {
            *value = version.into();
        }
    }
    entries.push((POLICY_SCOPED_GRANTS_KEY.into(), Value::Array(grants)));
    encode(&Value::Map(entries))
}

fn grant(actor: &str, effector: &str, scope: Value) -> Value {
    Value::Map(vec![
        ("actor_ref".into(), actor.into()),
        (GRANT_EFFECTOR_KEY.into(), effector.into()),
        (GRANT_SCOPE_KEY.into(), scope),
        ("receipt_required".into(), false.into()),
    ])
}

fn append_field(mut row: Value, key: &str, value: Value) -> Value {
    let Value::Map(entries) = &mut row else {
        panic!("grant map");
    };
    entries.push((key.into(), value));
    row
}

fn stored_manifest(vault: &Vault) -> Result<Vec<u8>> {
    Ok(vault
        .get(&default_policy_manifest_id()?)?
        .expect("stored manifest"))
}

fn put_manifest(vault: &Vault, data: Vec<u8>) -> Result<()> {
    vault.with_write_txn(|txn| {
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            vec![BatchOp::Put {
                id: default_policy_manifest_id()?,
                entity_type: ENTITY_TYPE_POLICY_MANIFEST,
                occurred: AT,
                learned_at: 1,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            true,
            false,
            true,
        )
    })
}

fn policy(vault: &Vault) -> Result<PolicyManifestResolution> {
    let txn = vault.store.env.read_txn()?;
    resolve_policy_manifest(&vault.store, &txn)
}

fn effect_outcome(vault: &Vault, channel: &str) -> Result<GateOutcome> {
    let effect = ExternalEffectGateInput {
        actor: GateActor {
            actor_class: "first_party".into(),
            actor_ref: Some("sender".into()),
            delegation_grant_ref: None,
        },
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(entity(0xE0)),
            ..GateProvenanceHandles::default()
        },
        verb: "send".into(),
        channel: channel.into(),
        channel_identity_ref: None,
        counterparty: None,
        brief_ref: None,
        send_ref: None,
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: true,
        has_permission: true,
        policy_risk: ExternalEffectPolicyRisk::Normal,
    };
    let policy = policy(vault)?;
    vault.with_write_txn(|txn| {
        Ok(
            evaluate_external_effect_policy(&vault.store, txn, &effect, &policy, None, None)?
                .outcome(),
        )
    })
}

fn reader(vault: &Vault, actor: &str, id: &crate::EntityId) -> Result<bool> {
    Ok(vault
        .scoped_read(ScopedReadActorKey::new(actor).expect("actor"))
        .read(&[crate::claim::PointRead::id(*id)], None)?
        .single()
        .is_some())
}

fn assert_stored_scopes(vault: &Vault, expected: &[Scope]) -> Result<()> {
    let bytes = stored_manifest(vault)?;
    let Value::Map(entries) = rmpv::decode::read_value(&mut bytes.as_slice()).expect("map") else {
        panic!("manifest map");
    };
    assert_eq!(
        required_string(&entries, POLICY_SCHEMA_VERSION_KEY).as_deref(),
        Some("1.2")
    );
    let MapValue::Present(Value::Array(rows)) =
        single_map_value(&entries, POLICY_SCOPED_GRANTS_KEY)
    else {
        panic!("grant rows");
    };
    assert_eq!(rows.len(), expected.len());
    for (row, expected) in rows.iter().zip(expected) {
        let Value::Map(row) = row else {
            panic!("grant map");
        };
        let MapValue::Present(scope) = single_map_value(row, GRANT_SCOPE_KEY) else {
            panic!("scope");
        };
        // Observe the stored wire, not only the defaulting decoder: all six axes
        // must actually be present after the materialization door.
        assert_eq!(scope, &encode_scope_value(expected)?);
    }
    Ok(())
}

#[test]
fn empty_and_partial_new_scopes_persist_bottom_and_deny_real_reads_and_effects() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let person = entity(0x31);
    vault.put_entity(&person, ENTITY_TYPE_PERSON, AT, 1, b"person")?;
    let positive = vec![
        grant(
            "reader",
            "core:read",
            encode_scope_value(&crate::federation::scope_codec::read_preset())?,
        ),
        grant(
            "sender",
            "external:send",
            encode_scope_value(&effect_preset())?,
        ),
    ];
    put_manifest(&vault, manifest(POLICY_SCHEMA_VERSION, positive))?;
    assert!(reader(&vault, "reader", &person)?);
    assert_eq!(effect_outcome(&vault, "line")?, GateOutcome::Allow);

    for value in [
        Value::Map(vec![]),
        Value::Map(vec![(
            "worlds".into(),
            Value::Map(vec![("kind".into(), "all".into())]),
        )]),
    ] {
        let expected = decode_scope_value(&value)?;
        let rows = vec![
            grant("reader", "core:read", value.clone()),
            grant("sender", "external:send", value),
        ];
        put_manifest(&vault, manifest(POLICY_SCHEMA_VERSION, rows))?;
        assert_stored_scopes(&vault, &[expected.clone(), expected])?;
        assert!(
            !policy(&vault)?
                .diagnostics()
                .loaded_manifest_forces_fail_closed()
        );
        assert!(!reader(&vault, "reader", &person)?);
        assert_eq!(effect_outcome(&vault, "line")?, GateOutcome::Pending);
    }
    Ok(())
}

#[test]
fn legacy_policy_grants_migrate_on_write_and_once_on_open_with_selectors_and_budget() -> Result<()>
{
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let person = entity(0x32);
    vault.put_entity(&person, ENTITY_TYPE_PERSON, AT, 1, b"person")?;
    let read_selectors = Value::Map(vec![
        ("world_ref".into(), "base".into()),
        (
            "entity_types".into(),
            Value::Array(vec![ENTITY_TYPE_PERSON.into()]),
        ),
    ]);
    let effect_selectors = Value::Map(vec![("channel".into(), "line".into())]);
    let budget = Value::Map(vec![("limit".into(), 1u64.into())]);
    let legacy = manifest(
        LEGACY_POLICY_SCOPE_SCHEMA_VERSION,
        vec![
            // The second supported read spelling must migrate to read, not effect.
            grant("reader", "oneiron.read", read_selectors.clone()),
            grant("sender", "external:send", effect_selectors.clone()),
            append_field(
                grant("budget-reader", "core:read", Value::Map(vec![])),
                "budget",
                budget.clone(),
            ),
        ],
    );
    put_manifest(&vault, legacy.clone())?;
    let normalized = stored_manifest(&vault)?;
    let unchanged_envelope = |bytes: &[u8]| {
        let Value::Map(mut entries) = rmpv::decode::read_value(&mut &bytes[..]).expect("manifest")
        else {
            panic!("map");
        };
        entries.retain(|(key, _)| {
            !matches!(
                key.as_str(),
                Some(POLICY_SCHEMA_VERSION_KEY | POLICY_SCOPED_GRANTS_KEY)
            )
        });
        entries
    };
    assert_eq!(unchanged_envelope(&legacy), unchanged_envelope(&normalized));
    assert_stored_scopes(
        &vault,
        &[
            legacy_read_scope(Some(&read_selectors)).expect("legacy read"),
            effect_preset(),
            crate::federation::scope_codec::read_preset(),
        ],
    )?;
    assert!(reader(&vault, "reader", &person)?);
    assert!(!reader(
        &vault,
        "reader",
        &crate::claim::substrate_facet_id(person)
    )?);
    assert!(!reader(&vault, "budget-reader", &person)?);
    assert_eq!(effect_outcome(&vault, "line")?, GateOutcome::Allow);
    assert_eq!(effect_outcome(&vault, "email")?, GateOutcome::Pending);
    let resolved = policy(&vault)?;
    assert_eq!(
        resolved.scoped_grants()[0].scope.as_ref(),
        Some(&read_selectors)
    );
    assert_eq!(
        resolved.scoped_grants()[1].scope.as_ref(),
        Some(&effect_selectors)
    );
    assert_eq!(resolved.scoped_grants()[2].budget.as_ref(), Some(&budget));

    // Emulate an old stored row, with the earlier claim sweep ALREADY complete.
    put_policy_manifest_bytes(&vault, default_policy_manifest_id()?, &legacy)?;
    assert_eq!(stored_manifest(&vault)?, legacy);
    assert!(
        policy(&vault)?
            .diagnostics()
            .loaded_manifest_forces_fail_closed()
    );
    assert!(!reader(&vault, "reader", &person)?);
    vault.with_write_txn(|txn| {
        vault
            .store
            .vault_meta
            .delete(txn, b"scope:policy-manifest:v1.2")?;
        Ok(())
    })?;
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    assert_eq!(stored_manifest(&vault)?, normalized);
    assert!(reader(&vault, "reader", &person)?);
    assert_eq!(effect_outcome(&vault, "email")?, GateOutcome::Pending);
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    assert_eq!(stored_manifest(&vault)?, normalized);
    Ok(())
}

#[test]
fn current_selectors_and_budget_only_narrow_stored_scope() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let person = entity(0x33);
    vault.put_entity(&person, ENTITY_TYPE_PERSON, AT, 1, b"person")?;
    let selectors = Value::Map(vec![(
        "entity_types".into(),
        Value::Array(vec![crate::registry::ENTITY_TYPE_FACET.into()]),
    )]);
    let rows = vec![
        append_field(
            grant(
                "reader",
                "core:read",
                encode_scope_value(&crate::federation::scope_codec::read_preset())?,
            ),
            GRANT_SELECTORS_KEY,
            selectors,
        ),
        append_field(
            grant(
                "sender",
                "external:send",
                encode_scope_value(&effect_preset())?,
            ),
            "budget",
            Value::Map(vec![("limit".into(), 1u64.into())]),
        ),
    ];
    put_manifest(&vault, manifest(POLICY_SCHEMA_VERSION, rows))?;
    assert!(!reader(&vault, "reader", &person)?);
    assert!(reader(
        &vault,
        "reader",
        &crate::claim::substrate_facet_id(person)
    )?);
    assert_eq!(effect_outcome(&vault, "line")?, GateOutcome::Pending);

    // A generic bound the effect adapter cannot prove must not be ignored.
    let mut bounded = effect_preset();
    bounded.worlds = crate::federation::ScopeAxis::Some(std::collections::BTreeSet::from([
        crate::federation::ScopeId(crate::claim::base_world_id()),
    ]));
    put_manifest(
        &vault,
        manifest(
            POLICY_SCHEMA_VERSION,
            vec![grant(
                "sender",
                "external:send",
                encode_scope_value(&bounded)?,
            )],
        ),
    )?;
    assert_eq!(effect_outcome(&vault, "line")?, GateOutcome::Pending);
    Ok(())
}

#[test]
fn malformed_manifest_is_not_replaced_or_migrated_to_permissive_defaults() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let person = entity(0x34);
    vault.put_entity(&person, ENTITY_TYPE_PERSON, AT, 1, b"person")?;
    let Value::Map(mut missing_scope) = grant("reader", "core:read", Value::Map(vec![])) else {
        panic!("map");
    };
    missing_scope.retain(|(key, _)| key.as_str() != Some(GRANT_SCOPE_KEY));
    let malformed = [
        manifest(POLICY_SCHEMA_VERSION, vec![Value::Map(missing_scope)]),
        manifest(
            POLICY_SCHEMA_VERSION,
            vec![grant("reader", "core:read", Value::Nil)],
        ),
        manifest(
            POLICY_SCHEMA_VERSION,
            vec![grant(
                "reader",
                "core:read",
                Value::Map(vec![("worlds".into(), "all".into())]),
            )],
        ),
        manifest(
            LEGACY_POLICY_SCOPE_SCHEMA_VERSION,
            vec![grant(
                "reader",
                "core:read",
                encode_scope_value(&Scope::top())?,
            )],
        ),
    ];
    for bytes in malformed {
        put_manifest(&vault, bytes.clone())?;
        assert_eq!(stored_manifest(&vault)?, bytes);
        vault.with_write_txn(|txn| {
            vault
                .store
                .vault_meta
                .delete(txn, b"scope:policy-manifest:v1.2")?;
            Ok(())
        })?;
        crate::batch::sweep_scope_stamps(&vault.store)?;
        assert_eq!(stored_manifest(&vault)?, bytes);
        assert!(
            policy(&vault)?
                .diagnostics()
                .loaded_manifest_forces_fail_closed()
        );
        assert!(!reader(&vault, "reader", &person)?);
        assert_ne!(effect_outcome(&vault, "line")?, GateOutcome::Allow);
    }
    let before_reopen = stored_manifest(&vault)?;
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    assert_eq!(stored_manifest(&vault)?, before_reopen);
    assert!(
        policy(&vault)?
            .diagnostics()
            .loaded_manifest_forces_fail_closed()
    );
    Ok(())
}

#[test]
fn scope_only_narrowing_changes_the_consent_frontier() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let wide = crate::federation::scope_codec::read_preset();
    put_manifest(
        &vault,
        manifest(
            "1.2",
            vec![grant(
                "reader",
                "core:read",
                crate::federation::scope_codec::encode_scope_value(&wide)?,
            )],
        ),
    )?;
    let before = policy(&vault)?.read_frontier_hash()?;
    let mut narrow = wide;
    narrow.sensitivity =
        crate::federation::SensitivityCeiling::AtMost(crate::federation::Sensitivity::Public);
    put_manifest(
        &vault,
        manifest(
            "1.2",
            vec![grant(
                "reader",
                "core:read",
                crate::federation::scope_codec::encode_scope_value(&narrow)?,
            )],
        ),
    )?;
    assert_ne!(before, policy(&vault)?.read_frontier_hash()?);
    Ok(())
}
