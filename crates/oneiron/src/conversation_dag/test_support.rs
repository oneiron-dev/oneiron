//! Test-only policy fixture shared by engine and HTTP acceptance tests.

use crate::{EntityId, Vault, WriteActor};

/// Installs an explicit actor-bound auto grant (or clamp) for DAG acceptance
/// tests. This fixture door is absent from ordinary production builds.
pub fn put_dag_test_policy(vault: &Vault, actor: WriteActor, allow: bool) -> crate::Result<()> {
    let class = match actor.actor_class() {
        crate::EdgeActorClass::Human => "human",
        crate::EdgeActorClass::Agent => "agent",
        crate::EdgeActorClass::System => "system",
    };
    let policy = serde_json::json!({
        "schema_version": "1.1", "pack_id": "dag-test", "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality": "normal", "sensitivity": "normal"}, "rules": [],
        "actor_ceilings": [{"actor_class": class, "actor_ref": actor.entity_ref().to_hex(),
            "ceiling": if allow { "auto" } else { "proposed" }}],
        "source_trust": {"generated": {"max_auto_sensitivity": 2,
            "actor_ref": actor.entity_ref().to_hex(), "receipted": true, "warned": true}}
    });
    put_test_policy_manifest(vault, crate::gate::default_policy_manifest_id()?, &policy)
}

/// Installs `policy` at `id` as a locally authored manifest. The default id
/// replaces the shipped policy; a fresh id folds beside it.
pub fn put_test_policy_manifest(
    vault: &Vault,
    id: EntityId,
    policy: &serde_json::Value,
) -> crate::Result<()> {
    let bytes = rmp_serde::to_vec_named(policy)
        .map_err(|_| crate::Error::InvariantViolation("test policy encode"))?;
    vault.with_write_txn(|txn| {
        crate::batch::apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            vec![crate::batch::BatchOp::Put {
                id,
                entity_type: crate::registry::ENTITY_TYPE_POLICY_MANIFEST,
                occurred: crate::TimeRange { start: 1, end: 1 },
                learned_at: 1,
                data: bytes,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            true,
            true,
        )
    })
}
