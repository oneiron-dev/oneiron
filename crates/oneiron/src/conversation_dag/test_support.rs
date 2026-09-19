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
    let bytes = rmp_serde::to_vec_named(&policy)
        .map_err(|_| crate::Error::InvariantViolation("test policy encode"))?;
    let id: EntityId = crate::gate::default_policy_manifest_id()?;
    let mut row = vec![crate::registry::ENTITY_TYPE_POLICY_MANIFEST];
    for at in [1_u64; 3] {
        row.extend_from_slice(&at.to_be_bytes());
    }
    row.extend_from_slice(&bytes);
    vault.with_write_txn(|txn| {
        vault.store.entities.put(txn, id.as_bytes(), &row)?;
        let type_key =
            crate::store::Store::encode_type_key(crate::registry::ENTITY_TYPE_POLICY_MANIFEST, &id);
        vault.store.type_index.put(txn, &type_key, &[])?;
        Ok(())
    })
}
