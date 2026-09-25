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
        "schema_version": "1.2", "pack_id": "dag-test", "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality": "normal", "sensitivity": "normal"}, "rules": [],
        "actor_ceilings": [{"actor_class": class, "actor_ref": actor.entity_ref().to_hex(),
            "ceiling": if allow { "auto" } else { "proposed" }}],
        "source_trust": {"generated": {"max_auto_sensitivity": 2,
            "actor_ref": actor.entity_ref().to_hex(), "receipted": true, "warned": true}}
    });
    // Reuse this actor's test pack so an auto/proposed flip replaces its own
    // ceiling rather than leaving an earlier restrictive row in the fold.
    let hash = blake3::hash(format!("dag-test-policy:{}", actor.entity_ref().to_hex()).as_bytes());
    let id = EntityId::from_bytes(hash.as_bytes()[..16].try_into().expect("manifest id width"))?;
    put_test_policy_manifest(vault, actor, id, &policy)
}

/// Installs `policy` under a non-default id as an owner-authored test manifest.
/// A fresh id folds beside the unchanged shipped policy.
pub fn put_test_policy_manifest(
    vault: &Vault,
    actor: WriteActor,
    id: EntityId,
    policy: &serde_json::Value,
) -> crate::Result<()> {
    if id == crate::gate::default_policy_manifest_id()? {
        return Err(crate::Error::InvalidConfig(
            "test policy cannot replace default".into(),
        ));
    }
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|_| crate::Error::InvariantViolation("fixture owner actor"))?;
    let owner = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::from_bytes(vault.store.clock.ulid()?),
    )?;
    let bytes = rmp_serde::to_vec_named(policy)
        .map_err(|_| crate::Error::InvariantViolation("test policy encode"))?;
    vault.with_write_txn(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        let crate::vault::LiveEntityRow::Live { entity_type, .. } =
            crate::vault::live_entity_row_in_txn(&vault.store, txn, &actor.entity_ref())?
        else {
            return Err(crate::Error::EntityNotFound);
        };
        crate::provenance::validate_actor_class(entity_type, actor.actor_class())?;
        if let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? {
            let header = crate::batch::EntityMetadataHeader::parse(&raw)
                .ok_or(crate::Error::CorruptedIndex("test policy manifest header"))?;
            if header.entity_type != crate::registry::ENTITY_TYPE_POLICY_MANIFEST {
                return Err(crate::Error::InvalidConfig(
                    "test policy id belongs to another entity".into(),
                ));
            }
        }
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
