//! Manifest criticality is a read-time priority and a narrowing selector only.
use super::*;
use crate::serialize::{SerializeConfig, project_pack_for_json_response, serialize_pack};
use crate::tokenizer::DEFAULT_CONTEXT_PACK_TOKENIZER;

fn set_policy(vault: &Vault, critical: bool) {
    let bytes = crate::gate::default_policy_manifest().unwrap();
    let rmpv::Value::Map(mut fields) = rmpv::decode::read_value(&mut bytes.as_slice()).unwrap()
    else {
        panic!("manifest map");
    };
    fields.retain(|(key, _)| !matches!(key.as_str(), Some("defaults" | "rules")));
    let value = serde_json::json!({
        "defaults": {"criticality":"normal", "sensitivity":"normal"},
        "rules": [{"prefix":"boundary.", "axes":{"criticality": if critical {"critical"} else {"normal"}, "sensitivity":"normal"}}]
    });
    let encoded = rmp_serde::to_vec_named(&value).unwrap();
    let extra = rmpv::decode::read_value(&mut encoded.as_slice()).unwrap();
    let rmpv::Value::Map(extra) = extra else {
        panic!("map");
    };
    fields.extend(extra);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &rmpv::Value::Map(fields)).unwrap();
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id().unwrap(),
        &bytes,
    )
    .unwrap();
}
fn config(budget: usize) -> SerializeConfig {
    SerializeConfig {
        format: PackFormat::Json,
        profile: FieldProfile::Minimal,
        budget,
        allocation: TokenAllocation {
            claims: 1.0,
            turns: 0.0,
            summaries: 0.0,
            other: 0.0,
        },
        include_stats: false,
        merge_neighbors: true,
        max_field_chars: 0,
        max_item_tokens: 0,
    }
}
fn seed(
    vault: &Vault,
    id: EntityId,
    predicate: &str,
    lifecycle: crate::claim::ClaimLifecycleStatus,
) {
    put_claim_text_entity_with_lifecycle(
        vault,
        &id,
        "needle",
        predicate,
        "same size payload",
        lifecycle,
    )
    .unwrap();
}
fn ranked_pack(vault: &Vault, boundary: EntityId) -> ContextPack {
    let mut pack = vault
        .context_pack()
        .search_text("needle", 20)
        .run()
        .unwrap();
    for row in &mut pack.results {
        row.score = if row.id == boundary { 0.1 } else { 1.0 };
    }
    pack
}

#[test]
fn manifest_priority_flips_with_row_and_never_widens_status_gate() {
    let (_dir, vault) = open_test_vault();
    let boundary = EntityId::now();
    let normal = EntityId::now();
    let retracted = EntityId::now();
    seed(
        &vault,
        boundary,
        "boundary.test",
        crate::claim::ClaimLifecycleStatus::Active,
    );
    seed(
        &vault,
        normal,
        "ordinary.test",
        crate::claim::ClaimLifecycleStatus::Active,
    );
    seed(
        &vault,
        retracted,
        "boundary.hidden",
        crate::claim::ClaimLifecycleStatus::Retracted,
    );
    set_policy(&vault, true);
    let pack = ranked_pack(&vault, boundary);
    assert_eq!(pack.results.len(), 2);
    assert!(
        pack.results
            .iter()
            .find(|r| r.id == boundary)
            .unwrap()
            .critical
    );
    let mut single = pack.clone();
    single.results.retain(|r| r.id == boundary);
    let budget = DEFAULT_CONTEXT_PACK_TOKENIZER
        .count(std::str::from_utf8(&serialize_pack(&single, &config(0))).unwrap())
        + 5;
    let projected = project_pack_for_json_response(pack, &config(budget));
    assert_eq!(
        projected.results.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![boundary]
    );
    let narrowed = vault
        .context_pack()
        .search_text("needle", 20)
        .criticality(true)
        .run()
        .unwrap();
    assert_eq!(
        narrowed.results.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![boundary]
    );
    set_policy(&vault, false);
    let projected = project_pack_for_json_response(ranked_pack(&vault, boundary), &config(budget));
    assert_eq!(
        projected.results.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![normal]
    );
    assert!(
        vault
            .context_pack()
            .search_text("needle", 20)
            .criticality(true)
            .run()
            .unwrap()
            .results
            .is_empty()
    );
}

#[test]
fn critical_overflow_warns_and_keeps_serialized_and_item_budgets_hard() {
    let (_dir, vault) = open_test_vault();
    for _ in 0..5 {
        seed(
            &vault,
            EntityId::now(),
            "boundary.test",
            crate::claim::ClaimLifecycleStatus::Active,
        );
    }
    set_policy(&vault, true);
    let result = vault
        .context_pack()
        .search_text("needle", 20)
        .token_budget(100)
        .max_item_tokens(24)
        .max_field_chars(0)
        .format(PackFormat::Json)
        .run_serialized_with_stats()
        .unwrap()
        .value;
    assert!(result.stats.critical_over_budget);
    assert_eq!(result.stats.critical_count, 5);
    assert!(result.stats.tokens.items.iter().all(|row| row.tokens <= 24));
    assert!(
        DEFAULT_CONTEXT_PACK_TOKENIZER.count(std::str::from_utf8(&result.bytes).unwrap()) <= 100
    );
    for budget in [1, 2, 4, 8] {
        let result = vault
            .context_pack()
            .search_text("needle", 20)
            .token_budget(budget)
            .include_stats(true)
            .format(PackFormat::Json)
            .run_serialized_with_stats()
            .unwrap()
            .value;
        assert!(result.stats.critical_over_budget);
        assert!(
            DEFAULT_CONTEXT_PACK_TOKENIZER.count(std::str::from_utf8(&result.bytes).unwrap())
                <= budget
        );
    }
}
