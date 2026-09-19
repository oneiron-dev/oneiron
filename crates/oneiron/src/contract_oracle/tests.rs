use super::*;
use crate::{Vault, VaultConfig};
use std::collections::{BTreeMap, BTreeSet};

fn output(bytes: &[u8]) -> CommandOutput {
    CommandOutput {
        status: 0,
        stdout: bytes.to_vec(),
        stderr: Vec::new(),
    }
}

#[test]
fn removed_public_name_is_persisted_and_private_addition_passes() {
    let dir = tempfile::tempdir().unwrap();
    let vault_dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(vault_dir.path(), VaultConfig::default()).unwrap();
    std::fs::write(dir.path().join("lib.rs"), "pub fn keep() {} pub fn removed() {} mod hidden { pub fn invisible() {} } pub(crate) fn internal() {}\n").unwrap();
    let spec = ContractSpec {
        rust_crates: BTreeMap::from([("fixture".into(), "lib.rs".into())]),
        ..ContractSpec::default()
    };
    let oracle = ContractOracle::new(&vault);
    let baseline = oracle
        .record_baseline(
            spec.clone(),
            ContractOracle::capture(&spec, dir.path(), BTreeMap::new()).unwrap(),
        )
        .unwrap();
    assert_eq!(
        baseline.snapshot.public_names,
        BTreeSet::from(["fixture::keep".into(), "fixture::removed".into()])
    );
    std::fs::write(
        dir.path().join("lib.rs"),
        "pub fn keep() {} pub fn removed() {} fn private_added() {}\n",
    )
    .unwrap();
    let snapshot = ContractOracle::capture(&spec, dir.path(), BTreeMap::new()).unwrap();
    assert!(
        oracle
            .compare_and_record(&baseline.id, "private", &snapshot, true)
            .unwrap()
            .passes()
    );
    std::fs::write(
        dir.path().join("lib.rs"),
        "pub fn keep() {} fn renamed_private() {}\n",
    )
    .unwrap();
    let changed = ContractOracle::capture(&spec, dir.path(), BTreeMap::new()).unwrap();
    let verdict = oracle
        .compare_and_record(&baseline.id, "removed", &changed, true)
        .unwrap();
    assert!(!verdict.passes());
    assert_eq!(
        verdict.diffs,
        vec![ContractDiff::RemovedPublicName {
            name: "fixture::removed".into()
        }]
    );
    assert_eq!(
        ContractOracle::new(&vault).verdict(&verdict.id).unwrap(),
        Some(verdict)
    );
}

#[test]
fn external_and_inline_public_modules_and_export_aliases_are_namespaced() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("lib.rs"), "pub mod external; pub mod inline { pub fn call() {} } mod private { pub struct Thing; } pub use private::Thing as Export; pub struct Item { pub field: u8, hidden: u8 } impl Item { pub fn method(&self) {} fn hidden() {} }\n").unwrap();
    std::fs::write(
        dir.path().join("external.rs"),
        "pub fn call() {} fn hidden() {}\n",
    )
    .unwrap();
    let names = rust_public_names(dir.path(), "fixture", "lib.rs").unwrap();
    assert!(names.contains("fixture::external::call"));
    assert!(names.contains("fixture::inline::call"));
    assert!(names.contains("fixture::Export"));
    assert!(names.contains("fixture::Item::field"));
    assert!(names.contains("fixture::Item::method"));
    assert!(!names.iter().any(|name| name.ends_with("hidden")));
    std::fs::write(dir.path().join("lib.rs"), "pub use external::*;\n").unwrap();
    assert!(rust_public_names(dir.path(), "fixture", "lib.rs").is_err());
}

#[test]
fn resolved_workspace_graph_selects_downstream_tests_not_unrelated_crates() {
    let metadata = serde_json::json!({
        "workspace_root": "/workspace", "workspace_members": ["leaf-id", "app-id", "other-id"],
        "packages": [
            {"id":"leaf-id", "manifest_path":"/workspace/crates/leaf/Cargo.toml", "targets":[{"name":"leaf", "test":true}]},
            {"id":"app-id", "manifest_path":"/workspace/crates/app/Cargo.toml", "targets":[{"name":"app", "test":true}]},
            {"id":"other-id", "manifest_path":"/workspace/crates/other/Cargo.toml", "targets":[{"name":"other", "test":true}]}
        ],
        "resolve":{"nodes":[{"id":"leaf-id", "dependencies":[]}, {"id":"app-id", "dependencies":["leaf-id"]}, {"id":"other-id", "dependencies":[]}]}
    });
    let graph =
        WorkspaceGraph::from_cargo_metadata(&serde_json::to_vec(&metadata).unwrap()).unwrap();
    let affected = graph.affected_tests(["crates/leaf/src/lib.rs"]).unwrap();
    assert_eq!(
        affected.packages,
        BTreeSet::from(["leaf-id".into(), "app-id".into()])
    );
    assert_eq!(affected.targets["app-id"], BTreeSet::from(["app".into()]));
    assert!(
        graph
            .affected_tests(["notes/design.md"])
            .unwrap()
            .packages
            .is_empty()
    );
    assert_eq!(
        graph.affected_tests(["Cargo.lock"]).unwrap().packages.len(),
        3
    );
    let mut incomplete = metadata;
    incomplete["resolve"] = serde_json::Value::Null;
    assert!(
        WorkspaceGraph::from_cargo_metadata(&serde_json::to_vec(&incomplete).unwrap()).is_err()
    );
}

#[test]
fn schema_type_and_command_bytes_drift_with_precise_persisted_diff() {
    let vault_dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(vault_dir.path(), VaultConfig::default()).unwrap();
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("schema.json"),
        r#"{"properties":{"count":{"type":"integer"}}}"#,
    )
    .unwrap();
    let spec = ContractSpec {
        schemas: BTreeMap::from([("wire".into(), "schema.json".into())]),
        outputs: BTreeSet::from(["cli".into()]),
        ..ContractSpec::default()
    };
    let before = ContractOracle::capture(
        &spec,
        root.path(),
        BTreeMap::from([("cli".into(), output(b"ok\n"))]),
    )
    .unwrap();
    let oracle = ContractOracle::new(&vault);
    let baseline = oracle
        .record_baseline(spec.clone(), before.clone())
        .unwrap();
    assert!(
        oracle
            .compare_and_record(&baseline.id, "same", &before, true)
            .unwrap()
            .passes()
    );
    std::fs::write(
        root.path().join("schema.json"),
        r#"{"properties":{"count":{"type":"string"}}}"#,
    )
    .unwrap();
    let after = ContractOracle::capture(
        &spec,
        root.path(),
        BTreeMap::from([("cli".into(), output(b"OK\n"))]),
    )
    .unwrap();
    let verdict = oracle
        .compare_and_record(&baseline.id, "drift", &after, true)
        .unwrap();
    assert!(!verdict.passes());
    assert!(verdict.diffs.iter().any(|diff| matches!(diff, ContractDiff::SchemaDrift { pointer, before: Some(a), after: Some(b), .. } if pointer == "/properties/count/type" && a == "integer" && b == "string")));
    assert!(verdict.diffs.iter().any(|diff| matches!(diff, ContractDiff::OutputDrift { before: Some(a), after: Some(b), .. } if a.stdout == b"ok\n" && b.stdout == b"OK\n")));
    assert_eq!(oracle.verdict(&verdict.id).unwrap(), Some(verdict));
    assert!(ContractOracle::capture(&spec, root.path(), BTreeMap::new()).is_err());
    assert!(
        !oracle
            .compare_and_record(&baseline.id, "missing", &ContractSnapshot::default(), true)
            .unwrap()
            .passes()
    );
}

#[test]
fn exported_macros_are_root_api_even_from_private_modules() {
    let dir = tempfile::tempdir().unwrap();
    let vault_dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(vault_dir.path(), VaultConfig::default()).unwrap();
    std::fs::write(
        dir.path().join("lib.rs"),
        r#"
        #[macro_export] macro_rules! root_macro { () => {} }
        mod hidden {
            #[macro_export(local_inner_macros)] macro_rules! nested_macro { () => {} }
            #[doc = "macro_export"] macro_rules! private_macro { () => {} }
            pub fn hidden_function() {}
        }
        mod external;
    "#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("external.rs"),
        "#[macro_export] macro_rules! external_macro { () => {} }",
    )
    .unwrap();
    let spec = ContractSpec {
        rust_crates: BTreeMap::from([("fixture".into(), "lib.rs".into())]),
        ..ContractSpec::default()
    };
    let before = ContractOracle::capture(&spec, dir.path(), BTreeMap::new()).unwrap();
    assert_eq!(
        before.public_names,
        BTreeSet::from([
            "fixture::root_macro".into(),
            "fixture::nested_macro".into(),
            "fixture::external_macro".into(),
        ])
    );
    let oracle = ContractOracle::new(&vault);
    let baseline = oracle.record_baseline(spec.clone(), before).unwrap();
    std::fs::write(
        dir.path().join("external.rs"),
        "#[macro_export] macro_rules! renamed_macro { () => {} }",
    )
    .unwrap();
    let after = ContractOracle::capture(&spec, dir.path(), BTreeMap::new()).unwrap();
    let verdict = oracle
        .compare_and_record(&baseline.id, "macro-renamed", &after, true)
        .unwrap();
    assert!(!verdict.passes());
    assert!(verdict.diffs.contains(&ContractDiff::RemovedPublicName {
        name: "fixture::external_macro".into()
    }));
    std::fs::write(
        dir.path().join("external.rs"),
        "#[cfg_attr(feature = \"export\", macro_export)] macro_rules! conditional { () => {} }",
    )
    .unwrap();
    assert!(rust_public_names(dir.path(), "fixture", "lib.rs").is_err());
}
