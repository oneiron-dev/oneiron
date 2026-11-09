//! JSONL contract tests.

#[cfg(test)]
pub(crate) mod tests {
    use super::super::*;
    use std::path::Path;
    use std::path::PathBuf;

    #[test]
    fn jsonl_runner_keeps_loader_index_time_once_in_offline_cost() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run.jsonl");
        std::fs::write(&path, CONTRACT_RUN_JSONL).unwrap();
        let mut raw: serde_json::Value = serde_json::from_str(CONTRACT_MANIFEST_JSON).unwrap();
        raw["dataset"]["path"] = serde_json::json!(path);
        raw.as_object_mut().unwrap().remove("outputs");
        let manifest = parse_manifest_json(&raw.to_string()).unwrap();
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = oneiron::Vault::open(vault_dir.path(), beam_vault_config()).unwrap();
        let loaded = load_dataset(&vault, &manifest, None).unwrap();
        assert!(loaded.offline_index_build_us > 0);
        assert_eq!(
            loaded.offline.elapsed_us,
            loaded.offline_ingest_us + loaded.offline_index_build_us
        );
        let (cases, _) = run_loaded_cases(&vault, &manifest, &loaded).unwrap();
        let expected = loaded
            .offline
            .elapsed_us
            .div_ceil(manifest.case_ids.len() as u64);
        assert_eq!(cases[0].offline_amortized_cost.elapsed_us, expected);
        let isolated = run_manifest(&manifest, None).unwrap();
        assert!(isolated.cases[0].offline_amortized_cost.elapsed_us > 0);
        let isolated_elapsed = isolated.cases[0].offline_amortized_cost.elapsed_us;
        assert!(
            isolated.cases[0]
                .competitors
                .iter()
                .chain(&isolated.cases[0].appendix)
                .chain(&isolated.cases[0].dropped)
                .all(|row| row.costs.offline.elapsed_us == isolated_elapsed)
        );
    }

    pub(crate) fn fixture_file_manifest(dir: &Path, input: &str, output: &str) -> PathBuf {
        let mut manifest: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("fixture manifest");
        manifest["dataset"]["path"] = serde_json::json!(input);
        manifest["outputs"] = serde_json::json!({"packsJsonl": output});
        manifest["arms"] = serde_json::json!(["deterministic"]);
        let competitor = manifest["competitors"][0].clone();
        manifest["competitors"] = serde_json::json!([competitor]);
        let path = dir.join("run.json");
        std::fs::write(&path, manifest.to_string()).expect("manifest file");
        path
    }

    #[cfg(unix)]
    #[test]
    fn fixture_outputs_must_not_overwrite_symlink_alias_input() {
        for alias_is_input in [false, true] {
            let dir = tempfile::tempdir().expect("private test directory");
            let input = dir.path().join("fixture.json");
            std::fs::write(&input, BUILTIN_FIXTURE_JSON).expect("fixture file");
            std::os::unix::fs::symlink("fixture.json", dir.path().join("alias.json"))
                .expect("private fixture alias");
            let (source, output) = if alias_is_input {
                ("alias.json", "fixture.json")
            } else {
                ("fixture.json", "alias.json")
            };
            let manifest = fixture_file_manifest(dir.path(), source, output);
            assert!(matches!(
                run_manifest_path(&manifest),
                Err(BeamError::InvalidManifest { .. })
            ));
            assert_eq!(
                std::fs::read(&input).expect("preserved input"),
                BUILTIN_FIXTURE_JSON.as_bytes(),
            );
        }
    }
}
