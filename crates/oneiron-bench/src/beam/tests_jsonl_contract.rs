//! JSONL contract tests.

#[cfg(test)]
pub(crate) mod tests {
    use super::super::*;
    use std::path::Path;
    use std::path::PathBuf;

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
