//! Checkpoint-backed NER shadow proof beside an indexed fixture turn.
//! The checkpoint and Python runtime remain host-owned; the vault path is never
//! passed to the inference process. The report is emitted only after a byte-level
//! assertion that the shadow pass left the fixture vault unchanged.
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use oneiron::llm::tagger::{
    MentionTag, OneironerTagger, RetrievalTags, ShadowTagReport, shadow_tag_turn,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::{EntityId, ModelId, TimeRange, Vault, VaultConfig};
use serde::{Deserialize, Serialize};

const TURN_TEXT: &str = "Ada works here";

#[derive(Debug, Deserialize)]
struct Span {
    start: usize,
    end: usize,
    #[serde(rename = "type")]
    kind: String,
    score: f32,
}

/// The subprocess is the model-repository's real NER runner, never a Rust
/// heuristic or a substituted encoder. The fixture resolver is deliberately
/// separate: the checkpoint proposes spans, while the host maps known names
/// to existing vault entities. A NER label is not itself an entity ID.
struct CheckpointTagger {
    python: PathBuf,
    model_repo: PathBuf,
    checkpoint: PathBuf,
    sha256: String,
    person: EntityId,
}

impl OneironerTagger for CheckpointTagger {
    fn model(&self) -> ModelId {
        ModelId::new(format!("bench/oneironer-ner@{}", &self.sha256[..16]))
            .expect("checkpoint hash is a valid model revision")
    }

    fn tag(&self, text: &str) -> oneiron::Result<RetrievalTags> {
        // The helper imports the model repository at this explicit path. It
        // strict-loads the trained checkpoint and refuses a missing head.
        let helper =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/oneironer_shadow_infer.py");
        let mut child = Command::new(&self.python)
            .arg(helper)
            .arg(&self.model_repo)
            .arg(&self.checkpoint)
            .arg(&self.sha256)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| oneiron::Error::InvalidConfig(format!("NER runner launch: {e}")))?;
        let request = serde_json::to_vec(&serde_json::json!({"text": text}))
            .map_err(|e| oneiron::Error::InvalidConfig(format!("NER request encode: {e}")))?;
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(&request)?;
        let result = child.wait_with_output()?;
        if !result.status.success() {
            return Err(oneiron::Error::InvalidConfig(format!(
                "NER checkpoint failed: {}",
                String::from_utf8_lossy(&result.stderr)
            )));
        }
        let spans: Vec<Span> = serde_json::from_slice(&result.stdout)
            .map_err(|e| oneiron::Error::InvalidConfig(format!("NER response decode: {e}")))?;
        let mentions = spans
            .into_iter()
            .filter(|span| span.kind == "PERSON" && text.get(span.start..span.end) == Some("Ada"))
            .map(|span| MentionTag {
                start: span.start,
                end: span.end,
                entity: self.person,
                weight: span.score,
            })
            .collect::<Vec<_>>();
        Ok(RetrievalTags {
            mentions,
            ..RetrievalTags::default()
        })
    }
}

#[derive(Debug, Serialize)]
struct Proof {
    checkpoint_sha256: String,
    live_ids: Vec<String>,
    report: ShadowTagReport,
    vault_writes: u8,
}

fn sha256(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    use sha2::Digest;
    let mut file = std::fs::File::open(path)?;
    let mut digest = sha2::Sha256::new();
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        digest.update(&chunk[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn vault_bytes(path: &Path) -> Result<blake3::Hash, Box<dyn std::error::Error>> {
    Ok(blake3::hash(&std::fs::read(path.join("data.mdb"))?))
}

fn run(
    python: &Path,
    model_repo: &Path,
    checkpoint: &Path,
    expected_sha256: &str,
) -> Result<Proof, Box<dyn std::error::Error>> {
    if !model_repo.join("model/head_runtime.py").is_file() {
        return Err("model repo must supply model/head_runtime.py".into());
    }
    let digest = sha256(checkpoint)?;
    if digest != expected_sha256 || digest.len() != 64 {
        return Err("NER checkpoint SHA-256 mismatch".into());
    }
    let dir = tempfile::tempdir()?;
    let mut cfg = VaultConfig::device();
    cfg.dimensions = 4;
    cfg.embedding_model = Some("bench/shadow@v1".into());
    let vault = Vault::open(dir.path(), cfg)?;
    let person = EntityId::from_bytes([31; 16])?;
    let turn = EntityId::from_bytes([32; 16])?;
    let time = TimeRange { start: 1, end: 1 };
    let body = rmp_serde::to_vec_named(&serde_json::json!({"txt": TURN_TEXT, "spkr": "user"}))?;
    vault
        .batch()
        .put(&person, ENTITY_TYPE_PERSON, time, 1, b"Ada")
        .text(&person, &[("body", "Ada")])
        .put(&turn, ENTITY_TYPE_TURN, time, 1, &body)
        .text(&turn, &[("body", TURN_TEXT)])
        .commit()?;
    // Live retrieval occurs BEFORE the no-write baseline: the retrieval API
    // may write telemetry. Only the shadow interval has a zero-write contract.
    let live = vault
        .search_text("Ada", 10)?
        .into_iter()
        .map(|hit| hit.id)
        .collect::<Vec<_>>();
    if !live.contains(&turn) {
        return Err("fixture turn missing from live retrieval".into());
    }
    let before = vault_bytes(dir.path())?;
    let tagger = CheckpointTagger {
        python: python.to_owned(),
        model_repo: model_repo.to_owned(),
        checkpoint: checkpoint.to_owned(),
        sha256: digest.clone(),
        person,
    };
    let outcome = shadow_tag_turn(&vault, turn, &tagger, &live);
    let after = vault_bytes(dir.path())?;
    if before != after {
        return Err("NER shadow wrote to the fixture vault".into());
    }
    let report = outcome?;
    Ok(Proof {
        checkpoint_sha256: digest,
        live_ids: live.into_iter().map(|id| id.to_hex()).collect(),
        report,
        vault_writes: 0,
    })
}

pub(super) fn cli(args: &[String]) -> std::process::ExitCode {
    cli_with_io(
        args,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    )
}

fn cli_with_io(
    args: &[String],
    output: &mut impl Write,
    errors: &mut impl Write,
) -> std::process::ExitCode {
    if args.len() != 4 {
        let _ = writeln!(
            errors,
            "usage: oneiron-bench oneironer-shadow <python> <model-repo> <checkpoint.safetensors> <sha256>"
        );
        return std::process::ExitCode::FAILURE;
    }
    match run(
        Path::new(&args[0]),
        Path::new(&args[1]),
        Path::new(&args[2]),
        &args[3],
    ) {
        Ok(proof) => {
            let json = serde_json::to_string_pretty(&proof).expect("serializable proof");
            if writeln!(output, "{json}").is_ok() {
                std::process::ExitCode::SUCCESS
            } else {
                let _ = writeln!(errors, "oneironer shadow: report write failed");
                std::process::ExitCode::FAILURE
            }
        }
        Err(error) => {
            let _ = writeln!(errors, "oneironer shadow: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_hash_matches_sha256_across_chunk_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture.safetensors");
        let bytes = vec![0x61_u8; 65_537];
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(
            sha256(&path).unwrap(),
            "008ffc88d3c96a9f307524eb361e47c5222a887fc45fa0c1fb8d429c5c23b430"
        );
    }

    #[test]
    fn rejects_missing_checkpoint_without_a_fake_ner_result() {
        let missing = Path::new("/missing/oneironer-ner-checkpoint");
        assert!(sha256(missing).is_err());
    }

    // This checks the harness, not model quality. The separate ignored test
    // below requires the actual trained checkpoint and runtime.
    #[cfg(unix)]
    #[test]
    fn fixture_shadow_compares_mentions_and_preserves_vault_bytes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join("model")).unwrap();
        std::fs::write(repo.join("model/head_runtime.py"), "").unwrap();
        let checkpoint = dir.path().join("checkpoint.safetensors");
        std::fs::write(&checkpoint, b"harness fixture; not a trained model").unwrap();
        let shim = dir.path().join("span-shim");
        std::fs::write(
            &shim,
            "#!/usr/bin/env python3\nimport json, sys\nassert json.load(sys.stdin)['text'] == 'Ada works here'\nprint(json.dumps([{'start': 0, 'end': 3, 'type': 'PERSON', 'score': 0.9}]))\n",
        ).unwrap();
        let mut permissions = std::fs::metadata(&shim).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&shim, permissions).unwrap();
        let proof = run(&shim, &repo, &checkpoint, &sha256(&checkpoint).unwrap()).unwrap();
        let person = EntityId::from_bytes([31; 16]).unwrap();
        let turn = EntityId::from_bytes([32; 16]).unwrap();
        assert_eq!(proof.report.tags.mentions[0].entity, person);
        assert_eq!(proof.report.common, vec![person]);
        assert!(proof.report.tag_only.is_empty());
        assert_eq!(proof.report.live_only, vec![turn]);
        assert!(proof.live_ids.contains(&person.to_hex()));
        assert!(proof.live_ids.contains(&turn.to_hex()));
        assert_eq!(proof.vault_writes, 0);

        // Pin the observable CLI output. Keep user-visible text on the
        // injected writer rather than adding print macros to the ratchet.
        let args = vec![
            shim.to_string_lossy().into_owned(),
            repo.to_string_lossy().into_owned(),
            checkpoint.to_string_lossy().into_owned(),
            sha256(&checkpoint).unwrap(),
        ];
        let (mut output, mut errors) = (Vec::new(), Vec::new());
        assert_eq!(
            cli_with_io(&args, &mut output, &mut errors),
            std::process::ExitCode::SUCCESS
        );
        assert!(errors.is_empty());
        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["vault_writes"], 0);
        let report: ShadowTagReport = serde_json::from_value(json["report"].clone()).unwrap();
        assert_eq!(report.common, vec![person]);
    }

    #[test]
    fn cli_bad_invocation_writes_usage_to_error_sink() {
        let (mut output, mut errors) = (Vec::new(), Vec::new());
        assert_eq!(
            cli_with_io(&[], &mut output, &mut errors),
            std::process::ExitCode::FAILURE
        );
        assert!(output.is_empty());
        assert!(
            String::from_utf8(errors)
                .unwrap()
                .starts_with("usage: oneiron-bench oneironer-shadow ")
        );
    }

    /// Run with ONEIRON_NER_PYTHON, ONEIRON_NER_REPO,
    /// ONEIRON_NER_CHECKPOINT and ONEIRON_NER_SHA256 set to the model-of-record
    /// checkpoint. This is a real checkpoint-backed fixture, never a stub.
    #[test]
    #[ignore = "requires an external trained NER checkpoint and Python model runtime"]
    fn real_checkpoint_shadow_emits_report_and_writes_zero_vault_bytes() {
        let var = |name| std::env::var(name).expect("real checkpoint test requires this variable");
        let proof = run(
            Path::new(&var("ONEIRON_NER_PYTHON")),
            Path::new(&var("ONEIRON_NER_REPO")),
            Path::new(&var("ONEIRON_NER_CHECKPOINT")),
            &var("ONEIRON_NER_SHA256"),
        )
        .unwrap();
        assert_eq!(proof.vault_writes, 0);
        assert!(
            !proof.report.tags.mentions.is_empty(),
            "trained NER must find Ada"
        );
        assert_eq!(
            proof.report.tags.mentions[0].entity,
            EntityId::from_bytes([31; 16]).unwrap()
        );
        assert_eq!(
            proof.report.live_only,
            vec![EntityId::from_bytes([32; 16]).unwrap()]
        );
        assert_eq!(
            proof.report.common,
            vec![EntityId::from_bytes([31; 16]).unwrap()]
        );
    }
}
