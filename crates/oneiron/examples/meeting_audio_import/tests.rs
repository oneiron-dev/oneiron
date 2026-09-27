//! Packaged adapter acceptance tests and host-policy regression fixtures.

use super::*;
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};

#[test]
fn adapter_registration_stays_imported_and_matches_the_harness() {
    let source = INGEST_SOURCE_REGISTRY
        .get_config(MEETING_TRANSCRIPT_SOURCE_ID)
        .unwrap();
    assert_eq!(
        KNOWN_INGEST_HARNESS_CONFIG.get_config(MEETING_TRANSCRIPT_SOURCE_ID),
        Some(source)
    );
    assert_eq!(
        source
            .adapter_skill
            .map(|skill| (skill.skill_id, skill.version)),
        Some(("builtin.ingest.meeting-transcript", "1"))
    );
    assert_eq!(source.trust_ceiling.claim_source, ClaimSource::Imported);
    assert_eq!(source.default_admission, ClaimApprovalStatus::Proposed);
    assert!(!source.trust_ceiling.permits_auto(Some(0)));
}

fn route(id: &str, revision: &str) -> ModelRoute {
    ModelRoute {
        model_id: id.into(),
        model_revision: revision.into(),
        route_receipt_ref: "host-of133:receipt".into(),
        execution: RouteExecution::Native,
    }
}

#[test]
fn no_selection_receipt_keeps_the_host_selected_model_provisional() {
    let selected = route("custom/asr-beta", "rev-42");
    assert_eq!(
        batch_default(&selected, None).unwrap().model_id(),
        "custom/asr-beta"
    );
    assert!(matches!(
        batch_default(&selected, None).unwrap(),
        BatchDefault::Provisional { .. }
    ));
}

#[test]
fn missing_route_receipt_refuses_before_inference() {
    let mut routes = ModelRoutes {
        asr: route("model-a", "rev-a"),
        aligner: route("model-b", "rev-b"),
        diarization: route("model-c", "rev-c"),
        cleanup: route("model-d", "rev-d"),
    };
    routes.aligner.route_receipt_ref.clear();
    assert!(routes.validate().is_err());
    routes.aligner.route_receipt_ref = "host-of133:receipt".into();
    routes.asr.route_receipt_ref.clear();
    assert!(batch_default(&routes.asr, None).is_err());
}

#[test]
fn remote_model_refuses_native_host_cleanly() {
    let mut routes = ModelRoutes {
        asr: route("model-a", "rev-a"),
        aligner: route("model-b", "rev-b"),
        diarization: route("model-c", "rev-c"),
        cleanup: route("model-d", "rev-d"),
    };
    routes.asr.execution = RouteExecution::Remote;
    assert!(
        routes
            .require_native_profile(Path::new("/missing/profile"), "sha256")
            .is_err()
    );
}

#[test]
fn glossary_policy_is_loaded_from_a_file_and_rejects_blank_terms() {
    let temp = std::env::temp_dir().join(format!(
        "oneiron-audio-glossary-{}.json",
        uuid::Uuid::new_v4()
    ));
    fs::write(&temp, "[\"Alice\",\"製品名\"]").unwrap();
    assert_eq!(
        read_glossary(&temp, &PolicyLimits::resolve(None).unwrap()).unwrap(),
        ["Alice", "製品名"]
    );
    fs::write(&temp, r#"["Alice"," "]"#).unwrap();
    assert!(read_glossary(&temp, &PolicyLimits::resolve(None).unwrap()).is_err());
    fs::remove_file(temp).unwrap();
}

#[test]
fn policy_rows_allow_nondefault_workloads_but_holder_cannot_widen_vault() {
    use serde_json::json;
    let dir = std::env::temp_dir().join(format!("oneiron-audio-policy-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir).unwrap();
    let policy_path = dir.join("policy.json");
    let glossary_path = dir.join("glossary.json");
    let terms = (0..257).map(|n| format!("term-{n}")).collect::<Vec<_>>();
    fs::write(&glossary_path, serde_json::to_vec(&terms).unwrap()).unwrap();
    fs::write(&policy_path, r#"{"vault":{"glossary_max_terms":300,"stage_timeout_seconds":1800},"holder":{"glossary_max_terms":260,"stage_timeout_seconds":1200}}"#).unwrap();
    let resolved = PolicyLimits::resolve(Some(&policy_path)).unwrap();
    assert_eq!(resolved.stage_timeout_seconds, 1200);
    assert_eq!(read_glossary(&glossary_path, &resolved).unwrap(), terms);
    fs::write(
        &policy_path,
        r#"{"vault":{"stage_timeout_seconds":1800},"holder":{"stage_timeout_seconds":1801}}"#,
    )
    .unwrap();
    assert!(PolicyLimits::resolve(Some(&policy_path)).is_err());
    fs::write(&policy_path, r#"{"vault":{"stage_timeout_seconds":7201}}"#).unwrap();
    assert!(PolicyLimits::resolve(Some(&policy_path)).is_err());

    // The precedence row is executed, not merely accepted as decoration:
    // this vault policy disables the holder layer entirely.
    fs::write(&policy_path, r#"{"precedence":{"layers":["shipped","vault"],"mode":"nested_narrowing","holder_cap":"vault"},"vault":{"stage_timeout_seconds":1800}}"#).unwrap();
    assert_eq!(
        PolicyLimits::resolve(Some(&policy_path))
            .unwrap()
            .stage_timeout_seconds,
        1800
    );
    fs::write(&policy_path, r#"{"precedence":{"layers":["shipped","vault"],"mode":"nested_narrowing","holder_cap":"vault"},"holder":{"stage_timeout_seconds":1000}}"#).unwrap();
    assert!(PolicyLimits::resolve(Some(&policy_path)).is_err());

    // Count limits are workload policy. 10,001 short terms still fit the
    // independent byte ceiling, and a vault row can allow them.
    let many = vec!["x".to_owned(); 10_001];
    fs::write(&glossary_path, serde_json::to_vec(&many).unwrap()).unwrap();
    fs::write(
        &policy_path,
        r#"{"vault":{"glossary_max_terms":11000},"holder":{"glossary_max_terms":10500}}"#,
    )
    .unwrap();
    let permitted = PolicyLimits::resolve(Some(&policy_path)).unwrap();
    assert_eq!(
        read_glossary(&glossary_path, &permitted).unwrap().len(),
        10_001
    );
    let defaults: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../scripts/meeting-audio-adapter/policy-defaults.json"
    ))
    .unwrap();
    let mut vault = defaults["limits"]["cleanup"].clone();
    vault["max_candidates_per_word"] = 20.into();
    vault["max_candidate_bytes"] = 1000.into();
    vault["language_rules"]["English"]["allowed_pairs"] = json!([{"from":"allice","to":"Alice"}]);
    let mut holder = vault.clone();
    holder["max_candidates_per_word"] = 18.into();
    holder["max_candidate_bytes"] = 900.into();
    fs::write(
        &policy_path,
        json!({"vault":{"cleanup":vault},"holder":{"cleanup":holder}}).to_string(),
    )
    .unwrap();
    assert_eq!(
        PolicyLimits::resolve(Some(&policy_path))
            .unwrap()
            .cleanup
            .max_candidates_per_word,
        18
    );
    holder["max_candidates_per_word"] = 21.into();
    fs::write(
        &policy_path,
        json!({"vault":{"cleanup":vault},"holder":{"cleanup":holder}}).to_string(),
    )
    .unwrap();
    assert!(PolicyLimits::resolve(Some(&policy_path)).is_err());
    holder["max_candidates_per_word"] = 18.into();
    holder["language_rules"]["English"]["protected_suffixes"] = json!([]);
    fs::write(
        &policy_path,
        json!({"vault":{"cleanup":vault},"holder":{"cleanup":holder}}).to_string(),
    )
    .unwrap();
    assert!(PolicyLimits::resolve(Some(&policy_path)).is_err());
    holder["language_rules"]["English"]["protected_suffixes"] =
        vault["language_rules"]["English"]["protected_suffixes"].clone();
    holder["language_rules"]["English"]["allowed_pairs"] = json!([
        {"from":"allice","to":"Alice"}, {"from":"cannot","to":"can"}
    ]);
    fs::write(
        &policy_path,
        json!({"vault":{"cleanup":vault},"holder":{"cleanup":holder}}).to_string(),
    )
    .unwrap();
    assert!(PolicyLimits::resolve(Some(&policy_path)).is_err());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn e1_default_accepts_three_arbitrary_arms_and_rejects_foreign_winner() {
    use oneiron::ingest::meeting_audio::CohortFile;
    use serde_json::json;

    let dir = std::env::temp_dir().join(format!("oneiron-audio-e1-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir).unwrap();
    let mut cohort = CohortManifest {
        corpus_id: "fixture-only-not-measured".into(),
        cohort_sha256: "0".repeat(64),
        files: vec![CohortFile {
            file_id: "synthetic".into(),
            audio_sha256: "a".repeat(64),
            reference_sha256: "b".repeat(64),
            consent_ref: "fixture-not-consent".into(),
        }],
    };
    cohort.cohort_sha256 = cohort.computed_hash().unwrap();
    let cohort_path = dir.join("cohort.json");
    let selection_path = dir.join("selection.json");
    fs::write(&cohort_path, serde_json::to_vec(&cohort).unwrap()).unwrap();
    let arm = |model_id: &str, revision: &str| {
        json!({
            "model_id": model_id,
            "model_revision": revision,
            "model_sha256": "c".repeat(64),
            "runtime_sha256": "d".repeat(64),
            "wer_by_lang": {"English": {
                "substitutions": 0, "deletions": 0,
                "insertions": 0, "reference_len": 1
            }}
        })
    };
    let mut receipt = json!({
        "corpus_id": cohort.corpus_id,
        "corpus_sha256": cohort.cohort_sha256,
        "arms": [arm("vendor-a", "r1"), arm("vendor-b", "r2"), arm("vendor-c", "r3")],
        "winner": "vendor-c"
    });
    let binding = MeasuredE1 {
        cohort: cohort_path,
        selection: selection_path.clone(),
        evidence_ref: "fixture-only-not-an-of133-act".into(),
    };
    let relative = MeasuredE1 {
        cohort: PathBuf::from("relative-cohort.json"),
        selection: selection_path.clone(),
        evidence_ref: "fixture-only".into(),
    };
    assert!(batch_default(&route("vendor-c", "r3"), Some(&relative)).is_err());
    let write = |value: &serde_json::Value| {
        fs::write(&selection_path, serde_json::to_vec(value).unwrap()).unwrap();
    };
    write(&receipt);
    assert_eq!(
        batch_default(&route("vendor-c", "r3"), Some(&binding))
            .unwrap()
            .model_id(),
        "vendor-c"
    );
    assert!(batch_default(&route("vendor-c", "wrong-revision"), Some(&binding)).is_err());
    assert!(batch_default(&route("vendor-a", "r1"), Some(&binding)).is_err());
    receipt["winner"] = "outside-the-arms".into();
    write(&receipt);
    assert!(batch_default(&route("outside-the-arms", "r4"), Some(&binding)).is_err());
    receipt["winner"] = "vendor-c".into();
    receipt["arms"] = json!([arm("vendor-c", "r3")]);
    write(&receipt);
    assert!(batch_default(&route("vendor-c", "r3"), Some(&binding)).is_err());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn native_profile_binds_all_four_route_models_and_revisions() {
    use serde_json::json;
    let dir = std::env::temp_dir().join(format!("oneiron-audio-route-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("profile.json");
    let routes = ModelRoutes {
        asr: route("custom-asr", "rev-a"),
        aligner: route("custom-aligner", "rev-b"),
        diarization: route("custom-diarizer", "rev-c"),
        cleanup: route("custom-cleanup", "rev-d"),
    };
    let profile = json!({
        "asr": {"model_id":"custom-asr", "snapshot":"/models/rev-a"},
        "alignment": {"model_id":"custom-aligner", "snapshot":"/models/rev-b"},
        "diarization": {"model_id":"custom-diarizer", "snapshot":"/models/rev-c"},
        "cleanup": {"model_id":"custom-cleanup", "snapshot":"/models/rev-d"}
    });
    let bytes = serde_json::to_vec(&profile).unwrap();
    fs::write(&path, &bytes).unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    routes.require_native_profile(&path, &digest).unwrap();
    let mut changed = profile;
    changed["cleanup"]["snapshot"] = "wrong-revision".into();
    let bytes = serde_json::to_vec(&changed).unwrap();
    fs::write(&path, &bytes).unwrap();
    assert!(
        routes
            .require_native_profile(&path, &format!("{:x}", Sha256::digest(&bytes)))
            .is_err()
    );
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn packaged_mp4_fixture_emits_normalizable_artifact_and_survives_consent_handoff() {
    use oneiron::ingest::meeting_audio::{
        BulkImportAuthorizer, BulkImportBinding, BulkImportReceipt, ProducedMeetingTranscript,
    };
    use serde_json::json;

    struct OwnerConsent {
        allow: bool,
        seen: Vec<BulkImportBinding>,
    }
    impl BulkImportAuthorizer for OwnerConsent {
        fn vault_scope(&self) -> &str {
            "fixture-owner-vault"
        }
        fn authorize_import(
            &mut self,
            binding: &BulkImportBinding,
        ) -> oneiron::ingest::meeting_audio::AudioResult<Option<BulkImportReceipt>> {
            self.seen.push(binding.clone());
            Ok(self.allow.then(|| BulkImportReceipt {
                binding: binding.clone(),
                receipt_ref: "fixture-owner-approved".into(),
            }))
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let media = root.join("crates/oneiron/tests/fixtures/ingest/native_audio/public-speech.mp4");
    let pcm =
        root.join("crates/oneiron/tests/fixtures/ingest/native_audio/public-speech.pcm16.zlib");
    let dir = std::env::temp_dir().join(format!("oneiron-audio-adapter-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir).unwrap();
    let bridge = dir.join("fixture-host.py");
    fs::copy(
        root.join("scripts/meeting-audio-adapter/fixture-host.py"),
        &bridge,
    )
    .unwrap();
    fs::copy(
        root.join("scripts/meeting_audio_runtime.py"),
        dir.join("meeting_audio_runtime.py"),
    )
    .unwrap();
    let snapshot = dir.join("asr-revision");
    fs::create_dir(&snapshot).unwrap();
    let mk_spec = |id: &str, rev: &str| json!({"model_id":id,"snapshot":dir.join(rev)});
    let prompt = dir.join("cleanup-v1.txt");
    fs::write(&prompt, "Fix only ASR-backed words: {{TRANSCRIPT_JSON}}").unwrap();
    let glossary = dir.join("glossary.json");
    fs::write(&glossary, r#"["Ada","製品名"]"#).unwrap();
    let policy_path = dir.join("policy.json");
    let mut shipped: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../scripts/meeting-audio-adapter/policy-defaults.json"
    ))
    .unwrap();
    shipped["limits"]["cleanup"]["language_rules"]["English"]["allowed_pairs"] =
        json!([{"from": "allice", "to": "Alice"}]);
    fs::write(
        &policy_path,
        json!({"vault": {"cleanup": shipped["limits"]["cleanup"]}}).to_string(),
    )
    .unwrap();
    let profile = json!({
        "asr": mk_spec("fixture-asr", "asr-revision"),
        "alignment": mk_spec("fixture-aligner", "aligner-revision"),
        "diarization": mk_spec("fixture-alternative-diarizer", "diarizer-revision"),
        "cleanup": {"model_id":"fixture-cleanup", "snapshot":dir.join("cleanup-revision"),
                    "instructions":prompt,"instructions_sha256":format!("{:x}", Sha256::digest(fs::read(&prompt).unwrap()))},
        "fixture_mp4_sha256": format!("{:x}", Sha256::digest(fs::read(&media).unwrap())),
        "fixture_pcm_sha256": "5e0f5f5721d8b79cfc91fe0fa0cc67dc37b495eec93c2706d02940dc9527cb8d",
        "fixture_pcm_zlib": pcm,
    });
    let profile_path = dir.join("profile.json");
    let bytes = serde_json::to_vec(&profile).unwrap();
    fs::write(&profile_path, &bytes).unwrap();
    let python = PathBuf::from("/usr/bin/python3");
    let output = dir.join("meeting-transcript.json");
    let routes = ModelRoutes {
        asr: route("fixture-asr", "asr-revision"),
        aligner: route("fixture-aligner", "aligner-revision"),
        diarization: route("fixture-alternative-diarizer", "diarizer-revision"),
        cleanup: route("fixture-cleanup", "cleanup-revision"),
    };
    run(AdapterConfig {
        python: python.clone(),
        bridge,
        // The fixture consumes retained PCM, so it does not execute this path.
        ffmpeg: python,
        workspace: dir.clone(),
        model_snapshot: snapshot,
        runtime_profile: profile_path,
        runtime_profile_sha256: format!("{:x}", Sha256::digest(bytes)),
        audio: media,
        output: output.clone(),
        language_hint: "English".into(),
        capture_started_at: None,
        glossary,
        policy_manifest: Some(policy_path),
        routes,
        measured_e1: None,
    })
    .unwrap();
    let saved = fs::read_to_string(output).unwrap();
    let document: serde_json::Value = serde_json::from_str(&saved).unwrap();
    assert_eq!(document["schema"], "oneiron.meeting_transcript.v1");
    assert_eq!(document["producer"]["execution"], "fixture");
    assert_eq!(
        document["diarization"]["provenance"]["model_id"],
        "fixture-alternative-diarizer"
    );
    assert_eq!(document["words"][0]["text"], "allice");
    assert_eq!(document["turns"][0]["text"], "Alice.");
    let artifact = ProducedMeetingTranscript::from_json(saved.clone()).unwrap();
    let normalized = INGEST_SOURCE_REGISTRY
        .normalize(MEETING_TRANSCRIPT_SOURCE_ID, artifact.json())
        .unwrap();
    assert_eq!(normalized.records.len(), 1);
    assert!(normalized.claims.is_empty());
    let mut pending = OwnerConsent {
        allow: false,
        seen: Vec::new(),
    };
    assert!(artifact.authorize_import(&mut pending).is_err());
    let mut approved = OwnerConsent {
        allow: true,
        seen: Vec::new(),
    };
    let imported = artifact.authorize_import(&mut approved).unwrap();
    assert_eq!(approved.seen[0], pending.seen[0]);
    assert_eq!(
        approved.seen[0].artifact_sha256,
        format!("{:x}", Sha256::digest(saved.as_bytes()))
    );
    assert_eq!(imported.normalized().records.len(), 1);
    fs::remove_dir_all(dir).unwrap();
}
