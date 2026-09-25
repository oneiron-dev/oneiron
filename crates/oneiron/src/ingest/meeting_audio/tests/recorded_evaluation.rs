//! Offline harness fixtures, not native model quality or host provisioning evidence.
use crate::ingest::meeting_audio::{
    CohortFile, CohortManifest, RecordedArm, RecordedFile, ReferenceDocument, WordCluster,
    evaluate_recorded_audio,
};
use sha2::{Digest, Sha256};
fn labels(values: &[&str]) -> Vec<WordCluster> {
    values
        .iter()
        .enumerate()
        .map(|(i, value)| WordCluster {
            word_id: i.to_string(),
            cluster: (*value).into(),
        })
        .collect()
}
#[test]
fn recorded_cohort_harness_binds_inputs_and_scores_global_not_per_chunk() {
    let reference = r#"{"language":"ja","tokenizer":"fixture-tokens-v1","tokens":["今日","は","晴れ","です"],"speakers":[{"word_id":"0","cluster":"a"},{"word_id":"1","cluster":"b"},{"word_id":"2","cluster":"a"},{"word_id":"3","cluster":"b"}]}"#;
    let mut cohort = CohortManifest {
        corpus_id: "offline-fixture".into(),
        cohort_sha256: String::new(),
        files: vec![CohortFile {
            file_id: "meeting".into(),
            audio_sha256: "a".repeat(64),
            reference_sha256: format!("{:x}", Sha256::digest(reference.as_bytes())),
            consent_ref: "fixture-no-inference".into(),
        }],
    };
    cohort.cohort_sha256 = cohort.computed_hash().unwrap();
    let references = vec![ReferenceDocument {
        file_id: "meeting".into(),
        json: reference.into(),
    }];
    let arm = |id: &str, tokens: &[&str], speakers: &[&str]| RecordedArm {
        model_id: id.into(),
        model_revision: "fixture-revision".into(),
        model_sha256: "b".repeat(64),
        runtime_sha256: "c".repeat(64),
        files: vec![RecordedFile {
            file_id: "meeting".into(),
            tokens: tokens.iter().map(|s| (*s).into()).collect(),
            speakers: labels(speakers),
        }],
    };
    let arms = vec![
        arm("flipped", &["今日", "晴れ", "です"], &["x", "y", "y", "x"]),
        arm(
            "consistent",
            &["今日", "は", "晴れ", "です"],
            &["x", "y", "x", "y"],
        ),
    ];
    let report = evaluate_recorded_audio(&cohort, &references, &arms).unwrap();
    assert_eq!(report.e1.winner, "consistent");
    assert_eq!(report.e1.winner_totals().unwrap().errors(), 0);
    assert_eq!(report.e3["consistent"]["meeting"].correct, 4);
    assert_eq!(report.e3["flipped"]["meeting"].wrong_speaker, 2);
    assert_eq!(report.evidence_kind, "offline_recorded_outputs_v1");
    let reversed: Vec<_> = arms.iter().cloned().rev().collect();
    assert_eq!(
        evaluate_recorded_audio(&cohort, &references, &reversed)
            .unwrap()
            .hypotheses_sha256,
        report.hypotheses_sha256
    );
    let mut wrong_refs = references.clone();
    wrong_refs[0].json.push(' ');
    assert!(evaluate_recorded_audio(&cohort, &wrong_refs, &arms).is_err());
    let mut duplicate = arms.clone();
    duplicate[0].files[0].speakers.push(WordCluster {
        word_id: "0".into(),
        cluster: "z".into(),
    });
    assert!(evaluate_recorded_audio(&cohort, &references, &duplicate).is_err());
    let mut missing = arms.clone();
    missing[0].files.clear();
    assert!(evaluate_recorded_audio(&cohort, &references, &missing).is_err());
    let mut changed = arms;
    changed[0].files[0].tokens.push("extra".into());
    assert_ne!(
        evaluate_recorded_audio(&cohort, &references, &changed)
            .unwrap()
            .hypotheses_sha256,
        report.hypotheses_sha256
    );
}
