//! K-proof (oracle) for PLAN-UC-04 stage 6.4e: seven digests of the oneiron crate keep their
//! bytes.
//!
//! A verdict memo's params hash, a saved query judge's rubric hash, a training swap
//! question's digest, a triage packet's content hash and an owner request's bundle content
//! hash and request hash now start through the fingerprint crate's K door
//! (`purposes::saved_query`, `training_pack`, `feedback`, `repo_mutation`), and a capsule
//! request piece's ref is `ContentHash::of`. Every verdict memo row stores the params hash,
//! the rubric hash seeds the membership question's id, a swap ask's route and key store its
//! digest, an issue signature row stores the packet's hash, an owner request's
//! `repo.provenance` claim stores both of its hashes, and the run's body row checks a piece's
//! ref. So each must give main's bytes for every value.
//!
//! `base_saved_query`, `base_question`, `base_pieces`, `base_packet_signature` and
//! `base_owner_request` hold main's lines at 0c11065c1d31, copied by range (each range is named
//! above its copy; the generator is `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`)
//! and differing from them only in indentation. The few lines around the copies are the
//! imports main's lines name, the `crate::llm` path they call (the engine's own
//! `canonical_json_bytes`), and stand-ins for what main's lines read (an owner request's staged
//! change and its refusal).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test fingerprint_keep_query_swap_piece_packet_repo_digests`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};

use oneiron::EntityId;
use oneiron::edit_distance::attribution::{
    AgentDefinitionRef, ArtifactPublisher, RecentChange, RecentChanges, SkillAtVersion,
    TriagePacket, TriageReceipt, TriageSubject, WorseningSignal,
};
use oneiron::repo_mutation::RepoBundleFile;
use oneiron::saved_query::{ClaimComparison, FilterAst, MatcherSpec};
use oneiron::test_doors::fingerprint_keep_query_swap_piece_packet_repo_digests as door;
use oneiron::training_pack::{CandleParityCheck, ExportCheck, SwapExpectation};
use oneiron_contracts::fingerprint::{LegacyHash, LegacyPurpose, TagMode, purposes};
use oneiron_model::llm::{ModelId, ModelTierRef};
use oneiron_model::model_binding::{ModelBinding, ModelSlot};
use serde_json::{Value as JsonValue, json};

/// The path main's lines name (`crate::llm::canonical_json_bytes`).
mod llm {
    pub(crate) use oneiron::llm::canonical_json_bytes;
}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_saved_query {
    use oneiron::Result;
    use oneiron::saved_query::{EVIDENCE_HASH_LEN, FilterAst, MatcherSpec};
    use oneiron_store::query_memo_codec::{EVALUATOR_VERSION, canonical_json_bytes, hex_lower};
    use oneiron_store::query_memos::SavedQueryDerivationEnvelope;
    use serde_json::{Map as JsonMap, Value};
    use sha2::{Digest, Sha256};

    // main 0c11065c1d31: crates/oneiron/src/saved_query/storage.rs:452-500
    fn filter_to_json(ast: &FilterAst) -> Value {
        let mut root = JsonMap::new();
        match ast {
            FilterAst::TaskOwner { owner } => {
                root.insert("op".to_owned(), Value::String("task_owner".to_owned()));
                root.insert("owner".to_owned(), Value::String(owner.to_hex()));
            }
            FilterAst::All { terms } | FilterAst::Any { terms } => {
                root.insert(
                    "op".to_owned(),
                    Value::String(
                        if matches!(ast, FilterAst::All { .. }) {
                            "all"
                        } else {
                            "any"
                        }
                        .to_owned(),
                    ),
                );
                root.insert(
                    "terms".to_owned(),
                    Value::Array(terms.iter().map(filter_to_json).collect()),
                );
            }
            FilterAst::Not { term } => {
                root.insert("op".to_owned(), Value::String("not".to_owned()));
                root.insert("term".to_owned(), filter_to_json(term));
            }
            FilterAst::Claim {
                predicate,
                cmp,
                value,
            } => {
                root.insert("op".to_owned(), Value::String("claim".to_owned()));
                root.insert("predicate".to_owned(), Value::String(predicate.clone()));
                root.insert("cmp".to_owned(), Value::String(cmp.as_str().to_owned()));
                root.insert("value".to_owned(), value.clone());
            }
            FilterAst::EdgeExists { edge_kind, target } => {
                root.insert("op".to_owned(), Value::String("edge_exists".to_owned()));
                root.insert("edge_kind".to_owned(), Value::String(edge_kind.clone()));
                root.insert(
                    "target".to_owned(),
                    target.map_or(Value::Null, |id| Value::String(id.to_hex())),
                );
            }
        }
        Value::Object(root)
    }

    // main 0c11065c1d31: crates/oneiron/src/saved_query/storage.rs:502-541
    pub(super) fn matcher_to_json(matcher: &MatcherSpec) -> Value {
        let mut root = JsonMap::new();
        match matcher {
            MatcherSpec::Hard { expression } => {
                root.insert("kind".to_owned(), Value::String("hard".to_owned()));
                root.insert("expression".to_owned(), filter_to_json(expression));
            }
            MatcherSpec::SemanticThreshold {
                exemplar_ref,
                minimum_similarity_micros,
            } => {
                root.insert(
                    "kind".to_owned(),
                    Value::String("semantic_threshold".to_owned()),
                );
                root.insert(
                    "exemplar_ref".to_owned(),
                    Value::String(exemplar_ref.to_hex()),
                );
                root.insert(
                    "minimum_similarity_micros".to_owned(),
                    Value::from(*minimum_similarity_micros),
                );
            }
            MatcherSpec::LlmJudge {
                model_id,
                rubric,
                rubric_version,
            } => {
                root.insert("kind".to_owned(), Value::String("llm_judge".to_owned()));
                root.insert("model_id".to_owned(), Value::String(model_id.clone()));
                root.insert("rubric".to_owned(), rubric.clone());
                root.insert(
                    "rubric_version".to_owned(),
                    Value::String(rubric_version.clone()),
                );
            }
        }
        Value::Object(root)
    }

    // main 0c11065c1d31: crates/oneiron/src/saved_query/evaluator.rs:902-918
    fn derivation_envelope(
        evidence_hash: &[u8; EVIDENCE_HASH_LEN],
        matcher: &MatcherSpec,
    ) -> Result<SavedQueryDerivationEnvelope> {
        let model_id = match matcher {
            MatcherSpec::Hard { .. } => "hard".to_owned(),
            MatcherSpec::SemanticThreshold { .. } => "semantic_threshold".to_owned(),
            MatcherSpec::LlmJudge { model_id, .. } => model_id.clone(),
        };
        let params = canonical_json_bytes(&matcher_to_json(matcher))?;
        Ok(SavedQueryDerivationEnvelope {
            content_hash: hex_lower(evidence_hash),
            model_id,
            version: EVALUATOR_VERSION.to_owned(),
            params_hash: hex_lower(&Sha256::digest(&params)),
        })
    }

    /// Main's params hash of `matcher`, as a verdict memo's envelope holds it.
    pub(crate) fn main_params_hash(matcher: &MatcherSpec) -> Result<String> {
        Ok(derivation_envelope(&[0; EVIDENCE_HASH_LEN], matcher)?.params_hash)
    }

    /// Main's rubric hash of `rubric`, which seeds the membership question.
    pub(crate) fn main_rubric_hash(rubric: &Value) -> Result<[u8; 32]> {
        // main 0c11065c1d31: crates/oneiron/src/saved_query/decisions.rs:96-96
            let rubric_hash = blake3::hash(&canonical_json_bytes(rubric)?);
        Ok(*rubric_hash.as_bytes())
    }
}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_question {
    use oneiron::training_pack::{ExportCheck, SwapExpectation};
    use oneiron::{Error, Result};
    use oneiron_contracts::entity_id::bytes_to_hex_lower;

    /// Main's digest of the swap question for `expected` and `checks`.
    pub(crate) fn main_swap_question_digest(
        expected: SwapExpectation,
        checks: &ExportCheck,
    ) -> Result<String> {
        // main 0c11065c1d31: crates/oneiron/src/task_verb/training_swap_ask/question.rs:124-126
            let bytes = crate::llm::canonical_json_bytes(&(&expected, checks))
                .map_err(|_| Error::InvalidConfig("training swap digest encoding failed".into()))?;
            let digest = bytes_to_hex_lower(blake3::hash(&bytes).as_bytes());
        Ok(digest)
    }
}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_pieces {
    use oneiron_records::compaction::output::OutputRef;

    // main 0c11065c1d31: crates/oneiron/src/code_run/storage/replay_capsule/pieces.rs:546-551
    pub(super) fn piece_ref(bytes: &[u8]) -> OutputRef {
        OutputRef {
            hash: *blake3::hash(bytes).as_bytes(),
            byte_len: bytes.len() as u64,
        }
    }
}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_packet_signature {
    use oneiron::edit_distance::attribution::TriagePacket;
    use oneiron::{Error, Result};

    /// Main's content hash of `packet`.
    pub(crate) fn main_content_hash(packet: &TriagePacket) -> Result<String> {
        // main 0c11065c1d31: crates/oneiron/src/feedback/report/delivery/packet_signature.rs:98-100
                let canonical = oneiron_model::llm::canonical_json_bytes(packet)
                    .map_err(|_| Error::InvariantViolation("triage packet encode"))?;
                let content_hash = blake3::hash(&canonical).to_hex().to_string();
        Ok(content_hash)
    }
}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_owner_request {
    use oneiron::repo_mutation::RepoBundleFile;
    use oneiron::{Error, Result};

    /// Main's refusal (`proposal::invalid`), as far as these lines need it: a refused bundle
    /// has no hash.
    fn invalid(reason: &'static str) -> Error {
        Error::InvalidConfig(reason.to_owned())
    }

    /// Main's staged change, as far as these lines build it.
    pub(crate) enum StagedChange {
        Bundle {
            #[allow(dead_code, reason = "main's field, which the copied lines fill")]
            files: Vec<(String, Option<String>)>,
            content_hash: String,
        },
    }

    impl StagedChange {
        // main 0c11065c1d31: crates/oneiron/src/repo_mutation/proposal/owner_request.rs:87-115
            fn bundle(files: &[RepoBundleFile]) -> Result<Self> {
                let mut ordered = std::collections::BTreeMap::new();
                for file in files {
                    let hash = file
                        .content
                        .as_ref()
                        .map(|content| blake3::hash(content).to_hex().to_string());
                    if ordered.insert(file.path.clone(), hash).is_some() {
                        return Err(invalid("an owner request's bundle names each path once"));
                    }
                }
                if ordered.is_empty() {
                    return Err(invalid("an owner request's bundle names at least one path"));
                }
                let files: Vec<(String, Option<String>)> = ordered.into_iter().collect();
                let listed = serde_json::Value::Array(
                    files
                        .iter()
                        .map(|(path, hash)| serde_json::json!({ "path": path, "content_hash": hash }))
                        .collect(),
                );
                let listed = crate::llm::canonical_json_bytes(&listed)
                    .map_err(|_| invalid("an owner request's bundle does not serialize"))?;
                let content_hash = blake3::hash(&listed).to_hex().to_string();
                Ok(Self::Bundle {
                    files,
                    content_hash,
                })
            }
    }

    /// Main's content hash of a native bundle of `files`.
    pub(crate) fn main_bundle_content_hash(files: &[RepoBundleFile]) -> Result<String> {
        let StagedChange::Bundle { content_hash, .. } = StagedChange::bundle(files)?;
        Ok(content_hash)
    }

    /// Main's request hash of an owner request whose hash input is `preimage`.
    pub(crate) fn main_request_hash(preimage: serde_json::Value) -> Result<String> {
        // main 0c11065c1d31: crates/oneiron/src/repo_mutation/proposal/owner_request.rs:200-202
                let preimage = crate::llm::canonical_json_bytes(&preimage)
                    .map_err(|_| invalid("an owner request's hash input does not serialize"))?;
                let request_hash = blake3::hash(&preimage).to_hex().to_string();
        Ok(request_hash)
    }
}

fn id(n: u8) -> EntityId {
    let mut bytes = [0x5a_u8; 16];
    bytes[0] = n;
    EntityId::from_bytes(bytes).expect("an unreserved id")
}

/// Eleven rubrics: two objects that are equal once their keys are sorted, the same object
/// with its array in another order, nested arrays and objects, strings with escapes and
/// non-ASCII text, an integer, a negative fraction, an empty array, null and an empty object.
/// Ten of them differ as sorted JSON.
fn rubrics() -> Vec<JsonValue> {
    vec![
        json!({ "criteria": ["on topic", "cites a source"], "threshold": 2 }),
        json!({ "threshold": 2, "criteria": ["on topic", "cites a source"] }),
        json!({ "criteria": ["cites a source", "on topic"], "threshold": 2 }),
        json!({ "nested": { "b": [1, 2.5, -3], "a": { "y": null, "x": false } } }),
        json!("belongs when the note names the project"),
        json!("quote \" backslash \\ tab \t newline \n é 日本"),
        json!(0),
        json!(-0.5),
        json!([]),
        JsonValue::Null,
        json!({}),
    ]
}

fn claim(predicate: &str, cmp: ClaimComparison, value: JsonValue) -> FilterAst {
    FilterAst::Claim {
        predicate: predicate.to_owned(),
        cmp,
        value,
    }
}

fn judge(model_id: &str, rubric: JsonValue, rubric_version: &str) -> MatcherSpec {
    MatcherSpec::LlmJudge {
        model_id: model_id.to_owned(),
        rubric,
        rubric_version: rubric_version.to_owned(),
    }
}

/// Thirteen matchers: every filter operator (an owner, an empty and a full conjunction and
/// disjunction, a negation, every claim comparison, an edge with and without a target), two
/// semantic thresholds and four judges, two of which hold rubrics that are equal once their
/// keys are sorted. Twelve of them differ as sorted JSON.
fn matchers() -> Vec<MatcherSpec> {
    let rubrics = rubrics();
    vec![
        MatcherSpec::Hard {
            expression: FilterAst::TaskOwner { owner: id(1) },
        },
        MatcherSpec::Hard {
            expression: FilterAst::TaskOwner { owner: id(2) },
        },
        MatcherSpec::Hard {
            expression: FilterAst::All { terms: Vec::new() },
        },
        MatcherSpec::Hard {
            expression: FilterAst::Any { terms: Vec::new() },
        },
        MatcherSpec::Hard {
            expression: FilterAst::All {
                terms: vec![
                    claim("status", ClaimComparison::Eq, json!("open")),
                    FilterAst::Not {
                        term: Box::new(claim("priority", ClaimComparison::Gt, json!(3))),
                    },
                    FilterAst::EdgeExists {
                        edge_kind: "blocks".to_owned(),
                        target: Some(id(3)),
                    },
                ],
            },
        },
        MatcherSpec::Hard {
            expression: FilterAst::Any {
                terms: vec![
                    claim(
                        "tags",
                        ClaimComparison::Contains,
                        json!({ "z": 1, "a": [true, null] }),
                    ),
                    claim("due", ClaimComparison::Exists, JsonValue::Null),
                    FilterAst::EdgeExists {
                        edge_kind: "blocks".to_owned(),
                        target: None,
                    },
                ],
            },
        },
        MatcherSpec::Hard {
            expression: FilterAst::Not {
                term: Box::new(FilterAst::All {
                    terms: vec![
                        claim("score", ClaimComparison::NotEq, json!(1.5)),
                        claim("score", ClaimComparison::Lt, json!(-2)),
                        claim("score", ClaimComparison::Lte, json!(0)),
                        claim("score", ClaimComparison::Gte, json!(10)),
                    ],
                }),
            },
        },
        MatcherSpec::SemanticThreshold {
            exemplar_ref: id(4),
            minimum_similarity_micros: 750_000,
        },
        MatcherSpec::SemanticThreshold {
            exemplar_ref: id(4),
            minimum_similarity_micros: 0,
        },
        judge("fake/judge@v1", rubrics[0].clone(), "r1"),
        judge("fake/judge@v1", rubrics[1].clone(), "r1"),
        judge("fake/judge@v1", rubrics[0].clone(), "r2"),
        judge("fake/judge@v2", rubrics[3].clone(), "r1"),
    ]
}

fn binding(model: &str, slot: ModelSlot, reads_audio: bool) -> ModelBinding {
    ModelBinding {
        model: ModelId::new(model).expect("model id"),
        slot,
        tier: ModelTierRef("a".into()),
        route_models: BTreeMap::new(),
        disposition: None,
        reads_audio,
    }
}

/// Three expectations: no incumbent, and two incumbents that differ in their model, slot and
/// audio flag, over two evaluations.
fn expectations() -> Vec<SwapExpectation> {
    let expectation = |evaluation: u8, incumbent: Option<ModelBinding>| SwapExpectation {
        spec_blake3: [1; 32],
        checkpoint_blake3: [2; 32],
        evaluation_blake3: [evaluation; 32],
        incumbent,
    };
    vec![
        expectation(3, None),
        expectation(3, Some(binding("fake/small@v1", ModelSlot::Llm, false))),
        expectation(4, Some(binding("fake/large@v2", ModelSlot::Embedder, true))),
    ]
}

/// Five export checks: a clean one, hash mismatches with argmax flips, failed settings and
/// harness checks with a tiny tolerance, a Candle parity check, and a non-finite logit
/// difference (sorted JSON writes it as null).
fn checks() -> Vec<ExportCheck> {
    let clean = ExportCheck {
        hash_mismatches: Vec::new(),
        probe_coverage_matches: true,
        probe_checkpoints_match: true,
        settings_match: true,
        harness_matches: true,
        argmax_flips: 0,
        max_logit_difference: 0.0,
        tolerance: 0.001,
        question_check: None,
        candle_parity: None,
    };
    vec![
        clean.clone(),
        ExportCheck {
            hash_mismatches: vec!["model.safetensors".into(), "tokenizer.json".into()],
            argmax_flips: 3,
            max_logit_difference: 0.25,
            ..clean.clone()
        },
        ExportCheck {
            settings_match: false,
            harness_matches: false,
            tolerance: 1e-9,
            ..clean.clone()
        },
        ExportCheck {
            candle_parity: Some(CandleParityCheck {
                tokens_match: false,
                token_mismatches: vec!["probe-7".into()],
                logits_match: None,
            }),
            ..clean.clone()
        },
        ExportCheck {
            max_logit_difference: f64::NAN,
            ..clean
        },
    ]
}

fn skill_at(version: &str, via_attempt: bool) -> SkillAtVersion {
    SkillAtVersion {
        skill: "triage-notes".into(),
        skill_id: id(9).to_hex(),
        version: version.into(),
        via_attempt,
    }
}

fn receipt(n: u8, rejected: bool, skill: Option<SkillAtVersion>) -> TriageReceipt {
    TriageReceipt {
        receipt: id(n).to_hex(),
        delta_ref: (n % 2 == 0).then(|| id(n + 100).to_hex()),
        rejected,
        d_norm: 0.125 * f32::from(n),
        at: 1_700_000_000_000 + u64::from(n),
        attempt: Some(id(n + 50).to_hex()),
        executor: Some("fake/small@v1".into()),
        judge: (n % 3 == 0).then(|| "fake/judge@v1".to_owned()),
        skill,
    }
}

fn packet(
    signal: WorseningSignal,
    subject_kind: TriageSubject,
    publisher: ArtifactPublisher,
    receipts: Vec<TriageReceipt>,
) -> TriagePacket {
    TriagePacket {
        signal,
        subject: id(7).to_hex(),
        subject_kind,
        scope: "project".into(),
        project: Some(id(8).to_hex()),
        publisher,
        receipts,
        agent_definitions: Vec::new(),
        skills: Vec::new(),
        executors: vec!["fake/small@v1".into()],
        recent_changes: RecentChanges {
            window_from: 1_700_000_000_000,
            skill_revision: None,
            executor: None,
        },
        at: 1_700_000_100_000,
    }
}

/// Six packets: a skill's climbing edit cost under a shipped and an owner publisher, an
/// actor's rejection run, an actor's reliability floor with definitions, skills and recent
/// changes, the same with no project and no executors, and a skill with three judged
/// receipts. All six differ as sorted JSON.
fn packets() -> Vec<TriagePacket> {
    let climbing = WorseningSignal::EditCostClimbing {
        previous_head: id(20).to_hex(),
        previous_mean: 0.25,
        previous_spread: 0.0625,
        current_head: id(21).to_hex(),
        current_mean: 0.5,
        current_spread: 0.125,
    };
    let floor = WorseningSignal::ReliabilityFloor {
        proposal: id(22).to_hex(),
        executor: None,
        lower_bound: 0.375,
        floor: 0.5,
        crossed_at: 1_700_000_050_000,
    };
    let change = |n: u8| RecentChange {
        receipt: id(n).to_hex(),
        before: format!("v{n}"),
        after: format!("v{}", n + 1),
        at: 1_700_000_060_000 + u64::from(n),
    };
    let mut detailed = packet(
        floor,
        TriageSubject::Actor,
        ArtifactPublisher::Shipped,
        vec![receipt(4, false, None)],
    );
    detailed.agent_definitions = vec![AgentDefinitionRef {
        definition: id(30).to_hex(),
        agent_id: id(31).to_hex(),
        version: "3".into(),
        logical_id: Some("reviewer".into()),
    }];
    detailed.skills = vec![skill_at("2", false)];
    detailed.recent_changes.skill_revision = Some(change(32));
    detailed.recent_changes.executor = Some(change(33));
    let mut bare = detailed.clone();
    bare.project = None;
    bare.executors = Vec::new();
    vec![
        packet(
            climbing.clone(),
            TriageSubject::Skill,
            ArtifactPublisher::Shipped,
            vec![receipt(1, true, Some(skill_at("3", true)))],
        ),
        packet(
            climbing,
            TriageSubject::Skill,
            ArtifactPublisher::Owner,
            vec![receipt(1, true, Some(skill_at("3", true)))],
        ),
        packet(
            WorseningSignal::RejectionRun {
                length: 4,
                newest: id(23).to_hex(),
            },
            TriageSubject::Actor,
            ArtifactPublisher::Shipped,
            vec![receipt(2, true, None), receipt(3, true, None)],
        ),
        detailed,
        bare,
        packet(
            WorseningSignal::RejectionRun {
                length: 3,
                newest: id(24).to_hex(),
            },
            TriageSubject::Skill,
            ArtifactPublisher::Shipped,
            vec![
                receipt(3, true, Some(skill_at("1", true))),
                receipt(6, false, Some(skill_at("1", true))),
                receipt(9, true, Some(skill_at("2", false))),
            ],
        ),
    ]
}

fn file(path: &str, content: Option<&str>, mode: Option<u32>) -> RepoBundleFile {
    RepoBundleFile::new(
        path.to_owned(),
        content.map(|text| text.as_bytes().to_vec()),
        mode,
    )
}

/// Ten bundles: one file; two files in either order and with a mode (main's list ignores
/// modes and sorts paths, so these three are one list); a removal beside a change; non-ASCII
/// paths and text; an empty file and a removal of one path; and two that main refuses (a
/// repeated path, no path). Six of the eight it accepts differ.
fn bundles() -> Vec<Vec<RepoBundleFile>> {
    vec![
        vec![file("a.rs", Some("x"), None)],
        vec![file("b.rs", Some("y"), None), file("a.rs", Some("x"), None)],
        vec![file("a.rs", Some("x"), None), file("b.rs", Some("y"), None)],
        vec![
            file("a.rs", Some("x"), Some(0o100_755)),
            file("b.rs", Some("y"), Some(0o100_644)),
        ],
        vec![
            file(".env", None, None),
            file("src/main.rs", Some("fn main() {}\n"), None),
        ],
        vec![
            file("é.txt", Some("naïve"), None),
            file("dir/日本.md", Some("テキスト"), None),
        ],
        vec![file("a.rs", Some(""), None)],
        vec![file("a.rs", None, None)],
        vec![file("a.rs", Some("x"), None), file("a.rs", Some("z"), None)],
        Vec::new(),
    ]
}

fn preimage(verb: &str, input: JsonValue, base_commit: &str, content_hash: &str) -> JsonValue {
    json!({
        "version": "vault.code.owner_request.v1",
        "verb": verb,
        "actor": id(1).to_hex(),
        "session": id(2).to_hex(),
        "input": input,
        "repo_ref": "git:local/repo@0123456789abcdef0123456789abcdef01234567",
        "base_commit": base_commit,
        "effective_content_hash": content_hash,
    })
}

/// Seven hash inputs: an owner's file proposal whose input keys come unsorted, the same with
/// another base commit and another content hash, a remediation bundle's (the bundle's own
/// content hash), and inputs that are null, a nested array and a string with escapes. All
/// seven differ.
fn preimages() -> Vec<JsonValue> {
    let base = "0123456789abcdef0123456789abcdef01234567";
    let other = "fedcba9876543210fedcba9876543210fedcba98";
    let file_hash = "a".repeat(64);
    let bundle_hash = door::bundle_content_hash(&bundles()[4]).expect("a bundle hash");
    let input = json!({ "path": "src/lib.rs", "message": "fix", "content": "x", "ack": true });
    vec![
        preimage(
            "vault.code.proposal_submit",
            input.clone(),
            base,
            &file_hash,
        ),
        preimage(
            "vault.code.proposal_submit",
            input.clone(),
            other,
            &file_hash,
        ),
        preimage("vault.code.proposal_submit", input, base, &"b".repeat(64)),
        preimage(
            "vault.code.secrets.propose",
            json!({ "finding": id(5).to_hex(), "paths": [".env", "src/main.rs"] }),
            base,
            &bundle_hash,
        ),
        preimage(
            "vault.code.proposal_submit",
            JsonValue::Null,
            base,
            &file_hash,
        ),
        preimage(
            "vault.code.proposal_submit",
            json!([[1, [2, { "b": 0, "a": -1.25 }]], []]),
            base,
            &file_hash,
        ),
        preimage(
            "vault.code.proposal_submit",
            json!("quote \" é \u{0}"),
            base,
            &file_hash,
        ),
    ]
}

#[test]
fn the_purposes_keep_main_s_recipes() {
    // None of main's starts writes a tag: each is plain SHA-256 or BLAKE3 of sorted JSON.
    let recipes: [(LegacyPurpose, LegacyHash, &[u8]); 6] = [
        (
            purposes::saved_query::DERIVATION_PARAMS,
            LegacyHash::Sha256,
            b"oneiron.saved_query.derivation_params.v1",
        ),
        (
            purposes::saved_query::JUDGE_RUBRIC,
            LegacyHash::Blake3,
            b"oneiron.saved_query.judge_rubric.v1",
        ),
        (
            purposes::training_pack::SWAP_QUESTION,
            LegacyHash::Blake3,
            b"oneiron.training_pack.swap_question.v1",
        ),
        (
            purposes::feedback::TRIAGE_PACKET,
            LegacyHash::Blake3,
            b"oneiron.feedback.triage_packet.v1",
        ),
        (
            purposes::repo_mutation::OWNER_BUNDLE,
            LegacyHash::Blake3,
            b"oneiron.repo_mutation.owner_bundle.v1",
        ),
        (
            purposes::repo_mutation::OWNER_REQUEST,
            LegacyHash::Blake3,
            b"oneiron.repo_mutation.owner_request.v1",
        ),
    ];
    for (purpose, hash, tag) in recipes {
        assert_eq!(purpose.hash(), hash);
        assert_eq!(purpose.tag_mode(), TagMode::NotHashed);
        assert_eq!(purpose.tag().as_bytes(), tag);
    }
}

#[test]
fn the_verdict_memo_params_hash_keeps_its_bytes() {
    let matchers = matchers();
    let mut hashes = BTreeSet::new();
    for matcher in &matchers {
        let head = door::derivation_params_hash(matcher).expect("head params hash");
        assert_eq!(
            head,
            base_saved_query::main_params_hash(matcher).expect("main params hash"),
            "{matcher:?}"
        );
        assert_eq!(head.len(), 64);
        hashes.insert(head);
    }
    assert_eq!((matchers.len(), hashes.len()), (13, 12));
}

#[test]
fn the_judge_rubric_hash_keeps_its_bytes() {
    let rubrics = rubrics();
    let mut hashes = BTreeSet::new();
    for rubric in &rubrics {
        let head = door::rubric_digest(rubric).expect("head rubric hash");
        assert_eq!(
            head,
            base_saved_query::main_rubric_hash(rubric).expect("main rubric hash"),
            "{rubric}"
        );
        hashes.insert(head);
    }
    assert_eq!((rubrics.len(), hashes.len()), (11, 10));
}

#[test]
fn the_swap_question_digest_keeps_its_bytes() {
    let mut digests = BTreeSet::new();
    let mut pairs = 0;
    for expected in &expectations() {
        for checks in &checks() {
            let head = door::swap_question_digest(expected, checks).expect("head digest");
            assert_eq!(
                head,
                base_question::main_swap_question_digest(expected.clone(), checks)
                    .expect("main digest"),
                "{expected:?} {checks:?}"
            );
            digests.insert(head);
            pairs += 1;
        }
    }
    assert_eq!((pairs, digests.len()), (15, 15));
}

#[test]
fn the_capsule_piece_ref_keeps_its_bytes() {
    // A config or message piece is canonical JSON; a sequence node and the manifest are
    // MessagePack. The ref is the bytes' content hash either way.
    let mut pieces = vec![
        Vec::new(),
        vec![0x92, 0xc0, 0x01],
        vec![
            0x82, 0xa6, b'c', b'o', b'n', b'f', b'i', b'g', 0xc4, 0x02, 0xff, 0x00,
        ],
        b"not json".to_vec(),
    ];
    for value in &rubrics() {
        pieces.push(llm::canonical_json_bytes(value).expect("canonical bytes"));
    }
    let mut hashes = BTreeSet::new();
    for bytes in &pieces {
        let head = door::piece_ref(bytes);
        assert_eq!(head, base_pieces::piece_ref(bytes), "{bytes:?}");
        assert_eq!(head.byte_len, bytes.len() as u64);
        hashes.insert(head.hash);
    }
    assert_eq!((pieces.len(), hashes.len()), (15, 14));
}

#[test]
fn the_triage_packet_content_hash_keeps_its_bytes() {
    let packets = packets();
    let mut hashes = BTreeSet::new();
    for packet in &packets {
        let head = door::packet_content_hash(packet).expect("head content hash");
        assert_eq!(
            head,
            base_packet_signature::main_content_hash(packet).expect("main content hash"),
            "{packet:?}"
        );
        assert_eq!(head.len(), 64);
        hashes.insert(head);
    }
    assert_eq!((packets.len(), hashes.len()), (6, 6));
}

#[test]
fn the_owner_bundle_content_hash_keeps_its_bytes() {
    let bundles = bundles();
    let mut hashes = BTreeSet::new();
    let mut refused = 0;
    for files in &bundles {
        let head = door::bundle_content_hash(files);
        assert_eq!(
            head,
            base_owner_request::main_bundle_content_hash(files).ok(),
            "{files:?}"
        );
        match head {
            Some(hash) => {
                hashes.insert(hash);
            }
            None => refused += 1,
        }
    }
    assert_eq!((bundles.len(), hashes.len(), refused), (10, 6, 2));
}

#[test]
fn the_owner_request_hash_keeps_its_bytes() {
    let preimages = preimages();
    let mut hashes = BTreeSet::new();
    for preimage in &preimages {
        let head = door::owner_request_hash(preimage).expect("head request hash");
        assert_eq!(
            head,
            base_owner_request::main_request_hash(preimage.clone()).expect("main request hash"),
            "{preimage}"
        );
        hashes.insert(head);
    }
    assert_eq!((preimages.len(), hashes.len()), (7, 7));
}
