//! K-proof (oracle) for PLAN-UC-04 stage 3.4b: the executor's config and step checkpoint
//! hashes, the claim cohort id and the late-credit receipt key keep their bytes.
//!
//! Each now starts its BLAKE3 through the fingerprint crate's K door
//! (`purposes::engine_executor::{CONFIG, STEP_CHECKPOINT}`, `purposes::cluster::CLAIM_COHORT`,
//! `purposes::skill_attribution::LATE_CREDIT_RECEIPT`). A CodeRun config marker stores the
//! config hash's hex and every resume compares it; each replay checkpoint stores its step
//! hash and the next step chains it; the clustering door sends the cohort id; the stored
//! late-credit receipt is keyed by its receipt key. So each must give main's bytes for
//! every value. The `base_*` modules hold main's lines at 4692e7ed3a60, copied by range (each
//! range is named above its copy; the generator is
//! `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and differing from them
//! only in indentation. The few lines around the copies give them main's names: a storage
//! that answers main's two questions, the step's result digests and end, a cohort id, the
//! replay encoding (through the test door), and wrappers that call the private copies.
//!
//! The doors build only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_executor_cohort_credit`.
#![cfg(oneiron_test_support)]

use std::path::PathBuf;

use oneiron::claim::ClaimSubject;
use oneiron::cluster::{ClusterClaim, ClusterOptions, cluster_claims};
use oneiron::code_run::{CODE_RUN_RNG_SEED_LEN, CodeRunDeterminism, SelfEffect};
use oneiron::edge::EdgeKind;
use oneiron::engine_executor::{EngineExecutorConfig, EngineExecutorLimits};
use oneiron::entity_id::EntityId;
use oneiron::llm::{ModelId, ModelLocality, ModelTierRef, ReasoningEffort};
use oneiron::test_doors::fingerprint_keep_executor_cohort_credit::{self as door, StepState};
use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};
use oneiron_store::session_overlay::RouteTarget;
use rmpv::Value;

// Not formatted, so each copy stays line for line equal to main's. The copies keep main's
// `pub`, which these private modules cannot export.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_executor {
    use oneiron::code_run::CodeRunBridgeCall;
    use oneiron::engine_executor::{EngineExecutorConfig, EngineExecutorResult};
    use oneiron::llm::ModelLocality;
    use oneiron::test_doors::fingerprint_keep_executor_cohort_credit::encode_code_run_replay_value;
    use oneiron_store::session_overlay::RouteTarget;

    /// What main's config hash asks of its storage: the session ref of a session binding
    /// and the route target.
    pub(crate) struct ExecutorStorage<'a> {
        pub(crate) session_ref: Option<&'a str>,
        pub(crate) route_target: Option<RouteTarget>,
    }

    impl ExecutorStorage<'_> {
        pub(crate) fn session_ref(&self) -> Option<&str> {
            self.session_ref
        }

        pub(crate) fn session_route_target(&self) -> Option<RouteTarget> {
            self.route_target
        }
    }

    /// A step's result digests, by main's names.
    pub(crate) struct StepResultDigests {
        pub(crate) observation: [u8; 32],
        pub(crate) done: bool,
        pub(crate) outputs: Vec<(String, [u8; 32])>,
        pub(crate) bindings: Vec<(String, String)>,
    }

    /// Where a step's calls end and its replay context, by main's names.
    pub(crate) struct StepEnd {
        pub(crate) bridge_end: u64,
        pub(crate) context: [u8; 32],
    }

    /// Main's config hash, which is private there.
    pub(crate) fn main_config_hash(
        storage: &ExecutorStorage<'_>,
        config: &EngineExecutorConfig,
        continuation: Option<&[u8; 32]>,
    ) -> [u8; 32] {
        executor_config_hash(storage, config, continuation)
    }

    /// Main's config and checkpoint domains, which are private there.
    pub(crate) const MAIN_DOMAINS: [&[u8]; 2] = [CONFIG_HASH_DOMAIN, CHECKPOINT_DOMAIN];

// main 4692e7ed3a60: crates/oneiron/src/engine_executor/record.rs:119-138
const CHECKPOINT_DOMAIN: &[u8] = b"oneiron:engine-executor-repl-step:v1";

/// Marks a step that ran as the JavaScript Oxc printed for its TypeScript
/// program (FIX 8276); a JavaScript step hashes no such part.
const PREPARED_SOURCE_DOMAIN: &[u8] = b"oneiron:engine-executor-repl-step:prepared-source:v1";

const CONFIG_HASH_DOMAIN: &[u8] = b"oneiron:engine-executor-config:v1";

/// Storage-binding tags folded into the config marker (ONE-1729).
const CONFIG_BINDING_CANONICAL_TAG: &[u8] = b"storage:canonical";

const CONFIG_BINDING_SESSION_TAG: &[u8] = b"storage:off-record-session";

const CONFIG_ROUTE_OVERLAY_TAG: &[u8] = b"route:overlay";

const CONFIG_ROUTE_BASE_TAG: &[u8] = b"route:base";

/// Tags the digest of the approved continuation a child run was forked
/// under (FIX 3694); a run with none hashes nothing more.
const CONFIG_CONTINUATION_TAG: &[u8] = b"continuation";

// main 4692e7ed3a60: crates/oneiron/src/engine_executor/record.rs:353-400
fn executor_config_hash(
    storage: &ExecutorStorage<'_>,
    config: &EngineExecutorConfig,
    continuation: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_bytes(&mut hasher, CONFIG_HASH_DOMAIN);
    match storage.session_ref() {
        None => hash_bytes(&mut hasher, CONFIG_BINDING_CANONICAL_TAG),
        Some(session_ref) => {
            hash_bytes(&mut hasher, CONFIG_BINDING_SESSION_TAG);
            hash_str(&mut hasher, session_ref);
        }
    }
    if let Some(target) = storage.session_route_target() {
        hash_bytes(
            &mut hasher,
            match target {
                RouteTarget::Overlay => CONFIG_ROUTE_OVERLAY_TAG,
                RouteTarget::Base => CONFIG_ROUTE_BASE_TAG,
                RouteTarget::Discard => b"discard",
            },
        );
    }
    hash_str(&mut hasher, &config.run_id.to_hex());
    hash_str(&mut hasher, &config.task);
    hash_str(&mut hasher, config.model.as_str());
    hash_str(&mut hasher, model_locality_str(config.model_locality));
    if let Some(effort) = config.seat_effort {
        hash_str(&mut hasher, &format!("seat_effort:{effort:?}"));
    }
    hash_str(&mut hasher, config.global_tier.as_str());
    hash_u64(&mut hasher, config.determinism.frozen_unix_ms);
    hash_bytes(&mut hasher, &config.determinism.rng_seed);
    if let Some(digest) = continuation {
        hash_bytes(&mut hasher, CONFIG_CONTINUATION_TAG);
        hash_bytes(&mut hasher, digest);
    }
    *hasher.finalize().as_bytes()
}

fn model_locality_str(locality: ModelLocality) -> &'static str {
    match locality {
        ModelLocality::OnDevice => "on_device",
        ModelLocality::OwnServer => "own_server",
        ModelLocality::ThirdParty => "third_party",
    }
}

// main 4692e7ed3a60: crates/oneiron/src/engine_executor/record.rs:706-767
#[expect(
    clippy::too_many_arguments,
    reason = "the checkpoint hashes every part of the step's state"
)]
pub(super) fn prepared_step_state_hash(
    previous: [u8; 32],
    seq: u64,
    request_hash: &[u8; 32],
    script: &str,
    prepared: Option<&[u8; 32]>,
    result: &StepResultDigests,
    implicit_speak: Option<&str>,
    bridge_calls: &[CodeRunBridgeCall],
    end: StepEnd,
) -> EngineExecutorResult<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hash_bytes(&mut hasher, CHECKPOINT_DOMAIN);
    hash_bytes(&mut hasher, &previous);
    hash_u64(&mut hasher, seq);
    hash_bytes(&mut hasher, request_hash);
    hash_bytes(&mut hasher, blake3::hash(script.as_bytes()).as_bytes());
    if let Some(identity) = prepared {
        hash_bytes(&mut hasher, PREPARED_SOURCE_DOMAIN);
        hash_bytes(&mut hasher, identity);
    }
    hash_bytes(&mut hasher, &result.observation);
    hash_bytes(&mut hasher, &[u8::from(result.done)]);
    hash_bytes(&mut hasher, &[u8::from(implicit_speak.is_some())]);
    if let Some(text) = implicit_speak {
        hash_bytes(&mut hasher, blake3::hash(text.as_bytes()).as_bytes());
    }
    hash_u64(&mut hasher, result.outputs.len() as u64);
    for (path, digest) in &result.outputs {
        hash_str(&mut hasher, path);
        hash_bytes(&mut hasher, digest);
    }
    hash_u64(&mut hasher, result.bindings.len() as u64);
    for (name, handle) in &result.bindings {
        hash_str(&mut hasher, name);
        hash_str(&mut hasher, handle);
    }
    hash_u64(&mut hasher, bridge_calls.len() as u64);
    for call in bridge_calls {
        hash_u64(&mut hasher, call.seq);
        hash_str(&mut hasher, call.effect.as_str());
        let request =
            encode_code_run_replay_value(&call.request, "executor bridge call request hash")?;
        let outcome =
            encode_code_run_replay_value(&call.outcome, "executor bridge call outcome hash")?;
        hash_bytes(&mut hasher, &request);
        hash_bytes(&mut hasher, &outcome);
        // Rewritten rows are pinned; legacy rows hash identically (FIX 1442).
        if let Some(rewritten) = &call.rewritten_request {
            let rewritten =
                encode_code_run_replay_value(rewritten, "executor bridge call rewritten hash")?;
            hash_bytes(&mut hasher, &rewritten);
        }
    }
    hash_u64(&mut hasher, end.bridge_end);
    hash_bytes(&mut hasher, &end.context);
    Ok(*hasher.finalize().as_bytes())
}

// main 4692e7ed3a60: crates/oneiron/src/engine_executor/record.rs:769-780
fn hash_u64(hasher: &mut blake3::Hasher, value: u64) {
    hasher.update(&value.to_be_bytes());
}

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hash_u64(hasher, bytes.len() as u64);
    hasher.update(bytes);
}

fn hash_str(hasher: &mut blake3::Hasher, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_cohort {
    use oneiron::cluster::ClusterPartitionKey;
    use oneiron::entity_id::EntityId;

    /// A cohort id, by main's name; main's constructor is private to its module.
    pub(crate) struct CohortId(pub(crate) [u8; 32]);

    /// Main's cohort id, which is private there.
    pub(crate) fn main_cohort_id(partition: &ClusterPartitionKey, sorted_members: &[EntityId]) -> [u8; 32] {
        cohort_id(partition, sorted_members).0
    }

// main 4692e7ed3a60: crates/oneiron/src/memory/claim_cluster.rs:46-46
pub const CLUSTER_ID_DOMAIN: &[u8] = b"oneiron:claim-cohort:v1";

// main 4692e7ed3a60: crates/oneiron/src/memory/claim_cluster.rs:272-284
fn cohort_id(partition: &ClusterPartitionKey, sorted_members: &[EntityId]) -> CohortId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CLUSTER_ID_DOMAIN);
    hash_bytes(&mut hasher, &partition.subject.encode());
    hash_bytes(&mut hasher, partition.predicate_root.as_bytes());
    hash_optional_entity(&mut hasher, partition.world);
    hash_optional_entity(&mut hasher, partition.facet);
    hash_length(&mut hasher, sorted_members.len());
    for member in sorted_members {
        hasher.update(member.as_bytes());
    }
    CohortId(*hasher.finalize().as_bytes())
}

// main 4692e7ed3a60: crates/oneiron/src/memory/claim_cluster.rs:304-323
fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hash_length(hasher, bytes.len());
    hasher.update(bytes);
}

fn hash_length(hasher: &mut blake3::Hasher, length: usize) {
    hasher.update(&(length as u64).to_le_bytes());
}

fn hash_optional_entity(hasher: &mut blake3::Hasher, entity: Option<EntityId>) {
    match entity {
        Some(entity) => {
            hasher.update(&[1]);
            hasher.update(entity.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_credit {
// main 4692e7ed3a60: crates/oneiron/src/skill_attribution/late_credit.rs:81-88
pub(super) fn receipt_id(attempt: &str, outcome: &str, axis: &str) -> String {
    let mut hash = blake3::Hasher::new_derive_key("oneiron pack outcome credit v1");
    for text in [attempt, outcome, axis] {
        hash.update(&(text.len() as u64).to_be_bytes());
        hash.update(text.as_bytes());
    }
    format!("credit:{}", hash.finalize().to_hex())
}
}

fn id(byte: u8) -> EntityId {
    let mut bytes = [byte; 16];
    bytes[0] = 0x01;
    EntityId::from_bytes_unchecked(bytes)
}

/// Texts with every edge the framing has: empty, one byte, a NUL, `ÿ`, unicode and a
/// 300-byte value (its length has a second byte).
fn texts() -> Vec<String> {
    vec![
        String::new(),
        "a".to_owned(),
        "a\0b".to_owned(),
        "\u{ff}".to_owned(),
        "ünïcödé ✓".to_owned(),
        "x".repeat(300),
    ]
}

fn config(task: &str) -> EngineExecutorConfig {
    EngineExecutorConfig {
        run_id: id(0x11),
        task: task.to_owned(),
        prompt_package_root: PathBuf::from("/prompt-package"),
        model: ModelId::new("local/test-model@v1").expect("a valid model id"),
        model_locality: ModelLocality::OnDevice,
        seat_effort: None,
        global_tier: ModelTierRef("standard".to_owned()),
        determinism: CodeRunDeterminism::new(1_700_000_000_000, [0xab; CODE_RUN_RNG_SEED_LEN]),
        limits: EngineExecutorLimits::default(),
        wake: None,
    }
}

/// Configs that differ from one base config in one hashed field each.
fn configs() -> Vec<EngineExecutorConfig> {
    let mut configs: Vec<EngineExecutorConfig> = texts().iter().map(|task| config(task)).collect();
    for locality in [ModelLocality::OwnServer, ModelLocality::ThirdParty] {
        configs.push(EngineExecutorConfig {
            model_locality: locality,
            ..config("task")
        });
    }
    for effort in [
        ReasoningEffort::None,
        ReasoningEffort::Low,
        ReasoningEffort::Medium,
        ReasoningEffort::High,
        ReasoningEffort::XHigh,
    ] {
        configs.push(EngineExecutorConfig {
            seat_effort: Some(effort),
            ..config("task")
        });
    }
    configs.push(EngineExecutorConfig {
        run_id: id(0x22),
        model: ModelId::new("anthropic/claude-test@2026-01-01").expect("a valid model id"),
        global_tier: ModelTierRef(String::new()),
        determinism: CodeRunDeterminism::new(0, [0; CODE_RUN_RNG_SEED_LEN]),
        ..config("task")
    });
    configs.push(EngineExecutorConfig {
        global_tier: ModelTierRef("x".repeat(300)),
        determinism: CodeRunDeterminism::new(u64::MAX, [0xff; CODE_RUN_RNG_SEED_LEN]),
        ..config("task")
    });
    configs
}

#[test]
fn the_executor_purposes_keep_main_s_domains() {
    let [config, checkpoint] = base_executor::MAIN_DOMAINS;
    for (purpose, domain) in [
        (purposes::engine_executor::CONFIG, config),
        (purposes::engine_executor::STEP_CHECKPOINT, checkpoint),
    ] {
        assert_eq!(purpose.hash(), LegacyHash::Blake3);
        assert_eq!(purpose.tag_mode(), TagMode::NotHashed);
        assert_eq!(purpose.tag().as_bytes(), domain);
    }
}

#[test]
fn the_executor_config_hash_keeps_its_bytes() {
    let bindings: [(Option<&str>, Option<RouteTarget>); 7] = [
        (None, None),
        (None, Some(RouteTarget::Base)),
        (Some("session-a"), None),
        (Some("session-a"), Some(RouteTarget::Overlay)),
        (Some("session-a"), Some(RouteTarget::Base)),
        (Some(""), Some(RouteTarget::Discard)),
        (Some("ünï\0"), Some(RouteTarget::Discard)),
    ];
    let configs = configs();
    assert_eq!(configs.len(), 15);
    let mut seen = std::collections::BTreeSet::new();
    for (session_ref, route_target) in bindings {
        let storage = base_executor::ExecutorStorage {
            session_ref,
            route_target,
        };
        for config in &configs {
            for continuation in [None, Some(&[0x09; 32])] {
                let main = base_executor::main_config_hash(&storage, config, continuation);
                let head =
                    door::executor_config_hash(session_ref, route_target, config, continuation);
                assert_eq!(
                    head, main,
                    "{session_ref:?} {route_target:?} {config:?} {continuation:?}"
                );
                seen.insert(main);
            }
        }
    }
    assert_eq!(seen.len(), 7 * 15 * 2);
}

fn step(script: &str) -> StepState {
    StepState {
        previous: [0x01; 32],
        seq: 7,
        request_hash: [0x22; 32],
        script: script.to_owned(),
        prepared: None,
        observation: [0x33; 32],
        done: false,
        outputs: Vec::new(),
        bindings: Vec::new(),
        implicit_speak: None,
        bridge_calls: Vec::new(),
        bridge_end: 0,
        context: [0; 32],
    }
}

fn map(key: &str, value: &str) -> Value {
    Value::Map(vec![(Value::from(key), Value::from(value))])
}

/// Steps that differ from one base step in one hashed part each.
fn steps() -> Vec<StepState> {
    let mut steps: Vec<StepState> = texts().iter().map(|script| step(script)).collect();
    steps.push(StepState {
        previous: [0xfe; 32],
        seq: u64::MAX,
        request_hash: [0; 32],
        ..step("s")
    });
    steps.push(StepState {
        prepared: Some([0x44; 32]),
        ..step("s")
    });
    steps.push(StepState {
        done: true,
        observation: [0; 32],
        ..step("s")
    });
    for text in texts() {
        steps.push(StepState {
            implicit_speak: Some(text),
            ..step("s")
        });
    }
    steps.push(StepState {
        outputs: vec![
            ("out/a.txt".to_owned(), [0x55; 32]),
            (String::new(), [0x66; 32]),
        ],
        ..step("s")
    });
    steps.push(StepState {
        bindings: vec![
            ("result".to_owned(), "handle:1".to_owned()),
            ("ü".to_owned(), String::new()),
        ],
        ..step("s")
    });
    steps.push(StepState {
        bridge_calls: vec![
            door::bridge_call(
                0,
                SelfEffect::MemorySearch,
                map("a", "bc"),
                map("result", "ok"),
                None,
            ),
            door::bridge_call(
                1,
                SelfEffect::AgentsSpawn,
                map("ab", "c"),
                Value::Nil,
                Some(map("ab", "rewritten")),
            ),
        ],
        bridge_end: 2,
        ..step("s")
    });
    steps.push(StepState {
        bridge_calls: vec![door::bridge_call(
            u64::MAX,
            SelfEffect::Ask,
            Value::from(5),
            Value::from("x".repeat(300)),
            None,
        )],
        bridge_end: u64::MAX,
        context: [0x77; 32],
        ..step("s")
    });
    steps
}

#[test]
fn the_step_checkpoint_hash_keeps_its_bytes() {
    let steps = steps();
    assert_eq!(steps.len(), 6 + 3 + 6 + 4);
    let mut seen = std::collections::BTreeSet::new();
    for step in &steps {
        let result = base_executor::StepResultDigests {
            observation: step.observation,
            done: step.done,
            outputs: step.outputs.clone(),
            bindings: step.bindings.clone(),
        };
        let end = base_executor::StepEnd {
            bridge_end: step.bridge_end,
            context: step.context,
        };
        let main = base_executor::prepared_step_state_hash(
            step.previous,
            step.seq,
            &step.request_hash,
            &step.script,
            step.prepared.as_ref(),
            &result,
            step.implicit_speak.as_deref(),
            &step.bridge_calls,
            end,
        )
        .expect("main's step hash");
        let head = door::step_state_hash(step).expect("the head's step hash");
        assert_eq!(head, main, "{step:?}");
        seen.insert(main);
    }
    assert_eq!(seen.len(), steps.len());
}

#[test]
fn the_cohort_purpose_keeps_main_s_domain() {
    let purpose = purposes::cluster::CLAIM_COHORT;
    assert_eq!(purpose.hash(), LegacyHash::Blake3);
    assert_eq!(purpose.tag_mode(), TagMode::HashedFirst);
    assert_eq!(purpose.tag().as_bytes(), base_cohort::CLUSTER_ID_DOMAIN);
    assert_eq!(
        oneiron::cluster::CLUSTER_ID_DOMAIN,
        base_cohort::CLUSTER_ID_DOMAIN
    );
}

fn claim(
    byte: u8,
    subject: ClaimSubject,
    predicate: &str,
    scope: (Option<EntityId>, Option<EntityId>),
    embedding: [f32; 2],
) -> ClusterClaim {
    ClusterClaim {
        claim_id: id(byte),
        subject,
        predicate: predicate.to_owned(),
        world: scope.0,
        facet: scope.1,
        embedding: embedding.to_vec(),
    }
}

#[test]
fn the_cohort_id_keeps_its_bytes() {
    let person = ClaimSubject::Entity(id(0xa0));
    let edge = ClaimSubject::Edge {
        source: id(0xa1),
        kind: EdgeKind::DerivedFrom,
        target: id(0xa2),
    };
    let world = Some(id(0xb0));
    let facet = Some(id(0xc0));
    let claims = vec![
        // One partition, two cohorts: three close claims and one far one.
        claim(
            0x13,
            person.clone(),
            "person.name.given",
            (None, None),
            [1.0, 0.0],
        ),
        claim(
            0x11,
            person.clone(),
            "person.name.family",
            (None, None),
            [1.0, 0.0],
        ),
        claim(
            0x12,
            person.clone(),
            "person.name.middle",
            (None, None),
            [0.99, 0.01],
        ),
        claim(
            0x14,
            person.clone(),
            "person.name.given",
            (None, None),
            [0.0, 1.0],
        ),
        // The same predicate root under a world, a facet, and both.
        claim(
            0x21,
            person.clone(),
            "person.name.given",
            (world, None),
            [1.0, 0.0],
        ),
        claim(
            0x22,
            person.clone(),
            "person.name.given",
            (None, facet),
            [1.0, 0.0],
        ),
        claim(
            0x23,
            person.clone(),
            "person.name.given",
            (world, facet),
            [1.0, 0.0],
        ),
        claim(
            0x24,
            person,
            "person.name.given",
            (world, facet),
            [1.0, 0.0],
        ),
        // An edge subject, and a long predicate root.
        claim(
            0x31,
            edge.clone(),
            "relation.since",
            (None, None),
            [1.0, 0.0],
        ),
        claim(
            0x32,
            edge,
            &format!("{}.leaf", "r".repeat(300)),
            (None, None),
            [1.0, 0.0],
        ),
    ];
    let cohorts = cluster_claims(&claims, ClusterOptions::default())
        .expect("the claims cluster")
        .cohorts;
    assert_eq!(cohorts.len(), 7);
    assert!(cohorts.iter().any(|cohort| cohort.member_ids.len() == 3));
    for cohort in &cohorts {
        let main = base_cohort::main_cohort_id(&cohort.partition, &cohort.member_ids);
        assert_eq!(cohort.cohort_id.as_bytes(), &main, "{cohort:?}");
    }
}

#[test]
fn the_late_credit_purpose_keeps_main_s_context() {
    let purpose = purposes::skill_attribution::LATE_CREDIT_RECEIPT;
    assert_eq!(purpose.hash(), LegacyHash::Blake3);
    assert_eq!(purpose.tag_mode(), TagMode::DeriveKeyContext);
    assert_eq!(purpose.tag(), "oneiron pack outcome credit v1");
}

#[test]
fn the_late_credit_receipt_key_keeps_its_bytes() {
    let texts = texts();
    let mut seen = std::collections::BTreeSet::new();
    for attempt in &texts {
        for outcome in &texts {
            for axis in ["", "quality", "a\0b"] {
                let main = base_credit::receipt_id(attempt, outcome, axis);
                assert_eq!(door::late_credit_receipt_id(attempt, outcome, axis), main);
                assert!(
                    main.starts_with("credit:") && main.len() == 7 + 64,
                    "{main}"
                );
                seen.insert(main);
            }
        }
    }
    assert_eq!(seen.len(), 6 * 6 * 3);
}
