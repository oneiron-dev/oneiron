//! Measurement only, not for merge (OPUS-E2E-1, the 1.9 s pre-model gap of
//! FIX row [AGENT-RUN-START-LATENCY-4S]): what a code-mode step's request
//! costs before its model call. The executor's system prompt carries the
//! whole verb catalog's declarations, about 1.1 MB, and every step's replay
//! capture writes that request as the side-row wall admits it. Each line
//! `## COST <stage> ms=<n>` times one stage over the real prompt.
//!
//! A door for `tests/code_mode_capture_cost.rs`, compiled only under
//! `--cfg oneiron_test_support`: the oneiron lib test target does not build
//! on main (3 resolve errors in gate/tests/auto_checker.rs and
//! federation/system_agent_grant/narrowing/tests.rs, 13 Nov).

use std::collections::BTreeMap;
use std::time::Instant;

use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, LlmMessage, LlmMessageRole, LlmRequest,
    ModelId, ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence,
};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::{AttemptId, EdgeActorClass, EntityId, TimeRange, Vault, WriteActor};

fn timed<T>(stage: &str, run: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = run();
    eprintln!(
        "## COST {stage} ms={:.1}",
        start.elapsed().as_secs_f64() * 1000.0
    );
    out
}

fn code_mode_request(prompt: &str, task: &str) -> LlmRequest {
    LlmRequest {
        model: ModelId::new("test/executor@v1").expect("model id"),
        envelope: CallEnvelope {
            scope: crate::llm::Scope::default(),
            purpose: CallPurpose::AutoCheck,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AutoCheck,
                ModelTierRef("standard".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
            host_keyless: false,
            host_paid: false,
            seat_effort: None,
        },
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text {
                    text: prompt.to_owned(),
                    signature: None,
                }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: format!("Run id: 00\nTask:\n{task}"),
                    signature: None,
                }],
            },
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    }
}

/// Times each stage a code-mode step's request passes before its model
/// call, over the executor's real system prompt, and three saved-workflow
/// step captures of it (each a run of its own) in `vault`, a fresh vault the
/// caller opened. Prints one `## COST` line per stage.
pub fn measure_code_mode_step_capture(vault: &Vault) {
    let prompt = timed("system_prompt_render", || {
        super::host::executor_system_prompt("wire")
    });
    eprintln!("## COST prompt_bytes={}", prompt.len());
    let tokens = timed("tokens_o200k", || {
        crate::tokenizer::count_context_pack_tokens(&prompt)
    });
    eprintln!("## COST prompt_tokens={tokens}");
    let seam = timed("scan_write_seam", || {
        crate::batch::secret_scan::scan_write_seam(&prompt)
    });
    eprintln!("## COST scan_write_seam_ok={}", seam.is_ok());
    let facts = timed("body_meter_feed_finish", || {
        let mut meter = crate::store::BodyMeter::new();
        meter.feed(prompt.as_bytes());
        meter.finish(64)
    });
    eprintln!("## COST body_meter_secret={:?}", facts.secret);
    let request = code_mode_request(&prompt, "task 0");
    let bytes = timed("request_canonical_bytes", || {
        request.canonical_bytes().expect("canonical bytes")
    });
    eprintln!("## COST request_bytes={}", bytes.len());
    timed("request_canonical_hash", || {
        request.canonical_hash().expect("canonical hash")
    });
    timed("request_parse", || {
        serde_json::from_slice::<LlmRequest>(&bytes).expect("request parses")
    });
    let person = EntityId::from_bytes([0x5C; 16]).expect("entity id");
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("seed person");
    let actor = WriteActor::new(person, EdgeActorClass::Agent);
    for round in 0..3_u8 {
        let request = code_mode_request(&prompt, &format!("task {round}"));
        let handle = timed(&format!("capture_workflow_step_run{round}"), || {
            crate::code_run::capture_workflow_step(
                vault,
                AttemptId::now(),
                1,
                actor,
                &request,
                None,
                0,
            )
        });
        assert!(handle.is_some(), "run {round}: no capsule was staged");
    }
}
