//! Measurement only, not for merge (OPUS-E2E-1, the 1.9 s pre-model gap of
//! FIX row [AGENT-RUN-START-LATENCY-4S]): what a code-mode step's request
//! costs before its model call. The executor's system prompt carries the
//! whole verb catalog's declarations, about 1.1 MB, and every step's replay
//! capture writes that request as the side-row wall admits it. Each line
//! `## COST <stage> ms=<n>` times one stage over the real prompt.
use std::time::Instant;

use super::*;
use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence,
};

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
        model: model(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: crate::llm::Scope::default(),
            purpose: CallPurpose::AutoCheck,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AutoCheck,
                ModelTierRef("standard".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
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
        params: std::collections::BTreeMap::new(),
        provider_options: std::collections::BTreeMap::new(),
        host_segments: None,
    }
}

#[test]
fn code_mode_step_request_costs_before_its_model_call() {
    let prompt = timed("system_prompt_render", || {
        host::executor_system_prompt("wire")
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
    let (_dir, vault) = open_test_vault();
    let actor = WriteActor::new(seed_person(&vault, 0xA0), EdgeActorClass::Agent);
    for round in 0..3_u8 {
        let request = code_mode_request(&prompt, &format!("task {round}"));
        let handle = timed(&format!("capture_workflow_step_run{round}"), || {
            crate::code_run::capture_workflow_step(
                &vault,
                crate::AttemptId::now(),
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
