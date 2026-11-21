//! STEP-CORRECTION-HEALTH-PARK: a model step's submission row gained the
//! point a parked schema correction resumes at (STORED-CHANGE-RULE "keep").
//! A row kept before it, parked with its sends, still reads, with no point
//! and its request, result and sends as kept.
//!
//! Reaches the crate-private row through
//! `oneiron::test_doors::model_step_submission_codec`, built only under
//! `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used)]

use oneiron::llm::model_step::{ModelStepResult, ModelStepRetryPolicy, ModelStepSubmit};
use oneiron::test_doors::model_step_submission_codec::read_row_before_correction_point;
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, LlmMessage, LlmRequest, ModelId, ModelLocality,
    ModelTierRef, ResponseFormat, TierPrecedence,
};
use serde_json::json;

fn step() -> ModelStepSubmit {
    ModelStepSubmit {
        step_key: "kept-before-the-point".into(),
        request: LlmRequest {
            model: ModelId::new("local/reasoner@rev-a").unwrap(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Default::default(),
                purpose: CallPurpose::AnswerGen,
                class: CallClass::BestEffort,
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::AnswerGen,
                    ModelTierRef("global".into()),
                ),
                response_format: ResponseFormat::Json {
                    schema: json!({"type": "object"}),
                },
                locality: ModelLocality::OwnServer,
                host_keyless: false,
                host_paid: false,
            },
            messages: vec![
                serde_json::from_value::<LlmMessage>(
                    json!({"role": "user", "content": [{"kind": "text", "text": "hello"}]}),
                )
                .unwrap(),
            ],
            tools: vec![],
            params: Default::default(),
            provider_options: Default::default(),
            host_segments: None,
        },
        retry: ModelStepRetryPolicy { max_attempts: 2 },
    }
}

#[test]
fn a_row_kept_before_the_correction_point_still_reads() {
    let parked = ModelStepResult::Parked {
        until: Some(1_800_000_000),
        sends: 1,
    };
    let (input, result, sends) = read_row_before_correction_point(step(), Some(parked.clone()), 1)
        .expect("the old row reads, with no correction point");
    assert_eq!(
        serde_json::to_value(&input).unwrap(),
        serde_json::to_value(step()).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&result).unwrap(),
        serde_json::to_value(Some(parked)).unwrap()
    );
    assert_eq!(sends, 1);
}
