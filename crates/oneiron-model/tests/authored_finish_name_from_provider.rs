//! A provider finish string must never land in FinishReason::Other under an
//! engine-authored prefix (FIX-LIST row AUTHORED-FINISH-NAME-FROM-PROVIDER:
//! the provider adapters used to copy any unknown provider finish string
//! verbatim into the name, so an endpoint answering `fallback:x` got the
//! authored read).

use oneiron_model::llm::{
    DreamerFailureClass, FinishReason, LlmMessage, LlmMessageRole, LlmResponse, LlmUsage,
    fallback_failure_class, provider_finish_reason,
};

fn response(finish_reason: FinishReason) -> LlmResponse {
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: Vec::new(),
        },
        usage: LlmUsage::zero(),
        finish_reason,
        reply_assertions: Default::default(),
        token_scores: None,
    }
}

fn other_name(reason: &FinishReason) -> &str {
    let FinishReason::Other { name } = reason else {
        panic!("a provider finish string maps to Other, got {reason:?}");
    };
    name
}

#[test]
fn provider_finish_strings_with_engine_prefixes_gain_a_provider_prefix() {
    assert_eq!(
        other_name(&provider_finish_reason("fallback:x")),
        "provider:fallback:x"
    );
    assert_eq!(
        other_name(&provider_finish_reason("authored:y")),
        "provider:authored:y"
    );
    assert_eq!(
        other_name(&provider_finish_reason("fallback:")),
        "provider:fallback:"
    );
}

#[test]
fn other_provider_finish_strings_stay_verbatim() {
    for name in [
        "custom_reason",
        "Fallback:x",
        "authored",
        "fallback",
        "provider:fallback:x",
        "",
    ] {
        assert_eq!(other_name(&provider_finish_reason(name)), name);
    }
}

#[test]
fn a_provider_fallback_name_is_no_provider_failure() {
    // End to end across the write door and the failure-policy reader: what the
    // adapters store for a provider string `fallback:x` must not read as an
    // engine-authored fallback, while a real engine-authored name still does.
    assert_eq!(
        fallback_failure_class(&response(provider_finish_reason("fallback:x"))),
        None
    );
    assert_eq!(
        fallback_failure_class(&response(provider_finish_reason("authored:y"))),
        None
    );
    assert_eq!(
        fallback_failure_class(&response(FinishReason::Other {
            name: "fallback:json_rules_v1".to_owned(),
        })),
        Some(DreamerFailureClass::Fatal)
    );
}
