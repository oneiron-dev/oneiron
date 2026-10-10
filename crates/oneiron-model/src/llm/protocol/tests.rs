use std::collections::BTreeMap;

use serde_json::json;

use super::*;
use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, LlmCatalogEntry, ModelLocality, ModelTierRef,
    ResponseFormat, TierPrecedence,
};

fn request() -> LlmRequest {
    LlmRequest {
        model: ModelId::new("fake/small@v1").expect("model id"),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: crate::llm::Scope::default(),
            purpose: CallPurpose::AnswerGen,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(&CallPurpose::AnswerGen, ModelTierRef("a".into())),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
        },
        messages: Vec::new(),
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    }
}

#[test]
fn a_param_or_provider_option_that_picks_the_model_or_route_is_named() {
    let mut plain = request();
    plain.params.insert("temperature".into(), json!(0.2));
    plain
        .provider_options
        .insert("openai".into(), json!({ "reasoning": { "effort": "low" } }));
    assert_eq!(plain.route_selector_override(), None);

    for (param, expected) in [("model", "model"), ("models", "models"), ("route", "route")] {
        let mut swapped = request();
        swapped.params.insert(param.into(), json!("fake/large@v1"));
        assert_eq!(swapped.route_selector_override().as_deref(), Some(expected));
    }
    let mut nested = request();
    nested
        .provider_options
        .insert("openai".into(), json!({ "models": ["fake/large@v1"] }));
    assert_eq!(
        nested.route_selector_override().as_deref(),
        Some("openai.models")
    );
    let mut namespace = request();
    namespace
        .provider_options
        .insert("provider".into(), json!({ "order": ["other"] }));
    assert_eq!(
        namespace.route_selector_override().as_deref(),
        Some("provider")
    );
}

#[test]
fn a_catalog_row_refuses_a_request_that_picks_its_own_route() {
    let entry = LlmCatalogEntry {
        model: ModelId::new("fake/small@v1").expect("model id"),
        display_name: "small".into(),
        locality: ModelLocality::ThirdParty,
        context_window_tokens: 8_192,
        max_output_tokens: None,
        cost: None,
        capabilities: Vec::new(),
        metadata: BTreeMap::new(),
    };
    assert!(entry.admit(&request(), false).is_ok());
    let mut routed = request();
    routed
        .provider_options
        .insert("gemini".into(), json!({ "model": "fake/large@v1" }));
    assert!(entry.admit(&routed, false).is_err());
}
