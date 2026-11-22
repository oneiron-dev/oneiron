//! [AUTHORED-FINISH-NAME-FROM-PROVIDER] (FIX-LIST 26080): a provider finish
//! string the adapters do not know lands in `FinishReason::Other`. One that
//! starts with an engine-authored prefix (`fallback:`, `authored:`) is kept
//! under `provider:`, so no engine reader takes the reply as engine-authored;
//! every other unknown string stays as the provider sent it. Each adapter's
//! public decoder is driven with such a reply.
//!
//! Run: `cargo test --locked -p oneiron-llm --all-features --test
//! provider_finish_engine_prefix`.

use oneiron::FinishReason;
use oneiron_llm::anthropic::parse_anthropic_messages_response;
use oneiron_llm::openai_compat::parse_openai_chat_response;
use serde_json::json;

/// What a provider sends, and the name the decoder keeps for it.
const CASES: [(&str, &str); 3] = [
    ("fallback:x", "provider:fallback:x"),
    ("authored:y", "provider:authored:y"),
    ("provider_specific_end", "provider_specific_end"),
];

fn other(name: &str) -> FinishReason {
    FinishReason::Other {
        name: name.to_owned(),
    }
}

#[test]
fn an_openai_chat_finish_with_an_engine_prefix_is_kept_under_provider() {
    for (sent, kept) in CASES {
        let response = parse_openai_chat_response(&json!({ "choices": [{
            "finish_reason": sent,
            "message": { "role": "assistant", "content": "done" },
        }] }))
        .expect("the reply decodes");
        assert_eq!(response.finish_reason, other(kept), "{sent}");
    }
}

#[test]
fn an_anthropic_stop_reason_with_an_engine_prefix_is_kept_under_provider() {
    for (sent, kept) in CASES {
        let response = parse_anthropic_messages_response(&json!({
            "content": [{ "type": "text", "text": "done" }],
            "stop_reason": sent,
        }))
        .expect("the reply decodes");
        assert_eq!(response.finish_reason, other(kept), "{sent}");
    }
}
