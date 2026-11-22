//! The one language boundary (UC-02 B0): verb input and output as the
//! engine's JSON text, and the engine error as JSON text.
//!
//! These guard the boundary every binding moves onto in B2, B3 and B5: a
//! mistake in a DTO field gets the engine's one answer, text that is not one
//! JSON document is refused before any verb runs, and the error text carries
//! every field of the engine error.

use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MemoryError};
use oneiron_remote::{OneironClient, OpenOptions, error_json};
use serde_json::{Value, json};

fn embedded_client(dir: &tempfile::TempDir) -> OneironClient {
    OneironClient::open(Some(dir.path()), &OpenOptions::default()).expect("embedded open")
}

/// `author: "USER"` is not a witness author (the vocabulary is lower case):
/// the engine's input decode refuses it with the path of the field, the
/// answer HTTP gives, not a binding's own wording.
#[test]
fn a_wrong_witness_author_gets_the_engine_refusal_with_its_field_path() {
    let dir = tempfile::tempdir().unwrap();
    let client = embedded_client(&dir);
    let turn = json!({
        "conversation_ref": oneiron::EntityId::now().to_hex(),
        "turn_ref": null,
        "messages": [{
            "id": null,
            "author": "USER",
            "message_type": "text",
            "content": "hello",
            "metadata": null,
            "is_visible": true,
            "order": 0
        }],
        "occurred_at": 1_700_000_000_u64
    });
    let refusal = client
        .call_json("vault.witness", &turn.to_string())
        .expect_err("an unknown author is refused");
    assert_eq!(refusal.code, MEMORY_CODE_BAD_REQUEST, "{refusal:?}");
    assert!(
        refusal.message.starts_with("invalid SDK request"),
        "{refusal:?}"
    );
    assert!(
        refusal.message.contains("messages[0].author"),
        "the refusal names the field's path: {refusal:?}"
    );
    // The text door and the value door give one answer.
    let through_value = client
        .agent_verb("vault.witness", turn)
        .expect_err("an unknown author is refused");
    assert_eq!(refusal, through_value);
}

/// Text that is not exactly one JSON document is `BAD_REQUEST` before any
/// verb runs: truncated text, two documents, and no text at all.
#[test]
fn text_that_is_not_one_json_document_is_a_bad_request() {
    let dir = tempfile::tempdir().unwrap();
    let client = embedded_client(&dir);
    for text in ["{", "{} {}", "", "{\"a\": NaN}"] {
        let refusal = client.call_json("vault.rooms.list", text).expect_err(text);
        assert_eq!(
            refusal.code, MEMORY_CODE_BAD_REQUEST,
            "{text:?}: {refusal:?}"
        );
        assert!(
            refusal
                .message
                .starts_with("invalid SDK request: the input is not one JSON document"),
            "{text:?}: {refusal:?}"
        );
        assert!(!refusal.suggestions.is_empty(), "{text:?}");
    }
}

/// A well-formed call answers the same through the text door as through
/// `agent_verb`: the text is the serde form of the verb's output.
#[test]
fn the_text_door_answers_as_the_value_door_does() {
    let dir = tempfile::tempdir().unwrap();
    let client = embedded_client(&dir);
    let through_text = client.call_json("vault.rooms.list", "{}");
    let through_value = client.agent_verb("vault.rooms.list", json!({}));
    match (through_text, through_value) {
        (Ok(text), Ok(value)) => {
            assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), value);
        }
        (Err(left), Err(right)) => assert_eq!(left, right),
        (left, right) => panic!("the two doors disagree: {left:?} against {right:?}"),
    }
}

/// `error_json` carries all 14 fields of the engine error, under their wire
/// names (`read_receipt` crosses as `narrowing`; `wrong_root` is flattened
/// into `attempted`, `replacement` and `schemaRef`), and reads back as the
/// same error.
#[test]
fn error_json_carries_every_field_of_the_engine_error() {
    let scope = json!({
        "max_sensitivity_band": 3,
        "include_stale": false,
        "min_confidence": 0.5,
        "min_salience": 0.25,
        "deny_all": false
    });
    let whole = json!({
        "code": "FORBIDDEN",
        "message": "refused",
        "suggestions": ["Ask the owner."],
        "successor_short_id": "abc12:0123",
        "gate_denial": {
            "outcome": "deny",
            "reason_codes": ["gate.deny.test"],
            "ask_ref": "ask",
            "approval_digest": "digest"
        },
        "narrowing": {
            "requested": scope,
            "actor_ceiling": scope,
            "applied": scope,
            "narrowed_axes": ["max_sensitivity_band"],
            "suppressed_count": 1,
            "replan_hint": ["grant_scope"]
        },
        "policy_denial": {
            "level": "deny",
            "row_ref": "row",
            "role": "member",
            "exception_proposal": {"action": "except", "row_ref": "row", "required_role": "owner"}
        },
        "attempted": "vault.old",
        "replacement": "vault.new",
        "schemaRef": "schema/vault.new",
        "hook": {"status": "skipped", "hook": "pre", "reason": "not today"},
        "retry_after": 30,
        "resets_at": [100, 200],
        "reason_codes": ["gate.rooms.upkeep.test"],
        "legal_hold": {
            "state": "retained_for_law",
            "bound": {
                "kind": "law",
                "order_ref": "order",
                "legal_basis_ref": null,
                "jurisdiction": null,
                "issuing_authority_ref": null,
                "ends_at": null
            },
            "works_self_hosted": true,
            "self_hosted_note": "note"
        },
        "room_join_hold": {
            "room": oneiron::EntityId::now().to_hex(),
            "person": oneiron::EntityId::now().to_hex(),
            "intent_key": "join",
            "needs": []
        }
    });
    let error: MemoryError = serde_json::from_value(whole).expect("a whole engine error");
    // Each of the 14 fields is set, so a field the text dropped would show.
    assert!(error.successor_short_id.is_some());
    assert!(error.gate_denial.is_some());
    assert!(error.read_receipt.is_some());
    assert!(error.policy_denial.is_some());
    assert!(error.wrong_root.is_some());
    assert!(error.hook.is_some());
    assert!(error.retry_after.is_some());
    assert!(!error.resets_at.is_empty());
    assert!(!error.reason_codes.is_empty());
    assert!(error.legal_hold.is_some());
    assert!(error.room_join_hold.is_some());

    let text = error_json(&error);
    let Value::Object(object) = serde_json::from_str::<Value>(&text).expect("one JSON document")
    else {
        panic!("the error text is a JSON object: {text}");
    };
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "attempted",
            "code",
            "gate_denial",
            "hook",
            "legal_hold",
            "message",
            "narrowing",
            "policy_denial",
            "reason_codes",
            "replacement",
            "resets_at",
            "retry_after",
            "room_join_hold",
            "schemaRef",
            "successor_short_id",
            "suggestions",
        ]
    );
    let read_back: MemoryError = serde_json::from_str(&text).expect("the text reads back");
    assert_eq!(read_back, error);
}
