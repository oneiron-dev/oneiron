//! FIX WITNESS-TURN-NO-PROJECT-POSITION, the wire half: a turn witnessed
//! through `vault.witness` names an optional project on its wire shape. On
//! main the turn has no such field, so the attachment is refused as an
//! unknown field; with the fix it decodes and round-trips. The stamping
//! half reads the stamp through a test door, in
//! `witness_turn_no_project_position.rs`.
//!
//! `cargo test --locked -p oneiron --all-features --test witness_turn_wire_project`

use oneiron::EntityId;
use oneiron::memory::WitnessTurn;
use serde_json::json;

/// One visible user MESSAGE of `content` in a fresh turn of `conversation`,
/// as `vault.witness` takes it without a project, built on JSON, the shape
/// the facade decodes.
fn plain_turn(conversation: &str, content: &str) -> WitnessTurn {
    let value = json!({
        "conversation_ref": conversation,
        "messages": [{
            "author": "user",
            "message_type": "dialogue",
            "content": content,
            "is_visible": true,
            "order": 0,
        }],
        "occurred_at": 900,
    });
    serde_json::from_value(value).expect("the witness turn shape decodes")
}

#[test]
fn witness_turn_wire_shape_carries_an_optional_project() {
    let project = EntityId::now();
    let conversation = EntityId::now().to_hex();
    let turn = plain_turn(&conversation, "the lease ends in March");
    let mut value = serde_json::to_value(&turn).expect("a witness turn serializes");
    value["project"] = json!(project.to_hex());
    let turn: WitnessTurn =
        serde_json::from_value(value).expect("vault.witness turns carry an optional project");
    let back = serde_json::to_value(&turn).expect("a witnessed turn serializes");
    assert_eq!(
        back["project"],
        json!(project.to_hex()),
        "the turn round-trips its project"
    );
}
