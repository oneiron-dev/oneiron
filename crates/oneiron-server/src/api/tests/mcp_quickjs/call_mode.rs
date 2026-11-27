//! Call mode through code mode's `vault.recall` (retrieval hub #call-mode).

use super::*;

/// Code mode takes `effort: 'call'` and a `deadline_ms`, and a deadline
/// outside 1..=60000 is a typed refusal the guest catches: the door's stable
/// code, the two calls differing only in the deadline.
#[tokio::test]
async fn quickjs_code_mode_recall_takes_call_mode_and_refuses_a_deadline_out_of_range() {
    let script = "const pack = await vault.recall({query: 'heron lantern', effort: 'call', \
        deadline_ms: 30000, scope: {}}); let refused = 'reached'; try { await \
        vault.recall({query: 'heron lantern', effort: 'call', deadline_ms: 0, scope: {}}); \
        } catch (error) { refused = String(error); } finish(JSON.stringify({pack, refused}));";
    let mode = code_mode_server(vec![script.to_owned()]);
    let actor = seeded_test_entity_id(0x0024_6571);
    let credential = "quickjs-call-mode";
    register_mcp_actor(
        &mode.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    witness_through_tool_list(
        &mode.server,
        credential,
        actor,
        "The heron lantern hangs by the north gate.",
    )
    .await;
    // No MCP tool starts a task run anymore: the kept task handler enters it, rendering
    // the old task shape (FIX EXECUTE-CALLER-CODE).
    let body = execute_task_run_for_test(
        &mode.server,
        credential,
        "quickjs-call-mode",
        "recall the heron lantern in a call",
    )
    .await;
    assert!(body.get("error").is_none(), "{body}");
    let structured = &body["result"]["structuredContent"];
    assert_eq!(structured["result"]["status"], "complete", "{structured}");
    let steps = structured["steps"].as_array().expect("steps");
    assert_eq!(steps.len(), 2, "{structured}");
    let recalled = steps[0]["outcome"]["output"]
        .as_str()
        .expect("recall output");
    assert!(recalled.contains("north gate"), "{recalled}");
    assert_eq!(
        steps[1]["outcome"],
        verb_refusal("facade_error"),
        "{structured}"
    );
}
