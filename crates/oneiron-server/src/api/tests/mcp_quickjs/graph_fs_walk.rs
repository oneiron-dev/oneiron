//! A code-mode guest reaches the read-only graph-FS rows through the
//! verb-call import (census L3-38; GUEST-GRAPHFS-IMPORTS = A, 13 Nov 22:45):
//! `mount` and `graph_fs.<verb>` are rows of the SDK verb table, each call a
//! recorded `self.verbs.call` step, and an actor bound to `execute_code`
//! alone reaches none of them.

use super::*;

const NEEDLE: &str = "graphfswalkneedle";

/// One active CLAIM about `subject` holding `value`, indexed under
/// [`NEEDLE`] (as `mcp_memory.rs` seeds its claims).
fn seed_claim(server: &SyncServer, id: oneiron::EntityId, subject: oneiron::EntityId, value: &str) {
    let mut claim = oneiron::ClaimBody::new(
        "profile.note",
        oneiron::ClaimSubject::Entity(subject),
        rmpv::Value::from(value),
        1.0,
        oneiron::ClaimApprovalStatus::Auto,
        oneiron::ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    claim.source = Some(oneiron::ClaimSource::UserStated);
    server
        .vault
        .put_claim(&id, &claim, oneiron::TimeRange { start: 10, end: 10 }, 10)
        .expect("put claim");
    server
        .vault
        .batch()
        .text(&id, &[("body", NEEDLE)])
        .commit()
        .expect("index claim");
}

/// The typed output a verb call returned, as its step records it: the row's
/// output JSON, carried as text.
fn verb_output(outcome: &Value) -> Value {
    match &outcome["output"] {
        Value::String(text) => serde_json::from_str(text)
            .unwrap_or_else(|error| panic!("verb output is not JSON ({error}): {outcome}")),
        other => {
            assert!(other.is_object(), "no verb output: {outcome}");
            other.clone()
        }
    }
}

/// The one claim a grep page printed: the id of its single `/claims/<id>:`
/// line.
fn grep_page_hit(page: &Value) -> String {
    let output = page["output"].as_str().expect("grep output text");
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 1, "one hit a page: {page}");
    lines[0]
        .strip_prefix("/claims/")
        .and_then(|rest| rest.split_once(':'))
        .map(|(id, _)| id.to_owned())
        .unwrap_or_else(|| panic!("a claim hit line: {page}"))
}

/// Done means (L3-38, the guest's graph-FS reach): a first-party code-mode run
/// walks the live head through the verb-call import alone. It mounts the live
/// head, lists `/claims`, reads one claim's file, and greps the claims for a
/// word over two pages, the second page opened with the first page's sealed
/// cursor. The host records every one of the five calls as a
/// `self.verbs.call` step; the grep is the claims text index's pushdown, one
/// hit a page under the mount's `max_entries: 1`; and the two pages name the
/// two seeded claims, each once.
#[tokio::test]
async fn quickjs_code_mode_walks_the_live_head_through_the_graph_fs_rows() {
    let actor = seeded_test_entity_id(0x0033_8001);
    let first_claim = seeded_test_entity_id(0x0033_8002);
    let second_claim = seeded_test_entity_id(0x0033_8003);
    let script = format!(
        "const m = await mount({{ref: {{kind: 'live_head'}}, max_entries: 1}}); \
         const listed = await graph_fs.ls({{mount: m.mount, path: '/claims'}}); \
         const read = await graph_fs.cat({{mount: m.mount, path: '/claims/by-id/{first}'}}); \
         const first = await graph_fs.grep({{mount: m.mount, path: '/claims', \
         pattern: '{NEEDLE}', recursive: true}}); \
         const second = await graph_fs.grep({{mount: m.mount, path: '/claims', \
         pattern: '{NEEDLE}', recursive: true, cursor: first.next_cursor}}); \
         finish(JSON.stringify({{listed: listed.output, first: first.output, \
         second: second.output}}));",
        first = first_claim.to_hex(),
    );
    let mode = code_mode_server(vec![script]);
    let credential = "quickjs-graph-fs";
    register_mcp_actor(
        &mode.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    seed_claim(
        &mode.server,
        first_claim,
        actor,
        &format!("{NEEDLE} the first note"),
    );
    seed_claim(
        &mode.server,
        second_claim,
        actor,
        &format!("{NEEDLE} the second note"),
    );

    let args = mcp_merge_args(
        mcp_endpoint_envelope(actor, "read_memory"),
        json!({"run_ref": "quickjs-graph-fs", "task": "walk the claims as files"}),
    );
    let (_, body) = route_json(
        mode.server.clone(),
        mcp_endpoint_call_request("/mcp", credential, "walk", "execute_code", args),
    )
    .await;
    assert!(body.get("error").is_none(), "{body}");
    let structured = &body["result"]["structuredContent"];
    assert_eq!(structured["result"]["status"], "complete", "{structured}");

    // Every call is a recorded verb call that the door served.
    let outcomes = verb_call_outcomes(&body);
    assert_eq!(
        outcomes.len(),
        5,
        "mount, ls, cat, grep, grep: {structured}"
    );
    for outcome in &outcomes {
        assert_ne!(outcome["kind"], "denied", "{structured}");
    }
    let outputs: Vec<Value> = outcomes.iter().map(verb_output).collect();
    let [mounted, listed, read, first, second] = outputs.as_slice() else {
        unreachable!("five outputs");
    };

    // The mount is the live head's content selector, with its page bounds.
    assert_eq!(mounted["root"], "/", "{mounted}");
    assert_eq!(
        mounted["mount"]["ref"],
        json!({"kind": "live_head"}),
        "{mounted}"
    );
    assert_eq!(mounted["mount"]["max_entries"], 1, "{mounted}");

    // `/claims` is its fixed page, one entry a page.
    let names: Vec<&str> = listed["output"]
        .as_str()
        .expect("ls output text")
        .lines()
        .collect();
    assert!(
        !names.is_empty() && names.iter().all(|name| ["by-time", "by-id"].contains(name)),
        "{listed}"
    );

    // The claim's file is the projection's claim record.
    let text = read["output"].as_str().expect("cat output text");
    assert!(text.contains("\nkind\tclaim\n"), "{read}");
    assert!(
        text.contains(&format!("\nid\t{}\n", first_claim.to_hex())),
        "{read}"
    );

    // The grep is the claims text index's pushdown, paged by the sealed cursor.
    for page in [first, second] {
        assert_eq!(page["plan"], "pushdown", "{page}");
    }
    assert!(first["next_cursor"].is_string(), "{first}");
    assert!(second["next_cursor"].is_null(), "{second}");
    let mut hits = vec![grep_page_hit(first), grep_page_hit(second)];
    hits.sort();
    let mut seeded = vec![first_claim.to_hex(), second_claim.to_hex()];
    seeded.sort();
    assert_eq!(hits, seeded, "{first} {second}");
}

/// An actor whose binding lists `execute_code` alone runs code but reaches no
/// graph-FS row: the mount and a grep under a hand-written live-head mount
/// are each refused with the door's stable `mcp_verb_not_bound`, so a mount
/// descriptor is a content selector, never authority, and no claim text
/// leaves.
#[tokio::test]
async fn quickjs_code_mode_graph_fs_rows_refuse_an_actor_bound_to_execute_code_alone() {
    let owner = seeded_test_entity_id(0x0033_8011);
    let bound = seeded_test_entity_id(0x0033_8012);
    let claim = seeded_test_entity_id(0x0033_8013);
    let script = format!(
        "const tries = []; \
         for (const call of [() => mount({{ref: {{kind: 'live_head'}}}}), \
         () => graph_fs.grep({{mount: {{ref: {{kind: 'live_head'}}}}, path: '/claims', \
         pattern: '{NEEDLE}', recursive: true}})]) {{ \
         try {{ await call(); tries.push('reached'); }} \
         catch (error) {{ tries.push('refused ' + String(error)); }} }} \
         finish(tries.join(', '));"
    );
    let mode = code_mode_server(vec![script]);
    seed_claim(
        &mode.server,
        claim,
        owner,
        &format!("{NEEDLE} a note the bound actor never reads"),
    );
    register_bound_verb_mcp_actor(
        &mode.server,
        "quickjs-graph-fs-bound",
        bound,
        &["execute_code"],
    )
    .await;

    let args = mcp_merge_args(
        mcp_endpoint_envelope(bound, "read_memory"),
        json!({"run_ref": "quickjs-graph-fs-bound", "task": "walk the claims as files"}),
    );
    let (_, body) = route_json(
        mode.server.clone(),
        mcp_endpoint_call_request(
            "/mcp",
            "quickjs-graph-fs-bound",
            "bound",
            "execute_code",
            args,
        ),
    )
    .await;
    assert!(body.get("error").is_none(), "{body}");
    let text = body["result"]["structuredContent"].to_string();
    assert!(!text.contains("never reads"), "{text}");
    assert_eq!(
        verb_call_outcomes(&body),
        [
            verb_refusal("mcp_verb_not_bound"),
            verb_refusal("mcp_verb_not_bound")
        ],
        "{text}"
    );
}
