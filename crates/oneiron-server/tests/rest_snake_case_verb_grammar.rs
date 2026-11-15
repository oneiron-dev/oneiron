//! The verb grammar that is not stored speaks the engine's snake_case: every
//! verb input, reply and refusal that crosses the REST facade, the action
//! route, an MCP tool or a guest call names its fields in snake_case, and no
//! camelCase spelling of a renamed field is read on input (Engine RULINGs
//! UC02-REST-ENGINE-SCOPE = A, 15 Nov 22:37, PR (2); UC02-GUEST-REFUSAL-GRAMMAR
//! = A, 15 Nov 23:02; UC-02-TS-FIELD-NAMES = A).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --features oneiron/test-support --test
//! rest_snake_case_verb_grammar`.

use std::collections::BTreeSet;

use oneiron::code_run::vault_read::{
    CoreBatchShortIdHydrateRequest, CoreContextPackRequest, CoreHydrateRequest, CoreQueryMeta,
    CoreQueryRequest, CountMode, VaultReadMethod,
};
use serde_json::{Value, json};

/// Every property name a JSON schema declares, at any depth.
fn property_names(schema: &Value, names: &mut BTreeSet<String>) {
    match schema {
        Value::Object(object) => {
            if let Some(Value::Object(properties)) = object.get("properties") {
                names.extend(properties.keys().cloned());
            }
            for value in object.values() {
                property_names(value, names);
            }
        }
        Value::Array(items) => {
            for item in items {
                property_names(item, names);
            }
        }
        _ => {}
    }
}

fn assert_names(what: &str, schema: &Value, snake: &[&str], camel: &[&str]) {
    let mut names = BTreeSet::new();
    property_names(schema, &mut names);
    for name in snake {
        assert!(names.contains(*name), "{what} names `{name}`: {names:?}");
    }
    for name in camel {
        assert!(
            !names.contains(*name),
            "{what} still names `{name}`: {names:?}"
        );
    }
}

/// The input schema each verb row derives from its Rust type is what the MCP
/// tool schemas, the SDK typings and the guest catalog show: it names the
/// renamed fields in snake_case.
#[test]
fn verb_input_schemas_name_their_fields_in_snake_case() {
    let rows: &[(&str, &[&str], &[&str])] = &[
        ("vault.claims.put", &["learned_at"], &["learnedAt"]),
        (
            "vault.claims.supersede",
            &["new_id", "old_id"],
            &["newId", "oldId"],
        ),
        (
            "tasks.refuse",
            &["task_ref", "reason_ref"],
            &["taskRef", "reasonRef"],
        ),
        ("self.team.start", &["intent_key"], &["intentKey"]),
        (
            "self.team.record",
            &[
                "team_ref",
                "decided_by",
                "cells_filled",
                "cells_total",
                "signed_at",
            ],
            &[
                "teamRef",
                "decidedBy",
                "cellsFilled",
                "cellsTotal",
                "signedAt",
            ],
        ),
        ("self.team.vote", &["team_ref"], &["teamRef"]),
        (
            "self.team.submit",
            &["output_revision"],
            &["outputRevision"],
        ),
        (
            "vault.lenses.select",
            &["card_id", "atom_id"],
            &["cardId", "atomId"],
        ),
        (
            "vault.lenses.resolve",
            &["card_id", "selection_ref"],
            &["cardId", "selectionRef"],
        ),
        (
            "vault.lenses.result_set.action",
            &["idempotency_key"],
            &["idempotencyKey"],
        ),
        (
            "vault.calendar.create",
            &["occurred_at", "evidence_turn_ids", "source_frontiers"],
            &["occurredAt", "evidenceTurnIds", "sourceFrontiers"],
        ),
    ];
    for (verb, snake, camel) in rows {
        let schema = oneiron::task_verb::sdk::input_schema(verb)
            .unwrap_or_else(|| panic!("{verb} has an input schema"));
        assert_names(verb, schema, snake, camel);
    }
    let query = VaultReadMethod::ALL
        .into_iter()
        .find(|method| method.tool_name() == "memory.query")
        .expect("memory.query is a vault-read method");
    assert_names(
        "memory.query",
        &query.request_schema(),
        &["count_mode", "query_vector"],
        &["countMode", "queryVector"],
    );
}

/// The vault-read requests (MCP `memory.query`, `memory.hydrate`,
/// `memory.hydrate_many`, `memory.context_pack`, and the guest's vault reads)
/// refuse a camelCase spelling: they deny unknown fields, and the camelCase
/// aliases are gone.
#[test]
fn vault_read_requests_refuse_camel_case_spellings() {
    let query: CoreQueryRequest =
        serde_json::from_value(json!({ "query": "tea", "count_mode": "exact" }))
            .expect("a snake_case query decodes");
    assert_eq!(query.count_mode, CountMode::Exact);
    for camel in [
        json!({ "query": "tea", "countMode": "exact" }),
        json!({ "query": "tea", "queryVector": [0.5] }),
        json!({ "query": "tea", "queryAffect": { "valence": 0.0, "arousal": 0.0, "dominance": 0.0 } }),
    ] {
        assert!(
            serde_json::from_value::<CoreQueryRequest>(camel.clone()).is_err(),
            "memory.query reads {camel}"
        );
    }

    let hydrate: CoreHydrateRequest = serde_json::from_value(
        json!({ "short_id": "abc", "content_hash": "0f", "image_input": true }),
    )
    .expect("a snake_case hydrate decodes");
    assert_eq!(hydrate.short_id.as_deref(), Some("abc"));
    assert!(hydrate.image_input);
    for camel in [
        json!({ "shortId": "abc" }),
        json!({ "contentHash": "0f" }),
        json!({ "shortRef": "abc:0f" }),
        json!({ "ref": "abc:0f", "imageInput": true }),
    ] {
        assert!(
            serde_json::from_value::<CoreHydrateRequest>(camel.clone()).is_err(),
            "memory.hydrate reads {camel}"
        );
    }

    let many: CoreBatchShortIdHydrateRequest =
        serde_json::from_value(json!({ "refs": ["abc:0f"], "image_input": true }))
            .expect("a snake_case batch hydrate decodes");
    assert_eq!(many.refs, ["abc:0f"]);
    for camel in [
        json!({ "shortRefs": ["abc:0f"] }),
        json!({ "shortIds": ["abc"] }),
        json!({ "refs": ["abc:0f"], "imageInput": true }),
    ] {
        assert!(
            serde_json::from_value::<CoreBatchShortIdHydrateRequest>(camel.clone()).is_err(),
            "memory.hydrate_many reads {camel}"
        );
    }

    let pack: CoreContextPackRequest = serde_json::from_value(json!({
        "query": "tea",
        "edge_hop": 1,
        "budget": { "token_budget": 512, "max_item_tokens": 64, "max_field_chars": 80 },
    }))
    .expect("a snake_case context pack decodes");
    let encoded = serde_json::to_value(&pack).expect("encode the context pack");
    assert_eq!(encoded["edge_hop"], json!(1), "{encoded}");
    for camel in [
        json!({ "query": "tea", "edgeHop": 1 }),
        json!({ "query": "tea", "maxNeighbors": 2 }),
        json!({ "query": "tea", "queryVector": [0.5] }),
        json!({ "query": "tea", "budget": { "tokenBudget": 512 } }),
        json!({ "query": "tea", "budget": { "maxItemTokens": 64 } }),
        json!({ "query": "tea", "depth": { "edgeHop": 1 } }),
        json!({ "query": "tea", "media": { "space": "s", "mime": "image/png", "bytesB64": "", "limit_clamped": false } }),
    ] {
        assert!(
            serde_json::from_value::<CoreContextPackRequest>(camel.clone()).is_err(),
            "memory.context_pack reads {camel}"
        );
    }
}

/// The write inputs of vault.batch, vault.conversations.create and
/// .turns.create, and the vault.recall request read lenient bodies: a
/// camelCase spelling is no longer an alias of the snake field, so its value
/// is not read.
#[test]
fn write_and_recall_inputs_read_no_camel_case_alias() {
    let snake: oneiron::core_write::ConversationCreateInput = serde_json::from_value(json!({
        "occurred_start": 10, "occurred_end": 20, "learned_at": 30, "body": {},
    }))
    .expect("a snake_case conversation decodes");
    assert_eq!(
        (snake.occurred_start, snake.occurred_end, snake.learned_at),
        (Some(10), Some(20), Some(30))
    );
    let camel: oneiron::core_write::ConversationCreateInput = serde_json::from_value(json!({
        "occurredStart": 10, "occurredEnd": 20, "learnedAt": 30, "body": {},
    }))
    .expect("an unknown key is ignored");
    assert_eq!(
        (camel.occurred_start, camel.occurred_end, camel.learned_at),
        (None, None, None),
        "vault.conversations.create reads a camelCase time"
    );

    let turn: oneiron::core_write::ConversationTurnCreateInput = serde_json::from_value(json!({
        "conversation": "c", "occurredStart": 10, "learnedAt": 30, "body": {},
    }))
    .expect("an unknown key is ignored");
    assert_eq!(
        (turn.occurred_start, turn.learned_at),
        (None, None),
        "vault.conversations.turns.create reads a camelCase time"
    );

    assert!(
        serde_json::from_value::<oneiron::core_write::CoreBatchEntityInput>(
            json!({ "entityType": 1, "body": {} })
        )
        .is_err(),
        "vault.batch reads a camelCase entityType"
    );
    let entity: oneiron::core_write::CoreBatchEntityInput =
        serde_json::from_value(json!({ "entity_type": 1, "learnedAt": 30, "body": {} }))
            .expect("an unknown key is ignored");
    assert_eq!(
        entity.learned_at, None,
        "vault.batch reads a camelCase learnedAt"
    );

    let recall: oneiron::memory::RecallRequest = serde_json::from_value(json!({
        "query": "tea",
        "queryAffect": { "valence": 0.5, "arousal": 0.5, "dominance": 0.5 },
    }))
    .expect("an unknown key is ignored");
    assert!(
        recall.query_affect.is_none(),
        "vault.recall reads a camelCase queryAffect"
    );
}

/// The run-verb, team and lens inputs deny unknown fields: the snake_case
/// body decodes and the camelCase one is refused.
#[test]
fn run_team_and_lens_inputs_read_snake_case_and_refuse_camel_case() {
    let cases: Vec<(&str, Value, Value)> = vec![
        (
            "vault.claims.supersede",
            json!({ "new_id": "aa", "old_id": "bb", "now": 1 }),
            json!({ "newId": "aa", "oldId": "bb", "now": 1 }),
        ),
        (
            "tasks.refuse",
            json!({ "task_ref": "aa", "domain": "bond", "reason_ref": "cl_aa" }),
            json!({ "taskRef": "aa", "domain": "bond", "reasonRef": "cl_aa" }),
        ),
        (
            "vault.claims.put",
            json!({ "id": "aa", "predicate": "p", "subject": "s", "value": 1, "learned_at": 5 }),
            json!({ "id": "aa", "predicate": "p", "subject": "s", "value": 1, "learnedAt": 5 }),
        ),
        (
            "self.team.start",
            json!({ "pattern": "pair", "intent_key": "k", "members": [{ "agent": "a", "intent_key": "m" }] }),
            json!({ "pattern": "pair", "intentKey": "k", "members": [{ "agent": "a", "intentKey": "m" }] }),
        ),
        (
            "self.team.vote",
            json!({ "team_ref": "t", "choice": "a" }),
            json!({ "teamRef": "t", "choice": "a" }),
        ),
        (
            "self.team.submit",
            json!({ "team": "t", "output_revision": "r" }),
            json!({ "team": "t", "outputRevision": "r" }),
        ),
    ];
    for (verb, snake, camel) in cases {
        let decoded = decode_verb_input(verb, snake.clone());
        assert!(decoded.is_ok(), "{verb} refuses {snake}: {decoded:?}");
        let refused = decode_verb_input(verb, camel.clone());
        assert!(refused.is_err(), "{verb} reads {camel}");
    }

    let record = json!({
        "team_ref": "t",
        "members": ["a"],
        "axis": "converge",
        "decided_by": { "kind": "referee", "rule": "r", "signed_at": 7 },
        "coverage": { "cells_filled": 1, "cells_total": 2 },
    });
    serde_json::from_value::<oneiron::team::TeamRecordInput>(record.clone())
        .unwrap_or_else(|error| panic!("self.team.record refuses {record}: {error}"));
    for camel in [
        json!({ "teamRef": "t", "members": ["a"], "axis": "converge", "decided_by": { "kind": "leader" } }),
        json!({ "team_ref": "t", "members": ["a"], "axis": "converge", "decidedBy": { "kind": "leader" } }),
        json!({ "team_ref": "t", "members": ["a"], "axis": "converge", "decided_by": { "kind": "referee", "rule": "r", "signedAt": 7 } }),
        json!({ "team_ref": "t", "members": ["a"], "axis": "converge", "decided_by": { "kind": "leader" }, "coverage": { "cellsFilled": 1, "cellsTotal": 2 } }),
    ] {
        assert!(
            serde_json::from_value::<oneiron::team::TeamRecordInput>(camel.clone()).is_err(),
            "self.team.record reads {camel}"
        );
    }

    let resolve: oneiron::lens::LensSelectionResolveRequest =
        serde_json::from_value(json!({ "card_id": "card", "selection_ref": "sel" }))
            .expect("a snake_case resolve decodes");
    assert_eq!(resolve.selection_ref, "sel");
    assert!(
        serde_json::from_value::<oneiron::lens::LensSelectionResolveRequest>(
            json!({ "cardId": "card", "selectionRef": "sel" })
        )
        .is_err(),
        "vault.lenses.resolve reads camelCase"
    );

    let calendar = json!({
        "origin": "dreamer",
        "summary": "tea",
        "occurred_at": { "start": 1, "end": 2 },
        "evidence_turn_ids": ["t"],
        "source_frontiers": ["f"],
    });
    let decoded: oneiron::calendar::door::CalendarEventCreateRequest =
        serde_json::from_value(calendar.clone())
            .unwrap_or_else(|error| panic!("vault.calendar.create refuses {calendar}: {error}"));
    assert_eq!(serde_json::to_value(&decoded).expect("encode"), calendar);
    assert!(
        serde_json::from_value::<oneiron::calendar::door::CalendarEventCreateRequest>(json!({
            "origin": "native", "summary": "tea", "occurredAt": { "start": 1, "end": 2 },
        }))
        .is_err(),
        "vault.calendar.create reads camelCase"
    );
}

fn decode_verb_input(verb: &str, body: Value) -> Result<(), serde_json::Error> {
    match verb {
        "vault.claims.supersede" => {
            serde_json::from_value::<oneiron::code_run::MemorySupersedeInput>(body).map(drop)
        }
        "tasks.refuse" => {
            serde_json::from_value::<oneiron::code_run::TaskRefuseInput>(body).map(drop)
        }
        "vault.claims.put" => {
            serde_json::from_value::<oneiron::code_run::MemoryClaimInput>(body).map(drop)
        }
        "self.team.start" => {
            serde_json::from_value::<oneiron::team::TeamStartInput>(body).map(drop)
        }
        "self.team.vote" => serde_json::from_value::<oneiron::team::TeamVoteInput>(body).map(drop),
        "self.team.submit" => {
            serde_json::from_value::<oneiron::code_run::TeamSubmitInput>(body).map(drop)
        }
        other => panic!("no decoder for {other}"),
    }
}

/// `vault.agents.put`'s definition draft reads snake_case and refuses the
/// camelCase spelling (it denies unknown fields).
#[test]
fn agent_definition_draft_reads_snake_case_and_refuses_camel_case() {
    let id = oneiron::EntityId::now().to_hex();
    let snake = json!({
        "agent_id": "fixture.snake-draft",
        "desc": "snake_case draft",
        "version": "1",
        "scope": { "kind": "base" },
        "ceiling": "proposed",
        "display_name": "Snake draft",
    });
    oneiron::code_run::parse_agent_put_request(&id, snake, 10)
        .expect("a snake_case draft is a definition request");
    let camel = json!({
        "agentId": "fixture.snake-draft",
        "desc": "snake_case draft",
        "version": "1",
        "scope": { "kind": "base" },
        "ceiling": "proposed",
        "displayName": "Snake draft",
    });
    assert!(
        oneiron::code_run::parse_agent_put_request(&id, camel, 10).is_err(),
        "vault.agents.put reads a camelCase draft"
    );
}

/// The replies (MCP `memory.query`'s meta and cursor, the hydrate `deletion`,
/// self.team.submit's answer, a lens selection's span, the result-read
/// refusal and an xlsx sheet's visibility) write snake_case.
#[test]
fn verb_replies_write_snake_case() {
    let meta = serde_json::to_value(CoreQueryMeta {
        total: 3,
        count_mode: CountMode::Estimate,
        limit_clamped: true,
    })
    .expect("encode the meta");
    assert_eq!(
        meta,
        json!({ "total": 3, "count_mode": "estimate", "limit_clamped": true })
    );

    let deletion = serde_json::to_value(oneiron::deletion::HydratedShortIdDeletion {
        source: oneiron::deletion::HydratedShortIdDeletionSource::Tombstone,
        reason: None,
        deleted_at: Some(9),
        request_id: Some("req".to_owned()),
        hard: false,
    })
    .expect("encode the deletion");
    assert_eq!(deletion["deleted_at"], json!(9), "{deletion}");
    assert_eq!(deletion["request_id"], json!("req"), "{deletion}");
    assert!(deletion.get("deletedAt").is_none() && deletion.get("requestId").is_none());

    let answer = serde_json::to_value(oneiron::code_run::TeamSubmitAnswer {
        team: "t".to_owned(),
        output_revision: "r".to_owned(),
        review_claim: "c".to_owned(),
        already_submitted: true,
    })
    .expect("encode the answer");
    assert_eq!(
        answer,
        json!({ "team": "t", "output_revision": "r", "review_claim": "c", "already_submitted": true })
    );

    let span = serde_json::to_value(oneiron::lens::LensSelectedSpan {
        start: 1,
        end: 2,
        version: vec![1],
        start_cursor: vec![2],
        end_cursor: vec![3],
    })
    .expect("encode the span");
    assert_eq!(
        span,
        json!({ "start": 1, "end": 2, "version": [1], "start_cursor": [2], "end_cursor": [3] })
    );

    let refusal = serde_json::to_value(oneiron::memory::result_doors::ResultReadRefusal {
        denied: "tainted".to_owned(),
        reason_codes: vec!["tainted".to_owned()],
        error: None,
        bytes: None,
    })
    .expect("encode the refusal");
    assert_eq!(
        refusal,
        json!({ "denied": "tainted", "reason_codes": ["tainted"] })
    );

    assert_eq!(
        serde_json::to_value(oneiron_docedit::xlsx_body::XlsxSheetVisibility::VeryHidden)
            .expect("encode the visibility"),
        json!("very_hidden")
    );
    assert!(
        serde_json::from_value::<oneiron_docedit::xlsx_body::XlsxSheetVisibility>(json!(
            "veryHidden"
        ))
        .is_err()
    );
}

/// The refusal a guest's result call throws, and the result search input,
/// use the grammar's snake_case names: `{denied, reason_codes, live,
/// live_count}` and `ignore_case` (UC02-GUEST-REFUSAL-GRAMMAR = A).
#[cfg(oneiron_test_support)]
#[test]
fn guest_result_refusal_and_search_input_use_snake_case() {
    use oneiron::test_doors::verb_grammar_names::{
        decode_result_search_input, result_refusal, unknown_handle_refusal,
    };

    assert_eq!(
        result_refusal("result_withheld"),
        json!({ "denied": "result_withheld", "reason_codes": ["result_withheld"] })
    );
    assert_eq!(
        unknown_handle_refusal(),
        json!({ "denied": "unknown_handle", "reason_codes": ["unknown_handle"], "live": [], "live_count": 0 })
    );

    decode_result_search_input(json!({ "pattern": "tea", "ignore_case": true }))
        .unwrap_or_else(|refused| panic!("ignore_case is refused: {refused}"));
    let refused = decode_result_search_input(json!({ "pattern": "tea", "ignoreCase": true }))
        .expect_err("ignoreCase is refused");
    assert_eq!(
        refused["denied"],
        json!("invalid_result_input"),
        "{refused}"
    );
    assert_eq!(
        refused["reason_codes"],
        json!(["invalid_result_input"]),
        "{refused}"
    );
}
