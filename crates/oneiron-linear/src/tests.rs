use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use oneiron::{EntityId, LinearChangeSource, LinearEgress, LinearSyncError, MirroredTaskFields};
use serde_json::{Value, json};

use crate::{
    GraphQlCall, GraphQlExecutor, GraphQlTransportError, LinearHostChangeSource, LinearHostEgress,
    LinearTrackerConfig,
};

fn config() -> LinearTrackerConfig {
    LinearTrackerConfig {
        team_id: "team-1".into(),
        status_ids: BTreeMap::from([("queued".into(), "state-1".into())]),
        assignee_ids: BTreeMap::from([("owner".into(), "user-1".into())]),
        page_size: 2,
    }
}
fn issue(id: &str, updated: &str, title: &str) -> Value {
    json!({"id":id,"identifier":format!("TASK-{id}"),"updatedAt":updated,
        "title":title,"description":null,"priority":2,"team":{"id":"team-1"},
        "state":{"id":"state-1"},"assignee":{"id":"user-1"}})
}
fn fields() -> MirroredTaskFields {
    MirroredTaskFields {
        title: "New title".into(),
        description: None,
        priority: Some(2),
        assignee_ref: Some("owner".into()),
        status: "queued".into(),
    }
}

impl<T: GraphQlExecutor + ?Sized> GraphQlExecutor for &mut T {
    fn execute(&mut self, call: &GraphQlCall) -> Result<Value, GraphQlTransportError> {
        (**self).execute(call)
    }
}
struct StubReader {
    replies: Vec<Value>,
    calls: Rc<RefCell<Vec<GraphQlCall>>>,
}
impl GraphQlExecutor for StubReader {
    fn execute(&mut self, call: &GraphQlCall) -> Result<Value, GraphQlTransportError> {
        self.calls.borrow_mut().push(call.clone());
        if self.replies.is_empty() {
            return Err(GraphQlTransportError::Uncertain);
        }
        Ok(self.replies.remove(0))
    }
}

struct JournalTransport {
    writes: Rc<RefCell<usize>>,
    calls: Rc<RefCell<usize>>,
    failure: Option<GraphQlTransportError>,
}
impl GraphQlExecutor for JournalTransport {
    fn execute(&mut self, _: &GraphQlCall) -> Result<Value, GraphQlTransportError> {
        *self.calls.borrow_mut() += 1;
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        *self.writes.borrow_mut() += 1;
        Ok(json!({"data":{"issueCreate":{"success":true,
            "issue":issue("created","2026-09-26T00:00:00Z","New title")}}}))
    }
}
#[test]
fn response_journal_replays_success_and_never_retries_ambiguous_send() {
    let dir = tempfile::tempdir().expect("journal dir");
    let writes = Rc::new(RefCell::new(0));
    let call = GraphQlCall {
        query: crate::egress::CREATE,
        variables: json!({"input":{"teamId":"team-1"}}),
    };
    let make = |failure| {
        crate::journal::LinearResponseJournal::new(
            JournalTransport {
                writes: writes.clone(),
                calls: Rc::new(RefCell::new(0)),
                failure,
            },
            dir.path().to_path_buf(),
        )
        .expect("journal")
    };
    let mut first = make(None);
    let response = first.dispatch([1; 32], &call).expect("first");
    drop(first);
    let mut restarted = make(None);
    assert_eq!(
        restarted.dispatch([1; 32], &call).expect("replay"),
        response
    );
    assert_eq!(*writes.borrow(), 1);
    assert!(
        restarted
            .dispatch(
                [1; 32],
                &GraphQlCall {
                    query: call.query,
                    variables: json!({"input":{"teamId":"other"}})
                }
            )
            .is_err()
    );
    let mut uncertain = make(Some(GraphQlTransportError::Uncertain));
    assert_eq!(
        uncertain.dispatch([2; 32], &call),
        Err(GraphQlTransportError::Uncertain)
    );
    let mut recovered = make(None);
    assert_eq!(
        recovered.dispatch([2; 32], &call),
        Err(GraphQlTransportError::Uncertain)
    );
    assert_eq!(*writes.borrow(), 1);
}

#[test]
fn definitely_unsent_request_can_retry_after_restart() {
    let dir = tempfile::tempdir().expect("journal dir");
    let writes = Rc::new(RefCell::new(0));
    let call = GraphQlCall {
        query: crate::egress::CREATE,
        variables: json!({"input":{"teamId":"team-1"}}),
    };
    let mut offline = crate::journal::LinearResponseJournal::new(
        JournalTransport {
            writes: writes.clone(),
            calls: Rc::new(RefCell::new(0)),
            failure: Some(GraphQlTransportError::NotSent),
        },
        dir.path().to_path_buf(),
    )
    .expect("journal");
    assert_eq!(
        offline.dispatch([3; 32], &call),
        Err(GraphQlTransportError::NotSent)
    );
    drop(offline);
    let mut online = crate::journal::LinearResponseJournal::new(
        JournalTransport {
            writes: writes.clone(),
            calls: Rc::new(RefCell::new(0)),
            failure: None,
        },
        dir.path().to_path_buf(),
    )
    .expect("journal");
    online.dispatch([3; 32], &call).expect("safe retry");
    assert_eq!(*writes.borrow(), 1);
}

#[test]
fn page_query_variable_types_match_pinned_linear_filter_schema() {
    let schema = include_str!("../tests/fixtures/linear-page-schema.graphql");
    let type_of = |block: &str, field: &str| -> &str {
        let body = schema
            .split(block)
            .nth(1)
            .expect("pinned schema type")
            .split('}')
            .next()
            .expect("schema fields");
        body.lines()
            .find_map(|line| line.trim().strip_prefix(field))
            .expect("pinned schema field")
            .trim()
    };
    assert_eq!(type_of("input IDComparator {", "eq:"), "ID");
    assert_eq!(type_of("input TeamFilter {", "id:"), "IDComparator");
    assert_eq!(type_of("input IssueFilter {", "team:"), "TeamFilter");
    assert!(type_of("type Query {", "issues(").contains("filter: IssueFilter"));
    let mut reader = StubReader {
        replies: vec![json!({"data":{"issues":{"nodes":[],
            "pageInfo":{"hasPreviousPage":false,"startCursor":null}}}})],
        calls: Rc::new(RefCell::new(Vec::new())),
    };
    let calls = reader.calls.clone();
    let mut source = LinearHostChangeSource::new(&mut reader, config()).expect("source");
    source.changes_since(None).expect("query");
    let query = calls.borrow()[0].query;
    let type_token = type_of("input IDComparator {", "eq:");
    assert!(query.contains(&format!("$team: {type_token}!")));
    assert!(query.contains("$before: String"));
    assert!(query.contains("$last: Int!"));
    assert!(query.contains("eq: $team"));
    assert!(query.contains("orderBy: updatedAt, last: $last, before: $before"));
}

fn linear_receipts(vault: &oneiron::Vault) -> Vec<oneiron::receipt::ReceiptRecord> {
    let mut query = oneiron::receipt::ReceiptQuery::new(32);
    query.kinds.insert(oneiron::receipt::ReceiptKind::Outbound);
    vault
        .receipts(query)
        .expect("outbound receipt query")
        .into_iter()
        .filter(|row| {
            row.fields
                .get("channel")
                .is_some_and(|value| value == "linear")
        })
        .collect()
}

fn linear_scanned_receipts(vault: &oneiron::Vault) -> Vec<oneiron::receipt::ReceiptRecord> {
    let mut query = oneiron::receipt::ReceiptQuery::new(32);
    query.kinds.insert(oneiron::receipt::ReceiptKind::Outbound);
    let scan = vault.scan_receipts(query).expect("outbound receipt scan");
    assert!(scan.complete, "receipt scan must be complete");
    scan.records
        .into_iter()
        .filter(|row| {
            row.fields
                .get("channel")
                .is_some_and(|value| value == "linear")
        })
        .collect()
}

fn grant_linear_effects(vault: &oneiron::Vault, actor: EntityId) {
    use rmpv::Value as V;
    let mut scope = oneiron::federation::Scope::top();
    scope.verbs = oneiron::federation::ScopeAxis::Some(std::collections::BTreeSet::from([
        "effect".to_owned(),
    ]));
    let scope_bytes = rmp_serde::to_vec_named(&scope).expect("scope");
    let scope_value = rmpv::decode::read_value(&mut scope_bytes.as_slice()).expect("scope value");
    let entries = vec![
        (V::from("schema_version"), V::from("1.2")),
        (V::from("pack_id"), V::from("linear-egress-test")),
        (V::from("pack_version"), V::from("v1")),
        (
            V::from("min_engine_version"),
            V::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            V::from("defaults"),
            V::Map(vec![
                (V::from("criticality"), V::from("normal")),
                (V::from("sensitivity"), V::from("normal")),
            ]),
        ),
        (V::from("rules"), V::Array(vec![])),
        (
            V::from("actor_ceilings"),
            V::Array(vec![V::Map(vec![
                (V::from("actor_class"), V::from("agent")),
                (V::from("actor_ref"), V::from(actor.to_hex())),
                (V::from("ceiling"), V::from("auto")),
            ])]),
        ),
        (
            V::from("scoped_grants"),
            V::Array(
                ["create_issue", "update_issue"]
                    .iter()
                    .map(|verb| {
                        V::Map(vec![
                            (V::from("actor_ref"), V::from(actor.to_hex())),
                            (V::from("effector"), V::from(format!("external:{verb}"))),
                            (V::from("scope"), scope_value.clone()),
                            (
                                V::from("selectors"),
                                V::Map(vec![(V::from("channel"), V::from("linear"))]),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
    ];
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &V::Map(entries)).expect("encode policy");
    let owner = vault
        .authenticate_owner(
            actor,
            &actor.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("owner auth");
    vault
        .install_owner_policy_manifest(
            &owner,
            EntityId::from_bytes([0x77; 16]).expect("policy ref"),
            bytes,
            1,
        )
        .expect("install policy");
}

#[test]
fn vault_door_gate_and_budget_prevent_wire_and_replay_never_debits_twice() {
    use oneiron::connector_key::{
        CalendarPeriod, ConnectorKeyRecord, EffectorBudget, EffectorBudgetOnExhaust,
        EffectorBudgetWindow,
    };
    use oneiron::outbound::{OutboundDispatchActor, OutboundDispatchGate};
    let dir = tempfile::tempdir().expect("vault");
    let responses = tempfile::tempdir().expect("responses");
    let vault =
        oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).expect("vault open");
    let actor = EntityId::from_bytes([0x56; 16]).expect("actor");
    vault
        .put_entity(
            &actor,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"actor",
        )
        .expect("person");
    grant_linear_effects(&vault, actor);
    let key_id = EntityId::from_bytes([0x58; 16]).expect("key");
    vault
        .register_connector_key(
            &key_id,
            ConnectorKeyRecord::active(
                "linear",
                None,
                vec![EffectorBudget::sends(
                    1,
                    EffectorBudgetWindow::Calendar {
                        period: CalendarPeriod::Day,
                        tz: None,
                    },
                    EffectorBudgetOnExhaust::Suspend,
                )],
                1000,
            ),
        )
        .expect("budget");
    let writes = Rc::new(RefCell::new(0));
    let transport = || JournalTransport {
        writes: writes.clone(),
        calls: Rc::new(RefCell::new(0)),
        failure: None,
    };
    let door = crate::VaultLinearOutboundDoor::new(
        &vault,
        transport(),
        responses.path().to_path_buf(),
        OutboundDispatchActor::agent(actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        1000,
    )
    .expect("door");
    let mut egress = LinearHostEgress::new(door, config()).expect("egress");
    let first = egress
        .create_issue([41; 32], actor, &fields())
        .expect("first dispatch");
    let successful = linear_receipts(&vault);
    assert_eq!(successful.len(), 1);
    assert_eq!(successful[0].outcome, "delivered_to_channel");
    let content_ref = successful[0].fields["content_ref"].clone();
    assert!(content_ref.starts_with("linear:request:v1:"));
    assert!(!content_ref.contains("mutation"));
    let replay = egress
        .create_issue([41; 32], actor, &fields())
        .expect("engine replay");
    assert_eq!(first, replay);
    assert_eq!(linear_receipts(&vault), successful);
    assert_eq!(*writes.borrow(), 1);
    assert!(egress.create_issue([42; 32], actor, &fields()).is_err());
    assert_eq!(*writes.borrow(), 1);
    assert_eq!(
        vault
            .get_connector_key(&key_id)
            .expect("key read")
            .expect("key")
            .status,
        oneiron::connector_key::ConnectorKeyStatus::Suspended,
    );
    let budget_receipts = linear_receipts(&vault);
    assert_eq!(budget_receipts.len(), 2);
    assert_eq!(
        budget_receipts
            .iter()
            .filter(|row| row.outcome == "delivered_to_channel")
            .count(),
        1
    );
    assert!(
        budget_receipts
            .iter()
            .any(|row| row.outcome == "suppressed")
    );
    let door = egress.into_door();
    let frozen = door
        .request_by_ref(&content_ref)
        .expect("request read")
        .expect("frozen request");
    assert_eq!(frozen["query"], crate::egress::CREATE);
    assert_eq!(frozen["variables"]["input"]["teamId"], "team-1");
    let denied = crate::VaultLinearOutboundDoor::new(
        &vault,
        transport(),
        responses.path().to_path_buf(),
        OutboundDispatchActor::agent(actor),
        OutboundDispatchGate {
            has_opted_in: false,
            has_permission: false,
            policy_risk: Default::default(),
        },
        1001,
    )
    .expect("denied door");
    let mut denied = LinearHostEgress::new(denied, config()).expect("egress");
    assert!(denied.create_issue([43; 32], actor, &fields()).is_err());
    assert_eq!(*writes.borrow(), 1);
    let denied_receipts = linear_receipts(&vault);
    assert_eq!(denied_receipts.len(), 3);
    assert_eq!(
        denied_receipts
            .iter()
            .filter(|row| row.outcome != "delivered_to_channel")
            .count(),
        2
    );
    assert!(
        denied_receipts
            .iter()
            .any(|row| row.outcome == "suppressed")
    );
    for row in &denied_receipts {
        let reference = row
            .fields
            .get("content_ref")
            .expect("ordinary receipt content_ref");
        assert!(
            door.request_by_ref(reference)
                .expect("resolvable request")
                .is_some()
        );
    }
    drop(denied);
    drop(door);
    drop(vault);
    let reopened =
        oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).expect("reopen");
    let resumed = crate::VaultLinearOutboundDoor::new(
        &reopened,
        transport(),
        responses.path().to_path_buf(),
        OutboundDispatchActor::agent(actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        1002,
    )
    .expect("reopened door");
    let mut resumed = LinearHostEgress::new(resumed, config()).expect("egress");
    assert_eq!(
        resumed
            .create_issue([41; 32], actor, &fields())
            .expect("durable replay"),
        first
    );
    assert_eq!(linear_receipts(&reopened), denied_receipts);
    assert_eq!(*writes.borrow(), 1);
}

#[test]
fn uncertain_delivery_has_ordinary_receipt_and_never_blindly_resends_after_restart() {
    use oneiron::outbound::{OutboundDispatchActor, OutboundDispatchGate};
    let dir = tempfile::tempdir().expect("vault");
    let responses = tempfile::tempdir().expect("responses");
    let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).expect("open");
    let actor = EntityId::from_bytes([0x66; 16]).expect("actor");
    vault
        .put_entity(
            &actor,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"actor",
        )
        .expect("person");
    grant_linear_effects(&vault, actor);
    let calls = Rc::new(RefCell::new(0));
    let writes = Rc::new(RefCell::new(0));
    let failed = JournalTransport {
        writes: writes.clone(),
        calls: calls.clone(),
        failure: Some(GraphQlTransportError::Uncertain),
    };
    let door = crate::VaultLinearOutboundDoor::new(
        &vault,
        failed,
        responses.path().to_path_buf(),
        OutboundDispatchActor::agent(actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        1000,
    )
    .expect("door");
    let mut egress = LinearHostEgress::new(door, config()).expect("egress");
    assert!(egress.create_issue([44; 32], actor, &fields()).is_err());
    assert_eq!(*calls.borrow(), 1);
    let recorded = linear_receipts(&vault);
    assert_eq!(recorded.len(), 1);
    // ONE-1872: a failed attempt that may have delivered projects as ambiguous.
    assert_eq!(recorded[0].outcome, "ambiguous");
    assert_eq!(
        recorded[0]
            .fields
            .get("delivery_may_have_occurred")
            .map(String::as_str),
        Some("true")
    );
    let reference = recorded[0].fields.get("content_ref").expect("pointer");
    assert!(!reference.contains("mutation"));
    assert!(
        egress
            .into_door()
            .request_by_ref(reference)
            .expect("read")
            .is_some()
    );
    drop(vault);
    let reopened =
        oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).expect("reopen");
    let healthy = JournalTransport {
        writes: writes.clone(),
        calls: calls.clone(),
        failure: None,
    };
    let door = crate::VaultLinearOutboundDoor::new(
        &reopened,
        healthy,
        responses.path().to_path_buf(),
        OutboundDispatchActor::agent(actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        1000,
    )
    .expect("door");
    let mut egress = LinearHostEgress::new(door, config()).expect("egress");
    assert!(egress.create_issue([44; 32], actor, &fields()).is_err());
    assert_eq!(*calls.borrow(), 1);
    assert_eq!(*writes.borrow(), 0);
    assert_eq!(linear_receipts(&reopened), recorded);
}

#[test]
fn definite_failure_then_uncertain_send_preserves_both_receipts_after_reopen() {
    use oneiron::outbound::{OutboundDispatchActor, OutboundDispatchGate};
    fn make<'a>(
        vault: &'a oneiron::Vault,
        responses: &tempfile::TempDir,
        actor: EntityId,
        calls: &Rc<RefCell<usize>>,
        writes: &Rc<RefCell<usize>>,
        failure: Option<GraphQlTransportError>,
        now: u64,
    ) -> crate::VaultLinearOutboundDoor<'a, JournalTransport> {
        let transport = JournalTransport {
            writes: writes.clone(),
            calls: calls.clone(),
            failure,
        };
        crate::VaultLinearOutboundDoor::new(
            vault,
            transport,
            responses.path().to_path_buf(),
            OutboundDispatchActor::agent(actor),
            OutboundDispatchGate::allow_when_policy_grants(),
            now,
        )
        .expect("door")
    }
    let dir = tempfile::tempdir().expect("vault");
    let responses = tempfile::tempdir().expect("responses");
    let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).expect("open");
    let actor = EntityId::from_bytes([0x67; 16]).expect("actor");
    vault
        .put_entity(
            &actor,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"actor",
        )
        .expect("person");
    grant_linear_effects(&vault, actor);
    let calls = Rc::new(RefCell::new(0));
    let writes = Rc::new(RefCell::new(0));
    let mut first = LinearHostEgress::new(
        make(
            &vault,
            &responses,
            actor,
            &calls,
            &writes,
            Some(GraphQlTransportError::NotSent),
            1000,
        ),
        config(),
    )
    .expect("egress");
    assert!(first.create_issue([45; 32], actor, &fields()).is_err());
    assert_eq!(*calls.borrow(), 1);
    let definite = linear_receipts(&vault);
    assert_eq!(definite.len(), 1);
    assert_eq!(definite[0].outcome, "failed");
    assert_eq!(
        definite[0]
            .fields
            .get("delivery_may_have_occurred")
            .map(String::as_str),
        Some("false")
    );
    drop(first);
    let mut second = LinearHostEgress::new(
        make(
            &vault,
            &responses,
            actor,
            &calls,
            &writes,
            Some(GraphQlTransportError::Uncertain),
            1001,
        ),
        config(),
    )
    .expect("egress");
    assert!(second.create_issue([45; 32], actor, &fields()).is_err());
    assert_eq!(*calls.borrow(), 2);
    let outcomes = linear_receipts(&vault);
    assert_eq!(
        outcomes.len(),
        2,
        "later uncertain send must not be hidden by the first failure"
    );
    assert!(outcomes.iter().any(|row| {
        row.fields
            .get("delivery_may_have_occurred")
            .map(String::as_str)
            == Some("false")
    }));
    assert!(outcomes.iter().any(|row| {
        row.fields
            .get("delivery_may_have_occurred")
            .map(String::as_str)
            == Some("true")
            && row.fields.contains_key("retry_state")
    }));
    assert_eq!(linear_scanned_receipts(&vault), outcomes);
    drop(second);
    drop(vault);
    let reopened =
        oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).expect("reopen");
    let mut replay = LinearHostEgress::new(
        make(&reopened, &responses, actor, &calls, &writes, None, 1002),
        config(),
    )
    .expect("egress");
    assert!(replay.create_issue([45; 32], actor, &fields()).is_err());
    assert_eq!(
        *calls.borrow(),
        2,
        "uncertain response must not be blindly resent"
    );
    assert_eq!(*writes.borrow(), 0);
    assert_eq!(linear_receipts(&reopened), outcomes);
    assert_eq!(linear_scanned_receipts(&reopened), outcomes);
}

#[test]
fn interrupted_request_staging_retries_same_operation_after_restart() {
    use oneiron::outbound::{OutboundDispatchActor, OutboundDispatchGate};
    use std::io::Write;
    let vault_dir = tempfile::tempdir().expect("vault");
    let responses = tempfile::tempdir().expect("host response custody");
    let vault =
        oneiron::Vault::open(vault_dir.path(), oneiron::VaultConfig::default()).expect("open");
    let actor = EntityId::from_bytes([0x68; 16]).expect("actor");
    vault
        .put_entity(
            &actor,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"actor",
        )
        .expect("person");
    grant_linear_effects(&vault, actor);
    let calls = Rc::new(RefCell::new(0));
    let writes = Rc::new(RefCell::new(0));
    let op = [46; 32];
    let call = GraphQlCall {
        query: crate::egress::CREATE,
        variables: json!({"input":{"teamId":"team-1"}}),
    };
    let journal = crate::journal::LinearResponseJournal::new(
        JournalTransport {
            writes: writes.clone(),
            calls: calls.clone(),
            failure: None,
        },
        responses.path().to_path_buf(),
    )
    .expect("journal");
    // Interrupt the exact staging path after writing only part of its
    // temporary file, leaving an orphan as a process crash would. The final
    // request name must not exist; no gate or transport has run.
    let interrupted = journal.stage_request_with(&op, &call, |staged| {
        staged.as_file_mut().write_all(b"{").expect("partial write");
        staged.as_file().sync_all().expect("partial sync");
        std::fs::hard_link(
            staged.path(),
            responses.path().join("crashed-staging-partial"),
        )
        .expect("leave crash orphan");
        Err(LinearSyncError::Transport(
            "injected pre-publish crash".into(),
        ))
    });
    assert!(interrupted.is_err());
    let reference = format!("linear:request:v1:{}", blake3::Hash::from(op).to_hex());
    assert_eq!(
        journal.read_request(&reference).expect("request lookup"),
        None
    );
    assert_eq!(*calls.borrow(), 0);
    drop(journal);
    drop(vault);
    let reopened =
        oneiron::Vault::open(vault_dir.path(), oneiron::VaultConfig::default()).expect("reopen");
    let door = crate::VaultLinearOutboundDoor::new(
        &reopened,
        JournalTransport {
            writes: writes.clone(),
            calls: calls.clone(),
            failure: None,
        },
        responses.path().to_path_buf(),
        OutboundDispatchActor::agent(actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        1000,
    )
    .expect("door");
    let mut egress = LinearHostEgress::new(door, config()).expect("egress");
    let created = egress
        .create_issue(op, actor, &fields())
        .expect("safe retry");
    assert_eq!(created.issue.issue_id, "created");
    assert_eq!(*calls.borrow(), 1);
    assert_eq!(*writes.borrow(), 1);
    let door = egress.into_door();
    assert!(door.request_by_ref(&reference).expect("resolve").is_some());
    let mut egress = LinearHostEgress::new(door, config()).expect("egress");
    assert_eq!(
        egress.create_issue(op, actor, &fields()).expect("replay"),
        created
    );
    let mut altered = fields();
    altered.title = "changed payload".into();
    assert!(egress.create_issue(op, actor, &altered).is_err());
    assert_eq!(*calls.borrow(), 1);
}
