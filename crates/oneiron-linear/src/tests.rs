use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use oneiron::{EntityId, LinearChangeSource, LinearEgress, LinearSyncError, MirroredTaskFields};
use serde_json::{Value, json};

use crate::{
    GraphQlCall, GraphQlExecutor, LinearHostChangeSource, LinearHostEgress, LinearOutboundDoor,
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
struct StubReader {
    replies: Vec<Value>,
    calls: Rc<RefCell<Vec<GraphQlCall>>>,
}
impl GraphQlExecutor for StubReader {
    fn execute(&mut self, call: &GraphQlCall) -> Result<Value, LinearSyncError> {
        self.calls.borrow_mut().push(call.clone());
        if self.replies.is_empty() {
            return Err(LinearSyncError::Transport("no reply".into()));
        }
        Ok(self.replies.remove(0))
    }
}
#[test]
fn cursor_pages_normalize_issue_snapshots_and_preserve_cursor() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let a = issue("a", "2026-09-26T00:00:00.000Z", "First");
    let b = issue("b", "2026-09-26T00:00:00.500Z", "Second");
    let reader = StubReader {
        calls: calls.clone(),
        replies: vec![
            json!({"data":{"issues":{"nodes":[b,&a],"pageInfo":{"hasPreviousPage":true,"startCursor":"page-2"}}}}),
            json!({"data":{"issues":{"nodes":[issue("c", "2026-09-26T00:00:01.000Z", "Third")],
            "pageInfo":{"hasPreviousPage":false,"startCursor":null}}}}),
        ],
    };
    let mut source = LinearHostChangeSource::new(reader, config()).expect("source");
    let first = source.changes_since(None).expect("first page");
    assert_eq!(first.changes.len(), 2);
    assert_eq!(first.changes[0].issue.issue_id, "a");
    assert_eq!(first.changes[1].issue.issue_id, "b");
    assert!(first.changes[0].updated_at_ms < first.changes[1].updated_at_ms);
    assert_eq!(first.changes[0].fields.status, "queued");
    assert_eq!(
        first.changes[0].fields.assignee_ref.as_deref(),
        Some("owner")
    );
    assert_ne!(first.changes[0].event_id, first.changes[1].event_id);
    assert_eq!(first.next_cursor.as_deref(), Some("page-2"));
    let second = source
        .changes_since(first.next_cursor.as_deref())
        .expect("next page");
    assert_eq!(second.changes[0].issue.issue_id, "c");
    assert_eq!(second.next_cursor, None);
    assert_eq!(calls.borrow()[0].variables["before"], Value::Null);
    assert_eq!(calls.borrow()[1].variables["before"], "page-2");
    let reread = config().issue(&a).expect("stable event");
    assert_eq!(first.changes[0].event_id, reread.event_id);
}

#[test]
fn rejects_nonprogressing_cursor_and_unmapped_foreign_values() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let reader = StubReader {
        calls,
        replies: vec![json!({"data":{"issues":{
        "nodes":[issue("a","2026-09-26T00:00:00Z","A")],
        "pageInfo":{"hasPreviousPage":true,"startCursor":"same"}}}})],
    };
    let mut source = LinearHostChangeSource::new(reader, config()).expect("source");
    assert!(source.changes_since(Some("same")).is_err());
    let mut unknown = issue("a", "2026-09-26T00:00:00Z", "A");
    unknown["state"]["id"] = json!("unknown");
    assert!(config().issue(&unknown).is_err());
}

// The test door models a host-owned durable ledger: recreating the adapter
// retains the journal and no repeated operation reaches the tracker stub.
#[derive(Default)]
struct DoorState {
    receipts: BTreeMap<[u8; 32], (GraphQlCall, Value)>,
    writes: usize,
    allow: bool,
}
struct StubDoor(Rc<RefCell<DoorState>>);
impl LinearOutboundDoor for StubDoor {
    fn dispatch(&mut self, id: [u8; 32], call: &GraphQlCall) -> Result<Value, LinearSyncError> {
        let mut state = self.0.borrow_mut();
        if !state.allow {
            return Err(LinearSyncError::Transport("denied".into()));
        }
        if let Some((saved, response)) = state.receipts.get(&id) {
            if saved != call {
                return Err(LinearSyncError::Transport(
                    "operation payload changed".into(),
                ));
            }
            return Ok(response.clone());
        }
        state.writes += 1;
        let response = json!({"data": {"issueCreate": {"success":true,
            "issue":issue("created","2026-09-26T00:00:00Z","New title")},
            "issueUpdate": {"success":true,
            "issue":issue("created","2026-09-26T00:00:01Z","New title")}}});
        state.receipts.insert(id, (call.clone(), response.clone()));
        Ok(response)
    }
}
#[test]
fn operation_id_retry_after_adapter_restart_collapses_to_one_write() {
    let state = Rc::new(RefCell::new(DoorState {
        allow: true,
        ..DoorState::default()
    }));
    let task = EntityId::from_bytes([9; 16]).expect("id");
    let op = [7; 32];
    let mut first = LinearHostEgress::new(StubDoor(state.clone()), config()).expect("egress");
    let created = first.create_issue(op, task, &fields()).expect("create");
    assert_eq!(created.issue.issue_id, "created");
    drop(first);
    let mut restarted = LinearHostEgress::new(StubDoor(state.clone()), config()).expect("egress");
    assert_eq!(
        restarted.create_issue(op, task, &fields()).expect("retry"),
        created
    );
    assert_eq!(state.borrow().writes, 1);
    let mut altered = fields();
    altered.title = "changed".into();
    assert!(restarted.create_issue(op, task, &altered).is_err());
    let update = restarted
        .update_issue([8; 32], &created.issue, &fields())
        .expect("update");
    assert_eq!(update.issue.issue_id, created.issue.issue_id);
    assert_eq!(state.borrow().writes, 2);
    state.borrow_mut().allow = false;
    assert!(
        restarted
            .update_issue([9; 32], &created.issue, &fields())
            .is_err()
    );
    assert_eq!(state.borrow().writes, 2);
}

struct Allow;
impl crate::LinearOutboundAuthorization for Allow {
    fn authorize(&mut self, _: [u8; 32], _: &GraphQlCall) -> Result<(), LinearSyncError> {
        Ok(())
    }
}
struct JournalTransport {
    writes: Rc<RefCell<usize>>,
    fail: bool,
}
impl GraphQlExecutor for JournalTransport {
    fn execute(&mut self, _: &GraphQlCall) -> Result<Value, LinearSyncError> {
        *self.writes.borrow_mut() += 1;
        if self.fail {
            return Err(LinearSyncError::Transport("timeout after send".into()));
        }
        Ok(json!({"data":{"issueCreate":{"success":true,
            "issue":issue("created","2026-09-26T00:00:00Z","New title")}}}))
    }
}
#[test]
fn durable_door_replays_success_after_restart_and_never_retries_ambiguous_send() {
    let dir = tempfile::tempdir().expect("journal dir");
    let writes = Rc::new(RefCell::new(0));
    let call = GraphQlCall {
        query: "mutation { ok }",
        variables: json!({"input":"fixed"}),
    };
    let make = |fail| {
        crate::JournaledLinearOutboundDoor::new(
            JournalTransport {
                writes: writes.clone(),
                fail,
            },
            Allow,
            dir.path().to_path_buf(),
        )
        .expect("door")
    };
    let mut first = make(false);
    let response = first.dispatch([1; 32], &call).expect("first");
    drop(first);
    let mut restarted = make(false);
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
                    variables: json!({"input":"changed"})
                }
            )
            .is_err()
    );
    assert_eq!(*writes.borrow(), 1);
    let mut uncertain = make(true);
    assert!(uncertain.dispatch([2; 32], &call).is_err());
    let mut recovered = make(false);
    assert!(recovered.dispatch([2; 32], &call).is_err());
    assert_eq!(*writes.borrow(), 2);
}
