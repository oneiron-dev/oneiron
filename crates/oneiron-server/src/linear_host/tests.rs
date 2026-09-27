//! Live HTTP fixture at the host transport; no provider token leaves this process.
use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

fn host() -> LinearHttp {
    LinearHttp::new(LinearHostConfig {
        token: "fixture-private-key".into(),
        team_id: "team-id".into(),
        status_names: BTreeMap::from([("queued".into(), "Backlog".into())]),
    })
    .unwrap()
}
fn mock_http(replies: Vec<Value>) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/graphql", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        replies.into_iter().map(|reply| {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 4096];
        let headers_end = loop {
            let n = stream.read(&mut buffer).unwrap();
            assert_ne!(n, 0);
            bytes.extend_from_slice(&buffer[..n]);
            if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                break end + 4;
            }
        };
        let headers = String::from_utf8(bytes[..headers_end].to_vec()).unwrap();
        let length: usize = headers.lines().find_map(|line| {
            line.to_ascii_lowercase().strip_prefix("content-length: ")
                .and_then(|n| n.trim().parse().ok())
        }).unwrap();
        while bytes.len() - headers_end < length {
            let n = stream.read(&mut buffer).unwrap();
            assert_ne!(n, 0);
            bytes.extend_from_slice(&buffer[..n]);
        }
        let body = reply.to_string();
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        format!("{headers}{}", String::from_utf8_lossy(&bytes[headers_end..headers_end + length]))
    }).collect()
    });
    (url, handle)
}
fn issue(title: &str) -> Value {
    json!({"id":"issue-1","identifier":"TEST-1","updatedAt":"2026-09-26T12:00:00.000Z",
        "title":title,"description":null,"priority":2,"team":{"id":"team-id"},
        "assignee":null,"state":{"name":"Backlog"}})
}
#[test]
fn authenticated_page_has_stable_identity_and_carries_cursor() {
    let (url, log) = mock_http(vec![json!({"data":{"issues":{
        "nodes":[issue("Build one")],"pageInfo":{"endCursor":"next-page"}}}})]);
    let mut http = host();
    http.endpoint = Arc::from(url);
    let mut port = LinearPort(http, None);
    let page = port.changes_since(Some("before-page")).unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("next-page"));
    assert_eq!(page.changes[0].fields.status, "queued");
    assert_eq!(page.changes[0].fields.title, "Build one");
    assert!(!page.changes[0].event_id.is_empty());
    let wire = log.join().unwrap().remove(0);
    assert!(
        wire.contains("Authorization: fixture-private-key")
            || wire.contains("authorization: fixture-private-key")
    );
    assert!(wire.contains("before-page"));
    assert!(
        wire.contains("Ascending"),
        "poll cursor must advance oldest-first"
    );
}
#[test]
fn unknown_tracker_state_refuses_page_before_advancing_cursor() {
    let mut unknown = issue("Build one");
    unknown["state"]["name"] = json!("Unknown");
    let (url, log) = mock_http(vec![json!({"data":{"issues":{
        "nodes":[unknown],"pageInfo":{"endCursor":"unsafe-cursor"}}}})]);
    let mut http = host();
    http.endpoint = Arc::from(url);
    assert!(LinearPort(http, None).changes_since(None).is_err());
    log.join().unwrap();
}
#[test]
fn snapshot_identity_distinguishes_equal_timestamp_changes() {
    let first = parse_issue(&issue("old")).unwrap();
    let second = parse_issue(&issue("new")).unwrap();
    assert_eq!(first.updated_at_ms, second.updated_at_ms);
    assert_ne!(first.event_id, second.event_id);
}

#[test]
fn create_uses_stable_issue_id_and_retries_without_a_second_mutation() {
    let operation = [0x11_u8; 32];
    let uuid = "11111111-1111-4111-9111-111111111111";
    let mut created = issue("Build one");
    created["id"] = json!(uuid);
    let (url, calls) = mock_http(vec![
        json!({"data":null,"errors":[{"message":"Entity not found: Issue",
            "path":["issue"],"extensions":{"code":"INPUT_ERROR"}}]}),
        json!({"data":{"team":{"states":{"nodes":[{"id":"state-backlog","name":"Backlog"}]}}}}),
        json!({"data":{"issueCreate":{"success":true,"issue":created}}}),
    ]);
    let mut http = host();
    http.endpoint = Arc::from(url);
    let mut port = LinearPort(http, None);
    let fields = MirroredTaskFields {
        title: "Build one".into(),
        description: None,
        priority: Some(2),
        assignee_ref: None,
        status: "queued".into(),
    };
    let task = EntityId::from_bytes([1; 16]).unwrap();
    let linked = port.create_issue(operation, task, &fields).unwrap();
    assert_eq!(linked.issue.issue_id, uuid);
    assert_eq!(linked.fields, fields);
    let calls = calls.join().unwrap();
    assert_eq!(calls.len(), 3);
    assert!(calls[2].contains(uuid));
    assert!(calls[2].contains("state-backlog"));

    let mut existing = issue("Build one");
    existing["id"] = json!(uuid);
    let (url, calls) = mock_http(vec![json!({"data":{"issue":existing}})]);
    port.0.endpoint = Arc::from(url);
    assert_eq!(port.create_issue(operation, task, &fields).unwrap(), linked);
    assert_eq!(calls.join().unwrap().len(), 1);
}

#[test]
fn tracker_change_blocks_update_and_lost_response_retry_is_read_only() {
    use oneiron::TimeRange;
    use oneiron::edge::EdgeActorClass;
    use oneiron::linear_sync::{LinearSyncDirection, TaskIssueLink};
    use oneiron::task_verb::TaskCreateSpec;
    use std::collections::BTreeSet;
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let owner = EntityId::now();
    vault
        .put_entity(
            &owner,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )
        .unwrap();
    let task = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::from("work"),
            Some("base".into()),
            None,
            Some(100),
        ))
        .unwrap()
        .task_ref
        .unwrap();
    let mut store = VaultLinearTaskStore::new(&vault);
    let snapshot = store.task_snapshot(task).unwrap();
    let base = snapshot.fields;
    let issue_ref = LinearIssueRef {
        issue_id: "issue-1".into(),
        team_id: "team-id".into(),
        identifier: "TEST-1".into(),
    };
    store
        .put_link(
            None,
            &TaskIssueLink {
                task_ref: task,
                issue: issue_ref.clone(),
                task_revision: snapshot.revision,
                issue_updated_at_ms: 1_790_424_000_000,
                seen_event_digests: BTreeSet::new(),
                last_operation_id: [0; 32],
                last_direction: LinearSyncDirection::TaskToIssue,
                base_field_hashes: base.field_hashes(),
                unresolved_conflicts: vec![],
                link_revision: 0,
                updated_at: 100,
            },
        )
        .unwrap();
    let mut desired = base;
    desired.title = "local-changed".into();
    let mut remote = issue("remote-changed");
    remote["priority"] = Value::Null;
    let (url, calls) = mock_http(vec![json!({"data":{"issue":remote}})]);
    let mut http = host();
    http.endpoint = Arc::from(url);
    let mut port = LinearPort(http, Some(Arc::clone(&vault)));
    assert!(port.update_issue([1; 32], &issue_ref, &desired).is_err());
    assert_eq!(
        calls.join().unwrap().len(),
        1,
        "remote change forbids mutation"
    );
    let mut already_applied = issue("local-changed");
    already_applied["priority"] = Value::Null;
    let (url, calls) = mock_http(vec![json!({"data":{"issue":already_applied}})]);
    port.0.endpoint = Arc::from(url);
    assert_eq!(
        port.update_issue([1; 32], &issue_ref, &desired)
            .unwrap()
            .fields,
        desired
    );
    assert_eq!(
        calls.join().unwrap().len(),
        1,
        "retry must not mutate again"
    );
}

#[test]
fn other_graphql_errors_do_not_masquerade_as_a_missing_issue() {
    let (url, calls) = mock_http(vec![json!({"data":null,"errors":[{
        "message":"Entity not found: Issue", "path":["issue"],
        "extensions":{"code":"UNAUTHENTICATED"}}]})]);
    let mut http = host();
    http.endpoint = Arc::from(url);
    assert!(http.issue("issue-id").is_err());
    assert_eq!(calls.join().unwrap().len(), 1);
}
