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
        assignee_ids: BTreeMap::new(),
        scheduler_actor: EntityId::from_bytes([3; 16]).unwrap(),
        endpoint: None,
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
fn unprioritized_provider_issue_matches_an_unset_local_priority() {
    let mut provider = issue("Build one");
    provider["priority"] = json!(0);
    assert_eq!(parse_issue(&provider).unwrap().fields.priority, None);
}

#[test]
fn authenticated_page_has_stable_identity_and_carries_cursor() {
    let (url, log) = mock_http(vec![json!({"data":{"issues":{
        "nodes":[issue("Build one")],"pageInfo":{"endCursor":"next-page","hasNextPage":false}}}})]);
    let mut http = host();
    http.endpoint = Arc::from(url);
    let mut port = LinearPort::unchecked_for_test(http, None);
    let page = port.changes_since(Some("before-page")).unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("next-page"));
    assert!(!page.has_more, "final nonempty page is already caught up");
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
        "nodes":[unknown],"pageInfo":{"endCursor":"unsafe-cursor","hasNextPage":false}}}})]);
    let mut http = host();
    http.endpoint = Arc::from(url);
    assert!(
        LinearPort::unchecked_for_test(http, None)
            .changes_since(None)
            .is_err()
    );
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
    let task = EntityId::from_bytes([1; 16]).unwrap();
    let uuid = stable_issue_uuid(task, "team-id");
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
    let mut port = LinearPort::unchecked_for_test(http, None);
    let fields = MirroredTaskFields {
        title: "Build one".into(),
        description: None,
        priority: Some(2),
        assignee_ref: None,
        status: "queued".into(),
    };
    let linked = port.create_issue(operation, task, &fields).unwrap();
    assert_eq!(linked.issue.issue_id, uuid);
    assert_eq!(linked.fields, fields);
    let calls = calls.join().unwrap();
    assert_eq!(calls.len(), 3);
    assert!(calls[2].contains(&uuid));
    assert!(calls[2].contains("state-backlog"));

    let mut existing = issue("Build one");
    existing["id"] = json!(uuid);
    let (url, calls) = mock_http(vec![json!({"data":{"issue":existing}})]);
    port.http.endpoint = Arc::from(url);
    assert_eq!(port.create_issue(operation, task, &fields).unwrap(), linked);
    assert_eq!(calls.join().unwrap().len(), 1);

    // The TASK can move between a lost response and retry. The remote UUID
    // remains the original one and a mismatched payload never becomes a link.
    let mut edited = fields.clone();
    edited.title = "new local revision".into();
    let mut previous_remote = issue("Build one");
    previous_remote["id"] = json!(uuid);
    let (url, calls) = mock_http(vec![json!({"data":{"issue":previous_remote}})]);
    port.http.endpoint = Arc::from(url);
    assert!(matches!(
        port.create_issue([0x22; 32], task, &edited),
        Err(LinearSyncError::CreateConflict)
    ));
    let requests = calls.join().unwrap();
    assert_eq!(requests.len(), 1, "must not create a second issue");
    assert!(requests[0].contains(&uuid));
    let mut foreign = issue("foreign tracker edit");
    foreign["id"] = json!(uuid);
    let (url, calls) = mock_http(vec![json!({"data":{"issue":foreign}})]);
    port.http.endpoint = Arc::from(url);
    assert!(matches!(
        port.create_issue(operation, task, &fields),
        Err(LinearSyncError::CreateConflict)
    ));
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
    let mut port = LinearPort::unchecked_for_test(http, Some(Arc::clone(&vault)));
    assert!(port.update_issue([1; 32], &issue_ref, &desired).is_err());
    assert_eq!(
        calls.join().unwrap().len(),
        1,
        "remote change forbids mutation"
    );
    let mut already_applied = issue("local-changed");
    already_applied["priority"] = Value::Null;
    let (url, calls) = mock_http(vec![json!({"data":{"issue":already_applied}})]);
    port.http.endpoint = Arc::from(url);
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

#[tokio::test(flavor = "current_thread")]
async fn enabled_worker_initializes_off_runtime_and_polls_local_transport() {
    let (url, calls) = mock_http(vec![json!({"data":{"issues":{
        "nodes":[], "pageInfo":{"endCursor":null,"hasNextPage":false}}}})]);
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let config = LinearHostConfig {
        token: "fixture-private-key".into(),
        team_id: "team-id".into(),
        status_names: BTreeMap::from([("queued".into(), "Backlog".into())]),
        assignee_ids: BTreeMap::new(),
        scheduler_actor: EntityId::from_bytes([3; 16]).unwrap(),
        endpoint: Some(url),
    };
    // A valid opt-in must not panic while constructing reqwest's blocking
    // client from an async server path, and the first scheduled tick must run.
    let handle = spawn_linear_sync(Arc::clone(&vault), config).await.unwrap();
    let requests = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || calls.join().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].contains("Authorization: fixture-private-key")
            || requests[0].contains("authorization: fixture-private-key")
    );
    handle.abort();
    let _ = handle.await;
}

#[test]
fn assigned_task_maps_both_identity_namespaces_and_refuses_unknown_ids() {
    let actor = EntityId::from_bytes([8; 16]).unwrap().to_hex();
    let user = "12345678-1234-4234-8234-123456789abc";
    let (url, calls) = mock_http(vec![json!({"data":{"team":{
        "states":{"nodes":[{"id":"state-backlog","name":"Backlog"}]}}}})]);
    let mut http = host();
    http.endpoint = Arc::from(url);
    http.assignee_ids = Arc::new(BTreeMap::from([(actor.clone(), user.into())]));
    let fields = MirroredTaskFields {
        title: "assigned".into(),
        description: None,
        priority: Some(2),
        assignee_ref: Some(actor.clone()),
        status: "queued".into(),
    };
    let input = http.fields_input(&fields).unwrap();
    assert_eq!(input["assigneeId"], user);
    assert_ne!(input["assigneeId"], actor);
    assert_eq!(calls.join().unwrap().len(), 1);
    let mut inbound = issue("assigned");
    inbound["assignee"] = json!({"id":user});
    assert_eq!(
        http.parse_issue(&inbound).unwrap().fields.assignee_ref,
        Some(actor.clone())
    );
    inbound["assignee"] = json!({"id":"99999999-9999-4999-8999-999999999999"});
    assert!(matches!(
        http.parse_issue(&inbound),
        Err(LinearSyncError::AssigneeUnmapped)
    ));
    let mut unmapped = fields;
    unmapped.assignee_ref = Some(EntityId::from_bytes([9; 16]).unwrap().to_hex());
    assert!(matches!(
        LinearPort::unchecked_for_test(http, None).create_issue(
            [1; 32],
            EntityId::from_bytes([2; 16]).unwrap(),
            &unmapped
        ),
        Err(LinearSyncError::AssigneeUnmapped)
    ));
}

#[test]
fn enabled_linear_host_refuses_unauthenticated_core_writers() {
    assert!(validate_server_auth(true, None, true).is_err());
    assert!(validate_server_auth(true, Some("server-secret"), true).is_err());
    assert!(validate_server_auth(true, None, false).is_err());
    assert!(validate_server_auth(true, Some("server-secret"), false).is_ok());
    assert!(validate_server_auth(false, None, true).is_ok());
}

#[test]
fn missing_effect_grants_refuse_before_any_linear_http_request() {
    use oneiron::TimeRange;
    use oneiron::edge::EdgeActorClass;
    use oneiron::linear_sync::{LinearCreateIntent, LinearSyncDirection, linear_operation_id};
    use oneiron::task_verb::TaskCreateSpec;
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let writer = EntityId::now();
    let scheduler = EntityId::now();
    vault
        .put_entity(
            &writer,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"writer",
        )
        .unwrap();
    vault
        .put_entity(
            &scheduler,
            oneiron::registry::ENTITY_TYPE_MACHINE,
            TimeRange { start: 1, end: 1 },
            1,
            b"host",
        )
        .unwrap();
    let task = vault
        .memory(writer, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::from("work"),
            Some("mirror".into()),
            None,
            Some(100),
        ))
        .unwrap()
        .task_ref
        .unwrap();
    let mut store = VaultLinearTaskStore::new(&vault);
    let snapshot = store.task_snapshot(task).unwrap();
    let op = linear_operation_id(
        LinearSyncDirection::TaskToIssue,
        task,
        snapshot.revision,
        None,
        None,
        None,
    );
    store
        .create_intent(&LinearCreateIntent {
            task_ref: task,
            task_revision: snapshot.revision,
            operation_id: op,
            fields: snapshot.fields.clone(),
            writer: None,
        })
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut http = host();
    http.scheduler_actor = scheduler;
    http.endpoint = Arc::from(format!("http://{}/graphql", listener.local_addr().unwrap()));
    let mut port = LinearPort::new(http, Some(Arc::clone(&vault)));
    assert!(matches!(
        port.create_issue(op, task, &snapshot.fields),
        Err(LinearSyncError::AuthorizationDenied)
    ));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
