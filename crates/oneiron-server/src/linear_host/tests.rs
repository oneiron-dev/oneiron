use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;

#[test]
fn scheduled_pass_pushes_dirty_task_then_applies_inbound_page() {
    use oneiron::task_verb::{TaskAssignee, TaskCreateSpec};
    use oneiron::{
        EdgeActorClass, LinearMirrorStatus, LinearTaskStore, TimeRange, Vault, VaultConfig,
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let owner = EntityId::now();
    vault
        .put_entity(
            &owner,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )
        .expect("actor");
    let task = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(
            &TaskCreateSpec::new(
                rmpv::Value::from("work"),
                Some("work".into()),
                None,
                Some(100),
            )
            .with_assignee(TaskAssignee::Peer { actor_ref: owner }),
        )
        .expect("task")
        .task_ref
        .expect("task id");
    let initial = VaultLinearTaskStore::new(&vault)
        .task_snapshot(task)
        .expect("snapshot")
        .fields;
    let issue = LinearIssueRef {
        issue_id: "issue-2".into(),
        team_id: "team".into(),
        identifier: "TEAM-2".into(),
    };
    let created = LinearIssueChange {
        event_id: "create-event".into(),
        issue: issue.clone(),
        updated_at_ms: 1000,
        fields: initial.clone(),
    };
    let mut changed = initial;
    changed.description = Some("from Linear".into());
    let page = LinearChangePage {
        changes: vec![LinearIssueChange {
            event_id: "remote-event".into(),
            issue,
            updated_at_ms: 1001,
            fields: changed.clone(),
        }],
        next_cursor: None,
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("address");
    let server = std::thread::spawn(move || {
        for response in [
            serde_json::to_vec(&LinearChangePage {
                changes: vec![],
                next_cursor: None,
            })
            .unwrap(),
            serde_json::to_vec(&created).unwrap(),
            serde_json::to_vec(&page).unwrap(),
        ] {
            let (mut socket, _) = listener.accept().expect("accept");
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("timeout");
            let mut buffer = [0u8; 4096];
            let count = socket.read(&mut buffer).expect("request");
            assert!(count > 0);
            assert!(
                String::from_utf8_lossy(&buffer[..count])
                    .to_lowercase()
                    .contains("authorization: bearer test-token")
            );
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).expect("headers");
            socket.write_all(&response).expect("body");
        }
    });
    let bridge = LinearBridge {
        client: Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .expect("client"),
        base: reqwest::Url::parse(&format!("http://{addr}/")).expect("URL"),
        credential: reqwest::header::HeaderValue::from_static("Bearer test-token"),
        request_timeout: Duration::from_secs(3),
    };
    let (push, initial_pull) =
        synchronize_once(&vault, bridge.clone(), bridge.clone(), 100, 64).expect("link pass");
    assert_eq!(push.len(), 1);
    assert_eq!(push[0].status, LinearMirrorStatus::Linked);
    assert_eq!(initial_pull.applied, 0);
    let (_push, pulled) =
        synchronize_once(&vault, bridge.clone(), bridge, 101, 64).expect("pull pass");
    assert_eq!(pulled.applied, 1);
    assert_eq!(
        VaultLinearTaskStore::new(&vault)
            .task_snapshot(task)
            .expect("after poll")
            .fields,
        changed
    );
    server.join().expect("provider exchange");
}

#[test]
fn linked_update_sends_expected_base_and_refuses_remote_precondition_miss() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let fields = MirroredTaskFields {
        title: "task".into(),
        description: None,
        priority: None,
        assignee_ref: None,
        status: "queued".into(),
    };
    let expected = fields.field_hashes();
    let title_hash = hex_operation_id(expected["title"]);
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept");
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let size = socket.read(&mut buf).expect("read");
            assert!(size > 0);
            raw.extend_from_slice(&buf[..size]);
            if let Some(end) = raw.windows(4).position(|chunk| chunk == b"\r\n\r\n") {
                let header = String::from_utf8_lossy(&raw[..end]).to_lowercase();
                let len: usize = header
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .expect("body length")
                    .parse()
                    .expect("valid length");
                if raw.len() >= end + 4 + len {
                    break;
                }
            }
        }
        let request = String::from_utf8_lossy(&raw);
        assert!(request.starts_with("POST /issues/update "));
        assert!(request.contains("Bearer test-token"));
        assert!(request.contains("expected_base_field_hashes"));
        assert!(request.contains(&title_hash));
        socket.write_all(b"HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .expect("reject without a remote write");
    });
    let mut bridge = LinearBridge {
        client: Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .expect("client"),
        base: reqwest::Url::parse(&format!("http://{addr}/")).expect("url"),
        credential: reqwest::header::HeaderValue::from_static("Bearer test-token"),
        request_timeout: Duration::from_secs(3),
    };
    let issue = LinearIssueRef {
        issue_id: "opaque".into(),
        team_id: "team".into(),
        identifier: "TEAM-1".into(),
    };
    assert!(matches!(
        bridge.update_issue_conditional([1u8; 32], &issue, &expected, &fields),
        Err(LinearSyncError::RemoteChanged)
    ));
    server.join().expect("provider checked precondition");
}

#[test]
fn enabled_linear_host_refuses_unauthenticated_core_writers() {
    assert!(validate_server_auth(true, None, true).is_err());
    assert!(validate_server_auth(true, Some("server-secret"), true).is_err());
    assert!(validate_server_auth(true, None, false).is_err());
    assert!(validate_server_auth(true, Some(""), false).is_err());
    assert!(validate_server_auth(true, Some("server-secret"), false).is_ok());
    assert!(validate_server_auth(false, None, true).is_ok());
    assert!(scheduler_actor(None).is_err());
    assert!(scheduler_actor(Some("not-an-id".into())).is_err());
    let actor = EntityId::now();
    assert_eq!(scheduler_actor(Some(actor.to_hex())).unwrap(), actor);
}

#[test]
fn missing_effect_grants_refuse_before_any_linear_http_request() {
    use oneiron::linear_sync::{LinearSyncDirection, linear_operation_id};
    use oneiron::task_verb::TaskCreateSpec;
    use oneiron::{EdgeActorClass, TimeRange, Vault, VaultConfig};
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).unwrap());
    let writer = EntityId::now();
    let scheduler = EntityId::now();
    for (id, kind) in [
        (writer, oneiron::registry::ENTITY_TYPE_PERSON),
        (scheduler, oneiron::registry::ENTITY_TYPE_MACHINE),
    ] {
        vault
            .put_entity(&id, kind, TimeRange { start: 1, end: 1 }, 1, b"actor")
            .unwrap();
    }
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
    let snapshot = VaultLinearTaskStore::new(&vault)
        .task_snapshot(task)
        .unwrap();
    let op = linear_operation_id(
        LinearSyncDirection::TaskToIssue,
        task,
        snapshot.revision,
        None,
        None,
        None,
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut egress = GatedEgress {
        bridge: LinearBridge {
            client: Client::builder().build().unwrap(),
            base: reqwest::Url::parse(&format!("http://{}/", listener.local_addr().unwrap()))
                .unwrap(),
            credential: reqwest::header::HeaderValue::from_static("Bearer test-token"),
            request_timeout: Duration::from_secs(3),
        },
        vault: Arc::clone(&vault),
        scheduler_actor: scheduler,
    };
    assert!(matches!(
        egress.create_issue(op, task, &snapshot.fields),
        Err(LinearSyncError::AuthorizationDenied)
    ));
    // An update for an issue the vault never linked has no TASK authority.
    let issue = LinearIssueRef {
        issue_id: "issue-9".into(),
        team_id: "team".into(),
        identifier: "TEAM-9".into(),
    };
    assert!(matches!(
        egress.update_issue_conditional(op, &issue, &BTreeMap::new(), &snapshot.fields),
        Err(LinearSyncError::AuthorizationDenied)
    ));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
