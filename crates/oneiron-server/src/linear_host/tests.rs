use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;

#[test]
fn bridge_authenticates_pull_and_idempotent_push_with_normalized_receipts() {
    // The isolated integration target also compiles the scheduler; keep its
    // entry functions live without starting a global timer or reading env.
    let _ = LinearBridge::configured;
    let _ = spawn;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("address");
    let expected = LinearIssueChange {
        event_id: "event-1".into(),
        issue: LinearIssueRef {
            issue_id: "issue-1".into(),
            team_id: "team-1".into(),
            identifier: "TEAM-1".into(),
        },
        updated_at_ms: 1000,
        fields: MirroredTaskFields {
            title: "work".into(),
            description: None,
            priority: None,
            assignee_ref: None,
            status: "queued".into(),
        },
    };
    let receipt = serde_json::to_vec(&expected).expect("receipt");
    let changes = serde_json::to_vec(&LinearChangePage {
        changes: vec![expected.clone()],
        next_cursor: Some("next".into()),
    })
    .expect("changes");
    let server = std::thread::spawn(move || {
        for (index, response) in [changes, receipt].into_iter().enumerate() {
            let (mut socket, _) = listener.accept().expect("accept");
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("timeout");
            let mut data = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let count = socket.read(&mut buffer).expect("request");
                assert!(count > 0);
                data.extend_from_slice(&buffer[..count]);
                if let Some(end) = data.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&data[..end]).to_lowercase();
                    let content_length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .map(|value| value.parse::<usize>().expect("length"))
                        .unwrap_or(0);
                    if data.len() >= end + 4 + content_length {
                        break;
                    }
                }
            }
            let request = String::from_utf8_lossy(&data).to_lowercase();
            assert!(request.contains("authorization: bearer test-token\r\n"));
            if index == 0 {
                assert!(request.starts_with("get /changes?cursor=old%2fcursor "));
            } else {
                assert!(request.starts_with("post /issues "));
                assert!(request.contains("\"operation_id\":\""));
                assert!(request.contains("\"task_ref\":\""));
            }
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).expect("headers");
            socket.write_all(&response).expect("body");
        }
    });
    let mut bridge = LinearBridge {
        client: Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .expect("client"),
        base: reqwest::Url::parse(&format!("http://{addr}/")).expect("URL"),
        credential: reqwest::header::HeaderValue::from_static("Bearer test-token"),
    };
    let page = bridge.changes_since(Some("old/cursor")).expect("page");
    assert_eq!(page.next_cursor.as_deref(), Some("next"));
    assert_eq!(page.changes, vec![expected.clone()]);
    let created = bridge
        .create_issue([5u8; 32], EntityId::now(), &expected.fields)
        .expect("create");
    assert_eq!(created, expected);
    server.join().expect("requests authenticated");
}

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
    let mut changed = initial.clone();
    changed.description = Some("from Linear".into());
    let page = LinearChangePage {
        changes: vec![LinearIssueChange {
            event_id: "remote-event".into(),
            issue,
            updated_at_ms: 1001,
            fields: changed.clone(),
        }],
        next_cursor: Some("cursor-2".into()),
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("address");
    let server = std::thread::spawn(move || {
        for response in [
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
    };
    let (push, pull) = synchronize_once(&vault, bridge.clone(), bridge, 100).expect("pass");
    assert_eq!(push.len(), 1);
    assert_eq!(push[0].status, LinearMirrorStatus::Linked);
    assert_eq!(pull.applied, 1);
    assert_eq!(pull.new_cursor.as_deref(), Some("cursor-2"));
    assert_eq!(
        VaultLinearTaskStore::new(&vault)
            .task_snapshot(task)
            .expect("after poll")
            .fields,
        changed
    );
    server.join().expect("provider exchange");
}
