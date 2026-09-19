use super::*;

#[test]
fn response_has_no_write_velocity_pause_marker() {
    let node = || oneiron::RunTreeNode {
        attempt_id: "root".to_owned(),
        run_id: Some("run".to_owned()),
        parent_id: None,
        worker_kind: "worker".to_owned(),
        agent_id: None,
        status: oneiron::RunTreeStatus::Queued,
        timestamps: oneiron::run_tree::RunTreeTimestamps {
            created_at: 1,
            updated_at: 1,
        },
        failure: None,
        result_ref: None,
        events: Vec::new(),
        children: Vec::new(),
    };
    let mut root = node();
    root.children.push(node());
    let response = core_run_tree_response(oneiron::RunTree {
        roots: vec![root],
        repairs: Vec::new(),
    });
    let wire = serde_json::to_value(response).expect("serialize response");
    assert_eq!(wire["roots"][0]["status"], "queued");
    assert!(wire["roots"][0].get("gate_breaker_paused").is_none());
    assert!(
        wire["roots"][0]["children"][0]
            .get("gate_breaker_paused")
            .is_none()
    );
}
