use super::*;

#[test]
fn response_preserves_true_pause_marker_and_elides_false() {
    let node = |paused| oneiron::RunTreeNode {
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
        events: Vec::new(),
        children: Vec::new(),
        gate_breaker_paused: paused,
    };
    for paused in [false, true] {
        let mut root = node(paused);
        root.children.push(node(false));
        let response = core_run_tree_response(oneiron::RunTree {
            roots: vec![root],
            repairs: Vec::new(),
        });
        let wire = serde_json::to_value(response).expect("serialize response");
        assert_eq!(wire["roots"][0]["status"], "queued");
        if paused {
            assert_eq!(wire["roots"][0]["gate_breaker_paused"], true);
        } else {
            assert!(wire["roots"][0].get("gate_breaker_paused").is_none());
        }
        assert!(
            wire["roots"][0]["children"][0]
                .get("gate_breaker_paused")
                .is_none()
        );
    }
}
