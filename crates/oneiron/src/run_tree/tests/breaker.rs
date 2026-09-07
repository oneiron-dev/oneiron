use super::*;

#[test]
fn run_tree_breaker_marker_is_root_only_and_additive() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    // Two roots and one child, so "first root" is a real choice rather than
    // the only node in the tree.
    let first_root = enqueue(&runner, "orchestrator", None, 10, "run-breaker-marker")?;
    let _child = enqueue(
        &runner,
        "left-subagent",
        Some(first_root.attempt.id),
        20,
        "run-breaker-marker",
    )?;
    let _second_root = enqueue(
        &runner,
        "second-orchestrator",
        None,
        30,
        "run-breaker-marker",
    )?;
    dispatch_agent(
        &vault,
        "oneiron.agent.breaker",
        0x35,
        "run-breaker-marker",
        None,
    )?;

    let adapter = RunTreeAdapter::new(&vault);
    let mut tree = adapter.read_run("run-breaker-marker")?;
    assert!(tree.roots.len() > 1);
    assert!(
        tree.roots.iter().all(|root| !root.gate_breaker_paused),
        "a run without a breaker trip starts unmarked"
    );

    // False elides the field entirely under serde defaulting, so a tree
    // serialized before ONE-1453 and one serialized after are wire-identical.
    let unmarked = serde_json::to_string(&tree).expect("serialize unmarked tree");
    assert!(!unmarked.contains("gate_breaker_paused"));
    let round_tripped: crate::run_tree::RunTree =
        serde_json::from_str(&unmarked).expect("deserialize unmarked tree");
    assert_eq!(round_tripped, tree);

    // Public/deserialized input may already mark children at any depth.
    let mut grandchild = tree.roots[0].children[0].clone();
    grandchild.gate_breaker_paused = true;
    tree.roots[0].children[0].children.push(grandchild);
    tree.roots[0].children[0].gate_breaker_paused = true;
    let wire = serde_json::to_string(&tree).expect("serialize premarked descendants");
    tree = serde_json::from_str(&wire).expect("deserialize premarked descendants");
    tree.set_gate_breaker_paused_marker(true);
    assert!(!tree.roots[0].children[0].children[0].gate_breaker_paused);
    tree.roots[0].children[0].children.clear();
    assert!(tree.roots[0].gate_breaker_paused);
    assert!(
        tree.roots[1..].iter().all(|root| !root.gate_breaker_paused),
        "only the deterministic first root carries the marker"
    );
    assert!(
        tree.roots
            .iter()
            .flat_map(|root| root.children.iter())
            .all(|child| !child.gate_breaker_paused),
        "no non-root node is ever marked"
    );
    let marked = serde_json::to_string(&tree).expect("serialize marked tree");
    assert_eq!(marked.matches("\"gate_breaker_paused\":true").count(), 1);

    // The marker is presentation only: statuses, events and the consent-bundle
    // naming ONE-1452 landed are untouched.
    let unmarked_tree = adapter.read_run("run-breaker-marker")?;
    assert_eq!(
        tree.roots
            .iter()
            .map(|root| root.status)
            .collect::<Vec<_>>(),
        unmarked_tree
            .roots
            .iter()
            .map(|root| root.status)
            .collect::<Vec<_>>()
    );
    let bundle_id = [0x07; 32];
    let (name, agent_label) = adapter.consent_bundle_label("run-breaker-marker", &bundle_id)?;
    assert_eq!(agent_label.as_deref(), Some("oneiron.agent.breaker"));
    assert_eq!(name, "oneiron.agent.breaker · 07070707");

    // Clearing the marker returns the tree to its unmarked wire shape.
    tree.roots[0].children[0].gate_breaker_paused = true;
    tree.roots[1].gate_breaker_paused = true;
    tree.set_gate_breaker_paused_marker(false);
    assert!(!tree.roots[0].children[0].gate_breaker_paused);
    assert!(tree.roots.iter().all(|root| !root.gate_breaker_paused));
    assert_eq!(
        serde_json::to_string(&tree).expect("serialize cleared tree"),
        unmarked
    );
    Ok(())
}
