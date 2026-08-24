#[test]
fn known_csam_runbook_exists_and_is_linked_from_ops_index() {
    let index = include_str!("../../../../docs/ops/index.md");
    let runbook = include_str!("../../../../docs/ops/known-csam-hosted-media.md");

    assert!(
        index.contains("[Known-CSAM hosted media response](known-csam-hosted-media.md)"),
        "ops index must link the known-CSAM hosted media runbook"
    );
    assert!(
        runbook.contains("JP-entity-on-US-owned-host nexus"),
        "runbook must carry the U5 counsel-confirm open item"
    );
    assert!(
        runbook.contains("Vultr") && runbook.contains("AUP"),
        "runbook must include the Vultr AUP notice path"
    );
}
