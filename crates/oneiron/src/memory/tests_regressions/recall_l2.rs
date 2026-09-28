//! Typed recall retains a ranked owner claim even when L2 also caches it.

use super::*;

#[test]
fn typed_recall_keeps_an_implicit_l2_claim_and_its_count() {
    let (_dir, vault) = open_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner person");
    let facade = facade_for(&vault, owner);
    let id = EntityId::from_bytes([0xC1; 16]).unwrap();
    let now = crate::unix_seconds_now();
    let claim = crate::claim::ClaimBody::new(
        "profile.preference",
        crate::claim::ClaimSubject::Entity(owner),
        rmpv::Value::from("owner-recall-needle typed value"),
        0.9,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    ).unwrap();
    vault
        .put_claim(
            &id,
            &claim,
            crate::TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .expect("claim");
    vault
        .batch()
        .text(&id, &[("body", "owner-recall-needle")])
        .commit()
        .expect("text index");
    let base = vault
        .context_pack()
        .search_text("owner-recall-needle", 10)
        .run()
        .expect("assembled pack");
    assert_eq!(base.l2_base.unwrap().evidence_ids(), &[id]);
    let recalled = facade
        .recall(
            "owner-recall-needle",
            crate::memory::Effort::Light,
            &crate::memory::RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("typed recall");
    assert!(recalled.rendered.is_none());
    let item = recalled
        .items
        .iter()
        .find(|item| item.predicate.as_deref() == Some("profile.preference"))
        .expect("ranked owner claim survives");
    assert!(item.value_text.contains("owner-recall-needle"));
    assert!(item.confidence > 0.0);
    assert!(!item.provenance.source_revision_ids.is_empty());
    assert_eq!(recalled.retrieval_meta.claims_returned, 1);
}
