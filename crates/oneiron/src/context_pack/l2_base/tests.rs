use std::sync::Arc;

use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::context_pack::{ContextPackBuilder, PackFormat};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::temporal::TimeRange;

fn fixture() -> (tempfile::TempDir, Vault, EntityId) {
    let (dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let subject = crate::test_util::entity(0xE2);
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    (dir, vault, subject)
}

fn claim(vault: &Vault, id: EntityId, subject: EntityId, value: &str) -> Result<()> {
    let body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(value),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    let raw = crate::claim::encode_claim_body(&body)?;
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &raw,
        )
        .text(&id, &[("body", "l2needle")])
        .commit()?;
    vault.put_edge(&id, EdgeKind::ClaimOf, &subject, 1.0)
}

fn assembly(vault: &Vault, subject: EntityId) -> ContextPackBuilder<'_> {
    vault
        .context_pack()
        .l2_summary_subjects(&[subject])
        .search_text("l2needle", 10)
        .with_temporal_now(100)
        .token_budget(0)
        .max_field_chars(0)
}

#[test]
fn unchanged_evidence_reuses_render_and_only_new_query_items_enter_delta() -> Result<()> {
    let (_dir, vault, subject) = fixture();
    let first_id = crate::test_util::entity(0x31);
    let second_id = crate::test_util::entity(0x21);
    claim(&vault, first_id, subject, "first preference")?;
    claim(&vault, second_id, subject, "second preference")?;
    let first = assembly(&vault, subject).run()?;
    let summary = first.l2_base.as_ref().unwrap();
    assert_eq!(summary.evidence_ids(), &[second_id, first_id]);
    assert!(first.results.is_empty());
    assert!(first.empty.is_none());
    let rows: serde_json::Value = serde_json::from_str(&summary.body).unwrap();
    assert_eq!(rows[0]["id"], second_id.to_hex());
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .all(|row| row.get("score").is_none()
                && row.get("conf").is_none()
                && row.get("sal").is_none())
    );

    let second = assembly(&vault, subject).run_with_telemetry()?.value;
    assert!(Arc::ptr_eq(
        &summary.body,
        &second.l2_base.as_ref().unwrap().body
    ));
    let mut deferred = assembly(&vault, subject).run_unfinalized_with_telemetry()?;
    assert!(Arc::ptr_eq(
        &summary.body,
        &deferred.value.l2_base.as_ref().unwrap().body
    ));
    deferred.discard_telemetry();

    for format in [
        PackFormat::Json,
        PackFormat::Yaml,
        PackFormat::Toon,
        PackFormat::Markdown,
        PackFormat::Plaintext,
    ] {
        let a = assembly(&vault, subject).format(format).run_serialized()?;
        let b = assembly(&vault, subject).format(format).run_serialized()?;
        assert_eq!(a, b);
    }
    let before = assembly(&vault, subject).run_serialized()?;
    let fresh = crate::test_util::entity(0x41);
    let raw = rmp_serde::to_vec_named(&serde_json::json!({"txt": "new l2needle event"})).unwrap();
    vault
        .batch()
        .put(
            &fresh,
            ENTITY_TYPE_TURN,
            TimeRange { start: 2, end: 2 },
            2,
            &raw,
        )
        .text(&fresh, &[("body", "l2needle")])
        .commit()?;
    let after = assembly(&vault, subject).run()?;
    assert!(Arc::ptr_eq(
        &summary.body,
        &after.l2_base.as_ref().unwrap().body
    ));
    assert_eq!(
        after.results.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![fresh]
    );
    let after_bytes = assembly(&vault, subject).run_serialized()?;
    let before: serde_json::Value = serde_json::from_slice(&before).unwrap();
    let after: serde_json::Value = serde_json::from_slice(&after_bytes).unwrap();
    assert_eq!(before["l2_base"], after["l2_base"]);
    assert_ne!(before["delta"], after["delta"]);
    Ok(())
}

#[test]
fn evidence_change_rerenders_and_erasure_releases_the_cached_body() -> Result<()> {
    let (_dir, vault, subject) = fixture();
    let id = crate::test_util::entity(0x31);
    claim(&vault, id, subject, "old preference")?;
    let first = assembly(&vault, subject).run()?.l2_base.unwrap();
    claim(&vault, id, subject, "corrected preference")?;
    let second = assembly(&vault, subject).run()?.l2_base.unwrap();
    assert_ne!(first.content_hash, second.content_hash);
    assert!(!Arc::ptr_eq(&first.body, &second.body));
    assert_ne!(first.body, second.body);
    let old_render = Arc::downgrade(&first.body);
    let current_render = Arc::downgrade(&second.body);
    drop(first);
    drop(second);
    assert!(current_render.upgrade().is_some());
    assert!(vault.delete_entity(&id)?);
    assert!(old_render.upgrade().is_none());
    assert!(current_render.upgrade().is_none());
    assert!(assembly(&vault, subject).run()?.l2_base.is_none());
    Ok(())
}

#[test]
fn l2_respects_world_candidate_and_serialized_budgets() -> Result<()> {
    let (_dir, vault, subject) = fixture();
    let id = crate::test_util::entity(0x31);
    claim(&vault, id, subject, "scoped preference")?;
    let deny = |_: &crate::store::Store, _: &heed::RoTxn<'_>, _: &EntityId| Ok(false);
    assert!(
        assembly(&vault, subject)
            .filter_candidates(&deny)
            .run()?
            .l2_base
            .is_none()
    );
    assert!(matches!(
        assembly(&vault, subject)
            .world(crate::pipeline::WorldScope::ActiveSet)
            .run(),
        Err(crate::Error::InvalidConfig(_))
    ));
    let config = crate::serialize::SerializeConfig {
        format: PackFormat::Json,
        profile: crate::context_pack::FieldProfile::Standard,
        budget: 8,
        allocation: Default::default(),
        include_stats: false,
        merge_neighbors: true,
        max_field_chars: 0,
        max_item_tokens: 0,
    };
    let pack = assembly(&vault, subject).run()?;
    let projected = crate::serialize::project_pack_for_json_response(pack, &config);
    assert!(projected.l2_base.is_none());
    let bytes = crate::serialize::serialize_pack(&projected, &config);
    assert!(crate::tokenizer::count_context_pack_tokens(std::str::from_utf8(&bytes).unwrap()) <= 8);
    for format in [
        PackFormat::Json,
        PackFormat::Yaml,
        PackFormat::Toon,
        PackFormat::Markdown,
        PackFormat::Plaintext,
    ] {
        let bytes = assembly(&vault, subject)
            .format(format)
            .token_budget(8)
            .run_serialized()?;
        assert!(
            crate::tokenizer::count_context_pack_tokens(std::str::from_utf8(&bytes).unwrap()) <= 8
        );
    }
    Ok(())
}

#[test]
fn off_record_l2_renders_do_not_populate_the_vault_cache_or_telemetry() -> Result<()> {
    let (_dir, vault, subject) = fixture();
    claim(
        &vault,
        crate::test_util::entity(0x31),
        subject,
        "ephemeral preference",
    )?;
    let session = vault.off_record_session_vault().enter(
        "l2-off-record",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    let route = session.write_route()?;
    let door = session.retrieval_telemetry(&route)?;
    let summary = assembly(&vault, subject)
        .in_session(&door)
        .run()?
        .l2_base
        .unwrap();
    let body = Arc::downgrade(&summary.body);
    drop(summary);
    assert!(body.upgrade().is_none());
    assert!(vault.store.retrieval_runs(10)?.is_empty());
    Ok(())
}

#[test]
fn precommit_erase_snapshot_cannot_repopulate_the_cache() -> Result<()> {
    let (_dir, vault, subject) = fixture();
    let id = crate::test_util::entity(0x31);
    claim(&vault, id, subject, "erase-race preference")?;
    let first = assembly(&vault, subject).run()?.l2_base.unwrap();
    let previous = Arc::downgrade(&first.body);
    drop(first);
    vault.with_write_txn(|txn| {
        crate::batch::deindex_entity(&vault.store, txn, &id)?;
        assert!(previous.upgrade().is_none());
        // A read snapshot opened before this writer commits still sees the
        // old claim. It may render for that reader, but must not cache it.
        let transient =
            super::produce_l2_base(&vault, &vault.query(), &[subject], None, None, true)?.unwrap();
        let render = Arc::downgrade(&transient.body);
        drop(transient);
        assert!(render.upgrade().is_none());
        Ok(())
    })?;
    assert!(assembly(&vault, subject).run()?.l2_base.is_none());
    Ok(())
}

#[test]
fn changed_or_erased_evidence_refuses_an_earlier_prefix() -> Result<()> {
    let (_dir, vault, subject) = fixture();
    let id = crate::test_util::entity(0x31);
    claim(&vault, id, subject, "before")?;
    let old = assembly(&vault, subject).run()?.l2_base.unwrap();
    claim(&vault, id, subject, "after")?;
    let txn = vault.store.env.read_txn()?;
    assert!(!super::revalidate_l2_base(
        &vault,
        &vault.query(),
        &txn,
        &old,
        None,
        None
    )?);
    drop(txn);
    let current = assembly(&vault, subject).run()?.l2_base.unwrap();
    vault.delete_entity(&id)?;
    let txn = vault.store.env.read_txn()?;
    assert!(!super::revalidate_l2_base(
        &vault,
        &vault.query(),
        &txn,
        &current,
        None,
        None
    )?);
    Ok(())
}

#[test]
fn hydration_rechecks_candidate_admission_without_changing_evidence() -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};

    let (_dir, vault, subject) = fixture();
    let id = crate::test_util::entity(0x31);
    claim(&vault, id, subject, "unchanged evidence")?;
    let allowed = AtomicBool::new(true);
    let admits = |_: &crate::store::Store, _: &heed::RoTxn<'_>, _: &EntityId| {
        Ok(allowed.load(Ordering::SeqCst))
    };
    let pipeline = vault.query().filter_candidates(&admits);
    let summary = super::produce_l2_base(&vault, &pipeline, &[subject], None, None, true)?.unwrap();
    let txn = vault.store.env.read_txn()?;
    assert!(super::revalidate_l2_base(
        &vault, &pipeline, &txn, &summary, None, None
    )?);
    drop(txn);
    allowed.store(false, Ordering::SeqCst);
    let txn = vault.store.env.read_txn()?;
    assert!(!super::revalidate_l2_base(
        &vault, &pipeline, &txn, &summary, None, None
    )?);
    Ok(())
}

#[test]
fn unchanged_evidence_expires_at_the_hydration_time() -> Result<()> {
    let (_dir, vault, subject) = fixture();
    let id = crate::test_util::entity(0x31);
    claim(&vault, id, subject, "time-bounded evidence")?;
    let mut body = vault.get_claim(&id)?.unwrap();
    body.valid_to = Some(101);
    vault.put_entity(
        &id,
        ENTITY_TYPE_CLAIM,
        TimeRange { start: 1, end: 1 },
        1,
        &crate::claim::encode_claim_body(&body)?,
    )?;
    let summary = assembly(&vault, subject).run()?.l2_base.unwrap();
    let txn = vault.store.env.read_txn()?;
    assert!(super::revalidate_l2_base(
        &vault,
        &vault.query().with_temporal_now(100),
        &txn,
        &summary,
        None,
        None,
    )?);
    assert!(!super::revalidate_l2_base(
        &vault,
        &vault.query().with_temporal_now(101),
        &txn,
        &summary,
        None,
        None,
    )?);
    Ok(())
}
