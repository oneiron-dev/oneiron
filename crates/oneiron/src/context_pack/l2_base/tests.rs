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
    claim_with_text(vault, id, subject, value, "l2needle")
}

fn claim_with_text(
    vault: &Vault,
    id: EntityId,
    subject: EntityId,
    value: &str,
    text: &str,
) -> Result<()> {
    let body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(value),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
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
        .text(&id, &[("body", text)])
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
    assert!(first.results.iter().any(|row| row.id == first_id));
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
    assert!(after.results.iter().any(|row| row.id == fresh));
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
    assert!(
        vault.delete_entity_with_options(
            &id,
            crate::deletion::DeleteEntityOptions { purge: true }
        )?
    );
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
    vault.delete_entity_with_options(&id, crate::deletion::DeleteEntityOptions { purge: true })?;
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

#[test]
fn implicit_owner_subject_reuses_prefix_and_keeps_fresh_hits_in_delta() -> Result<()> {
    let (_dir, vault, _) = fixture();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let id = crate::test_util::entity(0x51);
    claim(&vault, id, owner, "owner preference")?;
    let assemble = || {
        vault
            .context_pack()
            .search_text("l2needle", 10)
            .with_temporal_now(100)
            .token_budget(0)
            .max_field_chars(0)
    };
    let first = assemble().run()?;
    let prefix = first.l2_base.as_ref().expect("implicit owner prefix");
    assert_eq!(prefix.evidence_ids(), &[id]);
    let again = assemble().run()?;
    assert!(Arc::ptr_eq(&prefix.body, &again.l2_base.unwrap().body));
    let before_bytes = assemble().run_serialized()?;
    assert_eq!(before_bytes, assemble().run_serialized()?);
    let before: serde_json::Value = serde_json::from_slice(&before_bytes).unwrap();
    let fresh = crate::test_util::entity(0x52);
    let fresh_body = rmp_serde::to_vec_named(&serde_json::json!({"txt": "new item"})).unwrap();
    vault
        .batch()
        .put(
            &fresh,
            ENTITY_TYPE_TURN,
            TimeRange { start: 2, end: 2 },
            2,
            &fresh_body,
        )
        .text(&fresh, &[("body", "l2needle")])
        .commit()?;
    let after = assemble().run()?;
    assert!(Arc::ptr_eq(&prefix.body, &after.l2_base.unwrap().body));
    assert!(after.results.iter().any(|row| row.id == fresh));
    let later: serde_json::Value = serde_json::from_slice(&assemble().run_serialized()?).unwrap();
    assert_eq!(before["l2_base"], later["l2_base"]);
    assert_ne!(before["delta"], later["delta"]);
    claim(&vault, id, owner, "changed preference")?;
    let changed = assemble().run()?.l2_base.unwrap();
    assert_ne!(prefix.content_hash, changed.content_hash);
    assert!(!Arc::ptr_eq(&prefix.body, &changed.body));
    Ok(())
}

#[test]
fn implicit_person_subjects_do_not_treat_unrelated_person_as_persona() -> Result<()> {
    use crate::claim::ScopedReadActorKey;
    let (_dir, vault, unrelated) = fixture();
    let person = crate::test_util::entity(0x64);
    let persona = crate::test_util::entity(0x65);
    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    // Persona identity now lives on PERSON. A second PERSON is not an
    // implicit companion just because it has a persona-flavoured claim.
    vault.put_entity(
        &persona,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"persona",
    )?;
    let user_claim = crate::test_util::entity(0x67);
    let persona_claim = crate::test_util::entity(0x68);
    let unrelated_claim = crate::test_util::entity(0x69);
    claim(&vault, user_claim, person, "user")?;
    claim(&vault, persona_claim, persona, "persona")?;
    claim(&vault, unrelated_claim, unrelated, "other user")?;
    crate::test_util::authorize_readers(&vault, &[&person.to_hex(), &unrelated.to_hex(), "reader"]);
    let reader = vault.scoped_read(ScopedReadActorKey::new(person.to_hex()).unwrap());
    let pack = vault
        .context_pack()
        .l2_summary_reader(&reader)
        .search_text("l2needle", 10)
        .with_temporal_now(100)
        .token_budget(0)
        .max_field_chars(0)
        .run()?;
    let prefix = pack.l2_base.expect("implicit personal prefix");
    assert_eq!(prefix.evidence_ids(), &[user_claim]);
    assert!(!prefix.evidence_ids().contains(&persona_claim));
    assert!(!prefix.evidence_ids().contains(&unrelated_claim));
    let delegated = vault.scoped_read(
        ScopedReadActorKey::new("reader")
            .unwrap()
            .require_access_grants(Some(person)),
    );
    let pack = vault
        .context_pack()
        .l2_summary_reader(&delegated)
        .search_text("l2needle", 10)
        .with_temporal_now(100)
        .run()?;
    assert_eq!(pack.l2_base.unwrap().evidence_ids(), &[user_claim]);
    let unbound = vault.scoped_read(
        ScopedReadActorKey::new("reader")
            .unwrap()
            .require_access_grants(None),
    );
    assert!(
        vault
            .context_pack()
            .l2_summary_reader(&unbound)
            .run()?
            .l2_base
            .is_none()
    );
    let other = vault.scoped_read(ScopedReadActorKey::new(unrelated.to_hex()).unwrap());
    let pack = vault
        .context_pack()
        .l2_summary_reader(&other)
        .search_text("l2needle", 10)
        .with_temporal_now(100)
        .token_budget(0)
        .max_field_chars(0)
        .run()?;
    assert_eq!(pack.l2_base.unwrap().evidence_ids(), &[unrelated_claim]);
    Ok(())
}

#[test]
fn implicit_prefix_limits_do_not_fail_an_otherwise_valid_pack() -> Result<()> {
    let (_dir, vault, _) = fixture();
    let first_persona = crate::test_util::entity(0x80);
    // Nine unrelated PERSON identities never become implicit L2 subjects.
    // Explicit subject selection retains its separate bounded contract.
    for n in 0..9_u8 {
        let person = crate::test_util::entity(0x80 + n);
        vault.put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
    }
    claim(&vault, crate::test_util::entity(0xA0), first_persona, "one")?;
    assert!(vault.context_pack().run()?.l2_base.is_none());
    assert!(
        vault
            .context_pack()
            .l2_summary_subjects(&[first_persona])
            .run()?
            .l2_base
            .is_some()
    );

    let (_dir, vault, _) = fixture();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    for n in 0..257_u16 {
        let mut bytes = [0x70; 16];
        bytes[14] = (n >> 8) as u8;
        bytes[15] = n as u8;
        claim(
            &vault,
            EntityId::from_bytes(bytes)?,
            owner,
            "bounded evidence",
        )?;
    }
    assert!(vault.context_pack().run()?.l2_base.is_none());
    assert!(matches!(
        vault.context_pack().l2_summary_subjects(&[owner]).run(),
        Err(crate::Error::IndexOverflow(_))
    ));
    Ok(())
}

#[test]
fn unscoped_owner_does_not_infer_an_unrelated_persona() -> Result<()> {
    let (_dir, vault, _stranger) = fixture();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let owner_persona = crate::test_util::entity(0xB0);
    let stranger_persona = crate::test_util::entity(0xB1);
    // A PERSON may hold persona identity, but the owner prefix cannot infer
    // that another PERSON belongs to this reader without a typed binding.
    for persona in [owner_persona, stranger_persona] {
        vault.put_entity(
            &persona,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"persona",
        )?;
    }
    let owner_claim = crate::test_util::entity(0xB4);
    let stranger_claim = crate::test_util::entity(0xB5);
    claim(&vault, owner_claim, owner, "owner truth")?;
    claim(&vault, stranger_claim, stranger_persona, "stranger persona")?;
    let base = vault.context_pack().run()?.l2_base.expect("owner persona");
    assert_eq!(base.evidence_ids(), &[owner_claim]);
    assert!(!base.evidence_ids().contains(&stranger_claim));
    Ok(())
}

#[test]
fn implicit_base_field_cap_restores_the_ranked_claim_in_serialized_output() -> Result<()> {
    let (_dir, vault, _) = fixture();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let id = crate::test_util::entity(0xC1);
    claim(&vault, id, owner, &format!("visible{}", "x".repeat(501)))?;
    let builder = || vault.context_pack().search_text("l2needle", 10);
    let pack = builder().run()?;
    assert!(pack.l2_base.is_some());
    assert!(pack.results.iter().any(|row| row.id == id));
    let projected = crate::serialize::project_pack_for_json_response(
        pack,
        &crate::serialize::SerializeConfig {
            format: PackFormat::Json,
            profile: crate::context_pack::FieldProfile::Standard,
            budget: 4000,
            allocation: Default::default(),
            include_stats: false,
            merge_neighbors: true,
            max_field_chars: crate::context_pack::DEFAULT_MAX_FIELD_CHARS,
            max_item_tokens: 0,
        },
    );
    assert!(projected.l2_base.is_none());
    assert!(projected.results.iter().any(|row| row.id == id));
    let bytes = builder().run_serialized()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(value.get("l2_base").is_none());
    assert!(String::from_utf8_lossy(&bytes).contains("visible"));
    Ok(())
}

#[test]
fn implicit_base_shed_by_token_budget_restores_a_fitting_ranked_claim() -> Result<()> {
    let (_dir, vault, _) = fixture();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let bulky = crate::test_util::entity(0xC2);
    let matched = crate::test_util::entity(0xC3);
    let large: String = (0..1200).map(|i| format!("{i:04x}")).collect();
    claim_with_text(&vault, bulky, owner, &large, "other evidence")?;
    claim(&vault, matched, owner, "budget-visible")?;
    let pack = vault.context_pack().search_text("l2needle", 10).run()?;
    assert_eq!(
        pack.l2_base.as_ref().unwrap().evidence_ids(),
        &[bulky, matched]
    );
    assert!(pack.results.iter().any(|row| row.id == matched));
    let bytes = vault
        .context_pack()
        .search_text("l2needle", 10)
        .max_field_chars(0)
        .token_budget(350)
        .run_serialized_with_stats()?
        .value;
    assert_eq!(
        bytes.stats.items_dropped.reason,
        crate::context_pack::PackItemAccountingReason::TokenBudget
    );
    let value: serde_json::Value = serde_json::from_slice(&bytes.bytes).unwrap();
    assert!(value.get("l2_base").is_none());
    assert!(String::from_utf8_lossy(&bytes.bytes).contains("budget-visible"));
    Ok(())
}

#[test]
fn implicit_l2_nulls_credentials_before_caching_and_in_every_output() -> Result<()> {
    let (_dir, vault, _) = fixture();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let id = crate::test_util::entity(0xC4);
    let body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(owner),
        rmpv::Value::Map(vec![
            (
                rmpv::Value::from("accessToken"),
                rmpv::Value::from("l2-private-material"),
            ),
            (
                rmpv::Value::from("ssh_key"),
                rmpv::Value::from("provider-private-material"),
            ),
            (
                rmpv::Value::from("ordinary"),
                rmpv::Value::from("safe-value"),
            ),
        ]),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&id, &body, TimeRange { start: 1, end: 1 }, 1)?;
    vault.batch().text(&id, &[("body", "l2needle")]).commit()?;
    let builder = || vault.context_pack().search_text("l2needle", 10);
    let first = builder().run()?.l2_base.expect("implicit prefix");
    let rows: serde_json::Value = serde_json::from_str(&first.body).unwrap();
    assert!(rows[0]["val"]["accessToken"].is_null());
    assert!(rows[0]["val"]["ssh_key"].is_null());
    assert_eq!(rows[0]["val"]["ordinary"], "safe-value");
    assert!(!first.body.contains("l2-private-material"));
    assert!(!first.body.contains("provider-private-material"));
    let again = builder().run()?.l2_base.unwrap();
    assert!(Arc::ptr_eq(&first.body, &again.body));

    let projected = crate::serialize::project_pack_for_json_response(
        builder().run()?,
        &crate::serialize::SerializeConfig {
            format: PackFormat::Json,
            profile: crate::context_pack::FieldProfile::Standard,
            budget: 4000,
            allocation: Default::default(),
            include_stats: false,
            merge_neighbors: true,
            max_field_chars: crate::context_pack::DEFAULT_MAX_FIELD_CHARS,
            max_item_tokens: 0,
        },
    );
    assert!(
        !projected
            .l2_base
            .as_ref()
            .unwrap()
            .body
            .contains("l2-private-material")
    );
    assert!(
        projected
            .results
            .iter()
            .all(|row| row.fields.as_ref().is_none_or(|fields| {
                !serde_json::to_string(fields)
                    .unwrap()
                    .contains("l2-private-material")
            }))
    );
    for format in [
        PackFormat::Json,
        PackFormat::Yaml,
        PackFormat::Toon,
        PackFormat::Markdown,
        PackFormat::Plaintext,
        PackFormat::OpenaiCompat,
        PackFormat::AnthropicMessages,
        PackFormat::Gemini,
    ] {
        let output = builder().format(format).token_budget(0).run_serialized()?;
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("l2-private-material"), "{format:?}");
        assert!(!text.contains("provider-private-material"), "{format:?}");
        assert!(text.contains("safe-value"), "{format:?}");
    }
    Ok(())
}

#[test]
fn implicit_l2_preserves_provider_envelopes_and_ingest_roundtrip() -> Result<()> {
    let (_dir, vault, _) = fixture();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    claim(
        &vault,
        crate::test_util::entity(0xC5),
        owner,
        "stable preference",
    )?;
    let fresh = crate::test_util::entity(0xC6);
    let raw = rmp_serde::to_vec_named(&serde_json::json!({"txt":"fresh-delta"})).unwrap();
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
    let summary = vault
        .context_pack()
        .search_text("l2needle", 10)
        .run()?
        .l2_base
        .unwrap();
    for (format, source, field) in [
        (PackFormat::OpenaiCompat, "openai-compat", "messages"),
        (
            PackFormat::AnthropicMessages,
            "anthropic-messages",
            "messages",
        ),
        (PackFormat::Gemini, "gemini-api", "contents"),
    ] {
        let builder = || {
            vault
                .context_pack()
                .search_text("l2needle", 10)
                .format(format)
                .token_budget(0)
                .max_field_chars(0)
        };
        let wire = builder().run_serialized()?;
        assert_eq!(
            wire,
            builder().run_serialized()?,
            "{format:?} must be stable"
        );
        let root: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        assert!(root.get("l2_base").is_none());
        assert!(root.get("delta").is_none());
        assert_eq!(root["secrets_nulled"], true);
        let messages = root[field]
            .as_array()
            .expect("provider's native message array");
        assert!(messages.len() >= 2, "{format:?} keeps the read-time delta");
        let prefix = match format {
            PackFormat::OpenaiCompat => messages[0]["content"].as_str().unwrap(),
            PackFormat::AnthropicMessages => messages[0]["content"][0]["text"].as_str().unwrap(),
            PackFormat::Gemini => messages[0]["parts"][0]["text"].as_str().unwrap(),
            _ => unreachable!(),
        };
        let prefix: serde_json::Value = serde_json::from_str(prefix).unwrap();
        assert_eq!(prefix["body"], summary.body.as_ref());
        let normalized = crate::ingest::INGEST_SOURCE_REGISTRY
            .normalize(source, &String::from_utf8(wire).unwrap())
            .expect("provider ingest");
        assert_eq!(normalized.records.len(), messages.len());
        assert!(
            normalized
                .records
                .iter()
                .skip(1)
                .any(|row| row.text.contains("fresh-delta"))
        );
    }
    Ok(())
}
