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
    )
    .unwrap();
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
