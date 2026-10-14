use std::sync::Arc;

use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::context_pack::{ContextPackBuilder, PackFormat};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
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
    value: impl Into<rmpv::Value>,
    text: &str,
) -> Result<()> {
    let body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        value.into(),
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

/// The cache is the vault's and outlives any room. A pack that read a room
/// computes its summary and keeps none, so the next pack on base renders its
/// own, and base packs after it share that one.
#[test]
fn a_pack_over_a_room_keeps_no_summary_in_the_vaults_cache() -> Result<()> {
    let (_dir, vault, subject) = fixture();
    claim(
        &vault,
        crate::test_util::entity(0x31),
        subject,
        "a preference",
    )?;
    let session = vault.off_record_session_vault().enter(
        "sess-l2-room",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    let view = session.read_view()?;
    let in_room = assembly(&vault, subject).reading(view.read()).run()?;
    drop(view);
    let on_base = assembly(&vault, subject).run()?;
    let again = assembly(&vault, subject).run()?;
    let body = |pack: &crate::context_pack::ContextPack| {
        pack.l2_base
            .as_ref()
            .expect("the pack carries its summary")
            .body
            .clone()
    };
    assert!(
        !Arc::ptr_eq(&body(&in_room), &body(&on_base)),
        "the room's summary was not kept"
    );
    assert!(
        Arc::ptr_eq(&body(&on_base), &body(&again)),
        "a base pack keeps its own"
    );
    session.close()?;
    Ok(())
}

/// The public BIP39 test vector, as a recovery phrase's words.
const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

#[test]
fn a_body_the_write_door_refuses_is_withheld_whole_from_every_context_output() -> Result<()> {
    let (_dir, vault, subject) = fixture();
    let id = crate::vault::embedded_owner_actor_id()?;
    let owner =
        vault.authenticate_owner(id, &id.to_hex(), true, crate::store::GateDecisionId::now())?;
    vault.set_secret_scan_mode(&owner, crate::batch::secret_scan::SecretScanMode::Off, 10)?;
    let field = |key: String, value: &str| (rmpv::Value::from(key), rmpv::Value::from(value));
    let words = PHRASE.split(' ').enumerate();
    // Sol R8: a word per field and the phrase whole under a key the context
    // handles drop; then a word per field behind keys that Markdown and
    // Plaintext rows leave out, and the phrase whole under a credential name.
    let mut handled: Vec<_> = words
        .clone()
        .map(|(at, word)| match at {
            0..6 => field(format!("{:02}", at + 1), word),
            _ => field(format!("~{:02}", at + 1), word),
        })
        .collect();
    handled.insert(6, field("identity_key".into(), PHRASE));
    let mut keyed: Vec<_> = words
        .map(|(at, word)| field(format!("PROSE{:02}", at + 1), word))
        .collect();
    keyed.push(field("password".into(), PHRASE));
    // Bodies the write door accepts: a credential field holding a stand-in
    // the write door allows and every release door still clears.
    let accepted = |title: &str| {
        rmpv::Value::Map(vec![
            field("title".into(), title),
            field("password".into(), "changeme"),
        ])
    };
    let assets = [
        (rmpv::Value::Map(handled), true),
        (rmpv::Value::Map(keyed.clone()), true),
        (accepted("kept asset words"), false),
    ];
    for (at, (value, refused)) in (0x50..).zip(assets) {
        let mut body = Vec::new();
        rmpv::encode::write_value(&mut body, &value).unwrap();
        assert_eq!(
            crate::batch::secret_scan::scan_write_payload(&body).is_err(),
            refused,
            "{value}"
        );
        let asset = crate::test_util::entity(at);
        vault
            .batch()
            .put(
                &asset,
                ENTITY_TYPE_ASSET,
                TimeRange { start: 1, end: 1 },
                1,
                &body,
            )
            .text(&asset, &[("body", "l2needle")])
            .commit()?;
    }
    let refused = crate::test_util::entity(0x61);
    let kept = crate::test_util::entity(0x62);
    claim_with_text(
        &vault,
        refused,
        subject,
        rmpv::Value::Map(keyed),
        "l2needle",
    )?;
    claim_with_text(
        &vault,
        kept,
        subject,
        accepted("kept claim words"),
        "l2needle",
    )?;
    let full = || {
        assembly(&vault, subject)
            .field_profile(crate::context_pack::FieldProfile::Full)
            .max_item_tokens(0)
    };

    let pack = full().run()?;
    let l2 = pack.l2_base.as_ref().expect("L2 prefix");
    assert_eq!(l2.evidence_ids(), &[kept], "L2: {}", l2.body);
    assert!(!l2.body.contains("sausage"), "L2: {}", l2.body);
    assert!(!l2.body.contains("changeme"), "L2: {}", l2.body);
    assert!(l2.body.contains("kept claim words"), "L2: {}", l2.body);
    assert!(pack.results.iter().all(|row| row.id != refused));
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
        let text = String::from_utf8(full().format(format).run_serialized()?).unwrap();
        assert!(!text.contains("sausage"), "{format:?}: {text}");
        assert!(!text.contains("changeme"), "{format:?}: {text}");
        assert!(text.contains("kept asset words"), "{format:?}: {text}");
        assert!(text.contains("kept claim words"), "{format:?}: {text}");
    }
    Ok(())
}
