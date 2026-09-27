use super::*;
use crate::{
    TimeRange, Vault, config::VaultConfig, ports::ManualClock, registry::ENTITY_TYPE_TURN,
};

struct FixtureNer;
impl Tier2Redactor for FixtureNer {
    fn detect(&self, text: &str) -> crate::Result<Option<Vec<RedactionSpan>>> {
        Ok(Some(
            [
                ("Ada", RedactionKind::Person),
                ("ada@example.invalid", RedactionKind::Email),
                ("+1 555 123 4567", RedactionKind::Phone),
            ]
            .into_iter()
            .filter_map(|(needle, kind)| {
                text.find(needle).map(|start| RedactionSpan {
                    start,
                    end: start + needle.len(),
                    kind,
                })
            })
            .collect(),
        ))
    }
}
struct Unknown;
impl Tier2Redactor for Unknown {
    fn detect(&self, _: &str) -> crate::Result<Option<Vec<RedactionSpan>>> {
        Ok(None)
    }
}
struct Miss;
impl Tier2Redactor for Miss {
    fn detect(&self, _: &str) -> crate::Result<Option<Vec<RedactionSpan>>> {
        Ok(Some(vec![]))
    }
}
fn turn(vault: &Vault, text: &str) -> crate::Result<crate::EntityId> {
    let id = crate::EntityId::now();
    let mut body = vec![];
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![("txt".into(), text.into())]),
    )
    .expect("encode fixture");
    vault.put_entity(
        &id,
        ENTITY_TYPE_TURN,
        TimeRange { start: 10, end: 10 },
        10,
        &body,
    )?;
    Ok(id)
}
fn vault() -> (tempfile::TempDir, Vault, std::sync::Arc<ManualClock>) {
    let clock = ManualClock::new(1_800_000_000);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    config.failure_signals.export_opt_in = true;
    let (dir, vault) = crate::test_util::open_test_vault_with(config);
    (dir, vault, clock)
}
#[test]
fn pii_is_replaced_before_storage_and_read_and_uncertainty_fails_closed() -> crate::Result<()> {
    let (_dir, vault, _) = vault();
    let id = turn(
        &vault,
        "Ada email ada@example.invalid or call +1 555 123 4567",
    )?;
    let got = capture_tier2_samples(&vault, &[id], &FixtureNer, &["private-phrase"])?;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].text, "[PERSON] email [EMAIL] or call [PHONE]");
    assert_eq!(read_tier2_samples(&vault)?, got);
    let raw = vault.store.env.read_txn()?;
    let stored = vault
        .store
        .vault_meta
        .get(
            &raw,
            &super::sample_key(got[0].sampled_at / super::WEEK, &id),
        )?
        .expect("persisted redacted sample");
    assert!(!stored.windows(3).any(|chunk| chunk == b"Ada"));
    drop(raw);
    let uncertain = turn(&vault, "a private phrase")?;
    assert!(capture_tier2_samples(&vault, &[uncertain], &Unknown, &[]).is_err());
    assert!(capture_tier2_samples(&vault, &[uncertain], &Miss, &["private phrase"]).is_err());
    let email = turn(&vault, "a2@example.invalid")?;
    assert!(capture_tier2_samples(&vault, &[email], &Miss, &[]).is_err());
    assert_eq!(read_tier2_samples(&vault)?.len(), 1);
    Ok(())
}
#[test]
fn cap_is_durable_weekly_and_expiry_is_35_days() -> crate::Result<()> {
    let (dir, vault, clock) = vault();
    let ids = (0..54)
        .map(|_| turn(&vault, "safe transcript"))
        .collect::<crate::Result<Vec<_>>>()?;
    assert_eq!(
        capture_tier2_samples(&vault, &ids, &FixtureNer, &[])?.len(),
        50
    );
    assert!(capture_tier2_samples(&vault, &ids, &FixtureNer, &[])?.is_empty());
    assert_eq!(read_tier2_samples(&vault)?.len(), 50);
    drop(vault);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    config.failure_signals.export_opt_in = true;
    let vault = Vault::open(dir.path(), config)?;
    assert!(capture_tier2_samples(&vault, &ids, &FixtureNer, &[])?.is_empty());
    clock.set(1_800_000_000 + super::WEEK);
    assert_eq!(
        capture_tier2_samples(&vault, &ids[..1], &FixtureNer, &[])?.len(),
        1
    );
    clock.set(1_800_000_000 + super::TTL);
    assert_eq!(read_tier2_samples(&vault)?.len(), 1);
    clock.set(1_800_000_000 + super::TTL + super::WEEK);
    assert!(read_tier2_samples(&vault)?.is_empty());
    Ok(())
}
#[test]
fn off_record_rows_and_disabled_exports_never_reach_redactor() -> crate::Result<()> {
    use crate::off_record::OffRecordBackendClass;
    let (_dir, vault, _) = vault();
    let id = crate::EntityId::now();
    let room = vault
        .off_record_session_vault()
        .enter("tier2-room", OffRecordBackendClass::Local)?;
    let overlay = room.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(
        crate::session_overlay::OverlayKeyspace::Entities,
        id.as_bytes(),
        b"off-record raw",
    )?;
    segment.commit()?;
    assert!(capture_tier2_samples(&vault, &[id], &Unknown, &[])?.is_empty());
    assert!(read_tier2_samples(&vault)?.is_empty());
    let mut config = VaultConfig::device();
    config.failure_signals.export_opt_in = false;
    let (_other_dir, other) = crate::test_util::open_test_vault_with(config);
    let ordinary = turn(&other, "must not inspect")?;
    assert!(capture_tier2_samples(&other, &[ordinary], &Unknown, &[])?.is_empty());
    Ok(())
}

#[test]
fn witnessed_message_children_supply_transcript_without_exposing_metadata() -> crate::Result<()> {
    use crate::{
        edge::EdgeActorClass,
        memory::{WitnessAuthor, WitnessMessage, WitnessTurn},
        registry::ENTITY_TYPE_PERSON,
    };
    let dir = tempfile::tempdir().expect("vault root");
    let mut config = VaultConfig::device();
    config.failure_signals.export_opt_in = true;
    let vault = Vault::open(dir.path(), config)?;
    let actor = crate::EntityId::now();
    vault.put_entity(
        &actor,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )?;
    let id = crate::EntityId::now();
    let turn = WitnessTurn {
        conversation_ref: crate::EntityId::now().to_hex(),
        turn_ref: Some(id.to_hex()),
        occurred_at: 10,
        messages: [(1, "hello ada@example.invalid"), (2, "Ada says goodbye")]
            .into_iter()
            .map(|(order, content)| WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: content.to_owned(),
                metadata: Some(serde_json::json!({"private": "also-private"})),
                is_visible: true,
                order,
            })
            .collect(),
    };
    vault
        .memory(actor, EdgeActorClass::Human)
        .witness(&turn)
        .expect("authorized witness");
    let got = capture_tier2_samples(&vault, &[id], &FixtureNer, &["also-private"])?;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].text, "hello [EMAIL]\n[PERSON] says goodbye");
    assert_eq!(read_tier2_samples(&vault)?, got);
    Ok(())
}
