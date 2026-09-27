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
    use crate::{
        edge::EdgeActorClass,
        memory::{WitnessAuthor, WitnessMessage, WitnessTurn},
        registry::ENTITY_TYPE_PERSON,
    };
    let actor = crate::EntityId::from_bytes([0x61; 16])?;
    if vault.get_entity_type(&actor)?.is_none() {
        vault.put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"actor",
        )?;
    }
    let id = crate::EntityId::now();
    vault
        .memory(actor, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: crate::EntityId::now().to_hex(),
            turn_ref: Some(id.to_hex()),
            occurred_at: 10,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: text.to_owned(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
        })
        .expect("authorized witness");
    Ok(id)
}
fn bare_turn(vault: &Vault, text: &str) -> crate::Result<crate::EntityId> {
    let id = crate::EntityId::now();
    let mut body = vec![];
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![("txt".into(), text.into())]),
    )
    .expect("encode bare turn");
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
    let dir = tempfile::tempdir().expect("vault root");
    let vault = Vault::open(dir.path(), config).expect("vault open");
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
    assert!(capture_tier2_samples(&vault, &ids, &Unknown, &[])?.is_empty());
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
    let other_dir = tempfile::tempdir().expect("other root");
    let other = Vault::open(other_dir.path(), config)?;
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

#[test]
fn erasing_turn_or_message_revokes_the_derived_sample() -> crate::Result<()> {
    use crate::{edge::EdgeKind, registry::ENTITY_TYPE_MESSAGE};
    for erase_message in [false, true] {
        let (_dir, vault, _) = vault();
        let id = turn(&vault, "Ada is here")?;
        assert_eq!(
            capture_tier2_samples(&vault, &[id], &FixtureNer, &[])?.len(),
            1
        );
        let source = if erase_message {
            vault.sources(&id, EdgeKind::PartOf, Some(ENTITY_TYPE_MESSAGE))?[0]
        } else {
            id
        };
        assert!(vault.delete_entity(&source)?);
        assert!(read_tier2_samples(&vault)?.is_empty());
        let txn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .vault_meta
                .get(&txn, &super::sample_key(1_800_000_000 / super::WEEK, &id))?
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn deletion_during_redaction_cannot_commit_a_stale_sample() -> crate::Result<()> {
    use crate::{edge::EdgeKind, registry::ENTITY_TYPE_MESSAGE};
    struct DeleteDuringRedaction<'a> {
        vault: &'a Vault,
        source: crate::EntityId,
    }
    impl Tier2Redactor for DeleteDuringRedaction<'_> {
        fn detect(&self, _: &str) -> crate::Result<Option<Vec<RedactionSpan>>> {
            assert!(self.vault.delete_entity(&self.source)?);
            Ok(Some(vec![]))
        }
    }
    let (_dir, vault, _) = vault();
    let turn_id = turn(&vault, "unredacted safe phrase")?;
    let message = vault.sources(&turn_id, EdgeKind::PartOf, Some(ENTITY_TYPE_MESSAGE))?[0];
    let ner = DeleteDuringRedaction {
        vault: &vault,
        source: message,
    };
    assert!(capture_tier2_samples(&vault, &[turn_id], &ner, &[])?.is_empty());
    assert!(read_tier2_samples(&vault)?.is_empty());
    Ok(())
}

#[test]
fn expired_week_counter_cannot_be_revived_by_clock_rollback() -> crate::Result<()> {
    const T: u64 = 1_800_000_000;
    let (dir, vault, clock) = vault();
    let ids = (0..54)
        .map(|_| turn(&vault, "safe transcript"))
        .collect::<crate::Result<Vec<_>>>()?;
    assert_eq!(
        capture_tier2_samples(&vault, &ids, &FixtureNer, &[])?.len(),
        50
    );
    clock.set(T + super::WEEK);
    assert_eq!(read_tier2_samples(&vault)?.len(), 50);
    drop(vault);
    clock.set(T);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    config.failure_signals.export_opt_in = true;
    let vault = Vault::open(dir.path(), config)?;
    let second = capture_tier2_samples(&vault, &ids, &FixtureNer, &[])?;
    assert_eq!(second.len(), 50);
    assert!(
        second
            .iter()
            .all(|sample| sample.sampled_at >= T + super::WEEK)
    );
    assert_eq!(read_tier2_samples(&vault)?.len(), 100);
    Ok(())
}

#[test]
fn bare_turn_body_is_not_a_transcript_candidate() -> crate::Result<()> {
    let (_dir, vault, _) = vault();
    let id = bare_turn(&vault, "Ada email ada@example.invalid")?;
    assert!(capture_tier2_samples(&vault, &[id], &Unknown, &[])?.is_empty());
    assert!(read_tier2_samples(&vault)?.is_empty());
    Ok(())
}
