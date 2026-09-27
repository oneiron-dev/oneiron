use super::*;
use crate::voice_identity::ref_bank::{OwnerVoiceRefPack, VoiceRefOrigin, VoiceRegisterClip};

#[derive(Default)]
struct Capture {
    work: Vec<HostedWork>,
    reject: bool,
}
impl HostedTransport for Capture {
    fn try_submit(&mut self, work: HostedWork) -> Result<()> {
        if std::mem::take(&mut self.reject) {
            return Err(invalid("queue full"));
        }
        self.work.push(work);
        Ok(())
    }
}
fn bank() -> (tempfile::TempDir, Vault, OwnerVoiceRefPack) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).expect("open seeded vault");
    let pack = OwnerVoiceRefPack {
        version: 1,
        id: "banked-registers".into(),
        owner: EntityId::now(),
        origin: VoiceRefOrigin::OwnerCapture,
        clips: vec![VoiceRegisterClip {
            register: "neutral".into(),
            media_type: "audio/wav".into(),
            audio: vec![1, 2, 3],
            transcript: "example".into(),
        }],
    };
    vault.store_owner_voice_refs(&pack).unwrap();
    (dir, vault, pack)
}
fn epoch(n: u128) -> GenerationEpoch {
    GenerationEpoch {
        session: uuid::Uuid::from_u128(n),
        value: 1,
    }
}
fn text(generation: GenerationEpoch, text: &str) -> TtsCommand {
    TtsCommand::Text {
        generation,
        text: text.into(),
    }
}

#[test]
fn both_hosted_targets_render_from_bank_with_only_provisioned_locators() -> Result<()> {
    let (_dir, vault, pack) = bank();
    for provider in [HostedProvider::Cartesia, HostedProvider::ElevenLabsFlash] {
        let mut adapter = HostedTtsAdapter::bind(
            &vault,
            &pack.id,
            provider,
            "preprovisioned_id-1",
            Capture::default(),
        )?;
        assert_eq!(adapter.binding().source_pack, pack.id);
        assert_eq!(adapter.binding().owner, pack.owner);
        let generation = epoch(1);
        adapter.submit(TtsCommand::Start { generation })?;
        adapter.submit(text(generation, "test sentence"))?;
        adapter.submit(TtsCommand::Flush { generation })?;
        let HostedWork::Render(request) = &adapter.transport.work[0] else {
            panic!("render")
        };
        assert_eq!(request.generation, generation);
        assert_eq!(request.submission, 0);
        let wire = request.body.to_string();
        assert!(!wire.contains("banked-registers"));
        assert!(!wire.contains("example"));
        assert!(!wire.contains("1,2,3"));
        match provider {
            HostedProvider::Cartesia => {
                assert_eq!(request.url, "https://api.cartesia.ai/tts/bytes");
                assert_eq!(request.api_version, Some("2026-08-14"));
                assert_eq!(
                    request.body,
                    serde_json::json!({
                        "model_id":"sonic-3.5", "transcript":"test sentence", "voice":{"id":"preprovisioned_id-1"},
                        "output_format":{"container":"raw", "encoding":"pcm_s16le", "sample_rate":24000}
                    })
                );
            }
            HostedProvider::ElevenLabsFlash => {
                assert_eq!(
                    request.url,
                    "https://api.elevenlabs.io/v1/text-to-speech/preprovisioned_id-1/stream?output_format=pcm_24000"
                );
                assert_eq!(request.api_version, None);
                assert_eq!(
                    request.body,
                    serde_json::json!({"text":"test sentence", "model_id":"eleven_flash_v2_5"})
                );
            }
        }
        let frame = adapter.receive_pcm(generation, 0, 0, &[1, 0, 255, 255])?;
        assert_eq!(frame.samples, [1, -1]);
        assert_eq!(frame.sample_rate, 24_000);
        assert!(adapter.receive_pcm(generation, 0, 0, &[1, 0]).is_err());
        assert!(adapter.receive_pcm(generation, 0, 1, &[1]).is_err());
        adapter.submit(text(generation, "more"))?;
        adapter.submit(TtsCommand::Flush { generation })?;
        adapter.submit(TtsCommand::End { generation })?;
        assert_eq!(adapter.transport.work.len(), 2);
        assert!(adapter.receive_pcm(generation, 1, 0, &[1, 0]).is_err());
        adapter.finish_response(generation, 0)?;
        assert_eq!(adapter.receive_pcm(generation, 1, 0, &[1, 0])?.samples, [1]);
        adapter.finish_response(generation, 1)?;
        adapter.submit(TtsCommand::End { generation })?;
        assert!(adapter.receive_pcm(epoch(2), 1, 0, &[1, 0]).is_err());
    }
    Ok(())
}

#[test]
fn rejection_is_retryable_but_failed_cancellation_closes_output() -> Result<()> {
    let (_dir, vault, pack) = bank();
    for provider in [HostedProvider::Cartesia, HostedProvider::ElevenLabsFlash] {
        let mut adapter = HostedTtsAdapter::bind(
            &vault,
            &pack.id,
            provider,
            "preprovisioned",
            Capture::default(),
        )?;
        let generation = epoch(1);
        adapter.submit(TtsCommand::Start { generation })?;
        adapter.submit(text(generation, "one"))?;
        adapter.transport.reject = true;
        assert!(adapter.submit(TtsCommand::Flush { generation }).is_err());
        assert!(adapter.transport.work.is_empty());
        adapter.submit(TtsCommand::Flush { generation })?;
        adapter.transport.reject = true;
        assert!(adapter.submit(TtsCommand::Cancel { generation }).is_err());
        assert!(adapter.receive_pcm(generation, 0, 0, &[1, 0]).is_err());
        assert!(adapter.submit(text(generation, "late")).is_err());
        adapter.submit(TtsCommand::Cancel { generation })?;
        adapter.submit(TtsCommand::Cancel { generation })?;
        assert_eq!(adapter.transport.work.len(), 2);
        assert!(
            HostedTtsAdapter::bind(&vault, &pack.id, provider, "../key", Capture::default())
                .is_err()
        );
        assert!(
            HostedTtsAdapter::bind(&vault, "missing", provider, "id", Capture::default()).is_err()
        );
    }
    Ok(())
}

fn withdraw(vault: &Vault, owner: EntityId, event_id: &str) -> Result<()> {
    use crate::voice_identity::{VoiceConsentBasis, VoicePrintPurpose, VoiceWithdrawalRequest};
    vault.withdraw_voice_consent(&VoiceWithdrawalRequest {
        event_id: event_id.into(),
        subject_ref: owner,
        recorded_by_ref: owner,
        occurred_at: 10,
        purposes: vec![VoicePrintPurpose::LiveInterlocutor],
        basis: VoiceConsentBasis::ConversationalNotice {
            notice: "withdraw".into(),
        },
    })?;
    Ok(())
}

#[test]
fn withdrawal_before_first_flush_revokes_both_hosted_targets() -> Result<()> {
    for provider in [HostedProvider::Cartesia, HostedProvider::ElevenLabsFlash] {
        let (_dir, vault, pack) = bank();
        let generation = epoch(9);
        let mut adapter =
            HostedTtsAdapter::bind(&vault, &pack.id, provider, "voice", Capture::default())?;
        adapter.submit(TtsCommand::Start { generation })?;
        adapter.submit(text(generation, "never send"))?;
        withdraw(&vault, pack.owner, "withdraw-before-flush")?;
        assert!(adapter.submit(TtsCommand::Flush { generation }).is_err());
        assert_eq!(adapter.transport.work, [HostedWork::Cancel { generation }]);
        assert!(adapter.submit(text(generation, "late")).is_err());
        assert!(
            HostedTtsAdapter::bind(&vault, &pack.id, provider, "voice", Capture::default())
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn withdrawal_between_responses_cancels_all_pending_and_never_revives_a_binding() -> Result<()> {
    for provider in [HostedProvider::Cartesia, HostedProvider::ElevenLabsFlash] {
        let (_dir, vault, pack) = bank();
        let generation = epoch(10);
        let mut adapter =
            HostedTtsAdapter::bind(&vault, &pack.id, provider, "voice", Capture::default())?;
        adapter.submit(TtsCommand::Start { generation })?;
        for fragment in ["first", "second"] {
            adapter.submit(text(generation, fragment))?;
            adapter.submit(TtsCommand::Flush { generation })?;
        }
        adapter.submit(TtsCommand::End { generation })?;
        adapter.receive_pcm(generation, 0, 0, &[1, 0])?;
        adapter.finish_response(generation, 0)?;
        withdraw(&vault, pack.owner, "withdraw-between-responses")?;
        assert!(adapter.receive_pcm(generation, 1, 0, &[1, 0]).is_err());
        assert!(
            matches!(adapter.transport.work.last(), Some(HostedWork::Cancel { generation: g }) if *g == generation)
        );
        assert!(adapter.finish_response(generation, 1).is_err());
        assert!(adapter.submit(text(generation, "third")).is_err());
        assert_eq!(adapter.transport.work.len(), 3);
        // Reusing an ID (even with identical bytes) cannot resurrect the old incarnation.
        vault.store_owner_voice_refs(&pack)?;
        assert!(adapter.submit(TtsCommand::Flush { generation }).is_err());
    }
    Ok(())
}

#[test]
fn many_small_drained_requests_exceed_old_cumulative_limit_without_cancellation() -> Result<()> {
    let (_dir, vault, pack) = bank();
    for provider in [HostedProvider::Cartesia, HostedProvider::ElevenLabsFlash] {
        let mut adapter =
            HostedTtsAdapter::bind(&vault, &pack.id, provider, "voice", Capture::default())?;
        let generation = epoch(11);
        adapter.submit(TtsCommand::Start { generation })?;
        for n in 0..20 {
            adapter.submit(text(generation, &"x".repeat(600)))?;
            adapter.submit(TtsCommand::Flush { generation })?;
            adapter.receive_pcm(generation, n, 0, &[1, 0])?;
            adapter.finish_response(generation, n)?;
        }
        adapter.submit(TtsCommand::End { generation })?;
        assert_eq!(adapter.transport.work.len(), 20);
        assert!(
            adapter
                .transport
                .work
                .iter()
                .all(|work| matches!(work, HostedWork::Render(_)))
        );
    }
    Ok(())
}

fn narrow_policy(vault: &Vault, provider: HostedProvider, holder: EntityId) -> Result<()> {
    use rmpv::Value;
    let map = |entries: Vec<(&str, Value)>| {
        Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (Value::from(k), v))
                .collect(),
        )
    };
    let limits = map(vec![
        ("provider", Value::from(provider.target())),
        ("scope", Value::from("holder")),
        ("holder_ref", Value::from(holder.to_hex())),
        ("max_text_bytes", Value::from(3_u64)),
        ("max_pcm_fragment_bytes", Value::from(2_u64)),
    ]);
    let manifest = map(vec![
        (
            "schema_version",
            Value::from(crate::gate::POLICY_SCHEMA_VERSION),
        ),
        ("pack_id", Value::from("hosted-tts-narrow")),
        ("pack_version", Value::from("v1")),
        ("min_engine_version", Value::from(env!("CARGO_PKG_VERSION"))),
        (
            "defaults",
            map(vec![
                ("criticality", Value::from("normal")),
                ("sensitivity", Value::from("normal")),
            ]),
        ),
        ("rules", Value::Array(vec![])),
        ("actor_ceilings", Value::Array(vec![])),
        (
            "hosted_tts",
            map(vec![
                ("precedence", Value::from("nested_narrowing")),
                ("rows", Value::Array(vec![limits])),
            ]),
        ),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &manifest).unwrap();
    crate::test_util::put_policy_manifest_bytes(vault, crate::test_util::entity(0x43), &bytes)
}

#[test]
fn manifest_holder_limit_applies_to_live_text_and_pcm_fragments() -> Result<()> {
    for provider in [HostedProvider::Cartesia, HostedProvider::ElevenLabsFlash] {
        let (_dir, vault, pack) = bank();
        let mut adapter =
            HostedTtsAdapter::bind(&vault, &pack.id, provider, "voice", Capture::default())?;
        let generation = epoch(12);
        adapter.submit(TtsCommand::Start { generation })?;
        narrow_policy(&vault, provider, pack.owner)?; // change AFTER bind, at the admission door
        assert!(adapter.submit(text(generation, "four")).is_err());
        adapter.submit(text(generation, "ok"))?;
        adapter.submit(TtsCommand::Flush { generation })?;
        assert!(
            adapter
                .receive_pcm(generation, 0, 0, &[1, 0, 2, 0])
                .is_err()
        );
        assert_eq!(adapter.receive_pcm(generation, 0, 0, &[1, 0])?.samples, [1]);
        adapter.finish_response(generation, 0)?;
    }
    Ok(())
}

#[test]
fn withdrawal_and_same_id_recreation_cannot_revive_unobserved_old_binding() -> Result<()> {
    let (_dir, vault, pack) = bank();
    let generation = epoch(13);
    let mut adapter = HostedTtsAdapter::bind(
        &vault,
        &pack.id,
        HostedProvider::Cartesia,
        "old-voice",
        Capture::default(),
    )?;
    adapter.submit(TtsCommand::Start { generation })?;
    adapter.submit(text(generation, "unadmitted"))?;
    withdraw(&vault, pack.owner, "withdraw-replace")?;
    vault.store_owner_voice_refs(&pack)?;
    assert!(adapter.submit(TtsCommand::Flush { generation }).is_err());
    assert_eq!(adapter.transport.work, [HostedWork::Cancel { generation }]);
    let fresh = HostedTtsAdapter::bind(
        &vault,
        &pack.id,
        HostedProvider::Cartesia,
        "new-voice",
        Capture::default(),
    )?;
    assert_eq!(fresh.binding().source_pack, pack.id);
    Ok(())
}
