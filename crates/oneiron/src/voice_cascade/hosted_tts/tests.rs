use super::*;
use crate::voice_identity::ref_bank::{VoiceRefOrigin, VoiceRefPack, VoiceRegisterClip};

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
const VOICE: &str = "banked-voice";

fn pack(id: &str, owner: EntityId, origin: VoiceRefOrigin) -> VoiceRefPack {
    VoiceRefPack {
        version: 1,
        id: id.into(),
        voice_id: VOICE.into(),
        owner,
        origin,
        clips: vec![VoiceRegisterClip {
            register: "neutral".into(),
            media_type: "audio/wav".into(),
            audio: vec![1, 2, 3],
            transcript: "example".into(),
        }],
    }
}
/// The identity exists, but no hosted target has been provisioned yet.
fn bank() -> (tempfile::TempDir, Vault, VoiceRefPack) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).expect("open seeded vault");
    let pack = pack(
        "banked-registers",
        EntityId::now(),
        VoiceRefOrigin::Captured,
    );
    vault.store_voice_ref_pack(&pack).unwrap();
    (dir, vault, pack)
}
/// Stands in for the host's provisioning flow: the vendor clone call runs
/// outside the adapter, and only its returned voice ID is recorded.
fn provision(
    vault: &Vault,
    provider: HostedProvider,
    include_generated: bool,
    vendor_voice_id: &str,
) -> Result<()> {
    let request = vault.prepare_voice_clone(VOICE, provider.target(), include_generated)?;
    vault.record_voice_target_clone(&request, vendor_voice_id, 1)?;
    Ok(())
}
fn bind(vault: &Vault, provider: HostedProvider) -> Result<HostedTtsAdapter<'_, Capture>> {
    HostedTtsAdapter::bind(vault, VOICE, provider, false, Capture::default())
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
        // An identity with no target record has nothing to render through.
        assert!(bind(&vault, provider).is_err());
        provision(&vault, provider, false, "preprovisioned_id-1")?;
        let mut adapter = bind(&vault, provider)?;
        assert_eq!(adapter.binding().voice_id, VOICE);
        assert_eq!(adapter.binding().owner, pack.owner);
        assert_eq!(adapter.binding().vendor_voice_id, "preprovisioned_id-1");
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
        assert!(!wire.contains(VOICE));
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
    let (_dir, vault, _pack) = bank();
    for provider in [HostedProvider::Cartesia, HostedProvider::ElevenLabsFlash] {
        provision(&vault, provider, false, "preprovisioned")?;
        let mut adapter = bind(&vault, provider)?;
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
        vault.evict_voice_target(VOICE, provider.target())?;
        provision(&vault, provider, false, "../key")?;
        assert!(bind(&vault, provider).is_err());
        assert!(
            HostedTtsAdapter::bind(&vault, "missing", provider, false, Capture::default()).is_err()
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
        provision(&vault, provider, false, "voice")?;
        let mut adapter = bind(&vault, provider)?;
        adapter.submit(TtsCommand::Start { generation })?;
        adapter.submit(text(generation, "never send"))?;
        withdraw(&vault, pack.owner, "withdraw-before-flush")?;
        assert!(adapter.submit(TtsCommand::Flush { generation }).is_err());
        assert_eq!(adapter.transport.work, [HostedWork::Cancel { generation }]);
        assert!(adapter.submit(text(generation, "late")).is_err());
        assert!(bind(&vault, provider).is_err());
    }
    Ok(())
}

#[test]
fn withdrawal_between_responses_cancels_all_pending_and_never_revives_a_binding() -> Result<()> {
    for provider in [HostedProvider::Cartesia, HostedProvider::ElevenLabsFlash] {
        let (_dir, vault, pack) = bank();
        let generation = epoch(10);
        provision(&vault, provider, false, "voice")?;
        let mut adapter = bind(&vault, provider)?;
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
        vault.store_voice_ref_pack(&pack)?;
        provision(&vault, provider, false, "voice")?;
        assert!(adapter.submit(TtsCommand::Flush { generation }).is_err());
    }
    Ok(())
}

#[test]
fn withdrawal_and_same_id_recreation_cannot_revive_unobserved_old_binding() -> Result<()> {
    let (_dir, vault, pack) = bank();
    let generation = epoch(13);
    provision(&vault, HostedProvider::Cartesia, false, "old-voice")?;
    let mut adapter = bind(&vault, HostedProvider::Cartesia)?;
    adapter.submit(TtsCommand::Start { generation })?;
    adapter.submit(text(generation, "unadmitted"))?;
    withdraw(&vault, pack.owner, "withdraw-replace")?;
    // Same identity ID, pack bytes, vendor ID and clone time: only the
    // record revision differs, and it alone refuses the old binding.
    vault.store_voice_ref_pack(&pack)?;
    provision(&vault, HostedProvider::Cartesia, false, "old-voice")?;
    assert!(adapter.submit(TtsCommand::Flush { generation }).is_err());
    assert_eq!(adapter.transport.work, [HostedWork::Cancel { generation }]);
    let fresh = bind(&vault, HostedProvider::Cartesia)?;
    assert_eq!(fresh.binding().voice_id, VOICE);
    assert_eq!(fresh.binding().vendor_voice_id, "old-voice");
    assert_ne!(fresh.binding().revision, adapter.binding().revision);
    Ok(())
}

#[test]
fn hosted_binding_follows_target_record_currency() -> Result<()> {
    let (_dir, vault, source) = bank();
    let generation = epoch(14);
    // A source-only record on one target, a record with AI refs on the other.
    provision(&vault, HostedProvider::Cartesia, false, "source-only")?;
    provision(
        &vault,
        HostedProvider::ElevenLabsFlash,
        true,
        "with-generated",
    )?;
    let with_generated = || {
        HostedTtsAdapter::bind(
            &vault,
            VOICE,
            HostedProvider::ElevenLabsFlash,
            true,
            Capture::default(),
        )
    };
    let mut source_only = bind(&vault, HostedProvider::Cartesia)?;
    let mut all_refs = with_generated()?;
    for adapter in [&mut source_only, &mut all_refs] {
        adapter.submit(TtsCommand::Start { generation })?;
    }

    let generated = pack("generated", source.owner, VoiceRefOrigin::Generated);
    vault.store_voice_ref_pack(&generated)?;
    source_only.submit(text(generation, "still mine"))?;
    source_only.submit(TtsCommand::Flush { generation })?;
    assert!(matches!(
        source_only.transport.work[..],
        [HostedWork::Render(_)]
    ));
    assert!(all_refs.submit(text(generation, "stale")).is_err());
    assert_eq!(all_refs.transport.work, [HostedWork::Cancel { generation }]);
    assert!(with_generated().is_err());
    provision(
        &vault,
        HostedProvider::ElevenLabsFlash,
        true,
        "with-generated",
    )?;
    let mut all_refs = with_generated()?;
    all_refs.submit(TtsCommand::Start { generation })?;

    let designed = pack(
        "designed",
        source.owner,
        VoiceRefOrigin::Designed {
            vendor: "design-tool".into(),
        },
    );
    vault.store_voice_ref_pack(&designed)?;
    assert!(source_only.submit(text(generation, "stale")).is_err());
    assert!(matches!(
        source_only.transport.work[..],
        [HostedWork::Render(_), HostedWork::Cancel { .. }]
    ));
    assert!(all_refs.submit(text(generation, "stale")).is_err());
    assert!(bind(&vault, HostedProvider::Cartesia).is_err());
    assert!(with_generated().is_err());
    provision(&vault, HostedProvider::Cartesia, false, "source-only")?;
    provision(
        &vault,
        HostedProvider::ElevenLabsFlash,
        true,
        "with-generated",
    )?;
    bind(&vault, HostedProvider::Cartesia)?;
    with_generated()?;
    Ok(())
}

#[test]
fn hosted_bind_checks_url_safety_not_length() -> Result<()> {
    let (_dir, vault, _pack) = bank();
    let long = format!("{}_-9", "v".repeat(197));
    assert_eq!(long.len(), 200);
    for provider in [HostedProvider::Cartesia, HostedProvider::ElevenLabsFlash] {
        provision(&vault, provider, false, &long)?;
        let mut adapter = bind(&vault, provider)?;
        assert_eq!(adapter.binding().vendor_voice_id, long);
        let generation = epoch(15);
        adapter.submit(TtsCommand::Start { generation })?;
        adapter.submit(text(generation, "long id"))?;
        adapter.submit(TtsCommand::Flush { generation })?;
        let HostedWork::Render(request) = &adapter.transport.work[0] else {
            panic!("render")
        };
        match provider {
            HostedProvider::Cartesia => assert_eq!(request.body["voice"]["id"], long.as_str()),
            HostedProvider::ElevenLabsFlash => {
                assert!(
                    request
                        .url
                        .contains(&format!("/text-to-speech/{long}/stream"))
                );
            }
        }

        vault.evict_voice_target(VOICE, provider.target())?;
        provision(&vault, provider, false, "voice/../key")?;
        assert!(bind(&vault, provider).is_err());
        vault.evict_voice_target(VOICE, provider.target())?;
    }
    Ok(())
}
