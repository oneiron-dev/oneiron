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
    let (dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
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
        let HostedWork::Render(request) = &adapter.transport().work[0] else {
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
        assert!(adapter.submit(text(generation, "more")).is_ok());
        assert!(adapter.submit(TtsCommand::Flush { generation }).is_err());
        adapter.finish_response(generation, 0)?;
        adapter.submit(TtsCommand::End { generation })?;
        assert_eq!(adapter.transport().work.len(), 2);
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
        assert!(adapter.transport().work.is_empty());
        adapter.submit(TtsCommand::Flush { generation })?;
        adapter.transport.reject = true;
        assert!(adapter.submit(TtsCommand::Cancel { generation }).is_err());
        assert!(adapter.receive_pcm(generation, 0, 0, &[1, 0]).is_err());
        assert!(adapter.submit(text(generation, "late")).is_err());
        adapter.submit(TtsCommand::Cancel { generation })?;
        adapter.submit(TtsCommand::Cancel { generation })?;
        assert_eq!(adapter.transport().work.len(), 2);
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
