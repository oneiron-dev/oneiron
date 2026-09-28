use super::*;
use crate::voice_identity::ref_bank::{VoiceRefOrigin, VoiceRefPack};
use std::net::TcpListener;

#[test]
fn queued_render_after_withdrawal_never_uploads_deleted_reference() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let vault = Arc::new(vault);
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &crate::gate::default_policy_manifest().unwrap(),
    )?;
    let owner = EntityId::now();
    vault.store_voice_ref_pack(&VoiceRefPack {
        version: 1,
        id: "queued-ref".into(),
        voice_id: "queued-voice".into(),
        owner,
        origin: VoiceRefOrigin::Captured,
        clips: vec![VoiceRegisterClip {
            register: "neutral".into(),
            media_type: "audio/wav".into(),
            audio: b"RIFF0000WAVEfmt ".to_vec(),
            transcript: "reference".into(),
        }],
    })?;
    let (cloned, fence) = vault.prepare_fenced_voice_clone("queued-voice", TARGET, false)?;
    let limits = crate::gate::voice_serving::VoiceServingRows::decode(
        &crate::gate::voice_serving::VoiceServingRows::seeded(),
    )
    .expect("seeded limits")
    .vault;
    let warm = WarmTarget {
        limits,
        model: MODEL.into(),
        checkpoint: "pin".into(),
        boot_id: "test-boot".into(),
        sample_rate: 48_000,
    };
    let target = RenderTarget {
        voice_id: cloned.voice_id,
        register: "neutral".into(),
        fence,
        limits,
        warm,
    };
    let generation = GenerationEpoch {
        session: uuid::Uuid::new_v4(),
        value: 1,
    };
    let (sender, work) = mpsc::sync_channel(2);
    let (results, receiver) = mpsc::sync_channel(2);
    sender
        .send(VoxCpm2Work {
            generation,
            sequence: 0,
            operation: VoxCpm2Operation::Start {
                target: Box::new(target),
            },
        })
        .map_err(|_| invalid("test queue"))?;
    sender
        .send(VoxCpm2Work {
            generation,
            sequence: 1,
            operation: VoxCpm2Operation::Render {
                text: "not uploadable".into(),
            },
        })
        .map_err(|_| invalid("test queue"))?;
    drop(sender);
    vault.withdraw_voice_consent(&crate::voice_identity::VoiceWithdrawalRequest {
        event_id: "queued-withdrawal".into(),
        subject_ref: owner,
        recorded_by_ref: owner,
        occurred_at: 10,
        purposes: vec![crate::voice_identity::VoicePrintPurpose::LiveInterlocutor],
        basis: crate::voice_identity::VoiceConsentBasis::ConversationalNotice {
            notice: "withdraw".into(),
        },
    })?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let url = Url::parse(&format!("http://{}/render", listener.local_addr()?))
        .map_err(|_| invalid("test URL"))?;
    let client = Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .map_err(|_| invalid("test client"))?;
    let worker =
        thread::spawn(move || run_worker(vault, client, url, "t".repeat(32), work, results));
    assert!(matches!(
        receiver.recv_timeout(Duration::from_secs(2)),
        Ok(VoxCpm2Event::Failed { submission: 1, .. })
    ));
    worker.join().map_err(|_| invalid("worker panic"))?;
    assert!(
        listener.accept().is_err(),
        "withdrawn reference must never be uploaded"
    );
    Ok(())
}
