use super::*;
use crate::voice_identity::ref_bank::{OwnerVoiceRefPack, VoiceRefOrigin};
use std::sync::Arc;

#[derive(Default)]
struct Capture {
    work: Vec<VoxCpm2Work>,
    ready: bool,
    fail: bool,
}
impl VoxCpm2Queue for Capture {
    fn warm_target(&self) -> Result<WarmTarget> {
        if !self.ready {
            return Err(invalid("GPU worker not ready"));
        }
        Ok(WarmTarget {
            model: MODEL.into(),
            checkpoint: "openbmb/VoxCPM2@pinned".into(),
            boot_id: "gpu-boot-1".into(),
            sample_rate: 16_000,
        })
    }
    fn try_submit(&mut self, work: VoxCpm2Work) -> Result<()> {
        if std::mem::take(&mut self.fail) {
            return Err(invalid("queue full"));
        }
        self.work.push(work);
        Ok(())
    }
}
fn epoch(value: u64) -> GenerationEpoch {
    GenerationEpoch {
        session: uuid::Uuid::from_u128(7),
        value,
    }
}
fn bank(vault: &Vault) -> Result<EntityId> {
    let owner = EntityId::now();
    vault.store_owner_voice_refs(&OwnerVoiceRefPack {
        version: 1,
        id: "banked-owner".into(),
        owner,
        origin: VoiceRefOrigin::OwnerCapture,
        clips: vec![VoiceRegisterClip {
            register: "neutral".into(),
            media_type: "audio/wav".into(),
            audio: b"RIFF0000WAVEfmt ".to_vec(),
            transcript: "reference words".into(),
        }],
    })?;
    Ok(owner)
}
fn adapter(vault: &Arc<Vault>) -> Result<VoxCpm2Adapter<Capture>> {
    VoxCpm2Adapter::new(
        Arc::clone(vault),
        "banked-owner",
        "neutral",
        Capture {
            ready: true,
            ..Capture::default()
        },
    )
}

#[test]
fn banked_ref_renders_pcm_and_target_metadata_through_tts_seam() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let vault = Arc::new(vault);
    let owner = bank(&vault)?;
    let mut tts = adapter(&vault)?;
    let generation = epoch(1);
    tts.submit(TtsCommand::Start { generation })?;
    tts.submit(TtsCommand::Text {
        generation,
        text: "hello".into(),
    })?;
    tts.submit(TtsCommand::End { generation })?;
    let target = tts.target().expect("ready render target").clone();
    assert_eq!(target.source_pack, "banked-owner");
    assert_eq!(target.owner, owner);
    assert_eq!(target.register, "neutral");
    assert_eq!(target.warm.model, MODEL);
    assert_eq!(target.warm.sample_rate, 16_000);
    assert_eq!(target.warm.boot_id, "gpu-boot-1");
    assert_eq!(tts.queue.work.len(), 2);
    let VoxCpm2Operation::Start {
        target: queued_target,
        reference,
    } = &tts.queue.work[0].operation
    else {
        panic!("start must carry the banked ref");
    };
    assert_eq!(queued_target.as_ref(), &target);
    assert_eq!(reference.transcript, "reference words");
    assert_eq!(reference.audio, b"RIFF0000WAVEfmt ");
    assert_eq!(
        tts.queue.work[1].operation,
        VoxCpm2Operation::Render {
            text: "hello".into()
        }
    );
    let pcm = tts.handle_pcm(VoxCpm2Audio {
        generation,
        submission: 1,
        chunk_index: 0,
        target: target.clone(),
        channels: 1,
        bytes: &[1, 0, 255, 255],
    })?;
    assert_eq!(pcm.frame.samples, vec![1, -1]);
    assert_eq!(pcm.frame.sample_rate, 16_000);
    assert_eq!(pcm.target, target);
    Ok(())
}

#[test]
fn ref_withdrawal_cold_worker_queue_failure_and_forged_pcm_fail_closed() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let vault = Arc::new(vault);
    bank(&vault)?;
    let generation = epoch(1);
    let mut cold = VoxCpm2Adapter::new(
        Arc::clone(&vault),
        "banked-owner",
        "neutral",
        Capture::default(),
    )?;
    assert!(cold.submit(TtsCommand::Start { generation }).is_err());
    assert!(cold.queue.work.is_empty());
    let mut tts = adapter(&vault)?;
    tts.queue.fail = true;
    assert!(tts.submit(TtsCommand::Start { generation }).is_err());
    assert!(tts.target().is_none());
    tts.submit(TtsCommand::Start { generation })?;
    tts.submit(TtsCommand::Text {
        generation,
        text: "hello".into(),
    })?;
    tts.queue.fail = true;
    assert!(tts.submit(TtsCommand::Flush { generation }).is_err());
    assert_eq!(tts.buffer, "hello");
    tts.submit(TtsCommand::Flush { generation })?;
    let target = tts.target().unwrap().clone();
    let mut forged = target.clone();
    forged.source_pack = "vendor-born".into();
    for (submission, chunk_index, reported_target, bytes) in [
        (1, 0, forged, vec![1, 0]),
        (99, 0, target.clone(), vec![1, 0]),
        (1, 1, target.clone(), vec![1, 0]),
        (1, 0, target.clone(), vec![1]),
    ] {
        assert!(
            tts.handle_pcm(VoxCpm2Audio {
                generation,
                submission,
                chunk_index,
                target: reported_target,
                channels: 1,
                bytes: &bytes
            })
            .is_err()
        );
    }
    tts.queue.fail = true;
    assert!(tts.submit(TtsCommand::Cancel { generation }).is_err());
    assert!(
        tts.handle_pcm(VoxCpm2Audio {
            generation,
            submission: 2,
            chunk_index: 0,
            target,
            channels: 1,
            bytes: &[1, 0]
        })
        .is_err()
    );
    assert!(
        tts.submit(TtsCommand::Text {
            generation,
            text: "late".into()
        })
        .is_err()
    );
    tts.submit(TtsCommand::Cancel { generation })?;
    Ok(())
}

#[test]
fn missing_banked_register_and_withdrawal_refuse_render() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let vault = Arc::new(vault);
    let owner = bank(&vault)?;
    let queue = Capture {
        ready: true,
        ..Capture::default()
    };
    let mut missing = VoxCpm2Adapter::new(Arc::clone(&vault), "banked-owner", "not-banked", queue)?;
    assert!(
        missing
            .submit(TtsCommand::Start {
                generation: epoch(1)
            })
            .is_err()
    );
    assert!(missing.queue.work.is_empty());
    vault.withdraw_voice_consent(&crate::voice_identity::VoiceWithdrawalRequest {
        event_id: "withdraw-voice".into(),
        subject_ref: owner,
        recorded_by_ref: owner,
        occurred_at: 10,
        purposes: vec![crate::voice_identity::VoicePrintPurpose::LiveInterlocutor],
        basis: crate::voice_identity::VoiceConsentBasis::ConversationalNotice {
            notice: "withdraw".into(),
        },
    })?;
    let mut tts = adapter(&vault)?;
    assert!(
        tts.submit(TtsCommand::Start {
            generation: epoch(1)
        })
        .is_err()
    );
    assert!(tts.queue.work.is_empty());
    Ok(())
}
