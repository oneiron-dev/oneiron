use super::*;
use crate::voice_identity::ref_bank::{VoiceRefOrigin, VoiceRefPack};
use std::sync::Arc;

#[derive(Default)]
struct Capture {
    work: Vec<VoxCpm2Work>,
    ready: bool,
    fail: bool,
    limits: Option<VoiceServingLimits>,
}
impl VoxCpm2Queue for Capture {
    fn warm_target(&self) -> Result<WarmTarget> {
        if !self.ready {
            return Err(invalid("GPU worker not ready"));
        }
        Ok(WarmTarget {
            limits: self
                .limits
                .ok_or_else(|| invalid("test serving policy missing"))?,
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
    // Ref admission resolves the voice-ref policy rows: seed them first.
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &crate::gate::default_policy_manifest().unwrap(),
    )?;
    vault.store_voice_ref_pack(&VoiceRefPack {
        version: 1,
        id: "banked-owner".into(),
        voice_id: "owner-voice".into(),
        owner,
        origin: VoiceRefOrigin::Captured,
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
        "owner-voice",
        "neutral",
        Capture {
            ready: true,
            limits: Some(vault.voice_serving_limits(None)?),
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
    assert_eq!(target.voice_id, "owner-voice");
    assert_eq!(target.fence.owner, owner);
    assert_eq!(target.register, "neutral");
    assert_eq!(target.warm.model, MODEL);
    assert_eq!(target.warm.sample_rate, 16_000);
    assert_eq!(target.warm.boot_id, "gpu-boot-1");
    assert_eq!(tts.queue.work.len(), 2);
    let VoxCpm2Operation::Start {
        target: queued_target,
    } = &tts.queue.work[0].operation
    else {
        panic!("start must carry the banked ref");
    };
    assert_eq!(queued_target.as_ref(), &target);
    assert_eq!(
        target.fence,
        vault
            .prepare_fenced_voice_clone("owner-voice", TARGET, false)?
            .1
    );
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
        "owner-voice",
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
    tts.submit(TtsCommand::Flush { generation })?;
    assert_eq!(
        tts.queue.work.last().unwrap().operation,
        VoxCpm2Operation::Render {
            text: "hello".into()
        }
    );
    let target = tts.target().unwrap().clone();
    let mut forged = target.clone();
    forged.voice_id = "vendor-born".into();
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
        limits: Some(vault.voice_serving_limits(None)?),
        ..Capture::default()
    };
    let mut missing = VoxCpm2Adapter::new(Arc::clone(&vault), "owner-voice", "not-banked", queue)?;
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

#[test]
fn withdrawal_after_start_revokes_even_identical_rebank() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let vault = Arc::new(vault);
    let owner = bank(&vault)?;
    let generation = epoch(1);
    let mut tts = adapter(&vault)?;
    tts.submit(TtsCommand::Start { generation })?;
    let old = tts.target().unwrap().clone();
    vault.withdraw_voice_consent(&crate::voice_identity::VoiceWithdrawalRequest {
        event_id: "withdraw-after-start".into(),
        subject_ref: owner,
        recorded_by_ref: owner,
        occurred_at: 11,
        purposes: vec![crate::voice_identity::VoicePrintPurpose::LiveInterlocutor],
        basis: crate::voice_identity::VoiceConsentBasis::ConversationalNotice {
            notice: "withdraw".into(),
        },
    })?;
    tts.submit(TtsCommand::Text {
        generation,
        text: "later".into(),
    })?;
    tts.submit(TtsCommand::End { generation })?;
    assert!(
        tts.queue
            .work
            .iter()
            .any(|work| matches!(work.operation, VoxCpm2Operation::Render { .. }))
    );
    // Admission remains nonblocking. The queued render still cannot upload:
    // the sender re-reads the exact revision before dispatch.
    assert!(
        tts.handle_pcm(VoxCpm2Audio {
            generation,
            submission: 1,
            chunk_index: 0,
            target: old.clone(),
            channels: 1,
            bytes: &[1, 0]
        })
        .is_err()
    );
    assert!(!old.is_current_in(&vault));
    // A rebank of IDENTICAL PCM and transcript must not resurrect old work.
    vault.store_voice_ref_pack(&VoiceRefPack {
        version: 1,
        id: "banked-owner".into(),
        voice_id: "owner-voice".into(),
        owner,
        origin: VoiceRefOrigin::Captured,
        clips: vec![VoiceRegisterClip {
            register: "neutral".into(),
            media_type: "audio/wav".into(),
            audio: b"RIFF0000WAVEfmt ".to_vec(),
            transcript: "reference words".into(),
        }],
    })?;
    assert!(!old.is_current_in(&vault));
    let mut fresh = adapter(&vault)?;
    fresh.submit(TtsCommand::Start {
        generation: epoch(2),
    })?;
    // Same refs, new incarnation: only the identity's rebirth tells them apart.
    let fresh = &fresh.target().unwrap().fence;
    assert_eq!(old.fence.ref_digest, fresh.ref_digest);
    assert_ne!(old.fence.incarnation, fresh.incarnation);
    Ok(())
}

#[test]
fn resolved_serving_row_narrows_and_widening_holder_is_refused() -> Result<()> {
    use rmpv::Value;
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let holder = EntityId::now();
    let bytes = crate::gate::default_policy_manifest().unwrap();
    let mut value =
        rmpv::decode::read_value(&mut bytes.as_slice()).map_err(|e| invalid(&e.to_string()))?;
    let Value::Map(entries) = &mut value else {
        panic!("seed manifest");
    };
    let (_, serving) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("voice_serving"))
        .expect("serving manifest row");
    let Value::Map(fields) = serving else {
        panic!("serving row");
    };
    let (_, vault_limits) = fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("vault"))
        .expect("vault ceiling");
    let Value::Map(limits) = vault_limits else {
        panic!("limits");
    };
    limits
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("max_text_bytes"))
        .unwrap()
        .1 = Value::from(4096);
    let holder_limits = vault_limits.clone();
    fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("holders"))
        .unwrap()
        .1 = Value::Array(vec![Value::Map(vec![
        (Value::from("holder"), Value::from(holder.to_hex())),
        (Value::from("limits"), holder_limits),
    ])]);
    let bad = crate::gate::voice_serving::VoiceServingRows::decode(serving).expect("parsed row");
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &value).map_err(|e| invalid(&e.to_string()))?;
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &encoded,
    )?;
    assert_eq!(vault.voice_serving_limits(None)?.max_text_bytes, 4096);
    assert_eq!(
        vault.voice_serving_limits(Some(holder))?.max_text_bytes,
        4096
    );
    let owner = EntityId::now();
    vault.store_voice_ref_pack(&VoiceRefPack {
        version: 1,
        id: "banked-owner".into(),
        voice_id: "owner-voice".into(),
        owner,
        origin: VoiceRefOrigin::Captured,
        clips: vec![VoiceRegisterClip {
            register: "neutral".into(),
            media_type: "audio/wav".into(),
            audio: b"RIFF0000WAVEfmt ".to_vec(),
            transcript: "reference words".into(),
        }],
    })?;
    let vault = Arc::new(vault);
    let generation = epoch(1);
    let mut tts = VoxCpm2Adapter::new_for_holder(
        Arc::clone(&vault),
        "owner-voice",
        "neutral",
        Some(holder),
        Capture {
            ready: true,
            limits: Some(vault.voice_serving_limits(None)?),
            ..Capture::default()
        },
    )?;
    tts.submit(TtsCommand::Start { generation })?;
    assert!(
        tts.submit(TtsCommand::Text {
            generation,
            text: "x".repeat(4097)
        })
        .is_err()
    );
    tts.submit(TtsCommand::Text {
        generation,
        text: "x".repeat(4096),
    })?;
    tts.submit(TtsCommand::End { generation })?;
    assert_eq!(
        tts.queue.work.last().unwrap().operation,
        VoxCpm2Operation::Render {
            text: "x".repeat(4096)
        }
    );
    // A separate trusted row cannot grant this holder more than the vault.
    let mut widened = bad.clone();
    widened.holders[0].1.max_text_bytes = 8192;
    assert!(crate::gate::voice_serving::resolve(&[bad, widened], Some(holder)).is_err());
    Ok(())
}

#[test]
fn pending_withdrawal_does_not_wait_for_gpu_during_sentence_and_safeguard_submission() -> Result<()>
{
    use crate::policy_model::PolicyClassifyRequest;
    use crate::voice_cascade::{Safeguard, SafeguardRequest, SentenceWork};
    use std::{
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };
    struct CaptureSafeguard(Vec<GenerationEpoch>);
    impl Safeguard for CaptureSafeguard {
        fn submit(&mut self, request: SafeguardRequest) -> Result<()> {
            self.0.push(request.generation());
            Ok(())
        }
    }
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let vault = Arc::new(vault);
    let owner = bank(&vault)?;
    let generation = epoch(1);
    let mut tts = adapter(&vault)?;
    tts.submit(TtsCommand::Start { generation })?;
    let target = tts.target().expect("target").clone();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker_vault = Arc::clone(&vault);
    let worker = thread::spawn(move || {
        target.with_current(&worker_vault, |_| {
            entered_tx.send(()).map_err(|_| invalid("test signal"))?;
            release_rx
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| invalid("test release timeout"))?;
            Ok(())
        })
    });
    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .map_err(|_| invalid("worker did not start"))?;
    let writer_vault = Arc::clone(&vault);
    let writer = thread::spawn(move || {
        writer_vault.withdraw_voice_consent(&crate::voice_identity::VoiceWithdrawalRequest {
            event_id: "withdraw-during-gpu".into(),
            subject_ref: owner,
            recorded_by_ref: owner,
            occurred_at: 15,
            purposes: vec![crate::voice_identity::VoicePrintPurpose::LiveInterlocutor],
            basis: crate::voice_identity::VoiceConsentBasis::ConversationalNotice {
                notice: "withdraw".into(),
            },
        })
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    while vault.voice_ref_guard.try_read().is_ok() {
        assert!(
            Instant::now() < deadline,
            "writer must wait for in-flight render"
        );
        thread::yield_now();
    }
    let work = SentenceWork {
        generation,
        text: "parallel sentence".into(),
        safeguard: Some(SafeguardRequest {
            vault: Arc::clone(&vault),
            generation,
            sentence: 1,
            request: PolicyClassifyRequest::outbound_content("parallel sentence"),
        }),
    };
    let started = Instant::now();
    let mut safeguard = CaptureSafeguard(Vec::new());
    let errors = work.dispatch(&mut tts, &mut safeguard);
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "TTS submission must not wait for the GPU or withdrawal"
    );
    assert!(errors.is_empty(), "parallel submission errors: {errors:?}");
    assert_eq!(safeguard.0, [generation]);
    assert_eq!(
        tts.queue.work.last().unwrap().operation,
        VoxCpm2Operation::Render {
            text: "parallel sentence".into()
        }
    );
    let target = tts.target().unwrap().clone();
    let output_started = Instant::now();
    assert!(
        tts.handle_pcm(VoxCpm2Audio {
            generation,
            submission: 1,
            chunk_index: 0,
            target,
            channels: 1,
            bytes: &[1, 0],
        })
        .is_err()
    );
    assert!(
        output_started.elapsed() < Duration::from_millis(250),
        "PCM admission must fail closed without waiting for the GPU"
    );
    release_tx.send(()).map_err(|_| invalid("test release"))?;
    worker.join().map_err(|_| invalid("worker panic"))??;
    writer.join().map_err(|_| invalid("writer panic"))??;
    assert!(!tts.target().unwrap().is_current_in(&vault));
    Ok(())
}
