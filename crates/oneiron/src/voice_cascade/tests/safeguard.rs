use super::*;
use crate::gate;
use crate::policy_model::{PolicyEnforcementAction, PolicyModelConfig};

fn install_policy(vault: &Vault, action: &str) -> Result<()> {
    // Test-owned policy only. The cascade itself supplies no rules or persona.
    let manifest = json!({
        "schema_version": "1.1",
        "pack_id": "voice-cascade-fixture",
        "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [],
        "actor_ceilings": [{"actor_class": "human", "ceiling": "auto"}],
        (gate::POLICY_OWNER_POLICY_ENABLED_KEY): true,
        (gate::POLICY_OWNER_POLICY_ROWS_KEY): [{
            (gate::POLICY_ROW_REF_KEY): "owner:fixture",
            (gate::POLICY_ROW_TEXT_KEY): "Fixture content rule.",
            (gate::POLICY_ROW_ACTION_KEY): action,
            (gate::POLICY_ROW_ACTIVE_KEY): true
        }],
        (gate::POLICY_OWNER_POLICY_PATTERNS_KEY): [{
            "id": "fixture.rule", "pattern": "restricted",
            "category": "owner:fixture", "role": "decide"
        }]
    });
    let bytes = rmp_serde::to_vec_named(&manifest).expect("fixture manifest");
    crate::test_util::put_policy_manifest_bytes(vault, gate::default_policy_manifest_id()?, &bytes)
}

fn submit_sentence(
    session: &mut VoiceCascadeSession,
    generation: GenerationEpoch,
    text: &str,
    tts: &mut TestTts,
    safeguard: &mut TestSafeguard,
) -> Result<()> {
    let work = session
        .complete_sentence(generation, text.to_owned())?
        .expect("sentence accepted");
    assert!(work.dispatch(tts, safeguard).is_empty());
    Ok(())
}

#[test]
fn tainted_sentence_starts_tts_while_guard_pending_then_real_block_flushes() -> Result<()> {
    let (_dir, vault) = vault();
    install_policy(&vault, "block")?;
    let mut session = VoiceCascadeSession::new(vault, config())?;
    let generation = start(&mut session, true)?.generation;
    let mut tts = TestTts::default();
    let mut safeguard = TestSafeguard::default();
    tts.submit(TtsCommand::Start { generation })?;
    submit_sentence(
        &mut session,
        generation,
        "restricted sentence.",
        &mut tts,
        &mut safeguard,
    )?;
    assert_eq!(
        tts.commands,
        [
            TtsCommand::Start { generation },
            TtsCommand::Text {
                generation,
                text: "restricted sentence.".to_owned()
            },
            TtsCommand::Flush { generation },
        ]
    );
    assert_eq!(safeguard.pending.len(), 1);
    assert_eq!(
        safeguard.pending[0].request().content,
        "restricted sentence."
    );
    // No verdict has run: first PCM is not gated on safeguard completion.
    let first_pcm = session
        .filter_pcm(pcm(generation))
        .expect("parallel first audio");
    let mut control = TestControl::default();
    control.queued.push_back(first_pcm);
    control.client_queued.push(pcm(generation));
    let outcome = safeguard
        .pending
        .remove(0)
        .enforce(&PolicyModelConfig::default())?;
    assert_eq!(outcome.enforcement().action, PolicyEnforcementAction::Block);
    assert!(outcome.enforcement().receipt_ref.is_some());
    assert!(outcome.enforcement().final_content.is_none());
    let update = session.apply_safeguard(outcome).expect("matched sentence");
    assert!(matches!(
        update.control,
        ControlEvent::Safeguard {
            action: PolicyEnforcementAction::Block,
            ..
        }
    ));
    let stop = update.stop.expect("blocking stop");
    assert_eq!(stop.reason, StopReason::Safeguard);
    assert!(
        !session.accepts_pcm(generation),
        "invalidation precedes delivery"
    );
    let mut brain = TestBrain::default();
    assert!(stop.dispatch(&mut brain, &mut tts, &mut control).is_empty());
    assert_eq!(brain.cancelled, [generation]);
    assert!(tts.commands.contains(&TtsCommand::Cancel { generation }));
    assert!(control.queued.is_empty() && control.client_queued.is_empty());
    assert!(session.filter_pcm(pcm(generation)).is_none());
    assert!(
        session
            .complete_sentence(generation, "late".to_owned())?
            .is_none()
    );
    assert!(
        session
            .handle_brain(generation, BrainEvent::TextDelta("late".to_owned()), false)?
            .is_none()
    );
    Ok(())
}

#[test]
fn untainted_skips_guard_and_host_taint_is_monotonic() -> Result<()> {
    let (_dir, vault) = vault();
    install_policy(&vault, "block")?;
    let mut session = VoiceCascadeSession::new(vault, config())?;
    let generation = start(&mut session, false)?.generation;
    let mut tts = TestTts::default();
    let mut safeguard = TestSafeguard::default();
    let work = session
        .complete_sentence(generation, "restricted but untainted.".to_owned())?
        .expect("sentence");
    assert!(!work.needs_safeguard());
    assert!(work.dispatch(&mut tts, &mut safeguard).is_empty());
    assert!(
        safeguard.pending.is_empty(),
        "untainted has zero classify calls"
    );
    assert_eq!(tts.commands.len(), 2);
    assert!(session.taint_context(generation));
    assert!(
        session
            .handle_brain(generation, BrainEvent::TextDelta("more".to_owned()), false)?
            .is_some()
    );
    submit_sentence(
        &mut session,
        generation,
        "restricted and tainted.",
        &mut tts,
        &mut safeguard,
    )?;
    assert_eq!(safeguard.pending.len(), 1);
    Ok(())
}

#[test]
fn policy_cancel_llm_false_keeps_brain_context_but_cannot_resume_old_audio() -> Result<()> {
    let (_dir, vault) = vault();
    install_policy(&vault, "block")?;
    let mut session = VoiceCascadeSession::new(vault, config())?;
    let generation = start(&mut session, true)?.generation;
    assert!(
        session
            .handle_brain(generation, call("one"), false)?
            .is_some()
    );
    let mut tts = TestTts::default();
    let mut safeguard = TestSafeguard::default();
    submit_sentence(
        &mut session,
        generation,
        "restricted sentence.",
        &mut tts,
        &mut safeguard,
    )?;
    let mut outcome = safeguard
        .pending
        .remove(0)
        .enforce(&PolicyModelConfig::default())?;
    // Current engine block asks for full flush. Exercise the public kill
    // contract's optional LLM arm without inventing a second classifier.
    outcome
        .enforcement
        .barge_in_kill
        .as_mut()
        .expect("engine kill")
        .cancel_llm = false;
    let stop = session
        .apply_safeguard(outcome)
        .expect("verdict")
        .stop
        .expect("stop");
    assert!(!stop.kill.cancel_llm);
    assert!(stop.kill.cancel_tts && stop.kill.flush_playout_buffer);
    let mut brain = TestBrain::default();
    let mut control = TestControl::default();
    assert!(stop.dispatch(&mut brain, &mut tts, &mut control).is_empty());
    assert!(brain.cancelled.is_empty());
    assert!(
        session
            .handle_brain(generation, result("one"), true)?
            .is_some()
    );
    brain.update_context(
        session
            .brain_context(generation)
            .expect("retained brain context"),
    )?;
    assert_eq!(brain.contexts[0].tool_events.len(), 2);
    assert!(
        session
            .handle_brain(
                generation,
                BrainEvent::TextDelta("do not speak".to_owned()),
                false
            )?
            .is_none()
    );
    assert!(
        session
            .complete_sentence(generation, "Do not speak.".to_owned())?
            .is_none()
    );
    assert!(!session.accepts_pcm(generation));
    assert!(
        session
            .handle_brain(generation, BrainEvent::Done, false)?
            .is_some()
    );
    assert!(session.finish_playout(generation)?);
    let next = start(&mut session, false)?.generation;
    assert!(next.value() > generation.value());
    assert!(session.accepts_pcm(next));
    assert!(!session.accepts_pcm(generation));
    Ok(())
}

#[test]
fn late_verdict_cannot_kill_new_generation_and_duplicate_is_ignored() -> Result<()> {
    let (_dir, vault) = vault();
    install_policy(&vault, "block")?;
    let mut session = VoiceCascadeSession::new(vault, config())?;
    let old = start(&mut session, true)?.generation;
    let mut tts = TestTts::default();
    let mut safeguard = TestSafeguard::default();
    submit_sentence(
        &mut session,
        old,
        "restricted sentence.",
        &mut tts,
        &mut safeguard,
    )?;
    let outcome = safeguard
        .pending
        .remove(0)
        .enforce(&PolicyModelConfig::default())?;
    assert!(session.observe_speech(Duration::ZERO, true)?.is_none());
    let stop = session
        .observe_speech(Duration::from_millis(120), true)?
        .expect("barge-in");
    let mut brain = TestBrain::default();
    let mut control = TestControl::default();
    assert!(stop.dispatch(&mut brain, &mut tts, &mut control).is_empty());
    let next = start(&mut session, true)?.generation;
    assert!(session.apply_safeguard(outcome).is_none());
    assert!(session.accepts_pcm(next));
    submit_sentence(
        &mut session,
        next,
        "ordinary sentence.",
        &mut tts,
        &mut safeguard,
    )?;
    let allow = safeguard
        .pending
        .remove(0)
        .enforce(&PolicyModelConfig::default())?;
    let duplicate = SentenceEnforcement {
        generation: allow.generation,
        sentence: allow.sentence,
        enforcement: allow.enforcement.clone(),
    };
    assert!(
        session
            .apply_safeguard(allow)
            .expect("allow")
            .stop
            .is_none()
    );
    assert!(session.apply_safeguard(duplicate).is_none());
    assert!(session.accepts_pcm(next));
    Ok(())
}

#[test]
fn warn_is_backend_status_and_done_keeps_pending_block_reachable() -> Result<()> {
    let (_dir, vault) = vault();
    install_policy(&vault, "warn")?;
    let mut session = VoiceCascadeSession::new(Arc::clone(&vault), config())?;
    let generation = start(&mut session, true)?.generation;
    let mut tts = TestTts::default();
    let mut safeguard = TestSafeguard::default();
    submit_sentence(
        &mut session,
        generation,
        "restricted sentence.",
        &mut tts,
        &mut safeguard,
    )?;
    let outcome = safeguard
        .pending
        .remove(0)
        .enforce(&PolicyModelConfig::default())?;
    assert_eq!(
        outcome.enforcement().final_content.as_deref(),
        Some("restricted sentence.")
    );
    let update = session.apply_safeguard(outcome).expect("warn");
    assert!(update.stop.is_none());
    assert!(matches!(
        update.control,
        ControlEvent::Safeguard {
            action: PolicyEnforcementAction::Warn,
            ..
        }
    ));
    assert_eq!(
        tts.commands.len(),
        2,
        "no replacement or persona warning sentence"
    );
    install_policy(&vault, "block")?;
    submit_sentence(
        &mut session,
        generation,
        "restricted next sentence.",
        &mut tts,
        &mut safeguard,
    )?;
    assert!(
        session
            .handle_brain(generation, BrainEvent::Done, false)?
            .is_some()
    );
    assert!(session.finish_playout(generation).is_err());
    let outcome = safeguard
        .pending
        .remove(0)
        .enforce(&PolicyModelConfig::default())?;
    let stop = session
        .apply_safeguard(outcome)
        .expect("block after done")
        .stop
        .expect("stop");
    assert_eq!(stop.generation, Some(generation));
    assert!(!session.accepts_pcm(generation));
    Ok(())
}

#[test]
fn failed_cancel_arms_do_not_skip_queue_or_client_flush() -> Result<()> {
    let (_dir, vault) = vault();
    let mut session = VoiceCascadeSession::new(vault, config())?;
    let generation = start(&mut session, false)?.generation;
    assert!(session.observe_speech(Duration::ZERO, true)?.is_none());
    let stop = session
        .observe_speech(Duration::from_millis(120), true)?
        .expect("stop");
    let mut brain = TestBrain {
        fail_cancel: true,
        ..TestBrain::default()
    };
    let mut tts = TestTts {
        fail_cancel: true,
        ..TestTts::default()
    };
    let mut control = TestControl::default();
    control.queued.push_back(pcm(generation));
    control.client_queued.push(pcm(generation));
    let errors = stop.dispatch(&mut brain, &mut tts, &mut control);
    assert_eq!(errors.len(), 2);
    assert_eq!(brain.cancelled, [generation]);
    assert_eq!(tts.commands, [TtsCommand::Cancel { generation }]);
    assert!(control.queued.is_empty() && control.client_queued.is_empty());
    assert!(!session.accepts_pcm(generation));
    assert!(matches!(
        control.events[0],
        ControlEvent::PlayoutStop { .. }
    ));
    Ok(())
}
