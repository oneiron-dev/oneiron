use super::*;
use crate::interlocutor::{InterlocutorClass, InterlocutorPartyInput, PresenceEvidence};

#[test]
fn normalized_asr_metadata_round_trips_and_endpoint_does_not_finalize() -> Result<()> {
    let wire = json!({
        "kind": "endpoint", "text": "Tokyo launch", "tokens": [{
            "text": "Tokyo", "is_final": true, "start_ms": 1.5,
            "end_ms": 32.25, "confidence": 0.99
        }],
        "provider_latency_ms": 19.5, "endpoint_delay_ms": 150.0, "error": null
    });
    let decoded: AsrEvent = serde_json::from_value(wire.clone()).expect("normalized event");
    assert_eq!(serde_json::to_value(&decoded).expect("encode"), wire);
    for kind in ["partial", "final", "endpoint", "error", "closed"] {
        let mut shape = wire.clone();
        shape["kind"] = json!(kind);
        assert!(serde_json::from_value::<AsrEvent>(shape).is_ok());
    }
    let (_dir, vault) = vault();
    let mut session = VoiceCascadeSession::new(vault, config())?;
    let handle = session.open_utterance("endpoint", SpeculativeSessionConfig::default())?;
    let mut enricher = Enricher::default();
    let update = session.handle_asr(&handle, 1, decoded, false, &mut enricher)?;
    assert!(matches!(update, AsrUpdate::Endpoint));
    assert!(enricher.texts.is_empty());
    let update = session.handle_asr(
        &handle,
        1,
        event(AsrEventKind::Final, "Tokyo launch"),
        false,
        &mut enricher,
    )?;
    assert!(matches!(update, AsrUpdate::Final(_)));
    let late = session.handle_asr(
        &handle,
        2,
        event(AsrEventKind::Closed, ""),
        false,
        &mut enricher,
    )?;
    assert!(matches!(late, AsrUpdate::Ignored));
    assert!(!session.is_ended());
    Ok(())
}

#[test]
fn final_retrieval_and_existing_interlocutor_identity_semantics_reach_brain() -> Result<()> {
    let (_dir, vault) = vault();
    let result_ref = put_text(&vault, 11, "Tokyo launch")?;
    let mut config = config();
    config.interlocutors.owner_session = false;
    config
        .interlocutors
        .parties
        .push(InterlocutorPartyInput::UnknownLabel {
            label: "claimed owner".to_owned(),
            claimed_owner: true,
        });
    // Existing identity resolver must narrow an unresolved voice roster.
    config.interlocutors.voice_session_ref = Some("missing:roster".to_owned());
    let mut session = VoiceCascadeSession::new(vault, config)?;
    let handle = session.open_utterance("promoted", SpeculativeSessionConfig::default())?;
    let mut enricher = Enricher::default();
    let partial = session.handle_asr(
        &handle,
        1,
        event(AsrEventKind::Partial, "Tokyo launch"),
        false,
        &mut enricher,
    )?;
    assert!(matches!(partial, AsrUpdate::Partial(_)));
    let final_update = session.handle_asr(
        &handle,
        2,
        event(AsrEventKind::Final, "Tokyo launch plan"),
        true,
        &mut enricher,
    )?;
    let AsrUpdate::Final(request) = final_update else {
        panic!("final")
    };
    let mut brain = TestBrain::default();
    brain.start(&request)?;
    assert_eq!(brain.requests[0].retrieval.result_refs, [result_ref]);
    assert!(brain.requests[0].retrieval.promoted);
    assert!(brain.requests[0].retrieval.run_id.is_some());
    assert_eq!(brain.requests[0].transcript, "Tokyo launch plan");
    assert_eq!(brain.requests[0].session_ref, "session:test");
    assert!(brain.requests[0].externally_tainted);
    assert!(!request.interlocutors.supervised());
    assert_eq!(request.interlocutors.entries().len(), 2);
    assert!(request.interlocutors.entries().iter().all(|entry| {
        entry.class() == InterlocutorClass::Unknown
            && entry.evidence() == PresenceEvidence::FirstClaim
    }));
    assert!(
        request
            .interlocutors
            .stamps()
            .iter()
            .all(|stamp| stamp.claims_not_instructions)
    );
    assert!(
        !session.close_utterance(&handle),
        "final consumed the handle"
    );
    Ok(())
}

#[test]
fn sustained_speech_resets_on_silence_then_flushes_all_old_output() -> Result<()> {
    let (_dir, vault) = vault();
    let mut session = VoiceCascadeSession::new(vault, config())?;
    let old = start(&mut session, false)?.generation;
    let incoming = session.open_utterance("incoming", SpeculativeSessionConfig::default())?;
    let mut control = TestControl::default();
    control.queued.push_back(pcm(old));
    control.client_queued.push(pcm(old));
    assert!(session.observe_speech(Duration::ZERO, true)?.is_none());
    assert!(
        session
            .observe_speech(Duration::from_millis(119), true)?
            .is_none()
    );
    assert!(session.accepts_pcm(old));
    assert!(
        session
            .observe_speech(Duration::from_millis(120), false)?
            .is_none()
    );
    assert!(
        session
            .observe_speech(Duration::from_millis(121), true)?
            .is_none()
    );
    assert!(
        session
            .observe_speech(Duration::from_millis(240), true)?
            .is_none()
    );
    assert!(
        session
            .observe_speech(Duration::from_millis(239), true)
            .is_err()
    );
    let stop = session
        .observe_speech(Duration::from_millis(241), true)?
        .expect("120ms hold");
    assert_eq!(stop.reason, StopReason::UserBargeIn);
    assert_eq!(stop.generation, Some(old));
    assert!(stop.kill.cancel_llm && stop.kill.cancel_tts && stop.kill.flush_playout_buffer);
    assert!(
        !session.accepts_pcm(old),
        "closed before any external submission"
    );
    let mut brain = TestBrain::default();
    let mut tts = TestTts::default();
    assert!(stop.dispatch(&mut brain, &mut tts, &mut control).is_empty());
    assert_eq!(brain.cancelled, [old]);
    assert_eq!(tts.commands, [TtsCommand::Cancel { generation: old }]);
    assert_eq!(control.flushed, [old]);
    assert!(control.queued.is_empty() && control.client_queued.is_empty());
    assert_eq!(
        control.events,
        [ControlEvent::PlayoutStop {
            generation: old,
            reason: StopReason::UserBargeIn
        }]
    );
    assert!(
        session
            .observe_speech(Duration::from_millis(400), true)?
            .is_none()
    );
    // Barge-in must NOT close the incoming user's speculative utterance.
    let mut enricher = Enricher::default();
    let final_update = session.handle_asr(
        &incoming,
        1,
        event(AsrEventKind::Final, "Tokyo launch"),
        false,
        &mut enricher,
    )?;
    let AsrUpdate::Final(request) = final_update else {
        panic!("incoming final")
    };
    assert!(request.generation.value() > old.value());
    assert!(session.filter_pcm(pcm(request.generation)).is_some());
    assert!(session.filter_pcm(pcm(old)).is_none());
    for event in [
        BrainEvent::TextDelta("late".to_owned()),
        call("late"),
        result("late"),
        BrainEvent::Done,
        BrainEvent::Error("late".to_owned()),
    ] {
        assert!(session.handle_brain(old, event, true)?.is_none());
    }
    assert!(
        session
            .complete_sentence(old, "Late sentence.".to_owned())?
            .is_none()
    );
    assert!(
        session
            .brain_context(request.generation)
            .expect("current")
            .tool_events
            .is_empty()
    );
    Ok(())
}

#[test]
fn configured_hold_boundaries_and_foreign_epoch_are_enforced() -> Result<()> {
    let (_dir, vault) = vault();
    for milliseconds in [99, 151] {
        let mut config = config();
        config.barge_in_hold = Duration::from_millis(milliseconds);
        assert!(VoiceCascadeSession::new(Arc::clone(&vault), config).is_err());
    }
    for milliseconds in [100, 150] {
        let mut config = config();
        config.barge_in_hold = Duration::from_millis(milliseconds);
        let mut session = VoiceCascadeSession::new(Arc::clone(&vault), config)?;
        let generation = start(&mut session, false)?.generation;
        assert!(session.observe_speech(Duration::ZERO, true)?.is_none());
        assert!(
            session
                .observe_speech(Duration::from_millis(milliseconds - 1), true)?
                .is_none()
        );
        let stop = session
            .observe_speech(Duration::from_millis(milliseconds), true)?
            .expect("threshold");
        assert_eq!(stop.generation, Some(generation));
    }
    let mut first = VoiceCascadeSession::new(Arc::clone(&vault), config())?;
    let mut second = VoiceCascadeSession::new(vault, config())?;
    let foreign = start(&mut first, false)?.generation;
    let own = start(&mut second, false)?.generation;
    assert_eq!(foreign.value(), own.value());
    assert_ne!(foreign, own);
    assert!(!second.accepts_pcm(foreign));
    assert!(
        second
            .handle_brain(foreign, call("foreign"), false)?
            .is_none()
    );
    Ok(())
}

#[test]
fn tool_events_are_ordered_in_brain_context_and_taint_never_clears() -> Result<()> {
    let (_dir, vault) = vault();
    let mut session = VoiceCascadeSession::new(vault, config())?;
    let request = start(&mut session, false)?;
    let generation = request.generation;
    let mut brain = TestBrain::default();
    brain.start(&request)?;
    assert!(
        session
            .handle_brain(generation, result("one"), true)
            .is_err()
    );
    assert!(
        session
            .brain_context(generation)
            .expect("context")
            .tool_events
            .is_empty()
    );
    assert_eq!(
        session.handle_brain(generation, call("one"), false)?,
        Some(call("one"))
    );
    assert!(
        session
            .handle_brain(generation, call("one"), false)
            .is_err()
    );
    assert!(
        session
            .handle_brain(generation, BrainEvent::Done, false)
            .is_err()
    );
    assert!(
        session
            .handle_brain(generation, call("two"), false)?
            .is_some()
    );
    assert!(
        session
            .handle_brain(generation, result("two"), true)?
            .is_some()
    );
    assert!(
        session
            .handle_brain(generation, result("two"), false)
            .is_err()
    );
    assert!(
        session
            .handle_brain(generation, result("one"), false)?
            .is_some()
    );
    let context = session.brain_context(generation).expect("context");
    brain.update_context(context)?;
    let expected: Vec<_> = [call("one"), call("two"), result("two"), result("one")]
        .into_iter()
        .map(|event| {
            let BrainEvent::Tool(tool) = event else {
                panic!("tool")
            };
            tool
        })
        .collect();
    assert_eq!(brain.contexts[0].tool_events, expected);
    assert_eq!(brain.contexts[0].retrieval, request.retrieval);
    assert!(brain.contexts[0].externally_tainted);
    let work = session
        .complete_sentence(generation, "Tool-grounded sentence.".to_owned())?
        .expect("sentence");
    assert!(work.needs_safeguard());
    assert!(
        session
            .handle_brain(generation, BrainEvent::Done, false)?
            .is_some()
    );
    assert!(
        session
            .handle_brain(generation, call("late"), false)?
            .is_none()
    );
    assert!(
        session.finish_playout(generation).is_err(),
        "guard is still pending"
    );
    Ok(())
}

#[test]
fn disabled_tools_and_busy_final_do_not_advance_or_consume_context() -> Result<()> {
    let (_dir, vault) = vault();
    let mut config = config();
    config.tools_enabled = false;
    let mut session = VoiceCascadeSession::new(vault, config)?;
    let generation = start(&mut session, false)?.generation;
    assert!(
        session
            .handle_brain(generation, call("disabled"), false)
            .is_err()
    );
    let next = session.open_utterance("next", SpeculativeSessionConfig::default())?;
    let mut enricher = Enricher::default();
    assert!(
        session
            .handle_asr(
                &next,
                1,
                event(AsrEventKind::Final, "Tokyo launch"),
                false,
                &mut enricher
            )
            .is_err()
    );
    assert!(
        enricher.texts.is_empty(),
        "busy final does not spend retrieval"
    );
    assert!(session.finish_playout(generation).is_err());
    assert_eq!(
        session.handle_brain(generation, BrainEvent::Done, false)?,
        Some(BrainEvent::Done)
    );
    assert!(
        session.accepts_pcm(generation),
        "TTS can finish after brain done"
    );
    assert!(session.finish_playout(generation)?);
    assert!(!session.finish_playout(generation)?);
    assert!(!session.accepts_pcm(generation));
    let update = session.handle_asr(
        &next,
        1,
        event(AsrEventKind::Final, "Tokyo launch"),
        false,
        &mut enricher,
    )?;
    assert!(
        matches!(update, AsrUpdate::Final(_)),
        "same final revision was retryable"
    );
    Ok(())
}

#[test]
fn normal_end_is_idempotent_drops_context_handles_and_is_not_barge_in() -> Result<()> {
    let (_dir, vault) = vault();
    let weak = Arc::downgrade(&vault);
    let mut session = VoiceCascadeSession::new(vault, config())?;
    let generation = start(&mut session, true)?.generation;
    assert!(
        session
            .handle_brain(generation, call("pending"), true)?
            .is_some()
    );
    let handle = session.open_utterance("unfinished", SpeculativeSessionConfig::default())?;
    let mut enricher = Enricher::default();
    let partial = session.handle_asr(
        &handle,
        1,
        event(AsrEventKind::Partial, "Tokyo launch"),
        false,
        &mut enricher,
    )?;
    assert!(matches!(partial, AsrUpdate::Partial(_)));
    let stop = session.end();
    assert_eq!(stop.reason, StopReason::SessionEnd);
    assert!(session.is_ended());
    assert!(session.brain_context(generation).is_none());
    assert!(!session.close_utterance(&handle));
    assert!(session.filter_pcm(pcm(generation)).is_none());
    assert!(
        session
            .open_utterance("late", SpeculativeSessionConfig::default())
            .is_err()
    );
    let late = session.handle_asr(
        &handle,
        2,
        event(AsrEventKind::Final, "late"),
        true,
        &mut enricher,
    )?;
    assert!(matches!(late, AsrUpdate::Ignored));
    let mut brain = TestBrain::default();
    let mut tts = TestTts::default();
    let mut control = TestControl::default();
    control.queued.push_back(pcm(generation));
    control.client_queued.push(pcm(generation));
    assert!(stop.dispatch(&mut brain, &mut tts, &mut control).is_empty());
    assert!(control.queued.is_empty() && control.client_queued.is_empty());
    assert_eq!(control.events, [ControlEvent::SessionEnded]);
    let again = session.end();
    assert_eq!(again.generation, None);
    assert!(
        again
            .dispatch(&mut brain, &mut tts, &mut control)
            .is_empty()
    );
    assert_eq!(brain.cancelled, [generation]);
    drop(session);
    assert!(
        weak.upgrade().is_none(),
        "no hidden worker retains the vault"
    );
    Ok(())
}
