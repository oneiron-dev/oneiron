use super::*;
use crate::interlocutor::{InterlocutorClass, InterlocutorPartyInput, PresenceEvidence};
use crate::llm::ContentPart;

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
fn idle_continuous_speech_can_interrupt_output_started_by_asr_final() -> Result<()> {
    let (_dir, vault) = vault();
    let mut session = VoiceCascadeSession::new(vault, config())?;
    let handle = session.open_utterance("idle-speech", SpeculativeSessionConfig::default())?;
    for milliseconds in [0, 119, 120, 400] {
        assert!(
            session
                .observe_speech(Duration::from_millis(milliseconds), true)?
                .is_none(),
            "idle speech must not consume the interruption latch"
        );
    }
    let mut enricher = Enricher::default();
    let update = session.handle_asr(
        &handle,
        1,
        event(AsrEventKind::Final, "Tokyo launch"),
        false,
        &mut enricher,
    )?;
    let AsrUpdate::Final(request) = update else {
        panic!("final starts output")
    };
    let generation = request.generation;
    assert!(session.accepts_pcm(generation));
    // No intervening silence or new hold: this is still the idle speech interval.
    let stop = session
        .observe_speech(Duration::from_millis(401), true)?
        .expect("sustained speech must stop the new output");
    assert_eq!(stop.reason, StopReason::UserBargeIn);
    assert_eq!(stop.generation, Some(generation));
    assert!(stop.kill.cancel_llm && stop.kill.cancel_tts && stop.kill.flush_playout_buffer);
    assert!(session.filter_pcm(pcm(generation)).is_none());
    assert!(session.brain_context(generation).is_none());
    assert!(
        session
            .observe_speech(Duration::from_millis(402), true)?
            .is_none(),
        "only an actual stop consumes the latch"
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
fn tool_results_preserve_all_json_kinds_and_error_bits_in_brain_context() -> Result<()> {
    let (_dir, vault) = vault();
    let mut session = VoiceCascadeSession::new(vault, config())?;
    let request = start(&mut session, false)?;
    let generation = request.generation;
    let mut brain = TestBrain::default();
    brain.start(&request)?;
    let mut expected = Vec::new();
    for output in [
        json!(null),
        json!(false),
        json!(true),
        json!(42),
        json!(-7),
        json!(1.5),
        json!("plain text"),
        json!([]),
        json!(["ref", 1, null, {"nested": true}]),
        json!({"refs": ["tool:result"]}),
    ] {
        for is_error in [false, true] {
            let original = ContentPart::ToolResult {
                call_id: format!("result-{}", expected.len()),
                output: output.clone(),
                is_error,
            };
            let ContentPart::ToolResult {
                call_id,
                output,
                is_error,
            } = original.clone()
            else {
                panic!("provider-neutral tool result")
            };
            // Accepting arbitrary result JSON must not relax invocation inputs.
            if !output.is_object() {
                let invalid_call = BrainEvent::Tool(ToolEvent::Call {
                    call_id: call_id.clone(),
                    name: "lookup".to_owned(),
                    input: output.clone(),
                });
                assert!(
                    session
                        .handle_brain(generation, invalid_call, false)
                        .is_err()
                );
            }
            let result = BrainEvent::Tool(ToolEvent::Result {
                call_id: call_id.clone(),
                output,
                is_error,
            });
            assert!(
                session
                    .handle_brain(generation, result.clone(), false)
                    .is_err(),
                "every JSON kind still requires a prior call"
            );
            assert_eq!(
                session.handle_brain(generation, call(&call_id), false)?,
                Some(call(&call_id))
            );
            assert!(
                session
                    .handle_brain(generation, BrainEvent::Done, false)
                    .is_err(),
                "a result is outstanding"
            );
            assert_eq!(
                session.handle_brain(generation, result.clone(), false)?,
                Some(result.clone())
            );
            assert!(session.handle_brain(generation, result, false).is_err());
            expected.push(original);
        }
    }
    let context = session.brain_context(generation).expect("context");
    brain.update_context(context)?;
    assert_eq!(brain.contexts[0].tool_events.len(), expected.len() * 2);
    let restored: Vec<_> = brain.contexts[0]
        .tool_events
        .iter()
        .filter_map(|event| match event {
            ToolEvent::Result {
                call_id,
                output,
                is_error,
            } => Some(ContentPart::ToolResult {
                call_id: call_id.clone(),
                output: output.clone(),
                is_error: *is_error,
            }),
            ToolEvent::Call { .. } => None,
        })
        .collect();
    assert_eq!(restored, expected);
    assert!(
        !brain.contexts[0].externally_tainted,
        "error status is not host taint"
    );
    assert_eq!(
        session.handle_brain(generation, BrainEvent::Done, false)?,
        Some(BrainEvent::Done)
    );
    Ok(())
}
