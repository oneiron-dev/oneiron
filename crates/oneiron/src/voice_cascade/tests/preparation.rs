use super::*;

fn prepared(session: &mut VoiceCascadeSession, handle: &UtteranceHandle, revision: u64, text: &str) -> PreparedAsr {
    session.prepare_asr(handle, revision, event(AsrEventKind::Final, text), true)
        .unwrap().expect("live preparation")
}

#[test]
fn newer_preparation_rejects_old_before_retrieval_or_identity_effects() -> Result<()> {
    let (_dir, vault) = vault();
    let mut session = VoiceCascadeSession::new(Arc::clone(&vault), config())?;
    let handle = session.open_utterance("u", SpeculativeSessionConfig::default())?;
    let old = prepared(&mut session, &handle, 1, "old bytes");
    let current = prepared(&mut session, &handle, 2, "new bytes");
    let runs = vault.retrieval_runs(200)?.len();
    assert!(!session.cancel_prepared_asr(&old), "old cancellation cannot kill replacement");
    assert!(matches!(session.apply_prepared_asr(old, PartialEnrichment::default())?, AsrUpdate::Ignored));
    assert_eq!(vault.retrieval_runs(200)?.len(), runs);
    assert!(session.prepare_asr(&handle, 1, event(AsrEventKind::Final, "old bytes"), true).is_err());
    assert!(session.prepare_asr(&handle, 2, event(AsrEventKind::Final, "other bytes"), true).is_err());
    assert!(session.prepare_asr(&handle, 2, event(AsrEventKind::Final, "new bytes"), false).is_err());
    let AsrUpdate::Final(request) = session.apply_prepared_asr(current, PartialEnrichment::default())? else {
        panic!("fresh final must apply");
    };
    assert_eq!(request.transcript, "new bytes");
    assert!(request.externally_tainted);
    assert_eq!(vault.retrieval_runs(200)?.len(), runs + 1);
    Ok(())
}

#[test]
fn same_reference_different_session_and_reopened_handle_cannot_accept_ticket() -> Result<()> {
    let (_dir, vault) = vault();
    let mut first = VoiceCascadeSession::new(Arc::clone(&vault), config())?;
    let mut second = VoiceCascadeSession::new(Arc::clone(&vault), config())?;
    let a = first.open_utterance("same", SpeculativeSessionConfig::default())?;
    let b = second.open_utterance("same", SpeculativeSessionConfig::default())?;
    let foreign = prepared(&mut first, &a, 1, "same bytes");
    let local = prepared(&mut second, &b, 1, "same bytes");
    assert!(matches!(second.apply_prepared_asr(foreign, PartialEnrichment::default())?, AsrUpdate::Ignored));
    assert!(second.accepts_prepared_asr(&local));
    assert!(second.close_utterance(&b));
    let reopened = second.open_utterance("same", SpeculativeSessionConfig::default())?;
    let next = prepared(&mut second, &reopened, 1, "same bytes");
    assert!(matches!(second.apply_prepared_asr(local, PartialEnrichment::default())?, AsrUpdate::Ignored));
    assert!(second.accepts_prepared_asr(&next));
    assert!(vault.retrieval_runs(200)?.is_empty());
    Ok(())
}

#[test]
fn generation_stop_and_end_invalidate_pending_partial_without_effects() -> Result<()> {
    let (_dir, vault) = vault();
    let mut session = VoiceCascadeSession::new(Arc::clone(&vault), config())?;
    let generation = start(&mut session, false)?.generation;
    let handle = session.open_utterance("incoming", SpeculativeSessionConfig::default())?;
    let pending = session.prepare_asr(&handle, 1, event(AsrEventKind::Partial, "incoming"), true)?.unwrap();
    let runs = vault.retrieval_runs(200)?.len();
    assert!(session.observe_speech(Duration::ZERO, true)?.is_none());
    let stop = session.observe_speech(Duration::from_millis(120), true)?.unwrap();
    assert_eq!(stop.generation, Some(generation));
    assert!(matches!(session.apply_prepared_asr(pending, PartialEnrichment::default())?, AsrUpdate::Ignored));
    let pending = prepared(&mut session, &handle, 1, "incoming");
    let _stop = session.end();
    assert!(matches!(session.apply_prepared_asr(pending, PartialEnrichment::default())?, AsrUpdate::Ignored));
    assert_eq!(vault.retrieval_runs(200)?.len(), runs);
    Ok(())
}

#[test]
fn same_revision_retry_supersedes_attempt_and_sync_door_invalidates_ticket() -> Result<()> {
    let (_dir, vault) = vault();
    let mut session = VoiceCascadeSession::new(vault, config())?;
    let handle = session.open_utterance("u", SpeculativeSessionConfig::default())?;
    let first = prepared(&mut session, &handle, 1, "bytes");
    let retry = prepared(&mut session, &handle, 1, "bytes");
    assert!(matches!(session.apply_prepared_asr(first, PartialEnrichment::default())?, AsrUpdate::Ignored));
    let update = session.handle_asr(&handle, 2, event(AsrEventKind::Final, "sync bytes"), false, &mut Enricher::default())?;
    assert!(matches!(update, AsrUpdate::Final(_)));
    assert!(matches!(session.apply_prepared_asr(retry, PartialEnrichment::default())?, AsrUpdate::Ignored));
    Ok(())
}

#[test]
fn cancellation_keeps_revision_and_exact_input_fence_but_releases_attempt() -> Result<()> {
    let (_dir, vault) = vault();
    let mut session = VoiceCascadeSession::new(Arc::clone(&vault), config())?;
    let handle = session.open_utterance("u", SpeculativeSessionConfig::default())?;
    let cancelled = prepared(&mut session, &handle, 2, " exact bytes ");
    assert!(session.cancel_prepared_asr(&cancelled));
    assert!(!session.cancel_prepared_asr(&cancelled));
    assert!(!session.accepts_prepared_asr(&cancelled));
    assert!(matches!(
        session.apply_prepared_asr(cancelled, PartialEnrichment::default())?,
        AsrUpdate::Ignored
    ));
    for (revision, text, tainted) in [
        (1, "older", true),
        (2, "exact bytes", true),
        (2, " exact bytes ", false),
    ] {
        let event = event(AsrEventKind::Final, text);
        assert!(session.prepare_asr(&handle, revision, event.clone(), tainted).is_err());
        assert!(session.handle_asr(
            &handle, revision, event, tainted, &mut Enricher::default(),
        ).is_err());
    }
    assert!(vault.retrieval_runs(200)?.is_empty());
    let retry = prepared(&mut session, &handle, 2, " exact bytes ");
    let AsrUpdate::Final(request) = session.apply_prepared_asr(retry, PartialEnrichment::default())? else {
        panic!("exact retry must apply");
    };
    assert_eq!(request.transcript, " exact bytes ");
    assert_eq!(vault.retrieval_runs(200)?.len(), 1);
    Ok(())
}

fn reject_changed_prepared_input(
    session: &mut VoiceCascadeSession,
    handle: &UtteranceHandle,
    kind: AsrEventKind,
) {
    let changed = event(kind, "changed transcript");
    assert!(matches!(
        session.prepare_asr(handle, 1, changed.clone(), true),
        Err(Error::InvalidConfig(message))
            if message == "ASR preparation revision or exact input mismatch"
    ));
    let mut enricher = Enricher::default();
    assert!(matches!(
        session.handle_asr(handle, 1, changed, true, &mut enricher),
        Err(Error::InvalidConfig(message))
            if message == "ASR preparation revision or exact input mismatch"
    ));
    assert!(
        enricher.texts.is_empty(),
        "changed input must not reach extraction"
    );
}

#[test]
fn partial_retrieval_error_keeps_prepared_input_fence_and_exact_retry_works() -> Result<()> {
    for via_sync in [false, true] {
        let (_dir, vault) = vault();
        let result_ref = put_text(&vault, 0x70, "Tokyo launch")?;
        let mut session = VoiceCascadeSession::new(Arc::clone(&vault), config())?;
        let handle = session.open_utterance("partial-error", SpeculativeSessionConfig::default())?;
        let input = event(AsrEventKind::Partial, " Tokyo launch ");
        let stale = session
            .prepare_asr(&handle, 1, input.clone(), true)?
            .unwrap();
        let pending = session
            .prepare_asr(&handle, 1, input.clone(), true)?
            .unwrap();
        let mut enricher = Enricher::default();
        enricher.value.query_vector = Some(vec![f32::NAN, 0.0, 0.0, 0.0]);
        let failed = if via_sync {
            let failed = session.handle_asr(&handle, 1, input.clone(), true, &mut enricher);
            assert!(!session.accepts_prepared_asr(&pending));
            assert!(matches!(
                session.apply_prepared_asr(pending, PartialEnrichment::default())?,
                AsrUpdate::Ignored
            ));
            failed
        } else {
            session.apply_prepared_asr(pending, enricher.value.clone())
        };
        assert!(matches!(failed, Err(Error::InvalidVector { index: 0, .. })));
        assert!(session.is_utterance_open(&handle));
        assert!(vault.retrieval_runs(200)?.is_empty());
        reject_changed_prepared_input(&mut session, &handle, AsrEventKind::Partial);
        assert!(matches!(
            session.apply_prepared_asr(stale, PartialEnrichment::default())?,
            AsrUpdate::Ignored
        ));
        assert!(vault.retrieval_runs(200)?.is_empty());

        enricher.value.query_vector = None;
        let retry = session.prepare_asr(&handle, 1, input, true)?.unwrap();
        let AsrUpdate::Partial(partial) =
            session.apply_prepared_asr(retry, enricher.value.clone())?
        else {
            panic!("original partial must remain retryable");
        };
        let warm = partial.context.expect("real retrieval after vector repair");
        assert!(warm.result_refs.contains(&result_ref));
        assert_eq!(vault.retrieval_runs(200)?.len(), 1);
        assert!(
            session
                .prepare_asr(
                    &handle,
                    1,
                    event(AsrEventKind::Partial, " Tokyo launch "),
                    true,
                )
                .is_err(),
            "success consumes the revision"
        );
        let final_ticket = session
            .prepare_asr(
                &handle,
                2,
                event(AsrEventKind::Final, "Tokyo launch plans"),
                true,
            )?
            .unwrap();
        let AsrUpdate::Final(request) =
            session.apply_prepared_asr(final_ticket, enricher.value)?
        else {
            panic!("next revision must work");
        };
        assert!(request.retrieval.promoted);
        assert_eq!(request.retrieval.run_id, warm.run_id);
        assert_eq!(vault.retrieval_runs(200)?.len(), 1);
    }
    Ok(())
}

#[test]
fn final_identity_error_keeps_prepared_input_fence_and_exact_retry_works() -> Result<()> {
    use crate::counterparty_contact::CounterpartyContactRecord;
    use crate::interlocutor::InterlocutorPartyInput;

    for via_sync in [false, true] {
        let (_dir, vault) = vault();
        let contact = entity(0x71);
        let mut config = config();
        config
            .interlocutors
            .parties
            .push(InterlocutorPartyInput::ContactRef(contact));
        let mut session = VoiceCascadeSession::new(Arc::clone(&vault), config)?;
        let handle = session.open_utterance("identity-error", SpeculativeSessionConfig::default())?;
        let stale = prepared(&mut session, &handle, 1, " exact bytes ");
        let pending = prepared(&mut session, &handle, 1, " exact bytes ");
        let mut enricher = Enricher::default();
        let failed = if via_sync {
            let failed = session.handle_asr(
                &handle,
                1,
                event(AsrEventKind::Final, " exact bytes "),
                true,
                &mut enricher,
            );
            assert!(!session.accepts_prepared_asr(&pending));
            assert!(matches!(
                session.apply_prepared_asr(pending, PartialEnrichment::default())?,
                AsrUpdate::Ignored
            ));
            failed
        } else {
            session.apply_prepared_asr(pending, PartialEnrichment::default())
        };
        assert!(matches!(failed, Err(Error::EntityNotFound)));
        assert!(enricher.texts.is_empty(), "identity fails before enrichment");
        assert!(session.is_utterance_open(&handle));
        assert!(vault.retrieval_runs(200)?.is_empty());
        reject_changed_prepared_input(&mut session, &handle, AsrEventKind::Final);
        assert!(matches!(
            session.apply_prepared_asr(stale, PartialEnrichment::default())?,
            AsrUpdate::Ignored
        ));
        assert!(vault.retrieval_runs(200)?.is_empty());

        // Repair the concrete missing contact without changing session inputs.
        let record = CounterpartyContactRecord::user_introduction(entity(0x72), "mika", 10)?;
        vault.create_counterparty_contact(&contact, &record)?;
        let retry = prepared(&mut session, &handle, 1, " exact bytes ");
        let AsrUpdate::Final(request) =
            session.apply_prepared_asr(retry, PartialEnrichment::default())?
        else {
            panic!("original final must remain retryable");
        };
        assert_eq!(request.transcript, " exact bytes ");
        assert!(request.externally_tainted);
        assert_eq!(request.generation.value(), 1);
        assert_eq!(request.interlocutors.entries().len(), 2);
        assert!(session.accepts_pcm(request.generation));
        assert!(!session.is_utterance_open(&handle));
        assert_eq!(vault.retrieval_runs(200)?.len(), 1);
    }
    Ok(())
}
