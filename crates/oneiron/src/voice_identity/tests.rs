use super::*;

use crate::counterparty_contact::CounterpartyContactRecord;
use crate::error::ErrorKind;
use crate::temporal::TimeRange;
use crate::test_util::entity as test_id;

fn temp_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(crate::config::VaultConfig::default())
}

const DIMENSION: usize = 4;

fn space() -> VoiceEmbeddingSpaceV1 {
    space_with("rev-1", "mono/16k/vad-v1")
}

fn space_with(revision: &str, preprocessing: &str) -> VoiceEmbeddingSpaceV1 {
    VoiceEmbeddingSpaceV1::new(
        VoiceEmbeddingFamily::EcapaTdnn,
        "ecapa/voxceleb",
        revision,
        16_000,
        DIMENSION,
        preprocessing,
    )
    .expect("pinned test embedding space")
}

fn source_hash(tag: u8) -> String {
    bytes_to_hex_lower(&[tag; 32])
}

fn solo_origin() -> VoiceEnrollmentOrigin {
    VoiceEnrollmentOrigin::AuthenticatedSoloSession {
        session_ref: "session-solo-1".to_owned(),
        speaker_count: 1,
    }
}

fn segment_origin(recording_ref: &str, segment_id: &str) -> VoiceEnrollmentOrigin {
    VoiceEnrollmentOrigin::ConsentedDiarizedSegment {
        recording_ref: recording_ref.to_owned(),
        segment_id: segment_id.to_owned(),
    }
}

fn sample(
    sample_id: &str,
    source_ref: &str,
    language: &str,
    origin: VoiceEnrollmentOrigin,
    vector: [f32; DIMENSION],
) -> VoiceEnrollmentSampleV1 {
    VoiceEnrollmentSampleV1 {
        sample_id: sample_id.to_owned(),
        source_ref: source_ref.to_owned(),
        language: language.to_owned(),
        origin,
        duration_ms: 4_000,
        source_sha256: source_hash(0xAB),
        vector: vector.to_vec(),
    }
}

fn solo_sample(
    sample_id: &str,
    language: &str,
    vector: [f32; DIMENSION],
) -> VoiceEnrollmentSampleV1 {
    sample(sample_id, "session-solo-1", language, solo_origin(), vector)
}

fn notice_basis() -> VoiceConsentBasis {
    VoiceConsentBasis::ConversationalNotice {
        notice: "asked before recording".to_owned(),
    }
}

fn verbal_basis(recording_ref: &str) -> VoiceConsentBasis {
    VoiceConsentBasis::VerbalOnRecording {
        recording_ref: recording_ref.to_owned(),
        start_ms: 1_200,
        end_ms: 4_800,
        words: "yes, you can keep a voice print of me".to_owned(),
    }
}

fn granted_event(
    event_id: &str,
    subject: EntityId,
    recorder: EntityId,
    occurred_at: u64,
    basis: VoiceConsentBasis,
) -> VoiceConsentEventV1 {
    VoiceConsentEventV1 {
        event_id: event_id.to_owned(),
        subject_ref: subject,
        recorded_by_ref: recorder,
        occurred_at,
        purposes: vec![
            VoicePrintPurpose::MeetingAttribution,
            VoicePrintPurpose::LiveInterlocutor,
        ],
        basis,
        state: VoiceConsentState::Granted,
    }
}

fn enrollment(
    subject: EntityId,
    consent_event_ref: &str,
    samples: Vec<VoiceEnrollmentSampleV1>,
    requested_at: u64,
) -> VoiceEnrollmentRequest {
    VoiceEnrollmentRequest {
        subject_ref: subject,
        contact_ref: None,
        relationship_ref: None,
        consent_event_ref: consent_event_ref.to_owned(),
        purpose: VoicePrintPurpose::MeetingAttribution,
        space: space(),
        samples,
        requested_at,
    }
}

fn segment(
    segment_id: &str,
    start_ms: u64,
    vector: [f32; DIMENSION],
    space_id: &str,
) -> VoiceSegmentEmbeddingInput {
    VoiceSegmentEmbeddingInput {
        segment_id: segment_id.to_owned(),
        diarization_label: format!("cluster-{segment_id}"),
        start_ms,
        end_ms: start_ms + 1_000,
        space_id: space_id.to_owned(),
        vector: vector.to_vec(),
    }
}

fn match_request(
    voice_session_ref: &str,
    space_id: &str,
    segments: Vec<VoiceSegmentEmbeddingInput>,
    invite_attendee_refs: Vec<EntityId>,
) -> VoiceMatchRequest {
    VoiceMatchRequest {
        voice_session_ref: voice_session_ref.to_owned(),
        recording_id: "recording-1".to_owned(),
        space_id: space_id.to_owned(),
        segments,
        invite_attendee_refs,
        policy: VoiceMatchPolicy::with_known_default(0.7),
        created_at: 900,
    }
}

fn seed_contact(vault: &Vault, identity: EntityId, contact_id: EntityId, who: &str) -> Result<()> {
    let record = CounterpartyContactRecord::user_introduction(identity, who, 10)?;
    vault.create_counterparty_contact(&contact_id, &record)
}

fn seed_relationship(vault: &Vault, id: EntityId) -> Result<()> {
    vault.put_entity(
        &id,
        ENTITY_TYPE_RELATIONSHIP,
        TimeRange { start: 1, end: 1 },
        1,
        b"relationship",
    )
}

fn stored_print(vault: &Vault, subject: EntityId) -> Result<Option<VoicePrintRecordV1>> {
    let rtxn = vault.store.env.read_txn()?;
    read_active_print(&vault.store, &rtxn, &subject)
}

fn stored_consent(
    vault: &Vault,
    subject: EntityId,
    event_id: &str,
) -> Result<Option<VoiceConsentEventV1>> {
    let rtxn = vault.store.env.read_txn()?;
    read_consent_event(&vault.store, &rtxn, &subject, event_id)
}

fn stored_sample(
    vault: &Vault,
    subject: EntityId,
    sample_id: &str,
) -> Result<Option<VoiceEnrollmentSampleV1>> {
    let rtxn = vault.store.env.read_txn()?;
    read_sample(&vault.store, &rtxn, &subject, sample_id)
}

fn print_family_rows(vault: &Vault, subject: EntityId) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let rtxn = vault.store.env.read_txn()?;
    collect_prefix_rows(&vault.store, &rtxn, &voice_subject_prefix(&subject))
}

fn raw_roster_bytes(vault: &Vault, voice_session_ref: &str) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    let bytes = vault
        .store
        .vault_meta
        .get(&rtxn, &voice_roster_key(voice_session_ref))?
        .expect("stored roster row");
    Ok(bytes.into_owned())
}

fn evidence_of<'a>(
    roster: &'a VoiceSessionRosterV1,
    segment_id: &str,
) -> &'a VoiceAttributionEvidence {
    &roster
        .segments
        .iter()
        .find(|segment| segment.segment_id == segment_id)
        .expect("segment present in roster")
        .evidence
}

/// Records consent then enrolls a single-language principal print.
fn enroll_principal(
    vault: &Vault,
    subject: EntityId,
    recorder: EntityId,
    event_id: &str,
    vector: [f32; DIMENSION],
) -> Result<VoicePrintRecordV1> {
    vault.record_voice_consent(&granted_event(
        event_id,
        subject,
        recorder,
        100,
        notice_basis(),
    ))?;
    vault.enroll_voice_print(&enrollment(
        subject,
        event_id,
        vec![solo_sample("s-1", "en", vector)],
        200,
    ))
}

#[test]
fn threshold_dials_are_pinned_and_recorded_in_every_result() -> Result<()> {
    assert!((VOICE_MATCH_THRESHOLD_DEFAULT - 0.65).abs() < f32::EPSILON);
    assert!((VOICE_MATCH_THRESHOLD_MIN - 0.55).abs() < f32::EPSILON);
    assert!((VOICE_MATCH_THRESHOLD_MAX - 0.75).abs() < f32::EPSILON);
    assert!(
        (VoiceMatchPolicy::with_known_default(0.7).known_threshold - VOICE_MATCH_THRESHOLD_DEFAULT)
            .abs()
            < f32::EPSILON
    );

    let (_tmp, vault) = temp_vault();
    let subject = test_id(0x21);
    enroll_principal(
        &vault,
        subject,
        test_id(0x22),
        "consent-1",
        [1.0, 0.0, 0.0, 0.0],
    )?;

    for threshold in [
        VOICE_MATCH_THRESHOLD_MIN,
        VOICE_MATCH_THRESHOLD_DEFAULT,
        VOICE_MATCH_THRESHOLD_MAX,
    ] {
        let mut request = match_request(
            "call-threshold",
            &space().space_id,
            vec![segment("seg-1", 0, [1.0, 0.0, 0.0, 0.0], &space().space_id)],
            Vec::new(),
        );
        request.policy.known_threshold = threshold;
        let roster = vault.resolve_voice_segments(&request)?;
        assert!(
            (roster.known_threshold - threshold).abs() < f32::EPSILON,
            "every result records the threshold it ran at"
        );
    }
    Ok(())
}

#[test]
fn match_policy_rejects_thresholds_outside_the_accepted_band() {
    for known in [0.54_f32, 0.76, f32::NAN] {
        let policy = VoiceMatchPolicy {
            known_threshold: known,
            residual_threshold: 0.7,
        };
        assert_eq!(
            policy.validate().expect_err("out-of-band dial").kind(),
            ErrorKind::InvalidConfig
        );
    }
    for residual in [0.0_f32, -0.1, 1.1] {
        let policy = VoiceMatchPolicy {
            known_threshold: VOICE_MATCH_THRESHOLD_DEFAULT,
            residual_threshold: residual,
        };
        assert!(policy.validate().is_err());
    }
    assert!(VoiceMatchPolicy::with_known_default(0.7).validate().is_ok());
}

#[test]
fn vectors_reject_non_finite_zero_and_wrong_dimension() -> Result<()> {
    assert_eq!(
        validate_voice_vector(&[1.0, 0.0, 0.0], DIMENSION)
            .expect_err("wrong dimension")
            .kind(),
        ErrorKind::DimensionMismatch
    );
    assert_eq!(
        validate_voice_vector(&[1.0, f32::NAN, 0.0, 0.0], DIMENSION)
            .expect_err("non-finite component")
            .kind(),
        ErrorKind::InvalidVector
    );
    assert_eq!(
        validate_voice_vector(&[1.0, f32::INFINITY, 0.0, 0.0], DIMENSION)
            .expect_err("infinite component")
            .kind(),
        ErrorKind::InvalidVector
    );
    assert_eq!(
        validate_voice_vector(&[0.0, 0.0, 0.0, 0.0], DIMENSION)
            .expect_err("zero magnitude has no direction")
            .kind(),
        ErrorKind::InvalidVector
    );

    let (_tmp, vault) = temp_vault();
    let subject = test_id(0x23);
    vault.record_voice_consent(&granted_event(
        "consent-1",
        subject,
        test_id(0x24),
        100,
        notice_basis(),
    ))?;
    for bad in [
        vec![0.0, 0.0, 0.0, 0.0],
        vec![f32::NAN, 1.0, 0.0, 0.0],
        vec![1.0, 0.0, 0.0],
    ] {
        let mut sample = solo_sample("s-1", "en", [1.0, 0.0, 0.0, 0.0]);
        sample.vector = bad;
        assert!(
            vault
                .enroll_voice_print(&enrollment(subject, "consent-1", vec![sample], 200))
                .is_err(),
            "enrollment refuses an unusable vector"
        );
    }
    assert!(stored_print(&vault, subject)?.is_none());
    Ok(())
}

#[test]
fn cross_space_comparison_is_an_error_never_a_low_score() -> Result<()> {
    let other = space_with("rev-2", "mono/16k/vad-v1");
    assert_ne!(space().space_id, other.space_id);

    let vector = [1.0_f32, 0.0, 0.0, 0.0];
    let error = voice_cosine_in_space(&space().space_id, &vector, &other.space_id, &vector)
        .expect_err("comparison across spaces is refused outright");
    assert_eq!(error.kind(), ErrorKind::InvalidConfig);
    assert!(
        voice_cosine_in_space(&space().space_id, &vector, &space().space_id, &vector).is_ok(),
        "the same space still compares"
    );

    let (_tmp, vault) = temp_vault();
    let subject = test_id(0x25);
    enroll_principal(&vault, subject, test_id(0x26), "consent-1", vector)?;

    // A segment tagged with a foreign space is rejected, not scored low.
    let request = match_request(
        "call-cross",
        &space().space_id,
        vec![segment("seg-1", 0, vector, &other.space_id)],
        Vec::new(),
    );
    assert_eq!(
        vault
            .resolve_voice_segments(&request)
            .expect_err("foreign-space segment")
            .kind(),
        ErrorKind::InvalidConfig
    );
    assert!(vault.voice_session_roster("call-cross")?.is_none());
    Ok(())
}

#[test]
fn enrollment_requires_a_recorded_granted_consent_that_covers_the_purpose() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let subject = test_id(0x27);
    let recorder = test_id(0x28);
    let request = enrollment(
        subject,
        "consent-1",
        vec![solo_sample("s-1", "en", [1.0, 0.0, 0.0, 0.0])],
        200,
    );

    // No consent row at all: nothing may be buffered for later use.
    assert_eq!(
        vault
            .enroll_voice_print(&request)
            .expect_err("pre-consent enrollment")
            .kind(),
        ErrorKind::InvalidConfig
    );
    assert!(print_family_rows(&vault, subject)?.is_empty());

    // Consent recorded AFTER the request instant still does not admit it.
    vault.record_voice_consent(&granted_event(
        "consent-1",
        subject,
        recorder,
        900,
        notice_basis(),
    ))?;
    assert!(vault.enroll_voice_print(&request).is_err());

    // A grant that does not cover the purpose is not a grant for it.
    let mut narrow = granted_event("consent-2", subject, recorder, 100, notice_basis());
    narrow.purposes = vec![VoicePrintPurpose::LiveInterlocutor];
    vault.record_voice_consent(&narrow)?;
    let mut narrow_request = request.clone();
    narrow_request.consent_event_ref = "consent-2".to_owned();
    assert!(vault.enroll_voice_print(&narrow_request).is_err());

    // A covering grant that precedes the request admits it.
    vault.record_voice_consent(&granted_event(
        "consent-3",
        subject,
        recorder,
        100,
        notice_basis(),
    ))?;
    let mut good = request;
    good.consent_event_ref = "consent-3".to_owned();
    let record = vault.enroll_voice_print(&good)?;
    assert_eq!(record.consent_event_ref, "consent-3");
    assert!(stored_print(&vault, subject)?.is_some());
    Ok(())
}

#[test]
fn passive_multi_speaker_harvesting_is_rejected() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let subject = test_id(0x29);
    vault.record_voice_consent(&granted_event(
        "consent-1",
        subject,
        test_id(0x2A),
        100,
        notice_basis(),
    ))?;

    let mut multi = solo_sample("s-1", "en", [1.0, 0.0, 0.0, 0.0]);
    multi.origin = VoiceEnrollmentOrigin::AuthenticatedSoloSession {
        session_ref: "session-room".to_owned(),
        speaker_count: 3,
    };
    assert_eq!(
        vault
            .enroll_voice_print(&enrollment(subject, "consent-1", vec![multi], 200))
            .expect_err("multi-speaker audio never feeds a passive principal centroid")
            .kind(),
        ErrorKind::InvalidConfig
    );

    // A meeting segment cannot masquerade as principal material either.
    let meeting = sample(
        "s-2",
        "recording-9",
        "en",
        segment_origin("recording-9", "seg-3"),
        [1.0, 0.0, 0.0, 0.0],
    );
    assert!(
        vault
            .enroll_voice_print(&enrollment(subject, "consent-1", vec![meeting], 200))
            .is_err()
    );
    assert!(print_family_rows(&vault, subject)?.is_empty());
    Ok(())
}

#[test]
fn contact_enrollment_rejects_mismatched_recording_and_segment_refs() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let identity = test_id(0x2B);
    let contact_id = test_id(0x2C);
    let subject = test_id(0x2D);
    seed_contact(&vault, identity, contact_id, "kenji@example.com")?;
    vault.record_voice_consent(&granted_event(
        "consent-1",
        subject,
        test_id(0x2E),
        100,
        verbal_basis("recording-1"),
    ))?;

    let contact_request = |samples: Vec<VoiceEnrollmentSampleV1>| VoiceEnrollmentRequest {
        contact_ref: Some(contact_id),
        ..enrollment(subject, "consent-1", samples, 200)
    };

    // The consent names recording-1; a sample from recording-2 is not covered.
    let wrong_recording = sample(
        "s-1",
        "recording-2",
        "en",
        segment_origin("recording-2", "seg-1"),
        [0.0, 1.0, 0.0, 0.0],
    );
    assert!(
        vault
            .enroll_voice_print(&contact_request(vec![wrong_recording]))
            .is_err()
    );

    // The source ref must name the origin recording.
    let wrong_source = sample(
        "s-1",
        "recording-2",
        "en",
        segment_origin("recording-1", "seg-1"),
        [0.0, 1.0, 0.0, 0.0],
    );
    assert!(
        vault
            .enroll_voice_print(&contact_request(vec![wrong_source]))
            .is_err()
    );

    // An unnamed segment is not a named diarized segment.
    let blank_segment = sample(
        "s-1",
        "recording-1",
        "en",
        segment_origin("recording-1", "  "),
        [0.0, 1.0, 0.0, 0.0],
    );
    assert!(
        vault
            .enroll_voice_print(&contact_request(vec![blank_segment]))
            .is_err()
    );

    // A solo-session origin is not an admissible contact sample.
    assert!(
        vault
            .enroll_voice_print(&contact_request(vec![solo_sample(
                "s-1",
                "en",
                [0.0, 1.0, 0.0, 0.0]
            )]))
            .is_err()
    );

    // The named, consented diarized segment is admitted.
    let good = sample(
        "s-1",
        "recording-1",
        "en",
        segment_origin("recording-1", "seg-1"),
        [0.0, 1.0, 0.0, 0.0],
    );
    let record = vault.enroll_voice_print(&contact_request(vec![good]))?;
    assert_eq!(record.contact_ref, Some(contact_id));
    Ok(())
}

#[test]
fn consent_records_preserve_who_when_purposes_basis_and_evidence() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let subject = test_id(0x31);
    let recorder = test_id(0x32);

    let verbal = granted_event(
        "consent-verbal",
        subject,
        recorder,
        1_700,
        verbal_basis("recording-1"),
    );
    vault.record_voice_consent(&verbal)?;
    let stored = stored_consent(&vault, subject, "consent-verbal")?.expect("verbal consent row");
    assert_eq!(stored, verbal);
    assert_eq!(stored.subject_ref, subject);
    assert_eq!(stored.recorded_by_ref, recorder);
    assert_eq!(stored.occurred_at, 1_700);
    assert_eq!(
        stored.purposes,
        vec![
            VoicePrintPurpose::MeetingAttribution,
            VoicePrintPurpose::LiveInterlocutor
        ]
    );
    assert_eq!(
        stored.basis,
        VoiceConsentBasis::VerbalOnRecording {
            recording_ref: "recording-1".to_owned(),
            start_ms: 1_200,
            end_ms: 4_800,
            words: "yes, you can keep a voice print of me".to_owned(),
        }
    );
    assert_eq!(stored.state, VoiceConsentState::Granted);

    for basis in [
        notice_basis(),
        VoiceConsentBasis::SettingsToggle {
            surface_ref: "settings/voice".to_owned(),
        },
    ] {
        let event = granted_event("consent-other", subject, recorder, 1_800, basis.clone());
        vault.record_voice_consent(&event)?;
        assert_eq!(
            stored_consent(&vault, subject, "consent-other")?
                .expect("consent row")
                .basis,
            basis
        );
    }

    // A verbal basis without a time span, words, or recording is not a grant.
    for bad in [
        VoiceConsentBasis::VerbalOnRecording {
            recording_ref: String::new(),
            start_ms: 1,
            end_ms: 2,
            words: "yes".to_owned(),
        },
        VoiceConsentBasis::VerbalOnRecording {
            recording_ref: "recording-1".to_owned(),
            start_ms: 1,
            end_ms: 2,
            words: String::new(),
        },
        VoiceConsentBasis::VerbalOnRecording {
            recording_ref: "recording-1".to_owned(),
            start_ms: 4_800,
            end_ms: 1_200,
            words: "yes".to_owned(),
        },
    ] {
        let event = granted_event("consent-bad", subject, recorder, 1_900, bad);
        assert!(vault.record_voice_consent(&event).is_err());
    }
    assert!(stored_consent(&vault, subject, "consent-bad")?.is_none());
    Ok(())
}

#[test]
fn mixed_language_enrollment_calibrates_and_one_language_stays_collecting() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let subject = test_id(0x33);
    let recorder = test_id(0x34);
    vault.record_voice_consent(&granted_event(
        "consent-1",
        subject,
        recorder,
        100,
        notice_basis(),
    ))?;

    // One language: usable, never described as calibrated.
    let collecting = vault.enroll_voice_print(&enrollment(
        subject,
        "consent-1",
        vec![solo_sample("s-1", "ja", [1.0, 0.0, 0.0, 0.0])],
        200,
    ))?;
    assert_eq!(collecting.calibration, VoicePrintCalibration::Collecting);
    assert_eq!(collecting.sample_languages, vec!["ja".to_owned()]);

    let space_id = space().space_id;
    let roster = vault.resolve_voice_segments(&match_request(
        "call-collecting",
        &space_id,
        vec![segment("seg-1", 0, [1.0, 0.0, 0.0, 0.0], &space_id)],
        Vec::new(),
    ))?;
    match evidence_of(&roster, "seg-1") {
        VoiceAttributionEvidence::EnrolledPrint { calibration, .. } => {
            assert_eq!(*calibration, VoicePrintCalibration::Collecting);
        }
        other => panic!("expected an enrolled-print match, got {other:?}"),
    }

    // Mixed language across ja / en / uk / ru qualifies as calibrated and the
    // tags survive the round trip in deterministic sample order.
    let calibrated = vault.enroll_voice_print(&enrollment(
        subject,
        "consent-1",
        vec![
            solo_sample("s-1", "ja", [1.0, 0.0, 0.0, 0.0]),
            solo_sample("s-2", "en", [0.99, 0.14, 0.0, 0.0]),
            solo_sample("s-3", "uk", [0.98, 0.0, 0.2, 0.0]),
            solo_sample("s-4", "ru", [0.97, 0.0, 0.0, 0.24]),
        ],
        300,
    ))?;
    assert_eq!(calibrated.calibration, VoicePrintCalibration::Calibrated);
    assert_eq!(
        calibrated.sample_languages,
        vec![
            "ja".to_owned(),
            "en".to_owned(),
            "uk".to_owned(),
            "ru".to_owned()
        ]
    );
    assert_eq!(
        calibrated.sample_ids,
        vec![
            "s-1".to_owned(),
            "s-2".to_owned(),
            "s-3".to_owned(),
            "s-4".to_owned()
        ]
    );
    assert_eq!(
        stored_print(&vault, subject)?
            .expect("stored print")
            .calibration,
        VoicePrintCalibration::Calibrated
    );

    let roster = vault.resolve_voice_segments(&match_request(
        "call-calibrated",
        &space_id,
        vec![segment("seg-1", 0, [1.0, 0.0, 0.0, 0.0], &space_id)],
        Vec::new(),
    ))?;
    match evidence_of(&roster, "seg-1") {
        VoiceAttributionEvidence::EnrolledPrint { calibration, .. } => {
            assert_eq!(*calibration, VoicePrintCalibration::Calibrated);
        }
        other => panic!("expected an enrolled-print match, got {other:?}"),
    }
    Ok(())
}

#[test]
fn model_revision_or_preprocessing_change_creates_a_new_space() -> Result<()> {
    let base = space();
    let revised = space_with("rev-2", "mono/16k/vad-v1");
    let repreprocessed = space_with("rev-1", "mono/8k/vad-v2");
    assert_ne!(base.space_id, revised.space_id);
    assert_ne!(base.space_id, repreprocessed.space_id);
    assert_ne!(revised.space_id, repreprocessed.space_id);
    assert_eq!(base.space_id, base.derived_space_id());

    // A hand-edited space_id never validates.
    let forged = VoiceEmbeddingSpaceV1 {
        space_id: revised.space_id.clone(),
        ..base
    };
    assert!(forged.validate().is_err());

    let (_tmp, vault) = temp_vault();
    let subject = test_id(0x35);
    let vector = [1.0_f32, 0.0, 0.0, 0.0];
    enroll_principal(&vault, subject, test_id(0x36), "consent-1", vector)?;

    // The old centroid cannot answer for the new space.
    let roster = vault.resolve_voice_segments(&match_request(
        "call-new-space",
        &revised.space_id,
        vec![segment("seg-1", 0, vector, &revised.space_id)],
        Vec::new(),
    ))?;
    assert!(
        matches!(
            evidence_of(&roster, "seg-1"),
            VoiceAttributionEvidence::ResidualCluster { .. }
        ),
        "a re-pinned model requires re-enrollment, never centroid reuse"
    );

    // Re-enrolling in the new space moves the active pointer.
    vault.enroll_voice_print(&VoiceEnrollmentRequest {
        space: revised.clone(),
        ..enrollment(
            subject,
            "consent-1",
            vec![solo_sample("s-1", "en", vector)],
            400,
        )
    })?;
    let active = stored_print(&vault, subject)?.expect("re-enrolled print");
    assert_eq!(active.space.space_id, revised.space_id);
    assert_eq!(
        print_family_rows(&vault, subject)?.len(),
        2,
        "one active pointer plus exactly one print row survive re-enrollment"
    );

    let roster = vault.resolve_voice_segments(&match_request(
        "call-new-space-2",
        &revised.space_id,
        vec![segment("seg-1", 0, vector, &revised.space_id)],
        Vec::new(),
    ))?;
    assert!(matches!(
        evidence_of(&roster, "seg-1"),
        VoiceAttributionEvidence::EnrolledPrint { .. }
    ));
    Ok(())
}

#[test]
fn enrolled_matches_are_accepted_before_residual_clustering() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let subject = test_id(0x37);
    let space_id = space().space_id;
    enroll_principal(
        &vault,
        subject,
        test_id(0x38),
        "consent-1",
        [1.0, 0.0, 0.0, 0.0],
    )?;

    // seg-3 sits below the known threshold against the centroid but ABOVE the
    // residual threshold against seg-2. If accepted segments stayed in the
    // clustering pass it would be swept into their cluster.
    let segments = vec![
        segment("seg-1", 0, [1.0, 0.0, 0.0, 0.0], &space_id),
        segment("seg-2", 1_000, [0.9, 0.436, 0.0, 0.0], &space_id),
        segment("seg-3", 2_000, [0.6, 0.8, 0.0, 0.0], &space_id),
    ];
    let roster = vault.resolve_voice_segments(&match_request(
        "call-order",
        &space_id,
        segments,
        Vec::new(),
    ))?;

    for accepted in ["seg-1", "seg-2"] {
        match evidence_of(&roster, accepted) {
            VoiceAttributionEvidence::EnrolledPrint {
                subject_ref, score, ..
            } => {
                assert_eq!(*subject_ref, subject);
                assert!(
                    *score >= VOICE_MATCH_THRESHOLD_DEFAULT,
                    "accepted only at or above the recorded threshold"
                );
            }
            other => panic!("{accepted} should be an enrolled match, got {other:?}"),
        }
    }
    assert_eq!(
        evidence_of(&roster, "seg-3"),
        &VoiceAttributionEvidence::ResidualCluster {
            cluster_ref: "residual.1".to_owned()
        },
        "the only residual forms its own cluster; no accepted segment joins it"
    );
    assert!(
        roster
            .segments
            .iter()
            .filter(|segment| matches!(
                segment.evidence,
                VoiceAttributionEvidence::ResidualCluster { .. }
            ))
            .count()
            == 1
    );

    // Residual labels order by earliest start, then segment id.
    let strangers = vec![
        segment("seg-late", 5_000, [0.0, 0.0, 1.0, 0.0], &space_id),
        segment("seg-early", 100, [0.0, 1.0, 0.0, 0.0], &space_id),
    ];
    let roster = vault.resolve_voice_segments(&match_request(
        "call-labels",
        &space_id,
        strangers,
        Vec::new(),
    ))?;
    assert_eq!(
        evidence_of(&roster, "seg-early"),
        &VoiceAttributionEvidence::ResidualCluster {
            cluster_ref: "residual.1".to_owned()
        }
    );
    assert_eq!(
        evidence_of(&roster, "seg-late"),
        &VoiceAttributionEvidence::ResidualCluster {
            cluster_ref: "residual.2".to_owned()
        }
    );
    Ok(())
}

#[test]
fn roster_output_is_byte_identical_under_reordered_inputs() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let subject = test_id(0x39);
    let space_id = space().space_id;
    enroll_principal(
        &vault,
        subject,
        test_id(0x3A),
        "consent-1",
        [1.0, 0.0, 0.0, 0.0],
    )?;

    let forward = vec![
        segment("seg-a", 0, [1.0, 0.0, 0.0, 0.0], &space_id),
        segment("seg-b", 1_000, [0.0, 1.0, 0.0, 0.0], &space_id),
        segment("seg-c", 2_000, [0.0, 0.0, 1.0, 0.0], &space_id),
    ];
    let mut reversed = forward.clone();
    reversed.reverse();

    let first =
        vault.resolve_voice_segments(&match_request("call-det", &space_id, forward, Vec::new()))?;
    let first_bytes = raw_roster_bytes(&vault, "call-det")?;
    let second = vault.resolve_voice_segments(&match_request(
        "call-det",
        &space_id,
        reversed,
        Vec::new(),
    ))?;
    let second_bytes = raw_roster_bytes(&vault, "call-det")?;

    assert_eq!(first, second);
    assert_eq!(first_bytes, second_bytes);
    assert_eq!(
        first
            .segments
            .iter()
            .map(|segment| segment.segment_id.as_str())
            .collect::<Vec<_>>(),
        vec!["seg-a", "seg-b", "seg-c"]
    );
    Ok(())
}

/// Law 5: the score a caller sees is a cosine, not a loudness.
#[test]
fn non_unit_query_segment_scores_true_cosine_and_is_accepted() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let subject = test_id(0x62);
    let space_id = space().space_id;
    enroll_principal(
        &vault,
        subject,
        test_id(0x63),
        "consent-1",
        [1.0, 0.0, 0.0, 0.0],
    )?;

    // Exactly the centroid's direction at half its length. Compared without
    // normalizing, the segment would score 0.5 and false-REJECT the enrolled
    // principal below the 0.65 threshold; the cosine of a direction with
    // itself is 1.0 at any gain.
    let roster = vault.resolve_voice_segments(&match_request(
        "call-non-unit-accept",
        &space_id,
        vec![segment("seg-1", 0, [0.5, 0.0, 0.0, 0.0], &space_id)],
        Vec::new(),
    ))?;

    match evidence_of(&roster, "seg-1") {
        VoiceAttributionEvidence::EnrolledPrint {
            subject_ref, score, ..
        } => {
            assert_eq!(*subject_ref, subject);
            assert!(
                (*score - 1.0).abs() < 1e-6,
                "a shorter vector in the same direction still scores cosine 1.0, got {score}"
            );
        }
        other => panic!("the enrolled principal must be accepted, got {other:?}"),
    }
    Ok(())
}

/// Law 5 + Law 6: residual linkage is a cosine too, so gain cannot split one
/// stranger into two anonymous speakers.
#[test]
fn parallel_non_unit_residual_segments_cluster_together() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let space_id = space().space_id;

    // One direction, two gains eight times apart: cosine 1.0, but a raw dot
    // product of 0.5 — under the 0.7 linkage threshold.
    let roster = vault.resolve_voice_segments(&match_request(
        "call-residual-gain",
        &space_id,
        vec![
            segment("seg-loud", 0, [0.0, 2.0, 0.0, 0.0], &space_id),
            segment("seg-quiet", 1_000, [0.0, 0.25, 0.0, 0.0], &space_id),
        ],
        Vec::new(),
    ))?;

    for segment_id in ["seg-loud", "seg-quiet"] {
        assert_eq!(
            evidence_of(&roster, segment_id),
            &VoiceAttributionEvidence::ResidualCluster {
                cluster_ref: "residual.1".to_owned()
            },
            "{segment_id} belongs to the one anonymous speaker these segments share"
        );
    }
    Ok(())
}

/// Law 5, the dangerous arm: length must never buy an acceptance.
#[test]
fn non_unit_segment_below_cosine_threshold_is_not_accepted() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let subject = test_id(0x64);
    let space_id = space().space_id;
    enroll_principal(
        &vault,
        subject,
        test_id(0x65),
        "consent-1",
        [1.0, 0.0, 0.0, 0.0],
    )?;

    // A stranger at cosine 0.4 from the centroid, recorded twice: once at
    // length 2 (raw dot 0.8, which would clear the 0.65 threshold and
    // misattribute a stranger to an enrolled principal) and once at unit
    // length. The same angle must get the same answer.
    let scaled = [0.8, 1.833_030_2, 0.0, 0.0];
    let unit = [0.4, 0.916_515_1, 0.0, 0.0];
    let roster = vault.resolve_voice_segments(&match_request(
        "call-false-accept",
        &space_id,
        vec![
            segment("seg-scaled", 0, scaled, &space_id),
            segment("seg-unit", 1_000, unit, &space_id),
        ],
        Vec::new(),
    ))?;

    for segment_id in ["seg-scaled", "seg-unit"] {
        assert_eq!(
            evidence_of(&roster, segment_id),
            &VoiceAttributionEvidence::ResidualCluster {
                cluster_ref: "residual.1".to_owned()
            },
            "{segment_id} is below the threshold at every gain, and both gains are one speaker"
        );
    }
    assert!(
        roster
            .segments
            .iter()
            .all(|segment| segment.subject_ref.is_none()),
        "a below-threshold segment names no enrolled principal"
    );
    Ok(())
}

/// Law 6: earliest start, then SOURCE SEGMENT ID — never segment length.
#[test]
fn equal_start_residuals_label_in_segment_id_order() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let space_id = space().space_id;

    // Same start, and end_ms orders these two the opposite way their segment
    // ids do, so only the ruled key produces the labels below.
    let mut runs_long = segment("seg-a", 1_000, [0.0, 1.0, 0.0, 0.0], &space_id);
    runs_long.end_ms = 9_000;
    let mut runs_short = segment("seg-b", 1_000, [0.0, 0.0, 1.0, 0.0], &space_id);
    runs_short.end_ms = 1_500;

    let roster = vault.resolve_voice_segments(&match_request(
        "call-equal-start",
        &space_id,
        vec![runs_short.clone(), runs_long.clone()],
        Vec::new(),
    ))?;

    assert_eq!(
        roster
            .segments
            .iter()
            .map(|segment| segment.segment_id.as_str())
            .collect::<Vec<_>>(),
        vec!["seg-a", "seg-b"],
        "canonical order is (start_ms, segment_id)"
    );
    assert_eq!(
        evidence_of(&roster, "seg-a"),
        &VoiceAttributionEvidence::ResidualCluster {
            cluster_ref: "residual.1".to_owned()
        }
    );
    assert_eq!(
        evidence_of(&roster, "seg-b"),
        &VoiceAttributionEvidence::ResidualCluster {
            cluster_ref: "residual.2".to_owned()
        }
    );
    assert_eq!(roster.segments[0].speaker_label, "anonymous speaker 1");
    assert_eq!(roster.segments[1].speaker_label, "anonymous speaker 2");

    // The same two segments handed over in the other order label identically.
    let reordered = vault.resolve_voice_segments(&match_request(
        "call-equal-start",
        &space_id,
        vec![runs_long, runs_short],
        Vec::new(),
    ))?;
    assert_eq!(roster, reordered);
    Ok(())
}

#[test]
fn invite_elimination_names_only_the_unambiguous_remainder() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let identity = test_id(0x3B);
    let known_contact = test_id(0x3C);
    let guest_contact = test_id(0x3D);
    let second_guest = test_id(0x3E);
    let owner_subject = test_id(0x51);
    let contact_subject = test_id(0x52);
    let space_id = space().space_id;

    seed_contact(&vault, identity, known_contact, "kenji@example.com")?;
    seed_contact(&vault, identity, guest_contact, "mai@example.com")?;
    seed_contact(&vault, identity, second_guest, "ola@example.com")?;

    enroll_principal(
        &vault,
        owner_subject,
        test_id(0x53),
        "consent-owner",
        [1.0, 0.0, 0.0, 0.0],
    )?;
    vault.record_voice_consent(&granted_event(
        "consent-contact",
        contact_subject,
        test_id(0x54),
        100,
        verbal_basis("recording-1"),
    ))?;
    vault.enroll_voice_print(&VoiceEnrollmentRequest {
        contact_ref: Some(known_contact),
        ..enrollment(
            contact_subject,
            "consent-contact",
            vec![sample(
                "s-1",
                "recording-1",
                "en",
                segment_origin("recording-1", "seg-1"),
                [0.0, 1.0, 0.0, 0.0],
            )],
            200,
        )
    })?;

    // Canonical case: two enrolled principals, one remaining attendee, one
    // residual cluster.
    let segments = vec![
        segment("seg-1", 0, [1.0, 0.0, 0.0, 0.0], &space_id),
        segment("seg-2", 1_000, [0.0, 1.0, 0.0, 0.0], &space_id),
        segment("seg-3", 2_000, [0.0, 0.0, 1.0, 0.0], &space_id),
    ];
    let roster = vault.resolve_voice_segments(&match_request(
        "call-invite",
        &space_id,
        segments.clone(),
        vec![known_contact, guest_contact],
    ))?;
    assert_eq!(
        evidence_of(&roster, "seg-3"),
        &VoiceAttributionEvidence::InviteElimination {
            attendee_ref: guest_contact
        }
    );
    let named = roster
        .segments
        .iter()
        .find(|segment| segment.segment_id == "seg-3")
        .expect("named segment");
    assert_eq!(named.contact_ref, Some(guest_contact));
    assert_eq!(named.subject_ref, None, "naming is not a biometric claim");

    // The biometric scores are untouched by the naming step.
    let anonymous = vault.resolve_voice_segments(&match_request(
        "call-invite-none",
        &space_id,
        segments.clone(),
        Vec::new(),
    ))?;
    for id in ["seg-1", "seg-2"] {
        assert_eq!(evidence_of(&roster, id), evidence_of(&anonymous, id));
    }

    // Ambiguous: two remaining attendees, one residual cluster.
    let roster = vault.resolve_voice_segments(&match_request(
        "call-invite-many-attendees",
        &space_id,
        segments,
        vec![known_contact, guest_contact, second_guest],
    ))?;
    assert!(matches!(
        evidence_of(&roster, "seg-3"),
        VoiceAttributionEvidence::ResidualCluster { .. }
    ));

    // Ambiguous: one remaining attendee, two residual clusters.
    let roster = vault.resolve_voice_segments(&match_request(
        "call-invite-many-clusters",
        &space_id,
        vec![
            segment("seg-1", 0, [1.0, 0.0, 0.0, 0.0], &space_id),
            segment("seg-3", 2_000, [0.0, 0.0, 1.0, 0.0], &space_id),
            segment("seg-4", 3_000, [0.0, 0.0, 0.0, 1.0], &space_id),
        ],
        vec![known_contact, guest_contact],
    ))?;
    for id in ["seg-3", "seg-4"] {
        assert!(
            matches!(
                evidence_of(&roster, id),
                VoiceAttributionEvidence::ResidualCluster { .. }
            ),
            "ambiguous guests stay anonymous"
        );
    }
    Ok(())
}

#[test]
fn relationship_retention_validates_computes_and_prunes_when_due() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let subject = test_id(0x55);
    let relationship = test_id(0x56);
    let not_a_relationship = test_id(0x57);
    seed_relationship(&vault, relationship)?;
    vault.put_entity(
        &not_a_relationship,
        crate::registry::ENTITY_TYPE_EVENT,
        TimeRange { start: 1, end: 1 },
        1,
        b"event",
    )?;

    vault.record_voice_consent(&granted_event(
        "consent-1",
        subject,
        test_id(0x58),
        100,
        notice_basis(),
    ))?;
    // A retention link to a non-RELATIONSHIP entity never enrolls.
    assert!(matches!(
        vault
            .enroll_voice_print(&VoiceEnrollmentRequest {
                relationship_ref: Some(not_a_relationship),
                ..enrollment(
                    subject,
                    "consent-1",
                    vec![solo_sample("s-1", "en", [1.0, 0.0, 0.0, 0.0])],
                    200,
                )
            })
            .expect_err("non-relationship retention link"),
        Error::InvalidRelationship { .. }
    ));

    vault.enroll_voice_print(&VoiceEnrollmentRequest {
        relationship_ref: Some(relationship),
        ..enrollment(
            subject,
            "consent-1",
            vec![solo_sample("s-1", "en", [1.0, 0.0, 0.0, 0.0])],
            200,
        )
    })?;
    assert_eq!(
        stored_print(&vault, subject)?.expect("print").delete_after,
        None
    );

    assert!(matches!(
        vault
            .end_voice_relationship(subject, not_a_relationship, 1_000, 100)
            .expect_err("retention end must name a real RELATIONSHIP"),
        Error::InvalidRelationship { .. }
    ));
    let other_relationship = test_id(0x59);
    seed_relationship(&vault, other_relationship)?;
    assert!(
        vault
            .end_voice_relationship(subject, other_relationship, 1_000, 100)
            .is_err(),
        "a print is only ended through the relationship it is linked to"
    );

    vault.end_voice_relationship(subject, relationship, 1_000, 100)?;
    assert_eq!(
        stored_print(&vault, subject)?.expect("print").delete_after,
        Some(1_100)
    );

    assert!(vault.prune_expired_voice_prints(1_099)?.is_empty());
    assert!(
        stored_print(&vault, subject)?.is_some(),
        "retained while active"
    );

    assert_eq!(vault.prune_expired_voice_prints(1_100)?, vec![subject]);
    assert!(stored_print(&vault, subject)?.is_none());
    assert!(print_family_rows(&vault, subject)?.is_empty());
    assert!(stored_sample(&vault, subject, "s-1")?.is_none());
    assert!(vault.prune_expired_voice_prints(9_999)?.is_empty());
    Ok(())
}

#[test]
fn withdrawal_removes_every_biometric_row_in_one_transaction_and_is_idempotent() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let subject = test_id(0x5A);
    let recorder = test_id(0x5B);
    let space_id = space().space_id;
    vault.record_voice_consent(&granted_event(
        "consent-1",
        subject,
        recorder,
        100,
        notice_basis(),
    ))?;
    vault.enroll_voice_print(&enrollment(
        subject,
        "consent-1",
        vec![
            solo_sample("s-1", "ja", [1.0, 0.0, 0.0, 0.0]),
            solo_sample("s-2", "en", [0.99, 0.14, 0.0, 0.0]),
            solo_sample("s-3", "uk", [0.98, 0.0, 0.2, 0.0]),
        ],
        200,
    ))?;
    for id in ["s-1", "s-2", "s-3"] {
        assert!(stored_sample(&vault, subject, id)?.is_some());
    }

    let request = VoiceWithdrawalRequest {
        event_id: "consent-withdraw".to_owned(),
        subject_ref: subject,
        recorded_by_ref: recorder,
        occurred_at: 500,
        purposes: vec![
            VoicePrintPurpose::MeetingAttribution,
            VoicePrintPurpose::LiveInterlocutor,
        ],
        basis: notice_basis(),
    };
    let receipt = vault.withdraw_voice_consent(&request)?;
    assert_eq!(receipt.consent_event_ref, "consent-withdraw");
    assert_eq!(receipt.subject_ref, subject);
    assert!(!receipt.already_absent);
    assert!(receipt.deleted_print);
    assert!(receipt.deleted_active_pointer);
    assert_eq!(receipt.deleted_sample_count, 3);
    assert_eq!(
        receipt.deleted_vector_count, 4,
        "three sample vectors plus the centroid"
    );

    assert!(print_family_rows(&vault, subject)?.is_empty());
    for id in ["s-1", "s-2", "s-3"] {
        assert!(stored_sample(&vault, subject, id)?.is_none());
    }
    assert!(stored_print(&vault, subject)?.is_none());

    // The withdrawal evidence remains and carries no vector or audio.
    let event = stored_consent(&vault, subject, "consent-withdraw")?.expect("withdrawal event");
    assert_eq!(event.state, VoiceConsentState::Withdrawn);
    assert_eq!(event.recorded_by_ref, recorder);
    assert_eq!(event.occurred_at, 500);

    // No print is found on a subsequent match.
    let roster = vault.resolve_voice_segments(&match_request(
        "call-after-withdrawal",
        &space_id,
        vec![segment("seg-1", 0, [1.0, 0.0, 0.0, 0.0], &space_id)],
        Vec::new(),
    ))?;
    assert!(matches!(
        evidence_of(&roster, "seg-1"),
        VoiceAttributionEvidence::ResidualCluster { .. }
    ));

    // The withdrawn grant cannot be reused to re-enroll.
    assert!(
        vault
            .enroll_voice_print(&enrollment(
                subject,
                "consent-1",
                vec![solo_sample("s-1", "en", [1.0, 0.0, 0.0, 0.0])],
                600,
            ))
            .is_err()
    );

    // A second withdrawal is idempotent.
    let second = vault.withdraw_voice_consent(&VoiceWithdrawalRequest {
        event_id: "consent-withdraw-2".to_owned(),
        occurred_at: 600,
        ..request
    })?;
    assert!(second.already_absent);
    assert!(!second.deleted_print);
    assert!(!second.deleted_active_pointer);
    assert_eq!(second.deleted_sample_count, 0);
    assert_eq!(second.deleted_vector_count, 0);
    Ok(())
}

#[test]
fn sidecars_store_no_raw_audio_and_rosters_store_no_vectors() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let subject = test_id(0x5C);
    let space_id = space().space_id;
    let stranger = [0.0_f32, 0.0, 1.0, 0.0];
    enroll_principal(
        &vault,
        subject,
        test_id(0x5D),
        "consent-1",
        [1.0, 0.0, 0.0, 0.0],
    )?;

    // The sample row holds the vector, its provenance, language, and hash —
    // and, by the decoder's pinned key set, nothing else.
    let stored = stored_sample(&vault, subject, "s-1")?.expect("sample row");
    assert_eq!(stored.source_sha256, source_hash(0xAB));
    assert_eq!(stored.language, "en");
    assert_eq!(stored.origin, solo_origin());
    assert_eq!(stored.vector.len(), DIMENSION);
    let sample_bytes = encode_sample(&stored)?;
    for key in SAMPLE_KEYS {
        assert!(
            sample_bytes
                .windows(key.len())
                .any(|window| window == key.as_bytes()),
            "{key} is part of the pinned sample shape"
        );
    }
    for audio_key in ["audio", "waveform", "pcm", "samples_blob"] {
        assert!(
            !sample_bytes
                .windows(audio_key.len())
                .any(|window| window == audio_key.as_bytes()),
            "no raw audio field is stored"
        );
    }

    let roster = vault.resolve_voice_segments(&match_request(
        "call-vector-free",
        &space_id,
        vec![
            segment("seg-1", 0, [1.0, 0.0, 0.0, 0.0], &space_id),
            segment("seg-2", 1_000, stranger, &space_id),
        ],
        Vec::new(),
    ))?;
    let roster_bytes = raw_roster_bytes(&vault, "call-vector-free")?;
    let vector_bytes = write_body(&encode_vector(&stranger))?;
    assert!(
        !roster_bytes
            .windows(vector_bytes.len())
            .any(|window| window == vector_bytes.as_slice()),
        "a roster carries labels, scores, and evidence — never an embedding"
    );
    assert_eq!(decode_roster(&roster_bytes)?, roster);
    assert_eq!(roster.embedding_space_id, space_id);
    Ok(())
}

#[test]
fn record_decoders_reject_unknown_duplicate_keys_and_bad_schema_versions() -> Result<()> {
    let subject = test_id(0x5E);
    let event = granted_event(
        "consent-1",
        subject,
        test_id(0x61),
        100,
        verbal_basis("recording-1"),
    );
    let bytes = encode_consent_event(&event)?;
    assert_eq!(decode_consent_event(&bytes)?, event);

    let base = map_entries(&read_body(&bytes)?)?.clone();

    let mut unknown_key = base.clone();
    unknown_key.push((Value::from("smuggled"), Value::from(1_u64)));
    assert!(decode_consent_event(&write_body(&Value::Map(unknown_key))?).is_err());

    let mut duplicate_key = base.clone();
    duplicate_key.push((Value::from(CONSENT_KEYS[1]), Value::from("consent-2")));
    assert!(decode_consent_event(&write_body(&Value::Map(duplicate_key))?).is_err());

    let mut missing_key = base.clone();
    missing_key.pop();
    assert!(decode_consent_event(&write_body(&Value::Map(missing_key))?).is_err());

    let bad_version: Vec<(Value, Value)> = base
        .iter()
        .map(|(key, value)| {
            if key.as_str() == Some(KEY_SCHEMA_VERSION) {
                (key.clone(), Value::from(99_u64))
            } else {
                (key.clone(), value.clone())
            }
        })
        .collect();
    assert!(decode_consent_event(&write_body(&Value::Map(bad_version))?).is_err());

    let bad_id: Vec<(Value, Value)> = base
        .iter()
        .map(|(key, value)| {
            if key.as_str() == Some(CONSENT_KEYS[2]) {
                (key.clone(), Value::Binary(vec![0_u8; 15]))
            } else {
                (key.clone(), value.clone())
            }
        })
        .collect();
    assert!(decode_consent_event(&write_body(&Value::Map(bad_id))?).is_err());

    // Trailing bytes after a complete value are not a valid record either.
    let mut trailing = bytes;
    trailing.push(0x00);
    assert!(decode_consent_event(&trailing).is_err());

    // Non-finite floats never survive a decode.
    let record = VoicePrintRecordV1 {
        subject_ref: subject,
        contact_ref: None,
        relationship_ref: None,
        consent_event_ref: "consent-1".to_owned(),
        space: space(),
        centroid: vec![1.0, 0.0, 0.0, 0.0],
        sample_ids: vec!["s-1".to_owned()],
        sample_languages: vec!["en".to_owned()],
        calibration: VoicePrintCalibration::Collecting,
        created_at: 200,
        updated_at: 200,
        delete_after: None,
    };
    let print_bytes = encode_print_record(&record)?;
    assert_eq!(decode_print_record(&print_bytes)?, record);
    let poisoned: Vec<(Value, Value)> = map_entries(&read_body(&print_bytes)?)?
        .iter()
        .map(|(key, value)| {
            if key.as_str() == Some(PRINT_KEYS[6]) {
                (key.clone(), encode_vector(&[f32::NAN, 0.0, 0.0, 0.0]))
            } else {
                (key.clone(), value.clone())
            }
        })
        .collect();
    assert!(decode_print_record(&write_body(&Value::Map(poisoned))?).is_err());

    // Sample and origin bodies decode round-trip and reject foreign shapes.
    let sample = solo_sample("s-1", "en", [1.0, 0.0, 0.0, 0.0]);
    assert_eq!(decode_sample(&encode_sample(&sample)?)?, sample);
    assert!(
        decode_origin(&Value::Map(vec![(
            Value::from(KEY_KIND),
            Value::from("smuggled_origin")
        )]))
        .is_err()
    );
    Ok(())
}

/// An id has exactly ONE wire shape: a 16-byte MessagePack binary value.
#[test]
fn entity_ref_decoder_rejects_a_sixteen_byte_string_payload() -> Result<()> {
    // Sixteen bytes of valid UTF-8: the wrong MessagePack type at the right
    // length, a form the encoder never emits.
    let text = "0123456789abcdef";
    assert_eq!(text.len(), ENTITY_ID_LEN);
    let as_string = Value::from(text);
    assert!(matches!(as_string, Value::String(_)));
    assert!(
        decode_entity_ref(&as_string).is_err(),
        "a MessagePack string is never an entity id, whatever its length"
    );
    // The identical bytes in the canonical binary form ARE an id, so the
    // rejection is about the wire type and not about these bytes.
    assert!(decode_entity_ref(&Value::Binary(text.as_bytes().to_vec())).is_ok());

    // The record door refuses it in an id position, next to the short-binary
    // arm the codec test already pins.
    let event = granted_event(
        "consent-1",
        test_id(0x66),
        test_id(0x67),
        100,
        notice_basis(),
    );
    let bytes = encode_consent_event(&event)?;
    let smuggled: Vec<(Value, Value)> = map_entries(&read_body(&bytes)?)?
        .iter()
        .map(|(key, value)| {
            if key.as_str() == Some(CONSENT_KEYS[2]) {
                (key.clone(), Value::from(text))
            } else {
                (key.clone(), value.clone())
            }
        })
        .collect();
    assert!(
        decode_consent_event(&write_body(&Value::Map(smuggled))?).is_err(),
        "a string-shaped subject_ref is a corrupt row, not a decoded record"
    );
    Ok(())
}

/// A similarity result is evidence, never authority.
///
/// [`VoiceSessionRosterV1`], [`VoiceResolvedSegment`], and
/// [`VoiceAttributionEvidence`] are distinct types from
/// [`crate::genui::ConsentActorIdentity`] with no conversion into it: they
/// carry labels, refs, scores, and evidence, and not one of them carries an
/// actor identity or a verification flag. The only way to reach a consent
/// actor from roster data is for a caller to write the boolean itself, which
/// nothing in this module does — and doing so proves nothing, because the
/// consent door authenticates against a store-minted owner handle.
#[test]
fn similarity_result_is_not_a_consent_actor_and_cannot_auto_clear() -> Result<()> {
    use crate::genui::{
        ConsentActionKind, ConsentActionRequest, ConsentActorIdentity, ConsentAskCard,
        ConsentSurface,
    };
    use std::any::TypeId;

    let (_tmp, vault) = temp_vault();
    let subject = test_id(0x68);
    let space_id = space().space_id;
    enroll_principal(
        &vault,
        subject,
        test_id(0x69),
        "consent-owner",
        [1.0, 0.0, 0.0, 0.0],
    )?;

    // The strongest result this engine can produce: an enrolled print matched
    // at or above the recorded threshold.
    let roster = vault.resolve_voice_segments(&match_request(
        "call-consent-seam",
        &space_id,
        vec![segment("seg-1", 0, [1.0, 0.0, 0.0, 0.0], &space_id)],
        Vec::new(),
    ))?;
    let resolved = &roster.segments[0];
    let VoiceAttributionEvidence::EnrolledPrint { score, .. } = &resolved.evidence else {
        panic!("expected an enrolled match to test the seam");
    };
    assert!(
        *score >= VOICE_MATCH_THRESHOLD_DEFAULT,
        "the seam is tested against an accepted match"
    );

    // Not a consent actor: three distinct types, none of which IS one.
    assert_ne!(
        TypeId::of::<VoiceSessionRosterV1>(),
        TypeId::of::<ConsentActorIdentity>()
    );
    assert_ne!(
        TypeId::of::<VoiceResolvedSegment>(),
        TypeId::of::<ConsentActorIdentity>()
    );
    assert_ne!(
        TypeId::of::<VoiceAttributionEvidence>(),
        TypeId::of::<ConsentActorIdentity>()
    );

    // The most a caller can assemble from roster data is a CLAIMED voice path
    // whose verification flag no voice result supplies. It authenticates
    // nobody — not the owner principal, not even the speaker it names.
    let claimed = ConsentActorIdentity::VoicePath {
        speaker_ref: resolved.speaker_label.clone(),
        owner_voice_print_verified: false,
    };
    assert_eq!(claimed.actor_ref(), subject.to_hex());
    assert!(!claimed.authenticates_principal("principal:owner"));
    assert!(!claimed.authenticates_principal(&subject.to_hex()));

    // And it clears no consequential action: with a real store-authenticated
    // owner present, the consent door still refuses the voice claim as an
    // unauthenticated actor instead of approving.
    let owner_actor = test_id(0x6A);
    vault.put_entity(
        &owner_actor,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        owner_actor,
        "principal:owner",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let card = ConsentAskCard::new(
        "ask-voice-1",
        "principal:owner",
        "Send the meeting recap?",
        "recap preview",
        "send",
        Vec::new(),
    )?;
    let request = ConsentActionRequest::new(
        "ask-voice-1",
        "approve_once",
        ConsentActionKind::Approve,
        claimed,
        ConsentSurface::Voice,
        1_000,
    )?;
    assert_eq!(
        card.evaluate_action(&request, &owner)
            .expect_err("a voice similarity match must not clear a consequential action")
            .kind(),
        ErrorKind::ConsentUnauthenticatedActor,
        "the matched speaker label is evidence, not an authenticated actor"
    );
    Ok(())
}
