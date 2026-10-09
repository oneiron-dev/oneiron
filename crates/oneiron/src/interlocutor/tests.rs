use super::*;
use crate::counterparty_contact::CounterpartyContactRecord;

use crate::test_util::entity as test_id;
use crate::voice_identity::{
    VoicePrintCalibration, VoiceSessionRosterV1, put_raw_voice_roster_for_test,
    put_voice_roster_for_test,
};

fn temp_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(crate::config::VaultConfig::default())
}

fn resolution_input(parties: Vec<InterlocutorPartyInput>) -> InterlocutorResolutionInput {
    InterlocutorResolutionInput {
        owner_session: false,
        parties,
        voice_session_ref: None,
    }
}

fn roster_segment(
    segment_id: &str,
    speaker_label: &str,
    subject_ref: Option<EntityId>,
    contact_ref: Option<EntityId>,
    evidence: VoiceAttributionEvidence,
) -> VoiceResolvedSegment {
    VoiceResolvedSegment {
        segment_id: segment_id.to_owned(),
        start_ms: 0,
        end_ms: 1_000,
        speaker_label: speaker_label.to_owned(),
        subject_ref,
        contact_ref,
        evidence,
    }
}

/// An enrolled OWNER print match: enrolled-print evidence, no contact link.
fn enrolled_owner_segment(segment_id: &str, subject_ref: EntityId) -> VoiceResolvedSegment {
    roster_segment(
        segment_id,
        &subject_ref.to_hex(),
        Some(subject_ref),
        None,
        VoiceAttributionEvidence::EnrolledPrint {
            subject_ref,
            score: 0.9,
            calibration: VoicePrintCalibration::Calibrated,
            print_generation: test_id(0xF1),
        },
    )
}

fn seed_voice_roster(
    vault: &Vault,
    voice_session_ref: &str,
    segments: Vec<VoiceResolvedSegment>,
) -> Result<()> {
    put_voice_roster_for_test(
        vault,
        &VoiceSessionRosterV1 {
            voice_session_ref: voice_session_ref.to_owned(),
            recording_id: "recording-1".to_owned(),
            embedding_space_id: "space-1".to_owned(),
            known_threshold: 0.65,
            segments,
            created_at: 100,
        },
    )
}

fn put_raw_voice_roster(vault: &Vault, voice_session_ref: &str, bytes: &[u8]) -> Result<()> {
    put_raw_voice_roster_for_test(vault, voice_session_ref, bytes)
}

#[test]
fn contact_ref_resolution_covers_active_revoked_and_missing() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let identity = test_id(0x51);
    let contact_id = test_id(0xB1);
    let record = CounterpartyContactRecord::user_introduction(identity, "kenji@example.com", 10)?;
    vault.create_counterparty_contact(&contact_id, &record)?;

    let set = vault.resolve_interlocutors(&resolution_input(vec![
        InterlocutorPartyInput::ContactRef(contact_id),
    ]))?;
    let entry = &set.entries()[0];
    assert_eq!(entry.class(), InterlocutorClass::KnownContact);
    assert_eq!(entry.evidence(), PresenceEvidence::FirstClaim);
    assert_eq!(entry.label(), "kenji@example.com");
    assert_eq!(entry.contact_ref(), Some(contact_id.to_hex().as_str()));
    assert_eq!(
        entry.first_touch(),
        Some(CounterpartyFirstTouch::UserIntroduction)
    );
    assert_eq!(entry.relationship(), None);

    vault.revoke_counterparty_contact(&contact_id, 20)?;
    let set = vault.resolve_interlocutors(&resolution_input(vec![
        InterlocutorPartyInput::ContactRef(contact_id),
    ]))?;
    let entry = &set.entries()[0];
    assert_eq!(entry.class(), InterlocutorClass::Unknown);
    assert_eq!(entry.label(), "kenji@example.com");
    assert_eq!(entry.contact_ref(), None);

    let missing = vault
        .resolve_interlocutors(&resolution_input(vec![InterlocutorPartyInput::ContactRef(
            test_id(0xEE),
        )]))
        .expect_err("dangling explicit contact ref fails loudly");
    assert_eq!(missing.kind(), crate::error::ErrorKind::EntityNotFound);
    Ok(())
}

#[test]
fn matched_owner_print_without_session_is_a_non_owner_entry() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let owner_subject = test_id(0x65);
    seed_voice_roster(
        &vault,
        "call-owner",
        vec![enrolled_owner_segment("seg-1", owner_subject)],
    )?;

    let unsupervised = vault.resolve_interlocutors(&InterlocutorResolutionInput {
        owner_session: false,
        parties: Vec::new(),
        voice_session_ref: Some("call-owner".to_owned()),
    })?;
    assert_eq!(unsupervised.entries().len(), 1);
    assert!(
        !unsupervised.supervised(),
        "an enrolled print is corroboration, never authentication"
    );
    assert!(unsupervised.entries()[0].owner_print_matched());
    assert_eq!(
        unsupervised.entries()[0].class(),
        InterlocutorClass::Unknown
    );

    // With a real owner session, the session-created Owner stays the ONLY
    // Owner entry and the voice match remains a separate non-owner entry.
    let supervised = vault.resolve_interlocutors(&InterlocutorResolutionInput {
        owner_session: true,
        parties: Vec::new(),
        voice_session_ref: Some("call-owner".to_owned()),
    })?;
    assert!(supervised.supervised());
    assert_eq!(supervised.entries().len(), 2);
    let owners: Vec<&Interlocutor> = supervised
        .entries()
        .iter()
        .filter(|entry| entry.class() == InterlocutorClass::Owner)
        .collect();
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].evidence(), PresenceEvidence::AuthenticatedSession);
    assert_eq!(owners[0].label(), "owner");
    assert!(!owners[0].owner_print_matched());
    assert_eq!(supervised.non_owner().count(), 1);
    Ok(())
}

#[test]
fn missing_or_corrupt_voice_roster_yields_one_unknown_non_owner() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    // A supplied reference with no stored roster.
    let missing = vault.resolve_interlocutors(&InterlocutorResolutionInput {
        owner_session: true,
        parties: Vec::new(),
        voice_session_ref: Some("call-missing".to_owned()),
    })?;
    assert_eq!(missing.entries().len(), 2);
    assert_eq!(missing.non_owner().count(), 1);
    assert_eq!(
        missing.non_owner().next().expect("entry").class(),
        InterlocutorClass::Unknown
    );
    assert!(
        missing.has_non_owner(),
        "failure narrows disclosure: never owner-alone mode"
    );

    // A stored roster row whose bytes do not decode.
    put_raw_voice_roster(&vault, "call-corrupt", b"not a roster body")?;
    let corrupt = vault.resolve_interlocutors(&InterlocutorResolutionInput {
        owner_session: true,
        parties: Vec::new(),
        voice_session_ref: Some("call-corrupt".to_owned()),
    })?;
    assert_eq!(corrupt.entries().len(), 2);
    assert_eq!(corrupt.non_owner().count(), 1);
    assert_eq!(
        corrupt.non_owner().next().expect("entry").class(),
        InterlocutorClass::Unknown
    );
    assert!(!corrupt.non_owner().next().expect("entry").claimed_owner());
    Ok(())
}

#[test]
fn forged_owner_literals_are_filtered_from_set_constructors() {
    // Even a session-minted Owner must be filtered when supplied as a participant.
    let session = InterlocutorSet::owner_alone();
    let supplied_owner = session.entries()[0].clone();
    assert_eq!(supplied_owner.class(), InterlocutorClass::Owner);

    let without_owner = InterlocutorSet::without_owner(vec![supplied_owner.clone()]);
    assert!(without_owner.entries().is_empty());
    assert!(!without_owner.supervised());

    let with_owner = InterlocutorSet::with_session_owner(vec![
        supplied_owner,
        Interlocutor::unknown("guest", false),
    ]);
    assert!(with_owner.supervised());
    assert_eq!(with_owner.entries().len(), 2);
    let mut owners = with_owner
        .entries()
        .iter()
        .filter(|entry| entry.class() == InterlocutorClass::Owner);
    assert_eq!(
        owners.next().map(super::Interlocutor::evidence),
        Some(PresenceEvidence::AuthenticatedSession),
    );
    assert!(owners.next().is_none());
    let mut non_owner = with_owner.non_owner();
    assert_eq!(
        non_owner.next().map(super::Interlocutor::class),
        Some(InterlocutorClass::Unknown),
    );
    assert!(non_owner.next().is_none());
}

#[test]
fn stamps_derive_claims_not_instructions_from_class() {
    let contact_id = test_id(0xB4);
    let set = InterlocutorSet::with_session_owner(vec![
        Interlocutor::known_contact(
            contact_id,
            "kenji@example.com",
            CounterpartyFirstTouch::UserIntroduction,
        ),
        Interlocutor::unknown("guest", true),
    ]);
    let stamps = set.stamps();
    assert_eq!(stamps.len(), 3);
    assert_eq!(stamps[0].speaker, "owner");
    assert_eq!(stamps[0].class, InterlocutorClass::Owner);
    assert!(!stamps[0].claims_not_instructions);
    assert_eq!(stamps[1].speaker, contact_id.to_hex());
    assert_eq!(stamps[1].class, InterlocutorClass::KnownContact);
    assert!(stamps[1].claims_not_instructions);
    assert_eq!(stamps[2].speaker, "guest");
    assert!(stamps[2].claims_not_instructions);

    for entry in set.non_owner() {
        assert!(InterlocutorStamp::for_interlocutor(entry).claims_not_instructions);
    }
}

#[test]
fn owner_session_flag_is_the_only_supervision_path() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut input = resolution_input(vec![InterlocutorPartyInput::UnknownLabel {
        label: "guest".to_owned(),
        claimed_owner: true,
    }]);
    assert!(!vault.resolve_interlocutors(&input)?.supervised());

    input.owner_session = true;
    let set = vault.resolve_interlocutors(&input)?;
    assert!(set.supervised());
    assert_eq!(set.entries().len(), 2);
    assert_eq!(set.non_owner().count(), 1);
    Ok(())
}
