use super::*;
use crate::counterparty_contact::CounterpartyContactRecord;
use serde_json::json;

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

fn seed_contact(vault: &Vault, identity: EntityId, contact_id: EntityId, who: &str) -> Result<()> {
    let record = CounterpartyContactRecord::user_introduction(identity, who, 10)?;
    vault.create_counterparty_contact(&contact_id, &record)
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
        },
    )
}

/// An enrolled CONTACT print match.
fn enrolled_contact_segment(
    segment_id: &str,
    subject_ref: EntityId,
    contact_ref: EntityId,
) -> VoiceResolvedSegment {
    roster_segment(
        segment_id,
        &subject_ref.to_hex(),
        Some(subject_ref),
        Some(contact_ref),
        VoiceAttributionEvidence::EnrolledPrint {
            subject_ref,
            score: 0.8,
            calibration: VoicePrintCalibration::Collecting,
        },
    )
}

/// A non-biometric invite-elimination naming.
fn invite_segment(segment_id: &str, attendee_ref: EntityId) -> VoiceResolvedSegment {
    roster_segment(
        segment_id,
        &attendee_ref.to_hex(),
        None,
        Some(attendee_ref),
        VoiceAttributionEvidence::InviteElimination { attendee_ref },
    )
}

/// An anonymous residual cluster.
fn residual_segment(
    segment_id: &str,
    speaker_label: &str,
    cluster_ref: &str,
) -> VoiceResolvedSegment {
    roster_segment(
        segment_id,
        speaker_label,
        None,
        None,
        VoiceAttributionEvidence::ResidualCluster {
            cluster_ref: cluster_ref.to_owned(),
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
fn class_and_evidence_string_forms_are_pinned() {
    assert_eq!(InterlocutorClass::Owner.as_str(), "owner");
    assert_eq!(InterlocutorClass::KnownContact.as_str(), "known_contact");
    assert_eq!(InterlocutorClass::Unknown.as_str(), "unknown");
    for class in [
        InterlocutorClass::Owner,
        InterlocutorClass::KnownContact,
        InterlocutorClass::Unknown,
    ] {
        assert_eq!(InterlocutorClass::parse(class.as_str()), Some(class));
    }
    assert_eq!(InterlocutorClass::parse("root"), None);

    assert_eq!(
        PresenceEvidence::AuthenticatedSession.as_str(),
        "authenticated_session"
    );
    assert_eq!(
        PresenceEvidence::EnrolledVoicePrint.as_str(),
        "enrolled_voice_print"
    );
    assert_eq!(PresenceEvidence::FirstClaim.as_str(), "first_claim");
    assert_eq!(PresenceEvidence::AuthenticatedSession.rank(), 3);
    assert_eq!(PresenceEvidence::EnrolledVoicePrint.rank(), 2);
    assert_eq!(PresenceEvidence::FirstClaim.rank(), 1);
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
fn channel_counterparty_resolution_transitions_unknown_to_known() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let identity = test_id(0x52);
    let input = resolution_input(vec![InterlocutorPartyInput::ChannelCounterparty {
        identity_ref: identity,
        counterparty: "kenji@example.com".to_owned(),
    }]);

    let before = vault.resolve_interlocutors(&input)?;
    assert_eq!(before.entries()[0].class(), InterlocutorClass::Unknown);
    assert_eq!(before.entries()[0].label(), "kenji@example.com");
    assert_eq!(before.entries()[0].contact_ref(), None);

    let contact_id = test_id(0xB2);
    let record = CounterpartyContactRecord::user_introduction(identity, "kenji@example.com", 10)?;
    vault.create_counterparty_contact(&contact_id, &record)?;

    let after = vault.resolve_interlocutors(&input)?;
    assert_eq!(after.entries()[0].class(), InterlocutorClass::KnownContact);
    assert_eq!(
        after.entries()[0].contact_ref(),
        Some(contact_id.to_hex().as_str())
    );

    vault.revoke_counterparty_contact(&contact_id, 20)?;
    let revoked = vault.resolve_interlocutors(&input)?;
    assert_eq!(revoked.entries()[0].class(), InterlocutorClass::Unknown);
    Ok(())
}

#[test]
fn unknown_label_carries_claimed_owner_as_label_only() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let set = vault.resolve_interlocutors(&resolution_input(vec![
        InterlocutorPartyInput::UnknownLabel {
            label: "unknown speaker 2".to_owned(),
            claimed_owner: true,
        },
    ]))?;
    let entry = &set.entries()[0];
    assert_eq!(entry.class(), InterlocutorClass::Unknown);
    assert!(entry.claimed_owner());
    assert!(!set.supervised());
    let stamps = set.stamps();
    assert_eq!(stamps[0].speaker, "unknown speaker 2");
    assert!(stamps[0].claims_not_instructions);
    Ok(())
}

#[test]
fn duplicate_contact_inputs_collapse_to_one_entry() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let identity = test_id(0x53);
    let contact_id = test_id(0xB3);
    let record = CounterpartyContactRecord::user_introduction(identity, "kenji@example.com", 10)?;
    vault.create_counterparty_contact(&contact_id, &record)?;

    let set = vault.resolve_interlocutors(&resolution_input(vec![
        InterlocutorPartyInput::ContactRef(contact_id),
        InterlocutorPartyInput::ChannelCounterparty {
            identity_ref: identity,
            counterparty: "kenji@example.com".to_owned(),
        },
    ]))?;
    assert_eq!(set.entries().len(), 1);
    assert_eq!(
        set.entries()[0].contact_ref(),
        Some(contact_id.to_hex().as_str())
    );

    // Label collision between Unknowns is allowed: labels are display data.
    let unknowns = vault.resolve_interlocutors(&resolution_input(vec![
        InterlocutorPartyInput::UnknownLabel {
            label: "guest".to_owned(),
            claimed_owner: false,
        },
        InterlocutorPartyInput::UnknownLabel {
            label: "guest".to_owned(),
            claimed_owner: false,
        },
    ]))?;
    assert_eq!(unknowns.entries().len(), 2);
    Ok(())
}

#[test]
fn voice_session_ref_resolves_its_stored_roster_parties() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let identity = test_id(0x61);
    let contact_id = test_id(0x62);
    let owner_subject = test_id(0x63);
    let contact_subject = test_id(0x64);
    seed_contact(&vault, identity, contact_id, "kenji@example.com")?;
    seed_voice_roster(
        &vault,
        "call-123",
        vec![
            enrolled_owner_segment("seg-1", owner_subject),
            enrolled_contact_segment("seg-2", contact_subject, contact_id),
            residual_segment("seg-3", "anonymous speaker 1", "residual.1"),
        ],
    )?;

    let set = vault.resolve_interlocutors(&InterlocutorResolutionInput {
        owner_session: false,
        parties: Vec::new(),
        voice_session_ref: Some("call-123".to_owned()),
    })?;
    assert!(!set.supervised(), "a roster never mints supervision");
    assert_eq!(set.entries().len(), 3);

    let owner_match = &set.entries()[0];
    assert_eq!(owner_match.class(), InterlocutorClass::Unknown);
    assert_eq!(owner_match.evidence(), PresenceEvidence::EnrolledVoicePrint);
    assert!(owner_match.owner_print_matched());

    let contact_match = &set.entries()[1];
    assert_eq!(contact_match.class(), InterlocutorClass::KnownContact);
    assert_eq!(
        contact_match.evidence(),
        PresenceEvidence::EnrolledVoicePrint
    );
    assert_eq!(contact_match.label(), "kenji@example.com");
    assert_eq!(
        contact_match.contact_ref(),
        Some(contact_id.to_hex().as_str())
    );
    assert!(!contact_match.owner_print_matched());

    let residual = &set.entries()[2];
    assert_eq!(residual.class(), InterlocutorClass::Unknown);
    assert_eq!(residual.label(), "anonymous speaker 1");
    assert_eq!(residual.contact_ref(), None);
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
fn voice_derived_stamps_carry_claims_not_instructions() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let identity = test_id(0x66);
    let contact_id = test_id(0x67);
    let attendee_id = test_id(0x68);
    seed_contact(&vault, identity, contact_id, "kenji@example.com")?;
    seed_contact(&vault, identity, attendee_id, "mai@example.com")?;
    seed_voice_roster(
        &vault,
        "call-stamps",
        vec![
            enrolled_owner_segment("seg-1", test_id(0x69)),
            enrolled_contact_segment("seg-2", test_id(0x6A), contact_id),
            invite_segment("seg-3", attendee_id),
            residual_segment("seg-4", "anonymous speaker 1", "residual.1"),
        ],
    )?;

    let set = vault.resolve_interlocutors(&InterlocutorResolutionInput {
        owner_session: true,
        parties: Vec::new(),
        voice_session_ref: Some("call-stamps".to_owned()),
    })?;
    assert_eq!(set.non_owner().count(), 4);
    for entry in set.non_owner() {
        assert_ne!(entry.class(), InterlocutorClass::Owner);
        assert!(InterlocutorStamp::for_interlocutor(entry).claims_not_instructions);
    }

    // Invite elimination is non-biometric: it borrows no evidence rung.
    let named = set
        .non_owner()
        .find(|entry| entry.contact_ref() == Some(attendee_id.to_hex().as_str()))
        .expect("invite-eliminated attendee");
    assert_eq!(named.class(), InterlocutorClass::KnownContact);
    assert_eq!(named.evidence(), PresenceEvidence::FirstClaim);
    assert!(!named.owner_print_matched());
    Ok(())
}

#[test]
fn owner_entries_exist_only_via_session_constructors() {
    let owner_alone = InterlocutorSet::owner_alone();
    assert!(owner_alone.supervised());
    assert_eq!(owner_alone.entries().len(), 1);
    let owner = &owner_alone.entries()[0];
    assert_eq!(owner.class(), InterlocutorClass::Owner);
    assert_eq!(owner.evidence(), PresenceEvidence::AuthenticatedSession);
    assert_eq!(owner.label(), "owner");
    assert!(!owner.claimed_owner());
    assert!(!owner.owner_print_matched());

    let with_owner =
        InterlocutorSet::with_session_owner(vec![Interlocutor::unknown("guest", false)]);
    assert!(with_owner.supervised());
    assert!(with_owner.has_non_owner());

    let without_owner = InterlocutorSet::without_owner(vec![Interlocutor::unknown("guest", false)]);
    assert!(!without_owner.supervised());

    // A spoofed "it's me" is expressible only as an Unknown label flag.
    let spoof = Interlocutor::unknown("it's me", true);
    assert_eq!(spoof.class(), InterlocutorClass::Unknown);
    let spoofed_set = InterlocutorSet::without_owner(vec![spoof]);
    assert!(!spoofed_set.supervised());
}

#[test]
fn forged_owner_literals_are_filtered_from_set_constructors() {
    // In-module (test) code can express an Owner-class literal; the set
    // constructors must drop it so `supervised()` stays trustworthy.
    let forged_owner = Interlocutor {
        class: InterlocutorClass::Owner,
        evidence: PresenceEvidence::FirstClaim,
        label: "forged".to_owned(),
        contact_ref: None,
        first_touch: None,
        relationship: None,
        claimed_owner: true,
        owner_print_matched: false,
    };

    let without_owner = InterlocutorSet::without_owner(vec![forged_owner.clone()]);
    assert!(without_owner.entries().is_empty());
    assert!(!without_owner.supervised());

    let with_owner = InterlocutorSet::with_session_owner(vec![
        forged_owner,
        Interlocutor::unknown("guest", false),
    ]);
    assert_eq!(with_owner.entries().len(), 2);
    assert!(
        with_owner
            .entries()
            .iter()
            .filter(|entry| entry.class() == InterlocutorClass::Owner)
            .all(
                |entry| entry.evidence() == PresenceEvidence::AuthenticatedSession
                    && entry.label() == "owner"
            ),
        "the only surviving Owner entry is the constructor-minted one"
    );
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
fn stamp_value_validation_enforces_shape_and_class_consistency() {
    assert!(
        validate_interlocutor_stamp_value(&json!({
            "speaker": "kenji@example.com",
            "class": "known_contact",
            "claims_not_instructions": true
        }))
        .is_ok()
    );
    assert!(
        validate_interlocutor_stamp_value(&json!({
            "speaker": "owner",
            "class": "owner",
            "claims_not_instructions": false
        }))
        .is_ok()
    );

    // A non-owner stamp claiming instruction authority must be rejected.
    assert!(
        validate_interlocutor_stamp_value(&json!({
            "speaker": "guest",
            "class": "unknown",
            "claims_not_instructions": false
        }))
        .is_err()
    );
    // An owner stamp with the non-owner bit is inconsistent too.
    assert!(
        validate_interlocutor_stamp_value(&json!({
            "speaker": "owner",
            "class": "owner",
            "claims_not_instructions": true
        }))
        .is_err()
    );
    assert!(validate_interlocutor_stamp_value(&json!("stamp")).is_err());
    assert!(
        validate_interlocutor_stamp_value(&json!({
            "speaker": "",
            "class": "unknown",
            "claims_not_instructions": true
        }))
        .is_err()
    );
    assert!(
        validate_interlocutor_stamp_value(&json!({
            "speaker": "guest",
            "class": "intruder",
            "claims_not_instructions": true
        }))
        .is_err()
    );
    assert!(
        validate_interlocutor_stamp_value(&json!({
            "speaker": "guest",
            "class": "unknown",
            "claims_not_instructions": true,
            "extra": 1
        }))
        .is_err()
    );
    assert!(
        validate_interlocutor_stamp_value(&json!({
            "speaker": "guest",
            "class": "unknown"
        }))
        .is_err()
    );
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

#[test]
fn duplicate_heavy_inputs_resolve_in_one_pass_to_one_entry() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let identity = test_id(0x54);
    let contact_id = test_id(0xB5);
    let record = CounterpartyContactRecord::user_introduction(identity, "kenji@example.com", 10)?;
    vault.create_counterparty_contact(&contact_id, &record)?;

    // 200 duplicate references to the same contact (mixed input shapes) plus
    // interleaved unknowns: one KnownContact entry survives, unknowns keep
    // their set order, and the set-based dedup does no quadratic rescan.
    let mut parties = Vec::new();
    for index in 0..200 {
        parties.push(if index % 2 == 0 {
            InterlocutorPartyInput::ContactRef(contact_id)
        } else {
            InterlocutorPartyInput::ChannelCounterparty {
                identity_ref: identity,
                counterparty: "kenji@example.com".to_owned(),
            }
        });
    }
    parties.push(InterlocutorPartyInput::UnknownLabel {
        label: "guest".to_owned(),
        claimed_owner: false,
    });

    let set = vault.resolve_interlocutors(&resolution_input(parties))?;
    assert_eq!(set.entries().len(), 2);
    assert_eq!(
        set.entries()[0].contact_ref(),
        Some(contact_id.to_hex().as_str())
    );
    assert_eq!(set.entries()[1].label(), "guest");
    Ok(())
}
