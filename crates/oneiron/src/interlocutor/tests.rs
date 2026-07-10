use super::*;
use crate::counterparty_contact::CounterpartyContactRecord;
use serde_json::json;

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("valid entity id")
}

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
    let identity = test_id(0xA1);
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
    let identity = test_id(0xA2);
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
    let identity = test_id(0xA3);
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
fn voice_session_ref_is_accepted_and_resolves_to_no_entries() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let set = vault.resolve_interlocutors(&InterlocutorResolutionInput {
        owner_session: true,
        parties: Vec::new(),
        voice_session_ref: Some("call-123".to_owned()),
    })?;
    assert_eq!(set.entries().len(), 1);
    assert!(set.supervised());
    assert!(!set.has_non_owner());
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
    let identity = test_id(0xA4);
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
