use rmpv::Value;

use super::*;
use crate::config::VaultConfig;
use crate::{EntityId, ErrorKind, Vault};

use crate::test_util::entity;

fn test_profile() -> PsychProfile {
    PsychProfile::new(
        entity(0x51),
        "fast compact profile",
        "retrieval-friendly profile text",
        "A warm narrative profile.",
        vec![entity(0xC3), entity(0xC1), entity(0xC3), entity(0xC2)],
        PsychProfileConfidence::new(0.8, 0.7, 0.6).expect("valid confidence"),
    )
    .expect("valid profile")
}

fn test_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

fn msgpack_map(entries: Vec<(&'static str, Value)>) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(
        &mut out,
        &Value::Map(
            entries
                .into_iter()
                .map(|(key, value)| (Value::from(key), value))
                .collect(),
        ),
    )
    .expect("encode msgpack");
    out
}

#[test]
fn psych_profile_decoder_rejects_unknown_keys() {
    let profile = test_profile();
    let mut entries = vec![
        (
            KEY_SCHEMA_VERSION,
            Value::from(PSYCH_PROFILE_SCHEMA_VERSION),
        ),
        (KEY_SUBJECT_REF, Value::from(profile.subject_ref.to_hex())),
        (KEY_COMPACT, Value::from(profile.compact.as_str())),
        (KEY_TEXT, Value::from(profile.text.as_str())),
        (KEY_NARRATIVE, Value::from(profile.narrative.as_str())),
        (
            KEY_SOURCE_REVISION_IDS,
            encode_source_revision_ids(&profile.source_revision_ids),
        ),
        (KEY_CONFIDENCE, encode_confidence(profile.confidence)),
        (KEY_STATUS, Value::from(profile.status.as_code())),
    ];
    entries.push(("unexpected", Value::from(true)));

    let err = decode_psych_profile_body(&msgpack_map(entries))
        .expect_err("unknown psych profile keys fail closed");
    assert_eq!(err.kind(), ErrorKind::InvalidPsychProfileBody);
}

#[test]
fn psych_profile_decoder_rejects_noncanonical_source_revisions() {
    let profile = test_profile();
    let entries = vec![
        (
            KEY_SCHEMA_VERSION,
            Value::from(PSYCH_PROFILE_SCHEMA_VERSION),
        ),
        (KEY_SUBJECT_REF, Value::from(profile.subject_ref.to_hex())),
        (KEY_COMPACT, Value::from(profile.compact.as_str())),
        (KEY_TEXT, Value::from(profile.text.as_str())),
        (KEY_NARRATIVE, Value::from(profile.narrative.as_str())),
        (
            KEY_SOURCE_REVISION_IDS,
            Value::Array(vec![
                Value::from(entity(0xC2).to_hex()),
                Value::from(entity(0xC1).to_hex()),
            ]),
        ),
        (KEY_CONFIDENCE, encode_confidence(profile.confidence)),
        (KEY_STATUS, Value::from(profile.status.as_code())),
    ];

    let err = decode_psych_profile_body(&msgpack_map(entries))
        .expect_err("stored source revisions must be canonical");
    assert_eq!(err.kind(), ErrorKind::InvalidPsychProfileBody);
}

#[test]
fn psych_profile_status_persists_as_typed_code_and_rejects_strings() -> Result<()> {
    let profile = test_profile();
    let encoded = encode_psych_profile_body(&profile)?;
    let Value::Map(entries) = rmpv::decode::read_value(&mut Cursor::new(&encoded))
        .expect("encoded profile is MessagePack")
    else {
        panic!("encoded profile must be a MessagePack map");
    };
    assert_eq!(
        required_value(&entries, KEY_STATUS)?.as_u64(),
        Some(profile.status.as_code())
    );

    let string_status_body = msgpack_map(vec![
        (
            KEY_SCHEMA_VERSION,
            Value::from(PSYCH_PROFILE_SCHEMA_VERSION),
        ),
        (KEY_SUBJECT_REF, Value::from(profile.subject_ref.to_hex())),
        (KEY_COMPACT, Value::from(profile.compact.as_str())),
        (KEY_TEXT, Value::from(profile.text.as_str())),
        (KEY_NARRATIVE, Value::from(profile.narrative.as_str())),
        (
            KEY_SOURCE_REVISION_IDS,
            encode_source_revision_ids(&profile.source_revision_ids),
        ),
        (KEY_CONFIDENCE, encode_confidence(profile.confidence)),
        (KEY_STATUS, Value::from("fresh")),
    ]);

    let err = decode_psych_profile_body(&string_status_body)
        .expect_err("string status must fail closed under v6 schema");
    assert_eq!(err.kind(), ErrorKind::InvalidPsychProfileBody);
    Ok(())
}

#[test]
fn psych_profile_public_put_rejects_maintenance_type() -> Result<()> {
    let (_dir, vault) = test_vault();
    let id = entity(0xD1);
    let profile = test_profile();
    let data = encode_psych_profile_body(&profile)?;
    let err = vault
        .put_entity(
            &id,
            ENTITY_TYPE_PSYCH_PROFILE,
            TimeRange { start: 1, end: 1 },
            2,
            &data,
        )
        .expect_err("public generic puts cannot write PsychProfile records");
    assert_eq!(err.kind(), ErrorKind::MaintenanceKindNotWritable);
    assert!(vault.get_raw(&id)?.is_none());
    Ok(())
}

#[test]
fn psych_profile_address_bytes_and_person_facet_world_isolation_survive_reopen() -> Result<()> {
    let cases = [
        (
            PsychProfileKey {
                person: entity(0x61),
                facet: Some(entity(0x62)),
                world: Some(entity(0x63)),
            },
            "03b1eb4d88bd18e36ed1bb815d1cdb7b",
        ),
        (
            PsychProfileKey {
                person: entity(0x64),
                facet: Some(entity(0x62)),
                world: Some(entity(0x63)),
            },
            "9c14be15b61125026becf21c0f603c16",
        ),
        (
            PsychProfileKey {
                person: entity(0x61),
                facet: None,
                world: Some(entity(0x63)),
            },
            "09a2dc84b608c95950a41e09108bdc14",
        ),
        (
            PsychProfileKey {
                person: entity(0x61),
                facet: Some(entity(0x64)),
                world: Some(entity(0x63)),
            },
            "d0fbd354164458a5e4de2d170669d45e",
        ),
        (
            PsychProfileKey {
                person: entity(0x61),
                facet: Some(entity(0x62)),
                world: None,
            },
            "1263ff2b847c9d8d62404993bd7ba9d8",
        ),
        (
            PsychProfileKey {
                person: entity(0x61),
                facet: Some(entity(0x62)),
                world: Some(entity(0x65)),
            },
            "fd30cdd3fa91b67f93bc099152e4a8a5",
        ),
    ];
    let (dir, vault) = test_vault();
    for (index, (key, expected_hex)) in cases.iter().enumerate() {
        let id = EntityId::from_hex(expected_hex)?;
        assert_eq!(psych_profile_entity_id(key), id);
        assert!(matches!(
            vault.psych_profile_for(key)?,
            PsychProfileState::Missing
        ));
        let mut profile = test_profile();
        profile.subject_ref = key.person;
        profile.compact = format!("profile cell {index}");
        vault.put_psych_profile(&id, &profile)?;
    }
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::default())?;
    for (index, (key, expected_hex)) in cases.iter().enumerate() {
        let PsychProfileState::Fresh(profile) = reopened.psych_profile_for(key)? else {
            panic!("profile cell missing or stale")
        };
        assert_eq!(profile.subject_ref, key.person);
        assert_eq!(profile.compact, format!("profile cell {index}"));
        assert_eq!(
            reopened.get_psych_profile(&EntityId::from_hex(expected_hex)?)?,
            Some(profile)
        );
    }
    Ok(())
}
