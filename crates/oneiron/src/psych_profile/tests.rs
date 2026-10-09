use rmpv::Value;

use super::*;
use crate::config::VaultConfig;
use crate::{ErrorKind, Vault};

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
fn psych_profile_keying_is_deterministic_and_facet_isolated() -> Result<()> {
    let person = entity(0x61);
    let facet = entity(0x62);
    let world = entity(0x63);
    let key = PsychProfileKey {
        person,
        facet: Some(facet),
        world: Some(world),
    };
    assert_eq!(psych_profile_entity_id(&key), psych_profile_entity_id(&key));
    assert_ne!(
        psych_profile_entity_id(&key),
        psych_profile_entity_id(&PsychProfileKey {
            person,
            facet: None,
            world: Some(world)
        })
    );
    assert_ne!(
        psych_profile_entity_id(&key),
        psych_profile_entity_id(&PsychProfileKey {
            person,
            facet: Some(entity(0x64)),
            world: Some(world)
        })
    );
    assert_ne!(
        psych_profile_entity_id(&key),
        psych_profile_entity_id(&PsychProfileKey {
            person,
            facet: Some(facet),
            world: Some(entity(0x65))
        })
    );

    let (_dir, vault) = test_vault();
    vault.put_psych_profile(&psych_profile_entity_id(&key), &test_profile())?;
    assert!(matches!(
        vault.psych_profile_for(&key)?,
        PsychProfileState::Fresh(_)
    ));
    assert!(matches!(
        vault.psych_profile_for(&PsychProfileKey {
            person,
            facet: None,
            world: Some(world)
        })?,
        PsychProfileState::Missing
    ));
    Ok(())
}
