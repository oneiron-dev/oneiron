use super::*;
use crate::authority::{HostSlipIssuer, SlipCaveat};
use crate::claim::{ClaimSource, ScopedReadActorKey};
use crate::config::VaultConfig;
use crate::deletion::DeleteReason;
use crate::federation::{Scope, ScopeAxis, Sensitivity};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use crate::{EdgeKind, ErrorKind, Vault};

fn test_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

fn put_person(vault: &Vault, byte: u8) -> Result<EntityId> {
    let id = EntityId::from_bytes([byte; 16])?;
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    Ok(id)
}

fn claim_body(
    subject: EntityId,
    predicate: &str,
    text: &str,
    salience: f32,
    band: Option<u64>,
) -> ClaimBody {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::from(text),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.salience = Some(salience);
    body.source = Some(ClaimSource::UserStated);
    if let Some(band) = band {
        body.scope = Some(Value::Map(vec![(
            Value::from("sensitivity"),
            Value::from(band),
        )]));
    }
    body
}

fn put_claim(
    vault: &Vault,
    subject: EntityId,
    predicate: &str,
    text: &str,
    salience: f32,
    band: Option<u64>,
) -> Result<EntityId> {
    let id = EntityId::now();
    let body = claim_body(subject, predicate, text, salience, band);
    vault.put_claim(&id, &body, TimeRange { start: 10, end: 10 }, 10)?;
    Ok(id)
}

fn put_relationship(
    vault: &Vault,
    source: EntityId,
    target: EntityId,
    role: &str,
    sensitivity: Sensitivity,
) -> Result<()> {
    let relation = EntityId::now();
    let body = rmp_serde::to_vec_named(&serde_json::json!({
        "role": role,
        "sensitivity": sensitivity.as_str(),
    }))
    .expect("relationship body");
    vault
        .batch()
        .put(
            &relation,
            ENTITY_TYPE_RELATIONSHIP,
            TimeRange { start: 5, end: 5 },
            5,
            &body,
        )
        .edge(&source, EdgeKind::ParticipatesIn, &relation, 1.0)
        .edge(&target, EdgeKind::ParticipatesIn, &relation, 1.0)
        .commit()
}

fn owner_consent(compile: &PersonaSnapshotCompile) -> PersonaSnapshotExportConsent {
    PersonaSnapshotExportConsent {
        granted_by: "owner".to_owned(),
        compile_stamp: compile.stamp.identity(),
        granted_at_secs: 100,
    }
}

#[test]
fn tier_a_claims_never_enter_compile_or_renders() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0x61)?;
    put_claim(&vault, subject, "profile.name", "Lexi", 0.9, None)?;
    put_claim(
        &vault,
        subject,
        "profile.preference",
        "prefers tea over coffee",
        0.8,
        Some(0),
    )?;
    put_claim(
        &vault,
        subject,
        "profile.health",
        "restricted medical detail",
        0.99,
        Some(3),
    )?;

    let compile =
        vault.compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())?;
    assert!(
        compile
            .rows
            .iter()
            .all(|row| !row.text.contains("restricted medical detail")),
        "Tier A claim must never enter the strikeable row list"
    );

    let artifact = vault.export_persona_snapshot(
        &compile,
        &PersonaSnapshotStrikeList::default(),
        &owner_consent(&compile),
    )?;
    assert!(
        !artifact
            .memory_pack_json
            .contains("restricted medical detail")
    );
    assert!(!artifact.markdown.contains("restricted medical detail"));
    assert!(
        artifact
            .memory_pack_json
            .contains("prefers tea over coffee")
    );
    Ok(())
}

#[test]
fn ambiguous_sensitivity_band_fails_closed() {
    let subject = EntityId::from_bytes([0x62; 16]).expect("entity id");
    let mut body = claim_body(subject, "profile.preference", "text", 0.5, None);
    body.scope = Some(Value::Map(vec![
        (Value::from("sensitivity"), Value::from(0_u64)),
        (Value::from("sensitivity"), Value::from(3_u64)),
    ]));
    assert!(persona_snapshot_tier_a_clamped(&body));
}

#[test]
fn export_honors_strike_list_and_explicit_unstrike() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0x61)?;
    let friend = put_person(&vault, 0xB1)?;
    put_claim(&vault, subject, "profile.name", "Lexi", 0.9, None)?;
    put_claim(
        &vault,
        subject,
        "profile.preference",
        "prefers tea over coffee",
        0.8,
        None,
    )?;
    put_claim(&vault, friend, "profile.name", "Kenji", 0.9, None)?;
    put_claim(
        &vault,
        friend,
        "profile.worry",
        "worries about deadlines",
        0.7,
        Some(2),
    )?;
    put_relationship(&vault, subject, friend, "coworker", Sensitivity::Public)?;

    let compile =
        vault.compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())?;
    let preference_row = compile
        .rows
        .iter()
        .find(|row| row.text.contains("prefers tea over coffee"))
        .expect("subject claim row")
        .row_id
        .clone();
    let worry_row = compile
        .rows
        .iter()
        .find(|row| row.text.contains("worries about deadlines"))
        .expect("third-party claim row");
    assert!(worry_row.struck, "third-party claims default struck");
    let worry_row = worry_row.row_id.clone();

    let strikes = PersonaSnapshotStrikeList {
        strike: BTreeSet::from([preference_row]),
        unstrike: BTreeSet::from([worry_row]),
    };
    let artifact = vault.export_persona_snapshot(&compile, &strikes, &owner_consent(&compile))?;

    assert!(
        !artifact
            .memory_pack_json
            .contains("prefers tea over coffee")
    );
    assert!(!artifact.markdown.contains("prefers tea over coffee"));
    assert!(
        artifact
            .memory_pack_json
            .contains("worries about deadlines")
    );
    assert!(artifact.markdown.contains("worries about deadlines"));
    Ok(())
}

#[test]
fn stale_consent_stamp_rejects_export() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0x61)?;
    put_claim(&vault, subject, "profile.name", "Lexi", 0.9, None)?;

    let compile =
        vault.compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())?;
    let consent = PersonaSnapshotExportConsent {
        granted_by: "owner".to_owned(),
        compile_stamp: format!(
            "{PERSONA_SNAPSHOT_COMPILE_STAMP_SCHEMA_VERSION}:{}",
            "0".repeat(64)
        ),
        granted_at_secs: 100,
    };
    let err = vault
        .export_persona_snapshot(&compile, &PersonaSnapshotStrikeList::default(), &consent)
        .expect_err("consent bound to another compile must be rejected");
    assert_eq!(err.kind(), ErrorKind::PersonaSnapshotConsentStale);
    Ok(())
}

#[test]
fn persona_export_wire_fixture_is_persisted_and_malformed_rows_are_refused() -> Result<()> {
    let fixture = [
        b"\x8e".as_slice(),
        b"\xadschemaVersion\x01".as_slice(),
        b"\xaasubjectRef\xd9 61616161616161616161616161616161".as_slice(),
        b"\xabaudienceRef\xc0".as_slice(),
        b"\xacidentityLine\xa4card".as_slice(),
        b"\xaecompiledAtSecs\x01".as_slice(),
        b"\xaestaleAfterSecs\x02".as_slice(),
        b"\xb3compiledFingerprint\xd9@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_slice(),
        b"\xadtakesIncluded\xc2".as_slice(),
        b"\xa9grantedBy\xa5owner".as_slice(),
        b"\xadgrantedAtSecs\x03".as_slice(),
        b"\xaeexportedAtSecs\x04".as_slice(),
        b"\xaeincludedRowIds\x91\xa5row:a".as_slice(),
        b"\xacstruckRowIds\x91\xa5row:b".as_slice(),
        b"\xb3artifactFingerprint\xd9@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".as_slice(),
    ].concat();
    let fixture = fixture.as_slice();
    let (_dir, vault) = test_vault();
    let id = EntityId::from_bytes([0x71; 16])?;
    let record = decode_persona_snapshot_export_body(fixture)?;
    assert_eq!(record.subject_ref, EntityId::from_bytes([0x61; 16])?);
    assert_eq!(record.identity_line, "card");
    assert_eq!(
        record.compile_stamp_identity(),
        "oneiron.persona_snapshot_compile.v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    vault.put_persona_snapshot_export(&id, &record)?;
    let persisted = vault.get_raw(&id)?.unwrap();
    assert_eq!(
        &persisted[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        fixture
    );

    let write_bytes = |target: &EntityId, bytes: Vec<u8>| {
        vault.with_write_txn(|txn| {
            crate::batch::apply_ops(
                &vault.store,
                &vault.config,
                &vault.analyzer,
                txn,
                vec![crate::batch::BatchOp::Put {
                    id: *target,
                    entity_type: crate::registry::ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
                    occurred: TimeRange { start: 4, end: 4 },
                    learned_at: 4,
                    data: bytes,
                    allow_maintenance: true,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                }],
                vault
                    .text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                true,
            )
        })
    };
    let Value::Map(base) = rmpv::decode::read_value(&mut std::io::Cursor::new(fixture)).unwrap()
    else {
        panic!("fixture map")
    };
    let mut bad_version = base.clone();
    bad_version[0].1 = Value::from(2_u64);
    let mut missing = base.clone();
    missing.remove(0);
    let mut unknown = base.clone();
    unknown.push((Value::from("extra"), Value::Nil));
    let mut overlap = base;
    overlap
        .iter_mut()
        .find(|(k, _)| k.as_str() == Some("struckRowIds"))
        .unwrap()
        .1 = Value::Array(vec![Value::from("row:a")]);
    for (byte, entries) in [
        (0x72, bad_version),
        (0x73, missing),
        (0x74, unknown),
        (0x75, overlap),
    ] {
        let target = EntityId::from_bytes([byte; 16])?;
        let mut malformed = Vec::new();
        rmpv::encode::write_value(&mut malformed, &Value::Map(entries)).unwrap();
        assert_eq!(
            write_bytes(&target, malformed).unwrap_err().kind(),
            ErrorKind::InvalidPersonaSnapshot
        );
        assert!(vault.get_raw(&target)?.is_none());
    }
    let mut invalid_record = record;
    invalid_record.struck_row_ids = vec!["row:a".to_owned()];
    assert_eq!(
        vault
            .put_persona_snapshot_export(&id, &invalid_record)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidPersonaSnapshot
    );
    assert_eq!(
        &vault.get_raw(&id)?.unwrap()[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        fixture
    );
    Ok(())
}

#[test]
fn soft_deleted_subject_is_absent_for_compile() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0x61)?;
    put_claim(&vault, subject, "profile.name", "Lexi", 0.9, None)?;

    vault.delete_entity_with_reason(&subject, DeleteReason::UserDelete)?;

    let err = vault
        .compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())
        .expect_err("a soft-deleted person must be absent, not a fallback card");
    assert_eq!(err.kind(), ErrorKind::EntityNotFound);
    Ok(())
}

#[test]
fn soft_deleted_claim_shells_are_skipped_in_compile() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0x61)?;
    put_claim(&vault, subject, "profile.name", "Lexi", 0.9, None)?;
    let deleted = put_claim(
        &vault,
        subject,
        "profile.preference",
        "prefers tea over coffee",
        0.8,
        None,
    )?;
    put_claim(&vault, subject, "profile.hobby", "bouldering", 0.7, None)?;

    vault.delete_entity_with_reason(&deleted, DeleteReason::UserDelete)?;

    let compile =
        vault.compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())?;
    assert!(
        compile
            .rows
            .iter()
            .all(|row| !row.text.contains("prefers tea over coffee")),
        "a deleted claim shell must be suppressed, not compiled"
    );
    assert!(
        compile
            .rows
            .iter()
            .any(|row| row.text.contains("bouldering")),
        "one deleted claim must not block the rest of the compile"
    );
    Ok(())
}

#[test]
fn tampered_compile_is_rejected_at_export() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0x61)?;
    put_claim(&vault, subject, "profile.name", "Lexi", 0.9, None)?;
    put_claim(
        &vault,
        subject,
        "profile.preference",
        "prefers tea over coffee",
        0.8,
        None,
    )?;

    let compile =
        vault.compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())?;

    let mut text_tampered = compile.clone();
    let row = text_tampered
        .rows
        .iter_mut()
        .find(|row| row.kind == PersonaSnapshotRowKind::SubjectClaim)
        .expect("subject claim row");
    row.text = "prefers coffee over tea".to_owned();
    let err = vault
        .export_persona_snapshot(
            &text_tampered,
            &PersonaSnapshotStrikeList::default(),
            &owner_consent(&compile),
        )
        .expect_err("mutated row text under a kept stamp must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidPersonaSnapshot);

    let mut salience_tampered = compile.clone();
    let row = salience_tampered
        .rows
        .iter_mut()
        .find(|row| row.kind == PersonaSnapshotRowKind::SubjectClaim)
        .expect("subject claim row");
    row.salience = Some(0.01);
    let err = vault
        .export_persona_snapshot(
            &salience_tampered,
            &PersonaSnapshotStrikeList::default(),
            &owner_consent(&compile),
        )
        .expect_err("salience is rendered content, so it is stamp-bound too");
    assert_eq!(err.kind(), ErrorKind::InvalidPersonaSnapshot);
    Ok(())
}

#[test]
fn relationship_rows_render_coarse_without_internal_refs() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0x61)?;
    let friend = put_person(&vault, 0xB1)?;
    put_claim(&vault, subject, "profile.name", "Lexi", 0.9, None)?;
    put_claim(&vault, friend, "profile.name", "Kenji", 0.9, None)?;
    put_relationship(&vault, subject, friend, "coworker", Sensitivity::Public)?;

    let compile =
        vault.compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())?;
    let artifact = vault.export_persona_snapshot(
        &compile,
        &PersonaSnapshotStrikeList::default(),
        &owner_consent(&compile),
    )?;

    let pack: serde_json::Value =
        serde_json::from_str(&artifact.memory_pack_json).expect("valid JSON");
    let relationship_row = pack["rows"]
        .as_array()
        .expect("rows array")
        .iter()
        .find(|row| row["kind"] == "relationship")
        .expect("relationship row in pack");
    assert_eq!(relationship_row["text"], "Kenji — coworker");
    assert!(
        relationship_row.get("subject_ref").is_none(),
        "coarse relationship rows must not carry third-party entity ids"
    );
    assert!(
        relationship_row.get("provenance_refs").is_none(),
        "coarse relationship rows must not carry vault-internal refs"
    );
    assert!(
        !artifact.memory_pack_json.contains(&friend.to_hex()),
        "the third party's entity id must not appear anywhere in the pack"
    );
    assert!(
        !artifact.markdown.contains("companion:"),
        "the markdown card must not carry companion record refs"
    );
    Ok(())
}

#[test]
fn markdown_render_collapses_multiline_text() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0x61)?;
    put_claim(&vault, subject, "profile.name", "Lexi", 0.9, None)?;
    put_claim(
        &vault,
        subject,
        "profile.note",
        "line one\n# forged heading\n- forged bullet",
        0.8,
        None,
    )?;

    let compile =
        vault.compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())?;
    let artifact = vault.export_persona_snapshot(
        &compile,
        &PersonaSnapshotStrikeList::default(),
        &owner_consent(&compile),
    )?;

    assert!(
        !artifact.markdown.contains("\n# forged heading"),
        "claim text must not open a new markdown block"
    );
    assert!(
        !artifact.markdown.contains("\n- forged bullet"),
        "claim text must not inject new list items"
    );
    assert!(
        artifact
            .markdown
            .contains("line one # forged heading - forged bullet"),
        "the text itself stays, collapsed onto one line"
    );
    Ok(())
}

#[test]
fn struck_identity_line_stays_out_of_export_record() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0x61)?;
    put_claim(&vault, subject, "profile.name", "Lexi", 0.9, None)?;
    put_claim(&vault, subject, "profile.hobby", "bouldering", 0.7, None)?;

    let compile =
        vault.compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())?;
    let identity_row = compile
        .rows
        .iter()
        .find(|row| row.kind == PersonaSnapshotRowKind::Identity)
        .expect("identity row")
        .row_id
        .clone();

    let strikes = PersonaSnapshotStrikeList {
        strike: BTreeSet::from([identity_row]),
        unstrike: BTreeSet::new(),
    };
    let artifact = vault.export_persona_snapshot(&compile, &strikes, &owner_consent(&compile))?;

    assert!(!artifact.markdown.contains("Lexi"));
    assert!(!artifact.memory_pack_json.contains("Lexi"));
    let record = vault
        .get_persona_snapshot_export(&artifact.export_id)?
        .expect("export record persisted");
    assert_eq!(record.identity_line, STRUCK_IDENTITY_LINE_PLACEHOLDER);
    assert!(
        !record.identity_line.contains("Lexi"),
        "struck identity text must not survive in the queryable export record"
    );
    Ok(())
}

#[test]
fn public_body_cannot_export_relationship_hidden_from_audience() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0x61)?;
    let other = put_person(&vault, 0xB1)?;
    let relation = EntityId::now();
    let secret_role = "private association needle2284";
    let body = rmp_serde::to_vec_named(&serde_json::json!({
        "sensitivity": "public", "role": secret_role
    }))
    .expect("public relationship body");
    vault
        .batch()
        .put(
            &relation,
            ENTITY_TYPE_RELATIONSHIP,
            TimeRange { start: 5, end: 5 },
            5,
            &body,
        )
        .edge(&subject, EdgeKind::ParticipatesIn, &relation, 1.0)
        .edge(&other, EdgeKind::ParticipatesIn, &relation, 1.0)
        .commit()?;
    let issuer = HostSlipIssuer::from_secret(b"persona snapshot audience proof")?;
    let mut slip = vault.ensure_host_root_slip(&issuer)?;
    let mut ceiling = Scope::top();
    ceiling.bands = ScopeAxis::Some([ENTITY_TYPE_PERSON].into());
    issuer.attenuate(
        &mut slip,
        SlipCaveat {
            scope: Some(ceiling),
            ..Default::default()
        },
    )?;
    let proof = vault.verify_capability_slip(
        &issuer.public_key(),
        &slip,
        b"snapshot-read",
        &issuer.binding_proof(&slip, b"snapshot-read")?,
    )?;
    let key = ScopedReadActorKey::from_verified_slip(&proof).expect("read proof");
    let read = vault.scoped_read(key.clone());
    assert!(read.is_entity_readable(&subject)?);
    assert!(read.is_entity_readable(&other)?);
    assert!(
        read.read(&[crate::claim::PointRead::id(relation)], None)?
            .single()
            .value
            .is_none()
    );
    let compile = vault.compile_persona_snapshot(
        &subject,
        &PersonaSnapshotCompileOptions {
            audience: Some(key),
            ..PersonaSnapshotCompileOptions::default()
        },
    )?;
    assert!(compile.rows.iter().all(|row| row.subject_ref != other && row.kind != PersonaSnapshotRowKind::Relationship));
    let artifact = vault.export_persona_snapshot(
        &compile,
        &PersonaSnapshotStrikeList::default(),
        &owner_consent(&compile),
    )?;
    for text in [
        &compile.identity_line,
        &artifact.memory_pack_json,
        &artifact.markdown,
    ] {
        assert!(!text.contains(secret_role));
        assert!(!text.contains(&other.to_hex()));
        assert!(!text.contains(&relation.to_hex()));
    }
    Ok(())
}

#[test]
fn portable_card_refuses_shared_relationship_even_with_public_label() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0x61)?;
    let other = put_person(&vault, 0xB1)?;
    let relation = EntityId::now();
    let body = rmp_serde::to_vec_named(&serde_json::json!({
        "sensitivity": "public",
        "role": "colleague",
        "scope": {"kind": "shared_vault", "vault_id": 42},
    }))
    .expect("shared relationship body");
    vault
        .batch()
        .put(
            &relation,
            ENTITY_TYPE_RELATIONSHIP,
            TimeRange { start: 5, end: 5 },
            5,
            &body,
        )
        .edge(&subject, EdgeKind::ParticipatesIn, &relation, 1.0)
        .edge(&other, EdgeKind::ParticipatesIn, &relation, 1.0)
        .commit()?;
    let card =
        vault.compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())?;
    assert!(card.rows.iter().all(|row| row.subject_ref != other));
    Ok(())
}

#[test]
fn portable_card_excludes_nonpublic_relationships_and_their_claims() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0x61)?;
    let cases = [
        (Sensitivity::Public, 0xB1, "public contact"),
        (Sensitivity::Private, 0xB2, "private contact"),
        (Sensitivity::Sensitive, 0xB3, "sensitive contact"),
        (Sensitivity::Restricted, 0xB4, "restricted contact"),
    ];
    for (sensitivity, byte, name) in cases {
        let contact = put_person(&vault, byte)?;
        put_claim(&vault, contact, "profile.name", name, 0.9, Some(0))?;
        put_claim(&vault, contact, "profile.hobby", "hiking", 0.8, Some(0))?;
        put_relationship(&vault, subject, contact, "coworker", sensitivity)?;
    }

    let compile =
        vault.compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())?;
    for (sensitivity, byte, _) in cases {
        let contact = EntityId::from_bytes([byte; 16])?;
        for kind in [
            PersonaSnapshotRowKind::Relationship,
            PersonaSnapshotRowKind::ThirdPartyClaim,
        ] {
            assert_eq!(
                compile
                    .rows
                    .iter()
                    .any(|row| row.subject_ref == contact && row.kind == kind),
                sensitivity == Sensitivity::Public,
                "{sensitivity:?}: {kind:?}"
            );
        }
    }
    let artifact = vault.export_persona_snapshot(
        &compile,
        &PersonaSnapshotStrikeList::default(),
        &owner_consent(&compile),
    )?;
    for (sensitivity, _, name) in cases {
        assert_eq!(
            artifact.memory_pack_json.contains(name),
            sensitivity == Sensitivity::Public
        );
        assert_eq!(
            artifact.markdown.contains(name),
            sensitivity == Sensitivity::Public
        );
    }
    Ok(())
}

#[test]
fn persona_snapshot_reads_keep_their_receipts() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0x62)?;
    put_claim(&vault, subject, "profile.name", "Lexi", 0.9, None)?;
    // A card compiled for nobody reads through no audience.
    assert!(
        vault
            .compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())?
            .read_receipt
            .is_none()
    );
    // FOR an audience without a read grant, the name is withheld and counted.
    let for_kenji = vault.compile_persona_snapshot(
        &subject,
        &PersonaSnapshotCompileOptions {
            audience: ScopedReadActorKey::new("contact:kenji"),
            ..PersonaSnapshotCompileOptions::default()
        },
    )?;
    let receipt = for_kenji.read_receipt.expect("the audience read");
    assert_eq!(receipt.suppressed_count, 1);
    assert!(!for_kenji.identity_line.contains("Lexi"));

    // A standing block session reads the agent's claims as its reader: a
    // reader slip scoped to one world withholds the other world's claim.
    let agent = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let world = put_world(&vault, 0x64)?;
    let elsewhere = put_world(&vault, 0x65)?;
    let owner = vault.authenticate_owner(
        agent,
        &agent.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let handle = vault.open_standing_block(&owner, agent, world, "identity", 64)?;
    for (at_world, text) in [(world, "Be concise."), (elsewhere, "Be elsewhere.")] {
        let mut body = ClaimBody::new(
            "companion.standing.tone",
            ClaimSubject::Entity(agent),
            Value::from(text),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )?;
        body.source = Some(ClaimSource::UserStated);
        body.world = Some(at_world);
        body.scope = Some(Value::Map(vec![(
            Value::from("sensitivity"),
            Value::from("public"),
        )]));
        // Replicated: the fixture isolates the session's read, not the gate.
        let id = EntityId::now();
        vault
            .batch()
            .put_replicated(
                &id,
                crate::registry::ENTITY_TYPE_CLAIM,
                TimeRange { start: 1, end: 1 },
                1,
                &crate::claim::encode_claim_body(&body)?,
            )
            .edge(&id, crate::EdgeKind::ClaimOf, &agent, 1.0)
            .commit()?;
    }
    let issuer = crate::authority::HostSlipIssuer::from_secret(b"persona receipt fixture")?;
    let mut claims = vault.ensure_host_root_slip(&issuer)?.claims;
    claims.slip_id = [0x66; 32];
    claims.holder_ref = agent.to_hex();
    claims.actor_class = Some("agent".into());
    claims.scope = crate::federation::scope_codec::read_preset();
    claims.scope.worlds = crate::federation::ScopeAxis::Some(std::collections::BTreeSet::from([
        crate::federation::ScopeId(world),
    ]));
    let slip = vault.mint_capability_slip(&issuer, claims)?;
    let signature = issuer.binding_proof(&slip, b"persona-receipt")?;
    let verified = vault.verify_capability_slip(
        &issuer.public_key(),
        &slip,
        b"persona-receipt",
        &signature,
    )?;
    let reader = ScopedReadActorKey::from_verified_slip(&verified).expect("slip reader");
    let session = vault.begin_standing_block_session(
        &handle,
        reader,
        256,
        64,
        &mut crate::persona_snapshot::standing::StandingBlockCache::default(),
    )?;
    let compiled = String::from_utf8(session.compiled.clone()).expect("utf-8 block");
    assert!(compiled.contains("Be concise."));
    assert!(!compiled.contains("Be elsewhere."));
    // What the slip cannot read lies in a world it does not grant, so it
    // adds no count either (DEC-0005: no name, no count; Astra #1388 P2).
    assert_eq!(session.read_receipt.suppressed_count, 0);
    Ok(())
}

fn put_world(vault: &Vault, byte: u8) -> Result<EntityId> {
    let id = EntityId::from_bytes([byte; 16])?;
    vault.put_entity(
        &id,
        crate::registry::ENTITY_TYPE_WORLD,
        TimeRange { start: 1, end: 1 },
        1,
        b"world",
    )?;
    Ok(id)
}

/// F18 review (H397): owner-only configuration acts only under a proof this
/// vault authenticated. A proof another vault minted for the same PERSON id
/// opens no standing block here, so it cannot claim the pair first; the
/// owner's own proof then opens it with the intended configuration.
#[test]
fn a_foreign_owner_proof_opens_no_standing_block() -> Result<()> {
    let (_dir, vault) = test_vault();
    let (_other_dir, other) = test_vault();
    // Each vault's embedded owner: one id, the same in both.
    let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
    other.ensure_embedded_owner_actor().expect("embedded owner");
    let agent = put_person(&vault, 0x72)?;
    let world = put_world(&vault, 0x73)?;
    let foreign = other.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    assert!(
        vault
            .open_standing_block(&foreign, agent, world, "squatted", 8)
            .is_err()
    );
    let own = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault.open_standing_block(&own, agent, world, "identity", 64)?;
    Ok(())
}

mod revoked_owner_credential {
    use super::*;

    /// Astra r1 on #1458: the owner's credential is revoked while the block
    /// waits for the writer. The writing transaction refuses it.
    #[test]
    fn a_credential_revoked_while_the_block_waits_configures_no_standing_block() -> Result<()> {
        let (_dir, vault) = test_vault();
        let agent = put_person(&vault, 0x72)?;
        let world = put_world(&vault, 0x73)?;
        let vault = std::rc::Rc::new(vault);
        let (owner, slip) = crate::test_util::credentialed_owner_proof(&vault, b"standing block");
        crate::test_util::revoke_before_the_next_write(&vault, slip);

        assert_eq!(
            vault
                .open_standing_block(&owner, agent, world, "identity", 64)
                .unwrap_err()
                .kind(),
            ErrorKind::ConsentOwnerNotAuthenticated
        );
        assert!(vault.standing_block(agent, world)?.is_none());
        let (fresh, _) =
            crate::test_util::credentialed_owner_proof(&vault, b"standing block again");
        vault.open_standing_block(&fresh, agent, world, "identity", 64)?;
        assert!(vault.standing_block(agent, world)?.is_some());
        Ok(())
    }
}
