use super::*;
use crate::claim::ClaimSource;
use crate::companion::{
    CompanionExportClassification, CompanionProvenance, CompanionRecord, CompanionScope,
};
use crate::config::VaultConfig;
use crate::deletion::DeleteReason;
use crate::edge::EdgeActorClass;
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::{ErrorKind, Vault};

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
    );
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

fn put_relationship(vault: &Vault, source: EntityId, target: EntityId, role: &str) -> Result<()> {
    let record = CompanionRecord::relationship(
        CompanionScope::neutral(),
        source,
        target,
        Value::Map(vec![(Value::from("role"), Value::from(role))]),
        CompanionProvenance::new(
            source,
            EdgeActorClass::Human,
            ClaimSource::UserStated,
            ClaimApprovalStatus::Approved,
            Value::from("test"),
        ),
        CompanionExportClassification::Portable,
    );
    vault.create_companion_record(&EntityId::now(), &record, 5)
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
    let subject = put_person(&vault, 0xA1)?;
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
    let subject = EntityId::from_bytes([0xA2; 16]).expect("entity id");
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
    let subject = put_person(&vault, 0xA1)?;
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
    put_relationship(&vault, subject, friend, "coworker")?;

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
fn strike_list_with_unknown_row_id_is_rejected() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0xA1)?;
    put_claim(&vault, subject, "profile.name", "Lexi", 0.9, None)?;

    let compile =
        vault.compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())?;
    let strikes = PersonaSnapshotStrikeList {
        strike: BTreeSet::from(["row:doesnotexist".to_owned()]),
        unstrike: BTreeSet::new(),
    };
    let err = vault
        .export_persona_snapshot(&compile, &strikes, &owner_consent(&compile))
        .expect_err("unknown row id must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidPersonaSnapshot);
    Ok(())
}

#[test]
fn third_party_rows_default_coarse_name_and_role() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0xA1)?;
    let friend = put_person(&vault, 0xB1)?;
    put_claim(&vault, subject, "profile.name", "Lexi", 0.9, None)?;
    put_claim(&vault, friend, "profile.name", "Kenji", 0.9, None)?;
    put_claim(
        &vault,
        friend,
        "profile.worry",
        "worries about deadlines",
        0.7,
        None,
    )?;
    put_relationship(&vault, subject, friend, "coworker")?;

    let compile =
        vault.compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())?;
    let relationship_row = compile
        .rows
        .iter()
        .find(|row| row.kind == PersonaSnapshotRowKind::Relationship)
        .expect("relationship row");
    assert_eq!(relationship_row.text, "Kenji — coworker");
    assert!(!relationship_row.struck);

    let artifact = vault.export_persona_snapshot(
        &compile,
        &PersonaSnapshotStrikeList::default(),
        &owner_consent(&compile),
    )?;
    assert!(artifact.markdown.contains("Kenji — coworker"));
    assert!(
        !artifact.markdown.contains("worries about deadlines"),
        "third-party claims enter only via explicit un-strike"
    );
    Ok(())
}

#[test]
fn agent_takes_absent_unless_toggled_and_always_attributed() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0xA1)?;
    put_claim(&vault, subject, "profile.name", "Lexi", 0.9, None)?;
    let take = PersonaSnapshotAgentTake {
        actor_ref: "eiri".to_owned(),
        text: "seems energized by morning work".to_owned(),
        about_ref: None,
    };

    let mut options = PersonaSnapshotCompileOptions {
        agent_takes: vec![take],
        ..PersonaSnapshotCompileOptions::default()
    };
    let compile = vault.compile_persona_snapshot(&subject, &options)?;
    assert!(
        compile
            .rows
            .iter()
            .all(|row| row.kind != PersonaSnapshotRowKind::AgentTake),
        "takes must be absent while the per-card toggle is off"
    );
    assert!(!compile.takes_included);

    options.include_agent_takes = true;
    let compile = vault.compile_persona_snapshot(&subject, &options)?;
    let take_row = compile
        .rows
        .iter()
        .find(|row| row.kind == PersonaSnapshotRowKind::AgentTake)
        .expect("take row when toggled on");
    assert_eq!(take_row.attribution.as_deref(), Some("eiri"));
    assert!(compile.takes_included);

    let artifact = vault.export_persona_snapshot(
        &compile,
        &PersonaSnapshotStrikeList::default(),
        &owner_consent(&compile),
    )?;
    assert!(artifact.markdown.contains("eiri (take): seems energized"));
    assert!(
        artifact
            .memory_pack_json
            .contains("\"attribution\":\"eiri\"")
    );
    Ok(())
}

#[test]
fn one_compile_dual_renders_share_stamp_and_freshness_hints() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0xA1)?;
    put_claim(&vault, subject, "profile.name", "Lexi", 0.9, None)?;
    put_claim(&vault, subject, "profile.role", "founder", 0.8, None)?;
    put_claim(
        &vault,
        subject,
        "profile.preference",
        "prefers tea over coffee",
        0.7,
        None,
    )?;

    let compile =
        vault.compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())?;
    assert_eq!(compile.identity_line, "Lexi — founder");
    let artifact = vault.export_persona_snapshot(
        &compile,
        &PersonaSnapshotStrikeList::default(),
        &owner_consent(&compile),
    )?;

    let pack: serde_json::Value =
        serde_json::from_str(&artifact.memory_pack_json).expect("valid MemoryPack-lite JSON");
    assert_eq!(pack["schema"], MEMORY_PACK_LITE_SCHEMA_VERSION);
    assert_eq!(pack["identity_line"], "Lexi — founder");
    assert_eq!(
        pack["persona_compile_stamp"],
        serde_json::Value::from(compile.stamp.identity())
    );
    assert_eq!(
        pack["compiled_at_secs"],
        serde_json::Value::from(compile.compiled_at_secs)
    );
    assert_eq!(
        pack["stale_after_secs"],
        serde_json::Value::from(compile.stale_after_secs)
    );

    assert!(artifact.markdown.starts_with("# Lexi — founder"));
    assert!(artifact.markdown.contains(&compile.stamp.identity()));
    assert!(
        artifact
            .markdown
            .contains(&format!("compiled_at_secs: {}", compile.compiled_at_secs))
    );
    assert!(
        artifact
            .markdown
            .contains(&format!("stale_after_secs: {}", compile.stale_after_secs))
    );
    assert!(artifact.markdown.contains("prefers tea over coffee"));
    assert!(
        artifact
            .memory_pack_json
            .contains("prefers tea over coffee")
    );
    Ok(())
}

#[test]
fn export_receipt_carries_persona_compile_stamp() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0xA1)?;
    put_claim(&vault, subject, "profile.name", "Lexi", 0.9, None)?;

    let compile =
        vault.compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())?;
    let artifact = vault.export_persona_snapshot(
        &compile,
        &PersonaSnapshotStrikeList::default(),
        &owner_consent(&compile),
    )?;

    let receipts = vault.receipts(ReceiptQuery {
        kinds: BTreeSet::from([ReceiptKind::Share]),
        ..ReceiptQuery::default()
    })?;
    let receipt = receipts
        .iter()
        .find(|receipt| {
            receipt.receipt_id == format!("share:persona_snapshot:{}", artifact.export_id.to_hex())
        })
        .expect("persona snapshot export must project a Share receipt");
    assert_eq!(receipt.receipt_kind, ReceiptKind::Share);
    assert_eq!(receipt.actor.as_deref(), Some("owner"));
    assert_eq!(receipt.outcome, "exported");
    assert_eq!(
        receipt.fields.get("persona_compile_stamp"),
        Some(&compile.stamp.identity())
    );
    assert_eq!(receipt.fields.get("subject_ref"), Some(&subject.to_hex()));
    Ok(())
}

#[test]
fn stale_consent_stamp_rejects_export() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0xA1)?;
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
fn audience_scoped_compile_changes_stamp_identity() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0xA1)?;
    put_claim(&vault, subject, "profile.name", "Lexi", 0.9, None)?;

    let neutral =
        vault.compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())?;
    let for_kenji = vault.compile_persona_snapshot(
        &subject,
        &PersonaSnapshotCompileOptions {
            audience: ScopedReadActorKey::new("contact:kenji"),
            ..PersonaSnapshotCompileOptions::default()
        },
    )?;
    assert_eq!(for_kenji.audience_ref.as_deref(), Some("contact:kenji"));
    assert_ne!(
        neutral.stamp.identity(),
        for_kenji.stamp.identity(),
        "a card compiled FOR someone is a different card"
    );

    let recompiled =
        vault.compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())?;
    assert_eq!(
        neutral.stamp.identity(),
        recompiled.stamp.identity(),
        "an unchanged recompile keeps its content-addressed identity"
    );
    Ok(())
}

#[test]
fn export_record_body_round_trips() -> Result<()> {
    let record = PersonaSnapshotExportRecord {
        subject_ref: EntityId::from_bytes([0xA1; 16])?,
        audience_ref: Some("contact:kenji".to_owned()),
        identity_line: "Lexi — founder".to_owned(),
        compiled_at_secs: 1_000,
        stale_after_secs: 2_000,
        compiled_fingerprint: "a".repeat(64),
        takes_included: true,
        granted_by: "owner".to_owned(),
        granted_at_secs: 1_100,
        exported_at_secs: 1_200,
        included_row_ids: vec!["row:aaaa".to_owned()],
        struck_row_ids: vec!["row:bbbb".to_owned()],
        artifact_fingerprint: "b".repeat(64),
    };
    let bytes = encode_persona_snapshot_export_body(&record)?;
    let decoded = decode_persona_snapshot_export_body(&bytes)?;
    assert_eq!(decoded, record);
    assert_eq!(
        decoded.compile_stamp_identity(),
        format!(
            "{PERSONA_SNAPSHOT_COMPILE_STAMP_SCHEMA_VERSION}:{}",
            "a".repeat(64)
        )
    );

    let overlapping = PersonaSnapshotExportRecord {
        struck_row_ids: vec!["row:aaaa".to_owned()],
        ..record
    };
    let err = encode_persona_snapshot_export_body(&overlapping)
        .expect_err("overlapping row id lists must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidPersonaSnapshot);
    Ok(())
}

#[test]
fn soft_deleted_subject_is_absent_for_compile() -> Result<()> {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, 0xA1)?;
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
    let subject = put_person(&vault, 0xA1)?;
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
    let subject = put_person(&vault, 0xA1)?;
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
    let subject = put_person(&vault, 0xA1)?;
    let friend = put_person(&vault, 0xB1)?;
    put_claim(&vault, subject, "profile.name", "Lexi", 0.9, None)?;
    put_claim(&vault, friend, "profile.name", "Kenji", 0.9, None)?;
    put_relationship(&vault, subject, friend, "coworker")?;

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
    let subject = put_person(&vault, 0xA1)?;
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
    let subject = put_person(&vault, 0xA1)?;
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
