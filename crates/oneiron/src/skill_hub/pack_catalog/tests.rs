//! Source custody tests: exact bytes, inert imports, generic/replay parity and rollback.
use super::*;
use crate::batch::export::{ExportPack, WholeVaultDocument};
use crate::context_pack::PackFormat;
use crate::skill_hub::HubFile;
use crate::{EntityId, TimeRange, Vault, VaultConfig, error::Result};

fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}
fn files() -> Vec<HubFile> {
    vec![
    HubFile::new("PACK.md", b"---\nname: example.contacts\ndescription: Contact predicate pack\nversion: 1.0.0\nkind: capability\npredicates: [\"example.contacts.phone\"]\n---\nExact  source body.\n".to_vec()),
    HubFile::new("skills/contact/SKILL.md", b"---\nname: contact\ndescription: Contact format\nversion: 1.0.0\n---\nKeep spelling.\n".to_vec()),
]
}
#[test]
fn source_survives_reopen_and_all_formats_roundtrip_without_installing() -> Result<()> {
    let source = PackSource::from_files(files())?;
    let (dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let mut expected_sources = vault.list_pack_sources()?;
    let id = vault.stage_pack_source(&source, at(1), 2)?;
    assert_eq!(vault.stage_pack_source(&source, at(3), 4)?, id);
    expected_sources.push((id, source.clone()));
    expected_sources.sort_by_key(|(source_id, _)| *source_id.as_bytes());
    assert_eq!(vault.list_pack_sources()?, expected_sources);
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    assert_eq!(vault.list_pack_sources()?, expected_sources);
    assert_eq!(vault.get_pack_source(&id)?, Some(source.clone()));
    for format in [
        PackFormat::Json,
        PackFormat::Markdown,
        PackFormat::Toon,
        PackFormat::Yaml,
        PackFormat::Plaintext,
    ] {
        let artifact = vault.export_whole_vault(format)?;
        artifact.manifest().validate(format)?;
        assert!(String::from_utf8_lossy(artifact.bytes()).contains("Exact  source body."));
        if format == PackFormat::Json {
            let document = vault.read_whole_vault_json(artifact.bytes())?;
            let bundle = document
                .packs
                .iter()
                .find_map(|p| match p {
                    ExportPack::Source(p) if p.entity_id == id.to_hex() => Some(p),
                    _ => None,
                })
                .expect("source bundle");
            assert_eq!(
                bundle.source_tree.content_hash,
                Some(source.content_hash().to_hex())
            );
            assert_eq!(bundle.source_tree.import_files()?, source.files());
            let (_target_dir, target) =
                crate::test_util::open_test_vault_with(VaultConfig::default());
            target.import_whole_vault_json(artifact.bytes())?;
            assert_eq!(target.get_pack_source(&id)?, Some(source.clone()));
            assert_eq!(
                target
                    .import_whole_vault_json(artifact.bytes())?
                    .inserted_entities,
                0
            );
            // The source declares a predicate, but remains inert source data.
            assert!(target.get_skill_record(&id).is_err());
        }
    }
    Ok(())
}
#[test]
fn source_write_doors_refuse_identity_drift_and_roll_back() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let source = PackSource::from_files(files())?;
    let id = vault.stage_pack_source(&source, at(1), 1)?;
    let bytes = codec::encode(&source)?;
    let wrong = EntityId::now();
    assert!(
        vault
            .put_entity(&wrong, crate::registry::ENTITY_TYPE_ASSET, at(2), 2, &bytes)
            .is_err()
    );
    assert!(vault.get_raw(&wrong)?.is_none());
    assert!(
        vault
            .put_entity(
                &id,
                crate::registry::ENTITY_TYPE_ASSET,
                at(2),
                2,
                b"replacement"
            )
            .is_err()
    );
    assert!(
        vault
            .batch()
            .put_replicated(
                &id,
                crate::registry::ENTITY_TYPE_ASSET,
                at(2),
                2,
                b"replacement"
            )
            .commit()
            .is_err()
    );
    let first = EntityId::now();
    assert!(
        vault
            .batch()
            .put(
                &first,
                crate::registry::ENTITY_TYPE_PERSON,
                at(2),
                2,
                b"rollback"
            )
            .put(&wrong, crate::registry::ENTITY_TYPE_ASSET, at(2), 2, &bytes)
            .commit()
            .is_err()
    );
    assert!(vault.get_raw(&first)?.is_none());
    assert_eq!(vault.get_pack_source(&id)?, Some(source));
    Ok(())
}
#[test]
fn archive_rejects_replaced_or_missing_source_facets() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let source = PackSource::from_files(files())?;
    vault.stage_pack_source(&source, at(1), 1)?;
    let artifact = vault.export_whole_vault(PackFormat::Json)?;
    let mut document: WholeVaultDocument = serde_json::from_slice(artifact.bytes()).unwrap();
    let index = document
        .packs
        .iter()
        .position(|p| matches!(p, ExportPack::Source(_)))
        .unwrap();
    let ExportPack::Source(bundle) = &mut document.packs[index] else {
        unreachable!()
    };
    bundle.source_tree.files[0].content = Some("forged".into());
    assert!(
        vault
            .read_whole_vault_json(&serde_json::to_vec(&document).unwrap())
            .is_err()
    );
    let mut document: WholeVaultDocument = serde_json::from_slice(artifact.bytes()).unwrap();
    document.packs.remove(index);
    assert!(
        vault
            .read_whole_vault_json(&serde_json::to_vec(&document).unwrap())
            .is_err()
    );
    Ok(())
}

pub(super) fn agent_files() -> Result<Vec<HubFile>> {
    use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
    use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
    let definition = AgentDefinition::new(
        "example.worker",
        "Portable agent",
        "1.0.0",
        Some("Use the supplied facts.\n".into()),
        vec![],
        vec![],
        vec![],
        None,
        AgentScope::Base,
        AgentCeiling::Auto,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("fixture"),
            rmpv::Value::from("agent-pack"),
        )]),
        None,
        true,
        None,
    );
    crate::agent_def::agent_pack_files(&EntityId::now(), &definition, &[], &[])
}

#[test]
fn agent_facets_are_required_typed_and_bound_to_the_manifest() -> Result<()> {
    let files = agent_files()?;
    let mutate = |path: &str, content: Vec<u8>| {
        let mut files = files.clone();
        files.iter_mut().find(|f| f.path == path).unwrap().content = content;
        files
    };
    for missing in [
        "identity.md",
        "policy.md",
        "skills.json",
        "knowledge/selected.json",
    ] {
        let files = files
            .iter()
            .filter(|f| f.path != missing)
            .cloned()
            .collect();
        assert!(PackSource::from_files(files).is_err(), "missing {missing}");
    }
    for bad in [
        mutate(
            "identity.md",
            b"An identity different from the policy.\n".to_vec(),
        ),
        mutate("policy.md", b"not typed JSON".to_vec()),
        mutate(
            "skills.json",
            br#"[{"skill_id":"demo","content_hash":"unbound"}]"#.to_vec(),
        ),
        mutate(
            "PACK.md",
            String::from_utf8(files[0].content.clone())
                .unwrap()
                .replace("example.worker", "example.other")
                .into_bytes(),
        ),
        mutate(
            "PACK.md",
            String::from_utf8(files[0].content.clone())
                .unwrap()
                .replace("identity.md", "scripts/identity.md")
                .into_bytes(),
        ),
    ] {
        assert!(PackSource::from_files(bad).is_err());
    }
    let mut with_code = files;
    with_code.push(HubFile::new(
        "scripts/launch.sh",
        b"echo not an agent facet\n".to_vec(),
    ));
    assert!(PackSource::from_files(with_code).is_err());
    Ok(())
}

#[test]
fn credential_in_any_agent_facet_is_refused_with_named_reason() -> Result<()> {
    for path in [
        "PACK.md",
        "identity.md",
        "policy.md",
        "skills.json",
        "knowledge/selected.json",
    ] {
        let mut files = agent_files()?;
        files
            .iter_mut()
            .find(|f| f.path == path)
            .unwrap()
            .content
            .extend_from_slice(b"\ntoken=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n");
        let err = PackSource::from_files(files).expect_err("credential must refuse");
        assert!(
            format!("{err:?}").contains("gate.secret_scan.github_token"),
            "{path}: {err:?}"
        );
    }
    Ok(())
}

fn agent_knowledge_files() -> Result<(Vec<HubFile>, crate::batch::export::ExportEntity)> {
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    let files = agent_files()?;
    let policy: serde_json::Value = serde_json::from_slice(
        &files
            .iter()
            .find(|f| f.path == "policy.md")
            .unwrap()
            .content,
    )
    .unwrap();
    let agent = EntityId::from_hex(policy["entity_id"].as_str().unwrap())?;
    let claim = ClaimBody::new(
        "test.pack_knowledge",
        ClaimSubject::Entity(agent),
        rmpv::Value::from("safe"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    let body = crate::claim::encode_claim_body(&claim)?;
    Ok((
        files,
        crate::batch::export::ExportEntity {
            id: EntityId::now().to_hex(),
            short_ref: None,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred_start: 1,
            occurred_end: 1,
            learned_at: 1,
            body: crate::serialize::ExportBody::from_bytes(
                &body,
                crate::registry::ENTITY_TYPE_CLAIM,
            ),
        },
    ))
}

fn put_agent_knowledge(files: &mut [HubFile], row: &crate::batch::export::ExportEntity) {
    files
        .iter_mut()
        .find(|f| f.path == "knowledge/selected.json")
        .unwrap()
        .content = serde_json::to_vec(&[row]).unwrap();
}

#[test]
fn agent_knowledge_rejects_typed_credentials_at_source_stage_and_archive_doors() -> Result<()> {
    use crate::serialize::{ExportBody, ExportValue};
    let (mut files, mut row) = agent_knowledge_files()?;
    put_agent_knowledge(&mut files, &row);
    let source = PackSource::from_files(files.clone())?;
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let seeded_sources = vault.list_pack_sources()?.len();
    let id = vault.stage_pack_source(&source, at(1), 1)?;
    assert_eq!(vault.get_pack_source(&id)?, Some(source.clone()));
    let artifact = vault.export_whole_vault(PackFormat::Json)?;
    let document = vault.read_whole_vault_json(artifact.bytes())?;
    let exported_sources: Vec<_> = document
        .packs
        .iter()
        .filter_map(|pack| match pack {
            ExportPack::Source(row) => Some(&row.entity_id),
            _ => None,
        })
        .collect();
    assert_eq!(exported_sources.len(), seeded_sources + 1);
    assert_eq!(
        exported_sources
            .iter()
            .filter(|row| row.as_str() == id.to_hex())
            .count(),
        1
    );

    let ExportBody::MessagePack(ExportValue::Map(entries)) = &mut row.body else {
        panic!("claim body must be typed");
    };
    entries
        .iter_mut()
        .find(|(key, _)| key == &ExportValue::String("val".into()))
        .unwrap()
        .1 = ExportValue::Map(vec![(
        ExportValue::String("password".into()),
        ExportValue::String("review-only-fixture-password".into()),
    )]);
    assert!(
        row.body
            .validate(crate::registry::ENTITY_TYPE_CLAIM)
            .is_err()
    );
    put_agent_knowledge(&mut files, &row);
    assert!(matches!(
        PackSource::from_files(files.clone()),
        Err(crate::Error::InvalidConfig(_))
    ));
    // Even a forged PackSource with a recomputed tree hash cannot bypass the
    // stage/replay decoder's native-body check.
    let mut forged = source;
    forged.hash = crate::skill::canonical_skill_tree_hash(
        files
            .iter()
            .map(|f| (f.path.as_str(), f.content.as_slice())),
    )?;
    forged.files = files;
    assert!(vault.stage_pack_source(&forged, at(1), 1).is_err());
    assert!(vault.get_pack_source(&forged.entity_id()?)?.is_none());
    let mut document: WholeVaultDocument = serde_json::from_slice(artifact.bytes()).unwrap();
    let export = document
        .packs
        .iter_mut()
        .find_map(|pack| match pack {
            ExportPack::Source(source) => Some(source),
            _ => None,
        })
        .unwrap();
    export.source_tree = crate::serialize::export_source_tree(&forged.files)?;
    assert!(export.source_tree.content_hash.is_some());
    assert!(
        vault
            .read_whole_vault_json(&serde_json::to_vec(&document).unwrap())
            .is_err()
    );
    Ok(())
}
// The hub folder contract lists an optional `contact` (2026-09-22). This is
// oneiron-hub's claude-seat frontmatter with its real `contact` line, after the
// hub-side fix (one-line grants; terms and notes moved into the body).
#[test]
fn hub_pack_contact_line_loads_and_is_carried() -> Result<()> {
    const CONTACT: &str =
        "legal@oneiron.dev for removal requests, contact@oneiron.dev for everything else";
    let pack = |contact: &str| {
        PackSource::from_files(vec![HubFile::new(
            "PACK.md",
            format!(
                "---\nname: oneiron.claude-seat\ndescription: \"A person's own Claude Code, signed in by them, run headless inside their vault as a seat. Installs Anthropic's tool from Anthropic's source at first use. Never holds a token.\"\nversion: 0.1.1\nlicense: Apache-2.0\nkind: capability\ngrants: [\"run: the claude binary inside this vault's sandbox, as the seat's own user\", \"network: api.anthropic.com and claude.ai, for the login flow and the tool's own requests\", \"store: the seat's login directory on the vault volume, read and written only by the seat process\"]\nwakes: []\nadapter: built-in:seat-headless\ncontact: {contact}\n---\n\n# claude-seat\n"
            )
            .into_bytes(),
        )])
    };
    let source = pack(CONTACT)?;
    assert_eq!(source.manifest().contact.as_deref(), Some(CONTACT));
    // Bounded display text: no control characters, not blank, at most 512
    // bytes, and no credential hidden behind a JSON escape.
    for bad in [
        "\"legal@oneiron.dev\\u0007\"".to_owned(),
        "\" \"".to_owned(),
        "a".repeat(513),
        "\"\\u0067hp_0123456789abcdefghijklmnopqrstuvwxyz\"".to_owned(),
    ] {
        assert!(pack(&bad).is_err(), "{bad}");
    }
    assert!(pack(&"a".repeat(512)).is_ok());
    Ok(())
}

#[test]
fn escaped_credential_in_any_pack_md_value_is_refused() {
    // The source scans read the raw file, where a JSON escape hides a
    // credential, so every value class is read decoded. Each pair differs only
    // in what one escape decodes to.
    const HIDDEN: &str = "\\u0067hp_0123456789abcdefghijklmnopqrstuvwxyz";
    const KEPT: &str = "\\u0073elected";
    let capability = |line: String| {
        PackSource::from_files(vec![HubFile::new(
            "PACK.md",
            format!(
                "---\nname: example.contacts\ndescription: Contact predicate pack\nversion: 1.0.0\nkind: capability\npredicates: [\"example.contacts.phone\"]\n{line}\n---\nExact pack source.\n"
            )
            .into_bytes(),
        )])
    };
    let migration = |old: &str, note: &str| {
        format!(
            "migrations: [{{\"from\":\"0.9.0\",\"rewrites\":{{\"{old}\":{{\"kind\":\"equivalent\",\"to\":\"example.contacts.phone\",\"note\":\"{note}\"}}}}}}]"
        )
    };
    // The knowledge file carries the decoded name, so the facet resolves.
    let agent = |word: &str| -> Result<PackSource> {
        let decoded: String = serde_json::from_str(&format!("\"{word}\"")).unwrap();
        let mut files = agent_files()?;
        for file in &mut files {
            if file.path == "PACK.md" {
                file.content = String::from_utf8(file.content.clone())
                    .unwrap()
                    .replace("knowledge/selected.json", &format!("knowledge/{word}.json"))
                    .into_bytes();
            } else if file.path == "knowledge/selected.json" {
                file.path = format!("knowledge/{decoded}.json");
            }
        }
        PackSource::from_files(files)
    };
    let classes = |word: &str| {
        [
            ("quoted scalar", capability(format!("license: \"{word}\""))),
            ("list item", capability(format!("grants: [\"{word}\"]"))),
            ("facet", agent(word)),
            (
                "migration note",
                capability(migration("example.contacts.tel", word)),
            ),
            (
                "migration key",
                capability(migration(&format!("example.contacts.{word}"), "Same field")),
            ),
        ]
    };
    for (class, kept) in classes(KEPT) {
        assert!(kept.is_ok(), "{class}: {:?}", kept.err());
    }
    for (class, hidden) in classes(HIDDEN) {
        let err = hidden.expect_err(class);
        assert!(
            format!("{err:?}").contains("gate.secret_scan.github_token"),
            "{class}: {err:?}"
        );
    }
    // A recovery phrase spread over a list, one escaped word per entry, is
    // read as one run, as the raw file shows an unescaped list. A BIP39
    // reference vector (trezor/python-mnemonic); it guards no funds. Its twin
    // breaks the checksum.
    let escaped = |phrase: &str| {
        phrase
            .split(' ')
            .map(|word| format!("\"\\u{:04x}{}\"", word.as_bytes()[0], &word[1..]))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let words = "ozone drill grab fiber curtain grace pudding thank cruise elder eight";
    assert!(capability(format!("grants: [{}]", escaped(&format!("{words} pilot")))).is_ok());
    let err = capability(format!("grants: [{}]", escaped(&format!("{words} picnic"))))
        .expect_err("recovery phrase");
    assert!(
        format!("{err:?}").contains("credential material"),
        "{err:?}"
    );
    // The run is joined text, not a record: two entries that only form an
    // object once joined are not read as one.
    assert!(capability(r#"grants: ["{\"token\"", ": \"VALUE\"}"]"#.to_owned()).is_ok());
}
