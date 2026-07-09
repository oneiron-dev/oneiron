use super::*;
use crate::batch::{BatchOp, apply_ops};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::test_util::open_test_vault_with;
use crate::types::{TimeRange, VaultConfig};

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("valid id")
}

fn time_range(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn put_entity(vault: &crate::Vault, id: EntityId, entity_type: u8) -> Result<()> {
    vault.put_entity(&id, entity_type, time_range(1), 1, b"entity")
}

fn put_entity_learned_at(
    vault: &crate::Vault,
    id: EntityId,
    entity_type: u8,
    learned_at: u64,
) -> Result<()> {
    vault.put_entity(
        &id,
        entity_type,
        time_range(learned_at),
        learned_at,
        b"entity",
    )
}

fn put_claim(
    vault: &crate::Vault,
    id: EntityId,
    subject: EntityId,
    world: Option<EntityId>,
    learned_at: u64,
) -> Result<()> {
    put_claim_with_value(
        vault,
        id,
        subject,
        world,
        learned_at,
        &format!("claim-{}", id.to_hex()),
    )
}

fn put_claim_with_value(
    vault: &crate::Vault,
    id: EntityId,
    subject: EntityId,
    world: Option<EntityId>,
    learned_at: u64,
    value: &str,
) -> Result<()> {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        Value::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.world = world;
    vault.put_claim(&id, &body, time_range(learned_at), learned_at)
}

fn encode_policy_manifest(scoped_grants: Vec<Value>) -> Vec<u8> {
    let value = Value::Map(vec![
        (Value::from("schema_version"), Value::from("1.1")),
        (Value::from("pack_id"), Value::from("graph-fs-test")),
        (Value::from("pack_version"), Value::from("1")),
        (Value::from("min_engine_version"), Value::from("0.0.0")),
        (Value::from("defaults"), Value::Map(Vec::new())),
        (Value::from("rules"), Value::Array(Vec::new())),
        (Value::from("actor_ceilings"), Value::Array(Vec::new())),
        (Value::from("scoped_grants"), Value::Array(scoped_grants)),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &value).expect("policy manifest encodes");
    data
}

fn core_read_world_grant(actor_ref: &str, world: EntityId) -> Value {
    Value::Map(vec![
        (Value::from("actor_ref"), Value::from(actor_ref)),
        (Value::from("effector"), Value::from("core:read")),
        (
            Value::from("scope"),
            Value::Map(vec![(
                Value::from("world_ref"),
                Value::from(world.to_hex()),
            )]),
        ),
        (Value::from("receipt_required"), Value::Boolean(false)),
    ])
}

fn put_policy_manifest(vault: &crate::Vault, id: EntityId, data: Vec<u8>) -> Result<()> {
    let ops = vec![BatchOp::Put {
        id,
        entity_type: crate::registry::ENTITY_TYPE_POLICY_MANIFEST,
        occurred: time_range(1),
        learned_at: 1,
        data,
        allow_maintenance: true,
        allow_reserved_predicate: false,
    }];
    let mut wtxn = vault.store.env.write_txn()?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        ops,
        true,
        false,
        true,
    )?;
    wtxn.commit()?;
    Ok(())
}

fn resolver<'read, 'vault>(
    read: &'read ScopedRead<'vault>,
    cap: usize,
) -> GraphFsResolver<'read, 'vault> {
    read.graph_fs(GraphFsOptions::default().with_page_byte_cap(cap))
}

#[test]
fn worlds_readdir_omits_excluded_worlds_entirely() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(VaultConfig::default());
    let allowed_world = test_id(0x31);
    let excluded_world = test_id(0x32);
    let subject = test_id(0x33);
    let allowed_claim = test_id(0x41);
    let excluded_claim = test_id(0x42);
    put_entity(&vault, allowed_world, ENTITY_TYPE_WORLD)?;
    put_entity(&vault, excluded_world, ENTITY_TYPE_WORLD)?;
    put_entity(&vault, subject, ENTITY_TYPE_PERSON)?;
    put_claim(&vault, allowed_claim, subject, Some(allowed_world), 10)?;
    put_claim(&vault, excluded_claim, subject, Some(excluded_world), 11)?;
    put_policy_manifest(
        &vault,
        test_id(0x90),
        encode_policy_manifest(vec![core_read_world_grant("reader", allowed_world)]),
    )?;

    let reader =
        vault.scoped_read(crate::claim::ScopedReadActorKey::new("reader").expect("actor key"));
    let page = resolver(&reader, 1024).readdir("/worlds/", None)?;
    let names: Vec<_> = page.entries().iter().map(GraphFsEntry::name).collect();

    assert!(names.contains(&allowed_world.to_hex().as_str()));
    assert!(
        !names.contains(&excluded_world.to_hex().as_str()),
        "owner-excluded world must be absent from readdir, not listed as forbidden"
    );
    assert!(
        !page
            .render_bytes()
            .windows(excluded_world.to_hex().len())
            .any(|window| window == excluded_world.to_hex().as_bytes()),
        "rendered bytes must not leak the excluded world id"
    );

    let allowed_world_claims = resolver(&reader, 1024)
        .readdir(&format!("/worlds/{}/claims", allowed_world.to_hex()), None)?;
    let allowed_claim_names: Vec<_> = allowed_world_claims
        .entries()
        .iter()
        .map(GraphFsEntry::name)
        .collect();
    assert!(allowed_claim_names.contains(&allowed_claim.to_hex().as_str()));
    assert!(!allowed_claim_names.contains(&excluded_claim.to_hex().as_str()));

    let excluded_world_claims = resolver(&reader, 1024)
        .readdir(&format!("/worlds/{}/claims", excluded_world.to_hex()), None)?;
    assert!(
        excluded_world_claims.entries().is_empty(),
        "excluded world namespace must be empty, not forbidden"
    );
    Ok(())
}

#[test]
fn large_day_shard_returns_first_page_and_more_under_byte_cap() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(VaultConfig::default());
    let subject = test_id(0x44);
    put_entity(&vault, subject, ENTITY_TYPE_PERSON)?;
    let learned_at = 1_771_027_200;
    let mut ops = Vec::with_capacity(100_000);
    for index in 0..100_000_u32 {
        let mut bytes = [0x60; 16];
        bytes[12..16].copy_from_slice(&index.to_be_bytes());
        let id = EntityId::from_bytes(bytes).expect("valid claim id");
        let mut body = ClaimBody::new(
            "profile.note",
            ClaimSubject::Entity(subject),
            Value::from(format!("claim-{index}")),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.valid_from = Some(learned_at);
        let data = crate::claim::encode_claim_body(&body)?;
        ops.push(BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: time_range(learned_at),
            learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
        });
    }
    let mut wtxn = vault.store.env.write_txn()?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        ops,
        true,
        false,
        true,
    )?;
    wtxn.commit()?;

    let reader =
        vault.scoped_read(crate::claim::ScopedReadActorKey::new("reader").expect("actor key"));
    let day = format_day_shard(learned_at / 86_400);
    let page = resolver(&reader, 512).readdir(&format!("/claims/by-time/{day}/"), None)?;

    assert!(page.byte_count() <= 512);
    assert!(
        page.entries()
            .iter()
            .any(|entry| entry.name() == GRAPH_FS_MORE_ENTRY)
    );
    assert!(page.next_cursor().is_some());
    assert!(
        page.entries()
            .iter()
            .filter(|entry| entry.kind() == GraphFsEntryKind::File)
            .count()
            > 0
    );
    Ok(())
}

#[test]
fn same_fork_hash_mount_renders_byte_identical_readdir() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(VaultConfig::default());
    let subject = test_id(0x55);
    let claim = test_id(0x56);
    put_entity(&vault, subject, ENTITY_TYPE_PERSON)?;
    put_claim(&vault, claim, subject, None, 20)?;

    let reader =
        vault.scoped_read(crate::claim::ScopedReadActorKey::new("reader").expect("actor key"));
    let options = GraphFsOptions::default()
        .with_mount(GraphFsMount::ForkHash([0xA5; 32]))
        .with_page_byte_cap(1024);
    let fs = reader.graph_fs(options);
    let first = fs.readdir_bytes("/claims/by-id", None)?;
    let second = fs.readdir_bytes("/claims/by-id", None)?;

    assert_eq!(first, second);
    assert!(
        first
            .windows(claim.to_hex().len())
            .any(|window| window == claim.to_hex().as_bytes())
    );
    Ok(())
}

#[test]
fn graph_fs_host_imports_are_read_only() {
    assert!(
        GRAPH_FS_HOST_IMPORTS
            .iter()
            .all(|import| import.class() == SandboxImportClass::ReadOnly)
    );
    assert!(
        GRAPH_FS_HOST_IMPORTS
            .iter()
            .all(|import| !matches!(import.class(), SandboxImportClass::WriteTrap))
    );
}

#[test]
fn grep_r_claims_pushdown_matches_scoped_bm25_ids_and_logs() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(VaultConfig::default());
    let subject = test_id(0x61);
    let matching_claim = test_id(0x62);
    let other_claim = test_id(0x63);
    put_entity(&vault, subject, ENTITY_TYPE_PERSON)?;
    put_claim_with_value(
        &vault,
        matching_claim,
        subject,
        None,
        10,
        "pushdownneedle alpha",
    )?;
    put_claim_with_value(&vault, other_claim, subject, None, 11, "ordinary beta")?;
    vault
        .batch()
        .text(&matching_claim, &[("body", "pushdownneedle alpha")])
        .commit()?;

    let reader =
        vault.scoped_read(crate::claim::ScopedReadActorKey::new("reader").expect("actor key"));
    let expected_ids: Vec<_> = reader
        .search_text("pushdownneedle", 10)?
        .into_iter()
        .map(|hit| hit.id)
        .collect();
    let output = resolver(&reader, 1024).grep("pushdownneedle", "/claims", true, None)?;
    let rendered = String::from_utf8(output.bytes().to_vec()).expect("utf8 grep output");
    let actual_ids: Vec<_> = rendered
        .lines()
        .filter_map(|line| {
            line.strip_prefix("/claims/")
                .and_then(|rest| rest.split_once(':').map(|(id, _)| id))
        })
        .map(EntityId::from_hex)
        .collect::<Result<Vec<_>>>()?;

    assert_eq!(output.decision(), GraphFsCoreutilsDecision::Pushdown);
    assert_eq!(actual_ids, expected_ids);
    assert!(rendered.contains(&matching_claim.to_hex()));
    assert!(!rendered.contains(&other_claim.to_hex()));
    let telemetry = vault
        .retrieval_run(output.telemetry_run_id())?
        .expect("coreutils telemetry row is written");
    assert_eq!(telemetry.action, crate::RetrievalAction::GraphFsCoreutils);
    assert!(
        telemetry
            .empty_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("grep:pushdown"))
    );
    Ok(())
}

#[test]
fn find_root_under_clamped_actor_is_bounded_and_non_leaking() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(VaultConfig::default());
    let allowed_world = test_id(0x64);
    let excluded_world = test_id(0x65);
    let subject = test_id(0x66);
    let allowed_claim = test_id(0x67);
    let excluded_claim = test_id(0x68);
    put_entity(&vault, allowed_world, ENTITY_TYPE_WORLD)?;
    put_entity(&vault, excluded_world, ENTITY_TYPE_WORLD)?;
    put_entity(&vault, subject, ENTITY_TYPE_PERSON)?;
    put_claim(&vault, allowed_claim, subject, Some(allowed_world), 20)?;
    put_claim(&vault, excluded_claim, subject, Some(excluded_world), 21)?;
    put_policy_manifest(
        &vault,
        test_id(0x91),
        encode_policy_manifest(vec![core_read_world_grant("reader", allowed_world)]),
    )?;

    let reader =
        vault.scoped_read(crate::claim::ScopedReadActorKey::new("reader").expect("actor key"));
    let output = resolver(&reader, GRAPH_FS_MIN_PAGE_BYTE_CAP).find("/", None, None)?;
    let rendered = String::from_utf8(output.bytes().to_vec()).expect("utf8 find output");

    assert_eq!(output.decision(), GraphFsCoreutilsDecision::Walk);
    assert!(output.bytes().len() <= GRAPH_FS_MIN_PAGE_BYTE_CAP);
    assert!(!rendered.contains(&excluded_world.to_hex()));
    assert!(!rendered.contains(&excluded_claim.to_hex()));
    Ok(())
}

#[test]
fn find_newer_uses_scoped_temporal_pushdown() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(VaultConfig::default());
    let subject = test_id(0x69);
    let old_claim = test_id(0x6A);
    let new_claim = test_id(0x6B);
    put_entity(&vault, subject, ENTITY_TYPE_PERSON)?;
    put_claim(&vault, old_claim, subject, None, 10)?;
    put_claim(&vault, new_claim, subject, None, 20)?;

    let reader =
        vault.scoped_read(crate::claim::ScopedReadActorKey::new("reader").expect("actor key"));
    let output = resolver(&reader, 1024).find("/claims", Some(15), None)?;
    let rendered = String::from_utf8(output.bytes().to_vec()).expect("utf8 find output");

    assert_eq!(output.decision(), GraphFsCoreutilsDecision::Pushdown);
    assert!(rendered.contains(&format!("/claims/{}", new_claim.to_hex())));
    assert!(!rendered.contains(&old_claim.to_hex()));
    let telemetry = vault
        .retrieval_run(output.telemetry_run_id())?
        .expect("coreutils telemetry row is written");
    assert_eq!(telemetry.action, crate::RetrievalAction::GraphFsCoreutils);
    assert!(
        telemetry
            .empty_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("find:pushdown"))
    );
    Ok(())
}

#[test]
fn wikilink_deeplink_resolves_to_claim_symlink() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(VaultConfig::default());
    let subject = test_id(0x70);
    let claim = test_id(0x71);
    put_entity(&vault, subject, ENTITY_TYPE_PERSON)?;
    put_claim(&vault, claim, subject, None, 30)?;
    let reader =
        vault.scoped_read(crate::claim::ScopedReadActorKey::new("reader").expect("actor key"));
    let link = resolver(&reader, 1024)
        .read_link(&format!("/[[claim:{}]]", claim.to_hex()))?
        .expect("claim link resolves");

    assert_eq!(link, format!("/claims/{}", claim.to_hex()));
    Ok(())
}

#[test]
fn day_shard_date_round_trips() {
    let day = 1_771_027_200 / 86_400;
    let formatted = format_day_shard(day);
    assert_eq!(parse_day_shard(&formatted).expect("valid day"), day);
    assert_eq!(format_day_shard(0), "1970-01-01");
}

#[test]
fn ls_claims_by_time_scan_cap_hit_returns_progressing_cursor() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(VaultConfig::default());
    let subject = test_id(0x72);
    let old_claim = test_id(0x73);
    let new_claim = test_id(0x74);
    put_entity(&vault, subject, ENTITY_TYPE_PERSON)?;
    put_claim(&vault, old_claim, subject, None, 10)?;
    put_claim(&vault, new_claim, subject, None, 11)?;
    for index in 0..6_u8 {
        put_entity_learned_at(
            &vault,
            test_id(0x80 + index),
            ENTITY_TYPE_PERSON,
            100 + u64::from(index),
        )?;
    }

    let reader =
        vault.scoped_read(crate::claim::ScopedReadActorKey::new("reader").expect("actor key"));
    let fs = resolver(&reader, 1024);
    let (bytes, first_cursor, total) = fs.ls_claims_by_time_pushdown_with_scan_cap(None, 2)?;
    assert!(
        bytes.is_empty(),
        "cap-hit page before any claim emits no rows"
    );
    assert_eq!(total, 0);
    let first_cursor = first_cursor.expect("cap-hit page must return a resume cursor");

    let (_, second_cursor, _) =
        fs.ls_claims_by_time_pushdown_with_scan_cap(Some(&first_cursor), 2)?;
    let second_cursor = second_cursor.expect("cap-hit resume must return a cursor");
    assert_ne!(
        first_cursor, second_cursor,
        "cursor must advance across cap-hit pages"
    );

    let mut cursor = Some(second_cursor);
    let mut emitted = String::new();
    for _ in 0..32 {
        let Some(current) = cursor else { break };
        let (bytes, next_cursor, _) =
            fs.ls_claims_by_time_pushdown_with_scan_cap(Some(&current), 2)?;
        emitted.push_str(std::str::from_utf8(&bytes).expect("utf8 ls output"));
        assert_ne!(
            next_cursor.as_deref(),
            Some(current.as_str()),
            "cursor must always advance"
        );
        cursor = next_cursor;
    }
    assert!(cursor.is_none(), "pagination must terminate");
    let lines: Vec<_> = emitted.lines().map(str::to_owned).collect();
    assert_eq!(lines, vec![new_claim.to_hex(), old_claim.to_hex()]);
    Ok(())
}

#[test]
fn find_newer_scan_cap_hit_returns_progressing_cursor() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(VaultConfig::default());
    let subject = test_id(0x75);
    let claim = test_id(0x76);
    put_entity(&vault, subject, ENTITY_TYPE_PERSON)?;
    for index in 0..6_u8 {
        put_entity_learned_at(
            &vault,
            test_id(0x88 + index),
            ENTITY_TYPE_PERSON,
            100 + u64::from(index),
        )?;
    }
    put_claim(&vault, claim, subject, None, 200)?;

    let reader =
        vault.scoped_read(crate::claim::ScopedReadActorKey::new("reader").expect("actor key"));
    let fs = resolver(&reader, 1024);
    let (bytes, first_cursor, total) =
        fs.find_newer_pushdown_with_scan_cap("/claims", 50, None, 2)?;
    assert!(
        bytes.is_empty(),
        "cap-hit page before any match emits no rows"
    );
    assert_eq!(total, 0);
    let first_cursor = first_cursor.expect("cap-hit page must return a resume cursor");

    let (_, second_cursor, _) =
        fs.find_newer_pushdown_with_scan_cap("/claims", 50, Some(&first_cursor), 2)?;
    let second_cursor = second_cursor.expect("cap-hit resume must return a cursor");
    assert_ne!(
        first_cursor, second_cursor,
        "cursor must advance across cap-hit pages"
    );

    let mut cursor = Some(second_cursor);
    let mut emitted = String::new();
    for _ in 0..32 {
        let Some(current) = cursor else { break };
        let (bytes, next_cursor, _) =
            fs.find_newer_pushdown_with_scan_cap("/claims", 50, Some(&current), 2)?;
        emitted.push_str(std::str::from_utf8(&bytes).expect("utf8 find output"));
        assert_ne!(
            next_cursor.as_deref(),
            Some(current.as_str()),
            "cursor must always advance"
        );
        cursor = next_cursor;
    }
    assert!(cursor.is_none(), "pagination must terminate");
    assert_eq!(emitted, format!("/claims/{}\n", claim.to_hex()));
    Ok(())
}
