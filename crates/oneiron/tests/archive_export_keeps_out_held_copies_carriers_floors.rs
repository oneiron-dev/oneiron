#![cfg(oneiron_test_support)]
//! The whole-vault export keeps out what copies, carries or counts a row this vault holds back
//! (REVIEW-9874 round 1, FIX WHOLE-VAULT-EXPORT-HELD-BACK-REVIEW-TESTS). A held-back row reads to
//! no one here and never leaves while held; the archive carries no hold, so a restore would read
//! what it ships openly.
//!
//! Public doors plus the summary, skill package, epoch floor and source-audience hold doors;
//! neutral fixtures; vaults in tempdirs.
//!
//! * `a_reply_copying_a_held_summary_stays_out` (P1 1): a summary-as-record landing lands a reply
//!   TURN that copies the summary's words; once the vault holds the summary back, the export
//!   keeps the reply out, while the trunk TURNs the summary read still travel.
//! * `a_package_read_from_a_held_carrier_stays_out_of_its_skill` (P1 2): a SKILL whose package
//!   reads from its replicated carrier ASSET, as on a vault the skill reached by sync; once the
//!   carrier is held back, the skill's row still travels and its package does not.
//! * `an_epoch_floor_of_a_held_conversation_stays_out` (P1 3): a conversation's epoch floor is
//!   not written once the conversation is held back; its session's own floor still is.
//!
//! Each runs red at afe2d631eea (#9874 before round 1), whose source-audience walk names no
//! carried summary and whose carrier and floor writers ask only the use limit and the device-only
//! filter, and green at e95173f3140 and after.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test archive_export_keeps_out_held_copies_carriers_floors`.

use std::collections::BTreeSet;

use oneiron::conversation_dag::{ScopePath, ScopeSelector};
use oneiron::core_write::{ConversationCreateInput, DagRecordAppendInput};
use oneiron::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use oneiron::skill_hub::HubFile;
use oneiron::test_doors::compaction::raise_epoch_floor;
use oneiron::test_doors::fingerprint_keep_store_digests::skill_source_carrier;
use oneiron::test_doors::scope_summary::mint_scope_summary;
use oneiron::test_doors::skill_package::{
    drop_local_package_sidecar, land_active_skill_with_files,
};
use oneiron::test_doors::turn_programs::withhold_turn;
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor,
};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A default vault rooted as the server roots it, its owner, and one conversation whose
/// two-record trunk the owner wrote. The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    conversation: EntityId,
    trunk: [EntityId; 2],
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    // The server roots its vault and provisions the engine's MACHINE writers on every open; the
    // summary landing writes as one.
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let (conversation, trunk) = {
        let host = vault.memory(owner, EdgeActorClass::Human);
        let receipt = host.conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: json!({}),
            text: None,
        })?;
        let conversation = EntityId::from_hex(&receipt.id)?;
        let first =
            host.conversations_records_append(&trunk_record(conversation, None, "the plan"))?;
        let second = host.conversations_records_append(&trunk_record(
            conversation,
            Some(&first.id),
            "the first step",
        ))?;
        (
            conversation,
            [
                EntityId::from_hex(&first.id)?,
                EntityId::from_hex(&second.id)?,
            ],
        )
    };
    Ok(Fixture {
        vault,
        owner,
        conversation,
        trunk,
        _dir: dir,
    })
}

/// One trunk record that advances HEAD from `parent`.
fn trunk_record(conversation: EntityId, parent: Option<&str>, text: &str) -> DagRecordAppendInput {
    DagRecordAppendInput {
        conversation: conversation.to_hex(),
        parent: parent.map(str::to_owned),
        reply_to: None,
        containing_turn: None,
        addr: None,
        to: None,
        advance: true,
        body: json!({"txt": text, "speaker": "user"}),
        text: None,
        occurred_start: None,
        occurred_end: None,
        learned_at: None,
        session: None,
        quote: None,
        thread_audience: None,
    }
}

/// Holds `row` back here, as a sync import does when the vault it came from withheld it after
/// it travelled.
fn hold_back(vault: &Vault, row: EntityId) -> TestResult {
    assert!(withhold_turn(vault, row)?, "FIXTURE: the hold is new");
    Ok(())
}

/// The whole-vault archive of `vault`, read back.
fn archive(vault: &Vault) -> TestResult<oneiron::batch::export::WholeVaultDocument> {
    let bytes = vault.export_whole_vault(true)?.bytes().to_vec();
    Ok(vault.read_whole_vault_archive(&bytes)?)
}

/// The ids of every entity and claim a whole-vault export of `vault` carries.
fn carried_ids(vault: &Vault) -> TestResult<BTreeSet<String>> {
    let document = archive(vault)?;
    Ok(document
        .evidence_ledger
        .entities
        .iter()
        .chain(document.claims.iter())
        .map(|row| row.id.clone())
        .collect())
}

#[test]
fn a_reply_copying_a_held_summary_stays_out() -> TestResult {
    let fixture = open()?;
    let vault = &fixture.vault;
    let [asking, last] = fixture.trunk;
    let summary = mint_scope_summary(
        vault,
        &ScopeSelector {
            conversation: fixture.conversation,
            session: None,
            path: ScopePath::Canonical,
            include_forks: false,
        },
        "The plan, and its first step.",
    )?;
    let landed = vault.land_header(
        &summary,
        &asking,
        WriteActor::new(fixture.owner, EdgeActorClass::Human),
        true,
    )?;
    let reply = landed
        .record
        .ok_or("FIXTURE: as_record lands a reply TURN")?;
    let before = carried_ids(vault)?;
    for (kind, id) in [
        ("reply TURN", reply),
        ("asking TURN", asking),
        ("last trunk TURN", last),
    ] {
        assert!(
            before.contains(&id.to_hex()),
            "FIXTURE: before the hold the export carries the {kind}"
        );
    }

    hold_back(vault, summary)?;

    let after = carried_ids(vault)?;
    assert!(
        !after.contains(&reply.to_hex()),
        "the export keeps out a reply TURN that copies a held summary's words"
    );
    assert!(
        !after.contains(&summary.to_hex()),
        "the export keeps out the held summary"
    );
    for (kind, id) in [("asking TURN", asking), ("last trunk TURN", last)] {
        assert!(
            after.contains(&id.to_hex()),
            "the export still carries the {kind}, whose words came from no held row"
        );
    }
    Ok(())
}

/// Whether the export carries skill `skill`'s row (`None` when it does not) and, when it does,
/// whether its section holds the package files.
fn skill_package_travels(vault: &Vault, skill: EntityId) -> TestResult<Option<bool>> {
    Ok(archive(vault)?
        .skills
        .iter()
        .find(|bundle| bundle.entity.id == skill.to_hex())
        .map(|bundle| bundle.source_tree.is_some()))
}

#[test]
fn a_package_read_from_a_held_carrier_stays_out_of_its_skill() -> TestResult {
    let fixture = open()?;
    let vault = &fixture.vault;
    let files = vec![
        HubFile::new(
            "SKILL.md",
            b"# a skill whose package reads from its carrier\n".to_vec(),
        ),
        HubFile::new("scripts/count.py", b"print(3)\n".to_vec()),
    ];
    let tree = canonical_skill_tree_hash(
        files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )?;
    let tree_bytes = *tree.as_bytes();
    let record = SkillRecord::new(
        "held-carrier.skill",
        "A skill whose package reads from its carrier",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        0.9,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("held-carrier-fixture"),
        )]),
    )
    .with_content_hash(tree);
    let skill = land_active_skill_with_files(vault, &record, files)?;
    // As on a vault the skill reached by sync: no local sidecar, so its package reads from the
    // replicated carrier the landing wrote.
    drop_local_package_sidecar(vault, &skill)?;
    let carrier = skill_source_carrier(&skill, tree_bytes)?;
    assert_eq!(
        skill_package_travels(vault, skill)?,
        Some(true),
        "FIXTURE: before the hold the skill travels with its package, read from its carrier"
    );

    hold_back(vault, carrier)?;

    assert_eq!(
        skill_package_travels(vault, skill)?,
        Some(false),
        "the export carries the skill's row but not a package read from a held carrier"
    );
    Ok(())
}

/// The lineages, as `(session, conversation)` ids hex, whose epoch floors a whole-vault export
/// of `vault` writes.
fn carried_floors(vault: &Vault) -> TestResult<BTreeSet<(String, Option<String>)>> {
    Ok(archive(vault)?
        .epoch_floors
        .into_iter()
        .map(|floor| (floor.session, floor.conversation))
        .collect())
}

#[test]
fn an_epoch_floor_of_a_held_conversation_stays_out() -> TestResult {
    let fixture = open()?;
    let vault = &fixture.vault;
    let session = EntityId::now();
    raise_epoch_floor(vault, session, Some(fixture.conversation), 2, 7)?;
    raise_epoch_floor(vault, session, None, 3, 9)?;
    let conversation_lineage = (session.to_hex(), Some(fixture.conversation.to_hex()));
    let session_lineage = (session.to_hex(), None);
    let before = carried_floors(vault)?;
    for (kind, lineage) in [
        ("conversation's", &conversation_lineage),
        ("session's own", &session_lineage),
    ] {
        assert!(
            before.contains(lineage),
            "FIXTURE: before the hold the export writes the {kind} floor"
        );
    }

    hold_back(vault, fixture.conversation)?;

    let after = carried_floors(vault)?;
    assert!(
        !after.contains(&conversation_lineage),
        "the export writes no epoch floor of a conversation it holds back"
    );
    assert!(
        after.contains(&session_lineage),
        "the export still writes the session's own floor, which it does not hold back"
    );
    Ok(())
}
