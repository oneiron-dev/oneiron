use super::*;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::config::{HnswConfig, TextAnalyzerConfig, VaultConfig};
use crate::registry::ENTITY_TYPE_PERSON;

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test-model-v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    config.text_analyzer = TextAnalyzerConfig::default();
    config
}

fn test_time(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// Mirrors `test_util::open_test_vault_with`'s fixture cleanup for tests
/// that open a vault directly (to reopen the same path).
fn clear_default_policy_manifest(vault: &Vault) {
    let id = crate::gate::default_policy_manifest_id().expect("default policy manifest id");
    vault
        .with_write_txn(|wtxn| {
            crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id)?;
            Ok(())
        })
        .expect("clear default policy manifest");
}

fn put_actor(vault: &Vault, at: u64) -> WriteActor {
    let actor_id = EntityId::now();
    vault
        .put_entity(&actor_id, ENTITY_TYPE_PERSON, test_time(at), at, b"human")
        .expect("put actor");
    WriteActor::new(actor_id, EdgeActorClass::Human)
}

fn put_agent_actor(vault: &Vault, at: u64) -> WriteActor {
    let actor_id = EntityId::now();
    vault
        .put_entity(&actor_id, ENTITY_TYPE_PERSON, test_time(at), at, b"agent")
        .expect("put agent actor");
    WriteActor::new(actor_id, EdgeActorClass::Agent)
}

fn put_workbook(vault: &Vault, actor: WriteActor, at: u64) -> EntityId {
    let artifact_id = EntityId::now();
    vault
        .put_blob_artifact(
            &artifact_id,
            &BlobArtifactBody::new(
                "forecast.xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ),
            test_time(at),
            at,
        )
        .expect("put workbook");
    vault
        .append_blob_artifact_version(
            &artifact_id,
            b"workbook bytes v1",
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(at),
            at,
        )
        .expect("append v1");
    artifact_id
}

fn xlsx_anchor(artifact_id: EntityId, version: u64, sheet: &str, range: &str) -> Anchor {
    Anchor::new(
        artifact_id,
        version,
        Locator::xlsx(sheet, range).expect("xlsx locator"),
    )
}

/// The ids of every LIVE (`life = active`) thread-head claim on the
/// artifact, regardless of approval — the ungated cohort, so tests can
/// prove the read gate reduces it and that no orphan head leaked.
fn live_thread_head_claim_ids(vault: &Vault, artifact_id: &EntityId) -> Vec<EntityId> {
    let mut ids = Vec::new();
    for claim_id in vault
        .claims_for_subject(artifact_id)
        .expect("claims for subject")
    {
        let Some(body) = vault.get_claim(&claim_id).expect("get claim") else {
            continue;
        };
        if body.predicate == ANNOTATION_THREAD_PREDICATE
            && body.lifecycle == crate::claim::ClaimLifecycleStatus::Active
        {
            ids.push(claim_id);
        }
    }
    ids
}

#[test]
fn a1_range_round_trips_and_normalizes() {
    assert_eq!(
        A1Range::parse("B2").map(|r| r.to_a1()).as_deref(),
        Some("B2")
    );
    assert_eq!(
        A1Range::parse("b2:d5").map(|r| r.to_a1()).as_deref(),
        Some("B2:D5")
    );
    // Reversed corners normalize.
    assert_eq!(
        A1Range::parse("D5:B2").map(|r| r.to_a1()).as_deref(),
        Some("B2:D5")
    );
    assert_eq!(A1Range::parse("AA1").map(|r| r.col_start), Some(27));
    assert_eq!(A1Range::parse(""), None);
    assert_eq!(A1Range::parse("2B"), None);
    assert_eq!(A1Range::parse("B0"), None);
}

#[test]
fn replay_moves_anchor_on_row_insert_and_delete() {
    let locator = Locator::xlsx("Sheet1", "B5:D8").expect("locator");
    // Insert 2 rows above row 3: the anchored block shifts down by 2.
    let inserted = replay_locator(
        &locator,
        &[ReanchorOp::InsertRows {
            sheet: "Sheet1".to_owned(),
            at_row: 3,
            count: 2,
        }],
    );
    assert_eq!(
        inserted,
        ReanchorOutcome::Mapped(Locator::xlsx("Sheet1", "B7:D10").expect("locator"))
    );
    // Delete 2 rows above the block: it shifts up by 2.
    let deleted = replay_locator(
        &locator,
        &[ReanchorOp::DeleteRows {
            sheet: "Sheet1".to_owned(),
            at_row: 1,
            count: 2,
        }],
    );
    assert_eq!(
        deleted,
        ReanchorOutcome::Mapped(Locator::xlsx("Sheet1", "B3:D6").expect("locator"))
    );
    // Edits on another sheet do not move the anchor.
    let other_sheet = replay_locator(
        &locator,
        &[ReanchorOp::DeleteRows {
            sheet: "Sheet2".to_owned(),
            at_row: 1,
            count: 4,
        }],
    );
    assert_eq!(other_sheet, ReanchorOutcome::Mapped(locator));
}

#[test]
fn replay_drifts_when_region_destroyed_or_ambiguous() {
    let locator = Locator::xlsx("Sheet1", "B5:C6").expect("locator");
    // Deleting every anchored row destroys the region.
    let destroyed = replay_locator(
        &locator,
        &[ReanchorOp::DeleteRows {
            sheet: "Sheet1".to_owned(),
            at_row: 5,
            count: 2,
        }],
    );
    assert_eq!(destroyed, ReanchorOutcome::Drifted);
    // A partial move overlap is ambiguous.
    let ambiguous = replay_locator(
        &locator,
        &[ReanchorOp::MoveRange {
            sheet: "Sheet1".to_owned(),
            from: A1Range::parse("C6:E9").expect("from"),
            to: A1Range::parse("H6:J9").expect("to"),
        }],
    );
    assert_eq!(ambiguous, ReanchorOutcome::Drifted);
    // Non-xlsx locators are non-mappable under the xlsx replay.
    let docx = Locator::docx("body/p[3]", 0, 12).expect("docx");
    assert_eq!(replay_locator(&docx, &[]), ReanchorOutcome::Drifted);
}

#[test]
fn replay_follows_sheet_rename_and_drifts_on_remove() {
    let locator = Locator::xlsx("Sheet1", "B2:C4").expect("locator");
    // A rename retargets the anchor's sheet name; the range is unchanged and
    // a later same-sheet op still matches under the NEW name.
    let renamed = replay_locator(
        &locator,
        &[
            ReanchorOp::RenameSheet {
                from: "Sheet1".to_owned(),
                to: "Q3".to_owned(),
            },
            ReanchorOp::InsertRows {
                sheet: "Q3".to_owned(),
                at_row: 1,
                count: 1,
            },
        ],
    );
    assert_eq!(
        renamed,
        ReanchorOutcome::Mapped(Locator::xlsx("Q3", "B3:C5").expect("locator"))
    );
    // Removing the anchor's sheet destroys the region.
    let removed = replay_locator(
        &locator,
        &[ReanchorOp::RemoveSheet {
            sheet: "Sheet1".to_owned(),
        }],
    );
    assert_eq!(removed, ReanchorOutcome::Drifted);
    // A rename/remove of a DIFFERENT sheet leaves the anchor untouched.
    let untouched = replay_locator(
        &locator,
        &[ReanchorOp::RemoveSheet {
            sheet: "Other".to_owned(),
        }],
    );
    assert_eq!(untouched, ReanchorOutcome::Mapped(locator));
}

#[test]
fn replay_drifts_anchor_overwritten_by_move_destination() {
    // Move A1:B2 to D1:E2. A thread anchored at D1 (in the destination, not
    // part of the moved source) had its content overwritten by the move, so
    // it must drift rather than keep pointing at replaced cells.
    let at_destination = Locator::xlsx("Sheet1", "D1").expect("locator");
    let overwritten = replay_locator(
        &at_destination,
        &[ReanchorOp::MoveRange {
            sheet: "Sheet1".to_owned(),
            from: A1Range::parse("A1:B2").expect("from"),
            to: A1Range::parse("D1:E2").expect("to"),
        }],
    );
    assert_eq!(overwritten, ReanchorOutcome::Drifted);

    // A thread disjoint from BOTH source and destination is untouched.
    let elsewhere = Locator::xlsx("Sheet1", "H8").expect("locator");
    let untouched = replay_locator(
        &elsewhere,
        &[ReanchorOp::MoveRange {
            sheet: "Sheet1".to_owned(),
            from: A1Range::parse("A1:B2").expect("from"),
            to: A1Range::parse("D1:E2").expect("to"),
        }],
    );
    assert_eq!(untouched, ReanchorOutcome::Mapped(elsewhere));
}

#[test]
fn anchor_effect_lowers_to_reanchor_op() {
    use crate::edit_roundtrip::{CellRef, RangeRef};

    // A row shift lowers to an insert/delete of matching magnitude.
    assert_eq!(
        ReanchorOp::from(&AnchorEffect::Shift(StructuralShift {
            sheet: "Sheet1".to_owned(),
            axis: Axis::Row,
            at: 3,
            delta: 2,
        })),
        ReanchorOp::InsertRows {
            sheet: "Sheet1".to_owned(),
            at_row: 3,
            count: 2,
        }
    );
    assert_eq!(
        ReanchorOp::from(&AnchorEffect::Shift(StructuralShift {
            sheet: "Sheet1".to_owned(),
            axis: Axis::Column,
            at: 4,
            delta: -1,
        })),
        ReanchorOp::DeleteCols {
            sheet: "Sheet1".to_owned(),
            at_col: 4,
            count: 1,
        }
    );
    // A range move lowers to the same-shape destination range.
    assert_eq!(
        ReanchorOp::from(&AnchorEffect::RangeMoved {
            sheet: "Sheet1".to_owned(),
            from: RangeRef::new(CellRef::new(1, 1), CellRef::new(2, 3)),
            to: CellRef::new(5, 10),
        }),
        ReanchorOp::MoveRange {
            sheet: "Sheet1".to_owned(),
            from: A1Range::new(1, 2, 1, 3).expect("from"),
            to: A1Range::new(5, 6, 10, 12).expect("to"),
        }
    );
    // Sheet-level effects lower to the sheet-level ops.
    assert_eq!(
        ReanchorOp::from(&AnchorEffect::SheetRenamed {
            from: "A".to_owned(),
            to: "B".to_owned(),
        }),
        ReanchorOp::RenameSheet {
            from: "A".to_owned(),
            to: "B".to_owned(),
        }
    );
    assert_eq!(
        ReanchorOp::from(&AnchorEffect::SheetRemoved {
            name: "Gone".to_owned(),
        }),
        ReanchorOp::RemoveSheet {
            sheet: "Gone".to_owned(),
        }
    );
}

// Acceptance test 1: a thread is engine memory, not viewer state — it
// survives the viewer (process) dying and reloads from disk.
#[test]
fn thread_survives_viewer_death() -> Result<()> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path();
    let (thread_id, artifact_id) = {
        let vault = Vault::open(path, test_config())?;
        clear_default_policy_manifest(&vault);
        let actor = put_actor(&vault, 10);
        let artifact_id = put_workbook(&vault, actor, 10);
        let thread = vault.open_annotation_thread(
            &xlsx_anchor(artifact_id, 1, "Sheet1", "B2:C4"),
            actor,
            "Please double-check this quarter's totals.",
            test_time(11),
            11,
        )?;
        vault.add_annotation_comment(
            &artifact_id,
            &thread.thread_id,
            actor,
            "Agreed, the Q3 column looks off.",
            test_time(12),
            12,
        )?;
        (thread.thread_id, artifact_id)
    };

    // The viewer is gone; reopen the vault from disk.
    let reopened = Vault::open(path, test_config())?;
    let thread = reopened
        .get_annotation_thread(&artifact_id, &thread_id)?
        .expect("thread persisted");
    assert_eq!(thread.state, ThreadState::Open);
    assert_eq!(thread.anchor.version, 1);
    assert_eq!(
        thread.anchor.locator,
        Locator::xlsx("Sheet1", "B2:C4").expect("locator")
    );
    let comments = reopened.annotation_thread_comments(&artifact_id, &thread_id)?;
    assert_eq!(comments.len(), 2);
    assert_eq!(
        comments[0].text,
        "Please double-check this quarter's totals."
    );
    assert_eq!(comments[1].text, "Agreed, the Q3 column looks off.");
    Ok(())
}

// Acceptance test 2: a manifest replay across a version bump moves an
// anchor to its new position.
#[test]
fn reanchor_moves_anchor_across_version_bump() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let actor = put_actor(&vault, 10);
    let artifact_id = put_workbook(&vault, actor, 10);
    let thread = vault.open_annotation_thread(
        &xlsx_anchor(artifact_id, 1, "Sheet1", "B5:D8"),
        actor,
        "Anchor me at B5:D8.",
        test_time(11),
        11,
    )?;
    // Bump to v2, inserting two rows above row 1 (the block slides down).
    vault.append_blob_artifact_version(
        &artifact_id,
        b"workbook bytes v2",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(12),
        12,
    )?;
    let summary = vault.reanchor_annotation_threads(
        &artifact_id,
        1,
        2,
        &[ReanchorOp::InsertRows {
            sheet: "Sheet1".to_owned(),
            at_row: 1,
            count: 2,
        }],
        actor,
        test_time(12),
        12,
    )?;
    assert_eq!(summary.remapped.len(), 1);
    assert!(summary.drifted.is_empty());

    let moved = vault
        .get_annotation_thread(&artifact_id, &thread.thread_id)?
        .expect("thread");
    assert!(!moved.is_drifted());
    assert_eq!(moved.anchor.version, 2);
    assert_eq!(
        moved.anchor.locator,
        Locator::xlsx("Sheet1", "B7:D10").expect("locator")
    );
    // The reader collapses to a single live head after the supersede.
    assert_eq!(
        vault.annotation_threads_for_artifact(&artifact_id)?.len(),
        1
    );
    Ok(())
}

// Acceptance test 3: a non-mappable anchor becomes DRIFTED, pinned to its
// original version — never silently repositioned.
#[test]
fn nonmappable_anchor_is_marked_drifted() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let actor = put_actor(&vault, 10);
    let artifact_id = put_workbook(&vault, actor, 10);
    let thread = vault.open_annotation_thread(
        &xlsx_anchor(artifact_id, 1, "Sheet1", "B5:C6"),
        actor,
        "This region gets deleted.",
        test_time(11),
        11,
    )?;
    vault.append_blob_artifact_version(
        &artifact_id,
        b"workbook bytes v2",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(12),
        12,
    )?;
    // Delete exactly the anchored rows: the region is destroyed.
    let summary = vault.reanchor_annotation_threads(
        &artifact_id,
        1,
        2,
        &[ReanchorOp::DeleteRows {
            sheet: "Sheet1".to_owned(),
            at_row: 5,
            count: 2,
        }],
        actor,
        test_time(12),
        12,
    )?;
    assert!(summary.remapped.is_empty());
    assert_eq!(summary.drifted.len(), 1);

    let drifted = vault
        .get_annotation_thread(&artifact_id, &thread.thread_id)?
        .expect("thread");
    assert!(drifted.is_drifted());
    // Pinned to the ORIGINAL version with the ORIGINAL locator — no lie.
    assert_eq!(drifted.anchor.version, 1);
    assert_eq!(
        drifted.anchor.locator,
        Locator::xlsx("Sheet1", "B5:C6").expect("locator")
    );
    let marker = drifted.drift.expect("drift marker");
    assert_eq!(marker.pinned_version, 1);
    assert_eq!(marker.drifted_at_version, 2);
    Ok(())
}

// Acceptance test 4: an assigned thread yields a task-brief carrying the
// anchor payload + thread text + artifact@version.
#[test]
fn assigned_thread_yields_task_brief() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let actor = put_actor(&vault, 10);
    let artifact_id = put_workbook(&vault, actor, 10);
    let thread = vault.open_annotation_thread(
        &xlsx_anchor(artifact_id, 1, "Sheet1", "B2:C4"),
        actor,
        "Please recompute the totals column.",
        test_time(11),
        11,
    )?;
    vault.add_annotation_comment(
        &artifact_id,
        &thread.thread_id,
        actor,
        "Use the new tax rate.",
        test_time(12),
        12,
    )?;
    let agent_id = EntityId::now();
    vault.put_entity(&agent_id, ENTITY_TYPE_PERSON, test_time(10), 10, b"agent")?;

    let brief = vault.assign_annotation_thread_to_brief(
        &artifact_id,
        &thread.thread_id,
        Some(agent_id),
        actor,
        test_time(13),
        13,
    )?;

    assert_eq!(brief.thread_id, thread.thread_id);
    assert_eq!(brief.assignee, Some(agent_id));
    // Anchor payload.
    assert_eq!(brief.anchor.artifact_id, artifact_id);
    assert_eq!(brief.anchor.version, 1);
    assert_eq!(
        brief.anchor.locator,
        Locator::xlsx("Sheet1", "B2:C4").expect("locator")
    );
    // artifact@version.
    assert_eq!(brief.artifact_version, 1);
    // Thread text (both comments, in order).
    assert_eq!(
        brief.thread_text,
        "Please recompute the totals column.\nUse the new tax rate."
    );
    assert!(brief.brief_ref.starts_with("brief:"));
    // The TASK entity is a real productivity task.
    assert_eq!(
        vault.get_entity_type(&brief.task_id)?,
        Some(ENTITY_TYPE_TASK)
    );
    Ok(())
}

#[test]
fn resolve_supersedes_thread_head() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let actor = put_actor(&vault, 10);
    let artifact_id = put_workbook(&vault, actor, 10);
    let thread = vault.open_annotation_thread(
        &xlsx_anchor(artifact_id, 1, "Sheet1", "A1"),
        actor,
        "Resolve me.",
        test_time(11),
        11,
    )?;
    let resolved = vault.set_annotation_thread_state(
        &artifact_id,
        &thread.thread_id,
        ThreadState::Resolved,
        actor,
        test_time(12),
        12,
    )?;
    assert_eq!(resolved.state, ThreadState::Resolved);
    assert_ne!(resolved.head_claim_id, thread.head_claim_id);
    // Exactly one live head remains after the supersede.
    let live = vault.annotation_threads_for_artifact(&artifact_id)?;
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].state, ThreadState::Resolved);
    Ok(())
}

#[test]
fn open_thread_rejects_bad_anchor_version() {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let actor = put_actor(&vault, 10);
    let artifact_id = put_workbook(&vault, actor, 10);
    // Version 2 does not exist yet (head is v1).
    let err = vault
        .open_annotation_thread(
            &xlsx_anchor(artifact_id, 2, "Sheet1", "A1"),
            actor,
            "no such version",
            test_time(11),
            11,
        )
        .expect_err("anchor beyond head must fail");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAnchor);
}

// PR #397 fix 1: the live-read gate ([`claim_surfaceable`]) hides an
// agent-authored (Proposed) head, so it can never override an admitted
// human head via newest-UUID-wins selection.
#[test]
fn agent_proposed_head_does_not_override_human_head() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let human = put_actor(&vault, 10);
    let agent = put_agent_actor(&vault, 10);
    let artifact_id = put_workbook(&vault, human, 10);
    let thread = vault.open_annotation_thread(
        &xlsx_anchor(artifact_id, 1, "Sheet1", "B2:C4"),
        human,
        "Human-opened, stays Open.",
        test_time(11),
        11,
    )?;

    // An agent writes a SECOND live head for the same thread, flipping the
    // state to Resolved. It lands `Active` but only `Proposed`.
    let agent_head = ThreadHead {
        thread_id: thread.thread_id,
        origin_version: thread.origin_version,
        anchor_version: thread.anchor.version,
        state: ThreadState::Resolved,
        locator: thread.anchor.locator.clone(),
        drift: thread.drift,
    };
    let agent_head_id = vault.with_write_txn(|wtxn| {
        vault.write_thread_head_in_txn(
            wtxn,
            &artifact_id,
            &agent_head,
            agent,
            "set_state",
            test_time(12),
            12,
        )
    })?;
    // The agent head really is a live-but-unadmitted second head.
    let agent_body = vault.get_claim(&agent_head_id)?.expect("agent head claim");
    assert_eq!(
        agent_body.lifecycle,
        crate::claim::ClaimLifecycleStatus::Active
    );
    assert_eq!(agent_body.approval, ClaimApprovalStatus::Proposed);
    // Both heads are live (ungated); the gate must pick only the human one.
    assert_eq!(live_thread_head_claim_ids(&vault, &artifact_id).len(), 2);

    let read = vault
        .get_annotation_thread(&artifact_id, &thread.thread_id)?
        .expect("thread");
    assert_eq!(read.state, ThreadState::Open);
    assert_eq!(read.head_claim_id, thread.head_claim_id);
    let listed = vault.annotation_threads_for_artifact(&artifact_id)?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].state, ThreadState::Open);
    assert_eq!(listed[0].head_claim_id, thread.head_claim_id);
    Ok(())
}

// PR #397 fix 2: the new-head write and the old-head supersession share one
// txn, so a supersession the source-trust guard rejects (an agent claim
// superseding human-stated truth) persists NOTHING — the original head
// stays the single live head and no orphan claim is left behind.
#[test]
fn agent_supersede_rejected_leaves_original_head_live() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let human = put_actor(&vault, 10);
    let agent = put_agent_actor(&vault, 10);
    let artifact_id = put_workbook(&vault, human, 10);
    let thread = vault.open_annotation_thread(
        &xlsx_anchor(artifact_id, 1, "Sheet1", "A1"),
        human,
        "Human truth.",
        test_time(11),
        11,
    )?;

    // An agent resolving the human-opened thread supersedes human-stated
    // truth: the guard rejects and the whole txn rolls back.
    let err = vault
        .set_annotation_thread_state(
            &artifact_id,
            &thread.thread_id,
            ThreadState::Resolved,
            agent,
            test_time(12),
            12,
        )
        .expect_err("agent cannot supersede human-stated head");
    assert!(matches!(err, Error::InvalidClaimBody(_)));

    // Original head still live and single; the rejected head left no orphan.
    assert_eq!(
        live_thread_head_claim_ids(&vault, &artifact_id),
        vec![thread.head_claim_id]
    );
    let read = vault
        .get_annotation_thread(&artifact_id, &thread.thread_id)?
        .expect("thread");
    assert_eq!(read.state, ThreadState::Open);
    assert_eq!(read.head_claim_id, thread.head_claim_id);
    Ok(())
}

// PR #397 fix 3: reanchor axis math is checked — an anchor near u32::MAX
// that an insert (or delete band) would push past the grid drifts rather
// than wrapping (release) or panicking (debug) into a corrupt locator.
#[test]
fn reanchor_math_drifts_near_u32_max_instead_of_wrapping() {
    let near_max = format!("B{}:B{}", u32::MAX - 5, u32::MAX);
    let locator = Locator::xlsx("Sheet1", &near_max).expect("locator");
    // Inserting rows below the anchor would shift it past u32::MAX.
    let insert_overflow = replay_locator(
        &locator,
        &[ReanchorOp::InsertRows {
            sheet: "Sheet1".to_owned(),
            at_row: 1,
            count: 10,
        }],
    );
    assert_eq!(insert_overflow, ReanchorOutcome::Drifted);
    // A delete band whose `at + count - 1` overflows is also non-mappable.
    let delete_overflow = replay_locator(
        &locator,
        &[ReanchorOp::DeleteRows {
            sheet: "Sheet1".to_owned(),
            at_row: u32::MAX,
            count: 10,
        }],
    );
    assert_eq!(delete_overflow, ReanchorOutcome::Drifted);
}

// PR #397 fix 4: reanchor validates `to_version` against the artifact's
// version chain (the same guard thread-open applies) before writing any
// head, so a replay against a not-yet-appended version writes nothing.
#[test]
fn reanchor_to_nonexistent_version_errors_and_writes_no_head() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let actor = put_actor(&vault, 10);
    let artifact_id = put_workbook(&vault, actor, 10);
    let thread = vault.open_annotation_thread(
        &xlsx_anchor(artifact_id, 1, "Sheet1", "B5:D8"),
        actor,
        "Anchor me.",
        test_time(11),
        11,
    )?;

    // v2 was never appended (head is still v1): reanchoring 1 -> 2 must fail.
    let err = vault
        .reanchor_annotation_threads(
            &artifact_id,
            1,
            2,
            &[ReanchorOp::InsertRows {
                sheet: "Sheet1".to_owned(),
                at_row: 1,
                count: 2,
            }],
            actor,
            test_time(12),
            12,
        )
        .expect_err("reanchor to nonexistent version must fail");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAnchor);

    // No replacement head was written; the original head is untouched.
    assert_eq!(
        live_thread_head_claim_ids(&vault, &artifact_id),
        vec![thread.head_claim_id]
    );
    let unchanged = vault
        .get_annotation_thread(&artifact_id, &thread.thread_id)?
        .expect("thread");
    assert_eq!(unchanged.anchor.version, 1);
    assert_eq!(unchanged.head_claim_id, thread.head_claim_id);
    assert!(!unchanged.is_drifted());
    Ok(())
}

// PR #397 fix 5: one malformed annotation.thread claim (writable through
// the generic claim API) is skipped on read instead of taking down the
// whole listing.
#[test]
fn malformed_thread_claim_is_skipped_on_listing() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let actor = put_actor(&vault, 10);
    let artifact_id = put_workbook(&vault, actor, 10);
    let thread = vault.open_annotation_thread(
        &xlsx_anchor(artifact_id, 1, "Sheet1", "B2:C4"),
        actor,
        "A well-formed thread.",
        test_time(11),
        11,
    )?;

    // A garbage annotation.thread claim whose value is not a decodable head.
    let garbage_id = EntityId::now();
    let envelope = annotation_envelope(actor, "open_thread")?;
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .claim_candidate(
                &garbage_id,
                ClaimCandidate::new(
                    ANNOTATION_THREAD_PREDICATE,
                    ClaimSubject::Entity(artifact_id),
                    Value::from("not a thread head"),
                    1.0,
                ),
                &envelope,
                test_time(12),
                12,
            )
            .apply(wtxn)
    })?;
    // The garbage really is a live annotation.thread claim on the artifact.
    assert_eq!(live_thread_head_claim_ids(&vault, &artifact_id).len(), 2);

    // The listing skips the garbage and still serves the valid thread.
    let threads = vault.annotation_threads_for_artifact(&artifact_id)?;
    assert_eq!(threads.len(), 1);
    assert_eq!(threads[0].thread_id, thread.thread_id);
    assert!(
        vault
            .get_annotation_thread(&artifact_id, &thread.thread_id)?
            .is_some()
    );
    Ok(())
}

// PR #397 fix 6: the transcript snapshot is persisted in the brief claim,
// so a comment appended after assignment does not rewrite the handed-off
// transcript that `annotation_brief_for_thread` reconstructs.
#[test]
fn persisted_brief_transcript_is_stable_after_later_comment() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let actor = put_actor(&vault, 10);
    let artifact_id = put_workbook(&vault, actor, 10);
    let thread = vault.open_annotation_thread(
        &xlsx_anchor(artifact_id, 1, "Sheet1", "B2:C4"),
        actor,
        "First note.",
        test_time(11),
        11,
    )?;

    let brief = vault.assign_annotation_thread_to_brief(
        &artifact_id,
        &thread.thread_id,
        None,
        actor,
        test_time(12),
        12,
    )?;
    assert_eq!(brief.thread_text, "First note.");

    // A comment added AFTER assignment must not change the durable brief.
    vault.add_annotation_comment(
        &artifact_id,
        &thread.thread_id,
        actor,
        "Later addendum.",
        test_time(13),
        13,
    )?;
    let persisted = vault
        .annotation_brief_for_thread(&artifact_id, &thread.thread_id)?
        .expect("persisted brief");
    assert_eq!(persisted.thread_text, "First note.");
    assert_eq!(persisted.brief_ref, brief.brief_ref);
    assert_eq!(persisted.task_id, brief.task_id);
    assert_eq!(persisted.anchor.version, 1);
    assert_eq!(persisted.anchor.locator, thread.anchor.locator);
    // The live thread does carry the new comment; only the snapshot froze.
    assert_eq!(
        vault
            .annotation_thread_comments(&artifact_id, &thread.thread_id)?
            .len(),
        2
    );
    Ok(())
}
