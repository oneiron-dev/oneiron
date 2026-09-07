//! Acceptance tests for CMT-4 (ONE-1541): explicit fulfillment dispatch, the
//! validated brief-fulfillment link, the gap-decay lapse sweep, the close-hook
//! repair arms, and the projected lifecycle receipts.
//!
//! Every instant is a literal. A lifecycle time that came from the host clock
//! would make the whole `t1`-not-`t2` law untestable.

use rmpv::Value;

use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::commitment::{
    CommitmentBirthKind, CommitmentBirthProvenance, CommitmentContent, CommitmentObligor,
    CommitmentObligorKind, CommitmentRecord, CommitmentStrength,
};
use crate::commitment_schedule::{
    CommitmentDueEntry, CommitmentSchedulePayload, Schedule, ScheduleResult,
    commitment_projection_actor,
};
use crate::config::{HnswConfig, VaultConfig};
use crate::edge::EdgeActorClass;
use crate::habit::{TaskRole, task_body_for_test};
use crate::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use crate::registry::{
    ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION, ENTITY_TYPE_TASK,
    ENTITY_TYPE_TURN,
};
use crate::write_envelope::{WriteActor, WriteProvenance};

const DAY: u64 = 86_400;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn temp_vault() -> Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    let vault = Vault::open(dir.path(), config)?;
    Ok((dir, vault))
}

const fn time(start: u64, end: u64) -> TimeRange {
    TimeRange { start, end }
}

/// The two human parties plus the projector's pinned System actor.
///
/// The last one is load-bearing: the claim-candidate door resolves
/// `envelope.actor()` against a stored entity and validates its class, so a
/// vault that expects the projector to mint anything must carry the derived
/// actor as a MACHINE entity.
struct Parties {
    obligor: EntityId,
    beneficiary: EntityId,
    envelope: WriteEnvelope,
}

fn parties(vault: &Vault) -> Result<Parties> {
    let obligor = crate::test_util::entity(0x71);
    let beneficiary = crate::test_util::entity(0x72);
    for id in [obligor, beneficiary] {
        vault.put_entity(&id, ENTITY_TYPE_PERSON, time(1, 1), 1, b"person")?;
    }
    vault.put_entity(
        &commitment_projection_actor().entity_ref(),
        ENTITY_TYPE_MACHINE,
        time(1, 1),
        1,
        b"commitment projector",
    )?;
    Ok(Parties {
        obligor,
        beneficiary,
        envelope: WriteEnvelope::new(
            WriteActor::new(obligor, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::from("cmt-4 lifecycle test write"))?,
            ClaimApprovalStatus::Auto,
        ),
    })
}

impl Parties {
    /// A CMT-1 commitment whose schedule is an OPAQUE non-CMT-2 blob: the
    /// plain, unscheduled shape.
    fn plain_record(&self) -> Result<CommitmentRecord> {
        self.record(Value::Map(vec![
            (Value::from("kind"), Value::from("once")),
            (Value::from("due"), Value::from(10_000_u64)),
        ]))
    }

    fn record(&self, schedule: Value) -> Result<CommitmentRecord> {
        CommitmentRecord::new(
            CommitmentObligor::new(CommitmentObligorKind::Owner, self.obligor),
            self.beneficiary,
            CommitmentContent::new("send the signed document", None)?,
            schedule,
            CommitmentStrength::Commitment,
            CommitmentStatus::Open,
            CommitmentBirthProvenance::new(CommitmentBirthKind::Brief, "brief:doc-1")?,
        )
    }

    /// Writes a plain open commitment and returns its id.
    fn put_plain(&self, vault: &Vault, id: &EntityId, learned_at: u64) -> Result<()> {
        vault.put_commitment_claim(
            id,
            &self.plain_record()?,
            &self.envelope,
            time(100, 200),
            learned_at,
        )
    }

    /// Indexes a weekly interval series and mints its first instance.
    ///
    /// Returns `(series_ref, instance_ref)`. The instance's `LifecycleDue` row
    /// sits exactly at `due_at`, which is what makes the strict `< now`
    /// boundary observable.
    fn put_interval_instance(
        &self,
        vault: &Vault,
        series: &EntityId,
        anchor: u64,
    ) -> ScheduleResult<EntityId> {
        let payload = CommitmentSchedulePayload::series(
            Schedule::Interval {
                period: 7 * DAY,
                anchor,
            },
            Some(DAY),
        )
        .encode()?;
        let record = self.record(payload)?;
        vault.put_commitment_series(
            series,
            &record,
            &self.envelope,
            time(10, anchor.saturating_add(400 * DAY)),
            10,
        )?;
        let report = vault.reconcile_commitment_schedule(anchor.saturating_sub(DAY))?;
        Ok(report.minted_instances[0])
    }
}

/// A stored task brief, minted through the ordinary TASK door.
fn put_brief(vault: &Vault, id: &EntityId, at: u64) -> Result<()> {
    vault.put_entity(
        id,
        ENTITY_TYPE_TASK,
        time(at, at),
        at,
        &task_body_for_test(TaskRole::Task),
    )
}

fn status(vault: &Vault, id: &EntityId) -> Result<CommitmentStatus> {
    Ok(vault
        .get_commitment_claim(id)?
        .expect("commitment claim exists")
        .status)
}

fn lifecycle_receipts(vault: &Vault) -> Result<Vec<ReceiptRecord>> {
    vault.receipts(ReceiptQuery::new(200).with_kind(ReceiptKind::CommitmentLifecycle))
}

fn receipts_for(vault: &Vault, id: &EntityId) -> Result<Vec<ReceiptRecord>> {
    let trigger = format!("commitment:{}", id.to_hex());
    Ok(lifecycle_receipts(vault)?
        .into_iter()
        .filter(|receipt| receipt.trigger_ref.as_deref() == Some(trigger.as_str()))
        .collect())
}

fn gate_receipts_for(vault: &Vault, id: &EntityId) -> Result<usize> {
    let trigger = format!("claim:{}", id.to_hex());
    Ok(vault
        .receipts(ReceiptQuery::new(1_000).with_kind(ReceiptKind::Gate))?
        .into_iter()
        .filter(|receipt| receipt.trigger_ref.as_deref() == Some(trigger.as_str()))
        .count())
}

fn due_rows(vault: &Vault) -> Result<Vec<CommitmentDueEntry>> {
    vault.commitment_entries_through(u64::MAX)
}

fn instance_rows(vault: &Vault, instance: &EntityId) -> Result<Vec<CommitmentDueEntry>> {
    Ok(due_rows(vault)?
        .into_iter()
        .filter(|entry| entry.instance_ref == Some(*instance))
        .collect())
}

/// Every instance the due index knows about other than `exclude`.
fn other_instances(vault: &Vault, exclude: &EntityId) -> Result<Vec<EntityId>> {
    let mut ids: Vec<EntityId> = due_rows(vault)?
        .into_iter()
        .filter_map(|entry| entry.instance_ref)
        .filter(|id| id != exclude)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

// ---------------------------------------------------------------------------
// Explicit dispatch
// ---------------------------------------------------------------------------

#[test]
fn user_done_uses_cmt1_verb_and_projects_fulfilled_receipt() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let id = crate::test_util::entity(0x21);
    parties.put_plain(&vault, &id, 300)?;

    let result = fulfill_commitment_from(
        &vault,
        &id,
        FulfillmentSource::UserDone,
        &parties.envelope,
        301,
    )?;
    assert_eq!(
        result,
        CommitmentCloseResult {
            commitment_ref: id,
            status: CommitmentStatus::Fulfilled,
        }
    );
    assert_eq!(status(&vault, &id)?, CommitmentStatus::Fulfilled);

    let receipts = receipts_for(&vault, &id)?;
    assert_eq!(receipts.len(), 1, "exactly one lifecycle receipt");
    let receipt = &receipts[0];
    assert_eq!(receipt.receipt_kind, ReceiptKind::CommitmentLifecycle);
    assert_eq!(receipt.outcome, "fulfilled");
    assert_eq!(receipt.policy_trace, vec!["commitment.lifecycle.fulfilled"]);
    assert_eq!(
        receipt.trigger_ref.as_deref(),
        Some(format!("commitment:{}", id.to_hex()).as_str())
    );
    assert_eq!(
        receipt.receipt_id,
        format!("commitment:{}:fulfilled", id.to_hex())
    );
    assert_eq!(receipt.occurred_at, 301);
    // The status writer is not the moral author; the same-transaction Gate
    // decision is the audit record.
    assert_eq!(receipt.actor, None);
    assert_eq!(
        receipt.fields.get("commitment_status").map(String::as_str),
        Some("fulfilled")
    );
    assert_eq!(
        receipt.fields.get("obligor_ref").map(String::as_str),
        Some(parties.obligor.to_hex().as_str())
    );
    assert_eq!(
        receipt.fields.get("beneficiary_ref").map(String::as_str),
        Some(parties.beneficiary.to_hex().as_str())
    );
    assert_eq!(
        receipt.fields.get("strength").map(String::as_str),
        Some("commitment")
    );
    Ok(())
}

#[test]
fn checklist_tick_hook_is_typed_and_unwired() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let id = crate::test_util::entity(0x22);
    parties.put_plain(&vault, &id, 300)?;

    // The ONLY claim: the dispatcher accepts the typed source. There is no
    // checklist producer anywhere in the engine to drive it.
    assert_eq!(FulfillmentSource::ChecklistTick.as_str(), "checklist_tick");
    let result = fulfill_commitment_from(
        &vault,
        &id,
        FulfillmentSource::ChecklistTick,
        &parties.envelope,
        302,
    )?;
    assert_eq!(result.status, CommitmentStatus::Fulfilled);
    Ok(())
}

#[test]
fn plain_commitment_close_has_no_schedule_side_effect() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let user_done = crate::test_util::entity(0x23);
    let via_brief = crate::test_util::entity(0x24);
    let brief = crate::test_util::entity(0x25);
    parties.put_plain(&vault, &user_done, 300)?;
    parties.put_plain(&vault, &via_brief, 300)?;
    put_brief(&vault, &brief, 300)?;
    link_brief_fulfillment(&vault, &brief, &via_brief, 300)?;

    fulfill_commitment_from(
        &vault,
        &user_done,
        FulfillmentSource::UserDone,
        &parties.envelope,
        310,
    )?;
    fulfill_commitment_from(
        &vault,
        &via_brief,
        FulfillmentSource::BriefCompletion { brief_ref: brief },
        &parties.envelope,
        311,
    )?;

    assert_eq!(status(&vault, &user_done)?, CommitmentStatus::Fulfilled);
    assert_eq!(status(&vault, &via_brief)?, CommitmentStatus::Fulfilled);
    // The close hook answered `Ok(vec![])`: no due row was ever written for an
    // unscheduled commitment, and none appeared.
    assert!(due_rows(&vault)?.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// The validated brief-fulfillment door
// ---------------------------------------------------------------------------

#[test]
fn brief_link_rejects_non_task_source() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let commitment = crate::test_util::entity(0x26);
    let missing = crate::test_util::entity(0x27);
    let person = parties.obligor;
    parties.put_plain(&vault, &commitment, 300)?;

    for source in [missing, person] {
        assert!(matches!(
            link_brief_fulfillment(&vault, &source, &commitment, 300),
            Err(Error::InvalidClaimBody(
                "fulfillment source is not a task brief"
            ))
        ));
        // Refused BEFORE either edge is written.
        assert!(!vault.edge_exists(&source, EdgeKind::Fulfills, &commitment)?);
        assert!(!vault.edge_exists(&commitment, EdgeKind::DischargedBy, &source)?);
    }
    Ok(())
}

#[test]
fn brief_link_writes_both_ruled_directions_atomically() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let brief = crate::test_util::entity(0x28);
    let open = crate::test_util::entity(0x29);
    let closed = crate::test_util::entity(0x2A);
    put_brief(&vault, &brief, 300)?;
    parties.put_plain(&vault, &open, 300)?;
    parties.put_plain(&vault, &closed, 300)?;
    vault.release_commitment(&closed, &parties.envelope, 301)?;

    // A fault before commit: the target is no longer open. NEITHER row exists.
    assert!(matches!(
        link_brief_fulfillment(&vault, &brief, &closed, 302),
        Err(Error::InvalidClaimBody(
            "brief fulfillment link requires an open commitment"
        ))
    ));
    assert!(!vault.edge_exists(&brief, EdgeKind::Fulfills, &closed)?);
    assert!(!vault.edge_exists(&closed, EdgeKind::DischargedBy, &brief)?);

    // A missing target refuses the same way.
    let absent = crate::test_util::entity(0x2B);
    assert!(matches!(
        link_brief_fulfillment(&vault, &brief, &absent, 302),
        Err(Error::EntityNotFound)
    ));
    assert!(!vault.edge_exists(&brief, EdgeKind::Fulfills, &absent)?);

    // The happy path writes BOTH ruled directions.
    link_brief_fulfillment(&vault, &brief, &open, 303)?;
    assert!(vault.edge_exists(&brief, EdgeKind::Fulfills, &open)?);
    assert!(vault.edge_exists(&open, EdgeKind::DischargedBy, &brief)?);
    // The inverse is an inverse TRAVERSAL, not a second forward claim.
    assert!(!vault.edge_exists(&open, EdgeKind::Fulfills, &brief)?);
    Ok(())
}

#[test]
fn reserved_fulfills_cannot_be_forged_publicly() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let brief = crate::test_util::entity(0x2C);
    let commitment = crate::test_util::entity(0x2D);
    put_brief(&vault, &brief, 300)?;
    parties.put_plain(&vault, &commitment, 300)?;

    for (src, kind, tgt, reason) in [
        (brief, EdgeKind::Fulfills, commitment, "fulfills"),
        (commitment, EdgeKind::DischargedBy, brief, "discharged_by"),
    ] {
        assert!(matches!(
            vault.batch().edge(&src, kind, &tgt, 1.0).commit(),
            Err(Error::ReservedEdgeKind(got)) if got == reason
        ));
        assert!(matches!(
            vault
                .batch()
                .edge_with_created_at(&src, kind, &tgt, 1.0, 300)
                .commit(),
            Err(Error::ReservedEdgeKind(got)) if got == reason
        ));
        assert!(matches!(
            vault.batch().delete_edge(&src, kind, &tgt).commit(),
            Err(Error::ReservedEdgeKind(got)) if got == reason
        ));
        assert!(!vault.edge_exists(&src, kind, &tgt)?);
    }

    // Only the validated door writes the pair.
    link_brief_fulfillment(&vault, &brief, &commitment, 300)?;
    assert!(vault.edge_exists(&brief, EdgeKind::Fulfills, &commitment)?);

    // A stored `Fulfills` edge onto a non-commitment CLAIM is stored-index
    // corruption, not caller input: the validated door checked the class at
    // write time, so the traversal refuses rather than blaming the caller.
    let stranger = crate::test_util::entity(0x2E);
    let stranger_body = crate::claim::ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(parties.obligor),
        Value::from("not a commitment"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&stranger, &stranger_body, time(10, 20), 300)?;
    vault
        .batch()
        .edge_with_value_fields(
            &brief,
            EdgeKind::Fulfills,
            &stranger,
            crate::batch::EdgeValueFields {
                weight: 1.0,
                created_at: 300,
                vad: crate::affect::Vad::NEUTRAL,
                provenance: None,
            },
        )
        .commit()?;
    assert!(matches!(
        fulfill_commitments_for_brief(&vault, &brief, &parties.envelope, 310),
        Err(Error::CorruptedIndex("brief fulfills non-commitment claim"))
    ));
    Ok(())
}

#[test]
fn brief_completion_rejects_missing_fulfills_edge() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let brief = crate::test_util::entity(0x2F);
    let unrelated = crate::test_util::entity(0x30);
    put_brief(&vault, &brief, 300)?;
    parties.put_plain(&vault, &unrelated, 300)?;

    assert!(matches!(
        fulfill_commitment_from(
            &vault,
            &unrelated,
            FulfillmentSource::BriefCompletion { brief_ref: brief },
            &parties.envelope,
            310,
        ),
        Err(Error::InvalidClaimBody("brief does not fulfill commitment"))
    ));
    assert_eq!(status(&vault, &unrelated)?, CommitmentStatus::Open);
    assert!(receipts_for(&vault, &unrelated)?.is_empty());
    Ok(())
}

#[test]
fn brief_completion_discharges_linked_commitment() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let brief = crate::test_util::entity(0x31);
    let linked = crate::test_util::entity(0x32);
    let unrelated = crate::test_util::entity(0x33);
    put_brief(&vault, &brief, 300)?;
    parties.put_plain(&vault, &linked, 300)?;
    parties.put_plain(&vault, &unrelated, 300)?;
    link_brief_fulfillment(&vault, &brief, &linked, 300)?;

    let report = fulfill_commitments_for_brief(&vault, &brief, &parties.envelope, 310)?;
    assert_eq!(
        report,
        BriefFulfillmentReport {
            brief_ref: brief,
            fulfilled: vec![linked],
            repaired: Vec::new(),
            already_closed: Vec::new(),
        }
    );
    assert_eq!(status(&vault, &linked)?, CommitmentStatus::Fulfilled);
    assert_eq!(status(&vault, &unrelated)?, CommitmentStatus::Open);
    assert!(receipts_for(&vault, &unrelated)?.is_empty());
    Ok(())
}

#[test]
fn brief_completion_receipt_is_queryable() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let brief = crate::test_util::entity(0x34);
    let linked = crate::test_util::entity(0x35);
    put_brief(&vault, &brief, 300)?;
    parties.put_plain(&vault, &linked, 300)?;
    link_brief_fulfillment(&vault, &brief, &linked, 300)?;
    fulfill_commitments_for_brief(&vault, &brief, &parties.envelope, 320)?;

    // Durable through the status-claim projection, not a return-only object:
    // the receipt is found by an independent query on a fresh read.
    let receipts = vault.receipts(
        ReceiptQuery::new(50)
            .with_kind(ReceiptKind::CommitmentLifecycle)
            .with_outcome("fulfilled"),
    )?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].trigger_ref.as_deref(),
        Some(format!("commitment:{}", linked.to_hex()).as_str())
    );
    assert_eq!(receipts[0].occurred_at, 320);
    Ok(())
}

#[test]
fn fulfilled_index_row_repairs_close_hook_idempotently() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let series = crate::test_util::entity(0x36);
    let brief = crate::test_util::entity(0x37);
    let instance = parties.put_interval_instance(&vault, &series, 1_000_000)?;
    put_brief(&vault, &brief, 300)?;
    link_brief_fulfillment(&vault, &brief, &instance, 300)?;

    // Simulate a post-status crash: the raw CMT-1 verb landed at t1, the close
    // hook never ran, so the due rows are still there.
    vault.fulfill_commitment(&instance, &parties.envelope, 1_000_050)?;
    assert!(!instance_rows(&vault, &instance)?.is_empty());
    let receipts_before = receipts_for(&vault, &instance)?;
    assert_eq!(receipts_before.len(), 1);
    let gate_before = gate_receipts_for(&vault, &instance)?;

    // Retrying the SAME source repairs only the hook.
    let report = fulfill_commitments_for_brief(&vault, &brief, &parties.envelope, 1_000_900)?;
    assert_eq!(
        report.repaired,
        vec![instance],
        "repaired, not already_closed"
    );
    assert!(report.fulfilled.is_empty());
    assert!(report.already_closed.is_empty());

    // No second status write, no second receipt, and the receipt still carries
    // the committed t1 rather than the retry time.
    assert_eq!(status(&vault, &instance)?, CommitmentStatus::Fulfilled);
    assert_eq!(receipts_for(&vault, &instance)?, receipts_before);
    assert_eq!(receipts_before[0].occurred_at, 1_000_050);
    assert_eq!(gate_receipts_for(&vault, &instance)?, gate_before);

    // The hook removed the stale rows and minted at most one successor.
    assert!(instance_rows(&vault, &instance)?.is_empty());
    assert_eq!(other_instances(&vault, &instance)?.len(), 1);
    assert_eq!(status(&vault, &series)?, CommitmentStatus::Open);
    Ok(())
}

// ---------------------------------------------------------------------------
// The gap-decay lapse sweep
// ---------------------------------------------------------------------------

#[test]
fn overdue_instance_lapses_with_let_go_receipt_and_successor() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let series = crate::test_util::entity(0x38);
    let instance = parties.put_interval_instance(&vault, &series, 1_000_000)?;
    assert_eq!(status(&vault, &instance)?, CommitmentStatus::Open);

    let now = 1_000_001;
    let report = lapse_overdue_commitments(&vault, now, &parties.envelope)?;
    assert_eq!(
        report,
        LapseSweepReport {
            lapsed: vec![instance],
            repaired_close_hooks: Vec::new(),
        }
    );
    assert_eq!(status(&vault, &instance)?, CommitmentStatus::Lapsed);

    let receipts = receipts_for(&vault, &instance)?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "let_go");
    assert_eq!(
        receipts[0].policy_trace,
        vec!["commitment.instance.gap_decayed"]
    );
    assert_eq!(receipts[0].occurred_at, now);

    // Due rows gone, series untouched, exactly one successor.
    assert!(instance_rows(&vault, &instance)?.is_empty());
    assert_eq!(status(&vault, &series)?, CommitmentStatus::Open);
    let successors = other_instances(&vault, &instance)?;
    assert_eq!(successors.len(), 1);
    assert_eq!(status(&vault, &successors[0])?, CommitmentStatus::Open);
    // ONE-1541 never marks the SERIES lapsed; survival is the schedule hook's.
    assert!(receipts_for(&vault, &series)?.is_empty());
    Ok(())
}

#[test]
fn due_now_is_not_overdue() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let series = crate::test_util::entity(0x39);
    let instance = parties.put_interval_instance(&vault, &series, 1_000_000)?;

    // The boundary is STRICT: `LifecycleDue.at == now` is not yet overdue.
    assert!(vault.overdue_commitment_instances(1_000_000)?.is_empty());
    let report = lapse_overdue_commitments(&vault, 1_000_000, &parties.envelope)?;
    assert!(report.lapsed.is_empty());
    assert!(report.repaired_close_hooks.is_empty());
    assert_eq!(status(&vault, &instance)?, CommitmentStatus::Open);

    // One second later it is.
    assert_eq!(
        vault.overdue_commitment_instances(1_000_001)?,
        vec![instance]
    );
    Ok(())
}

#[test]
fn lapse_batch_resolves_local_claim_policy() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let first = crate::test_util::entity(0x3A);
    let second = crate::test_util::entity(0x3B);
    let one = parties.put_interval_instance(&vault, &first, 1_000_000)?;
    let two = parties.put_interval_instance(&vault, &second, 1_000_000)?;

    let before_one = gate_receipts_for(&vault, &one)?;
    let before_two = gate_receipts_for(&vault, &two)?;
    let report = lapse_overdue_commitments(&vault, 1_000_001, &parties.envelope)?;
    assert_eq!(report.lapsed.len(), 2);

    // An admissible policy reached the gated Open→Lapsed write (it landed) and
    // EXACTLY ONE Gate decision was recorded per lapsed instance: the preflight
    // records, the apply reuses that identity instead of minting a second.
    assert_eq!(status(&vault, &one)?, CommitmentStatus::Lapsed);
    assert_eq!(status(&vault, &two)?, CommitmentStatus::Lapsed);
    assert_eq!(gate_receipts_for(&vault, &one)?, before_one + 1);
    assert_eq!(gate_receipts_for(&vault, &two)?, before_two + 1);
    Ok(())
}

#[test]
fn lapse_batch_is_all_or_nothing() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let open = crate::test_util::entity(0x3C);
    let terminal = crate::test_util::entity(0x3D);
    parties.put_plain(&vault, &open, 300)?;
    parties.put_plain(&vault, &terminal, 300)?;
    vault.release_commitment(&terminal, &parties.envelope, 301)?;
    let gate_before = gate_receipts_for(&vault, &open)?;

    // One non-open member takes the whole selection down.
    assert!(matches!(
        vault
            .batch()
            .commitment_gap_decay(&[open, terminal], &parties.envelope, 400)
            .commit(),
        Err(Error::InvalidClaimBody(
            "commitment status transition requires open source status"
        ))
    ));
    assert_eq!(status(&vault, &open)?, CommitmentStatus::Open);
    assert_eq!(status(&vault, &terminal)?, CommitmentStatus::Released);
    // The refusal happens before any decision is staged, so the aborted batch
    // leaves no orphan allow receipt behind.
    assert_eq!(gate_receipts_for(&vault, &open)?, gate_before);
    assert!(receipts_for(&vault, &open)?.is_empty());

    // A stale (superseded-lifecycle) member refuses the same way.
    let stale = crate::test_util::entity(0x3E);
    let successor = crate::test_util::entity(0x3F);
    parties.put_plain(&vault, &stale, 300)?;
    parties.put_plain(&vault, &successor, 302)?;
    vault.supersede_claim(&successor, &stale, 350)?;
    assert!(matches!(
        vault
            .batch()
            .commitment_gap_decay(&[open, stale], &parties.envelope, 400)
            .commit(),
        Err(Error::ClaimAlreadyClosed {
            status: ClaimLifecycleStatus::Superseded
        })
    ));
    assert_eq!(status(&vault, &open)?, CommitmentStatus::Open);
    Ok(())
}

#[test]
fn terminal_index_rows_repair_matching_close_hooks() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let t1 = 1_000_050;
    let t2 = 1_000_900;

    // Four series, each with one instance whose status landed at t1 through the
    // RAW CMT-1 verb — the status write committed, the due rows did not move.
    let seeds = [
        (0x50_u8, CommitmentStatus::Lapsed),
        (0x51, CommitmentStatus::Fulfilled),
        (0x52, CommitmentStatus::Released),
        (0x53, CommitmentStatus::Superseded),
    ];
    let mut instances = Vec::new();
    for (seed, terminal) in seeds {
        let series = crate::test_util::entity(seed);
        let instance = parties.put_interval_instance(&vault, &series, 1_000_000)?;
        match terminal {
            CommitmentStatus::Lapsed => vault.lapse_commitment(&instance, &parties.envelope, t1)?,
            CommitmentStatus::Fulfilled => {
                vault.fulfill_commitment(&instance, &parties.envelope, t1)?;
            }
            CommitmentStatus::Released => {
                vault.release_commitment(&instance, &parties.envelope, t1)?;
            }
            CommitmentStatus::Superseded => {
                vault.supersede_commitment(&instance, &parties.envelope, t1)?;
            }
            CommitmentStatus::Open => unreachable!("seed statuses are terminal"),
        }
        assert!(!instance_rows(&vault, &instance)?.is_empty());
        instances.push((series, instance, terminal));
    }
    let receipts_before = lifecycle_receipts(&vault)?;

    let report = lapse_overdue_commitments(&vault, t2, &parties.envelope)?;
    assert!(report.lapsed.is_empty(), "no terminal row is lapsed again");
    let mut repaired = report.repaired_close_hooks;
    repaired.sort_unstable();
    let mut expected: Vec<EntityId> = instances.iter().map(|(_, id, _)| *id).collect();
    expected.sort_unstable();
    assert_eq!(repaired, expected);

    // No duplicate status transition and no duplicate receipt.
    assert_eq!(lifecycle_receipts(&vault)?, receipts_before);
    for (series, instance, terminal) in &instances {
        assert_eq!(status(&vault, instance)?, *terminal);
        // Active due rows removed, at most one successor minted.
        assert!(instance_rows(&vault, instance)?.is_empty());
        let successors = other_instances(&vault, instance)?;
        let mine: Vec<EntityId> = successors
            .into_iter()
            .filter(|id| {
                due_rows(&vault)
                    .expect("due rows")
                    .iter()
                    .any(|entry| entry.instance_ref == Some(*id) && entry.series_ref == *series)
            })
            .collect();
        assert_eq!(mine.len(), 1, "exactly one successor for {series:?}");
        // closed_at came from the terminal claim header at t1, NOT retry t2:
        // the successor the hook minted carries t1 as its learned_at.
        assert_eq!(vault.get_learned_at(&mine[0])?, t1);
    }
    Ok(())
}

#[test]
fn supersede_wrapper_closes_immediately() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let series = crate::test_util::entity(0x54);
    let instance = parties.put_interval_instance(&vault, &series, 1_000_000)?;

    let result = supersede_commitment_with_close(&vault, &instance, &parties.envelope, 999_000)?;
    assert_eq!(result.status, CommitmentStatus::Superseded);
    // Due rows removed immediately — no sweep needed.
    assert!(instance_rows(&vault, &instance)?.is_empty());
    // A supersession closes the slot without counting as a completion, so it
    // projects no lifecycle receipt at all.
    assert!(receipts_for(&vault, &instance)?.is_empty());

    // Repeating repairs only the hook.
    let repeat = supersede_commitment_with_close(&vault, &instance, &parties.envelope, 999_500)?;
    assert_eq!(repeat.status, CommitmentStatus::Superseded);
    assert_eq!(status(&vault, &instance)?, CommitmentStatus::Superseded);
    Ok(())
}

#[test]
fn raw_supersede_repairs_on_next_sweep() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let series = crate::test_util::entity(0x55);
    let instance = parties.put_interval_instance(&vault, &series, 1_000_000)?;
    let t1 = 1_000_060;
    let t2 = 1_000_950;

    // The RAW CMT-1 verb leaves the due rows behind, temporarily.
    vault.supersede_commitment(&instance, &parties.envelope, t1)?;
    assert!(!instance_rows(&vault, &instance)?.is_empty());

    let report = lapse_overdue_commitments(&vault, t2, &parties.envelope)?;
    assert_eq!(report.repaired_close_hooks, vec![instance]);
    assert!(instance_rows(&vault, &instance)?.is_empty());
    let successors = other_instances(&vault, &instance)?;
    assert_eq!(successors.len(), 1);
    // Repaired with the COMMITTED t1, never with retry time t2.
    assert_eq!(vault.get_learned_at(&successors[0])?, t1);
    Ok(())
}

#[test]
fn release_projects_explicit_waive_receipt_and_closes_schedule() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let series = crate::test_util::entity(0x56);
    let instance = parties.put_interval_instance(&vault, &series, 1_000_000)?;

    let result = release_commitment_with_close(&vault, &instance, &parties.envelope, 999_100)?;
    assert_eq!(result.status, CommitmentStatus::Released);
    assert!(instance_rows(&vault, &instance)?.is_empty());

    let receipts = receipts_for(&vault, &instance)?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "released");
    assert_eq!(
        receipts[0].policy_trace,
        vec!["commitment.lifecycle.waived"]
    );
    assert_eq!(receipts[0].occurred_at, 999_100);

    // A release closes the slot WITHOUT counting as a completion; the interval
    // grid still owes exactly one successor.
    assert_eq!(other_instances(&vault, &instance)?.len(), 1);

    // Repeating repairs only the close hook: no second status write, no second
    // receipt, and the receipt keeps its committed time.
    let repeat = release_commitment_with_close(&vault, &instance, &parties.envelope, 999_800)?;
    assert_eq!(repeat.status, CommitmentStatus::Released);
    assert_eq!(receipts_for(&vault, &instance)?, receipts);

    // The wrong wrapper on a terminal row is a typed refusal, not a transition.
    assert!(matches!(
        supersede_commitment_with_close(&vault, &instance, &parties.envelope, 999_900),
        Err(Error::InvalidClaimBody(
            "supersede requires an open or already-superseded commitment"
        ))
    ));
    assert!(matches!(
        fulfill_commitment_from(
            &vault,
            &instance,
            FulfillmentSource::UserDone,
            &parties.envelope,
            999_900,
        ),
        Err(Error::InvalidClaimBody(
            "fulfillment requires an open or already-fulfilled commitment"
        ))
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Receipt projection
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_receipt_query_tolerates_reserved_claims() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let terminal = crate::test_util::entity(0x57);
    parties.put_plain(&vault, &terminal, 300)?;
    fulfill_commitment_from(
        &vault,
        &terminal,
        FulfillmentSource::UserDone,
        &parties.envelope,
        310,
    )?;

    // A reserved-predicate CLAIM sitting beside the terminal commitment. The
    // projector decodes with reserved predicates ALLOWED and exact-matches
    // `commitment.record` BEFORE the commitment codec, so this row coexists
    // instead of poisoning the query.
    let source = crate::test_util::entity(0x58);
    let target = crate::test_util::entity(0x59);
    for id in [source, target] {
        vault.put_entity(&id, ENTITY_TYPE_PERSON, time(1, 1), 1, b"person")?;
    }
    vault.put_edge(&source, EdgeKind::Mentions, &target, 0.5)?;
    vault.put_edge_provenance(
        &crate::test_util::entity(0x5A),
        &EdgeRef::new(source, EdgeKind::Mentions, target),
        &EdgeProvenanceClaimBody::new(parties.obligor, 0.5, SupersessionStatus::Proposed),
        EdgeActorClass::Human,
        320,
    )?;

    let receipts = lifecycle_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "fulfilled");
    assert_eq!(
        receipts[0].trigger_ref.as_deref(),
        Some(format!("commitment:{}", terminal.to_hex()).as_str())
    );
    Ok(())
}

/// The lifecycle invariant is deliberately SCAN-BOUNDED, and the bound is the
/// one every other receipt projector shares.
///
/// Within `MAX_RECEIPT_QUERY_SCAN` scanned CLAIM rows, a fulfilled, released or
/// lapsed commitment cannot exist without its lifecycle receipt. Nothing here
/// claims whole-vault coverage: a vault larger than the bound needs the
/// follow-up commitment-status receipt index, which is named work rather than a
/// silent gap.
#[test]
fn lifecycle_receipt_invariant_is_scan_bounded() -> Result<()> {
    assert_eq!(crate::receipt::MAX_RECEIPT_QUERY_SCAN, 100_000);

    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let fulfilled = crate::test_util::entity(0x5B);
    let released = crate::test_util::entity(0x5C);
    let open = crate::test_util::entity(0x5D);
    for id in [fulfilled, released, open] {
        parties.put_plain(&vault, &id, 300)?;
    }
    vault.fulfill_commitment(&fulfilled, &parties.envelope, 310)?;
    vault.release_commitment(&released, &parties.envelope, 311)?;

    // Every terminal row inside the bound projects; the open one does not.
    let receipts = lifecycle_receipts(&vault)?;
    assert_eq!(receipts.len(), 2);
    assert!(receipts_for(&vault, &open)?.is_empty());
    assert_eq!(receipts_for(&vault, &fulfilled)?[0].outcome, "fulfilled");
    assert_eq!(receipts_for(&vault, &released)?[0].outcome, "released");
    Ok(())
}

// ---------------------------------------------------------------------------
// The Dreamer witness path
// ---------------------------------------------------------------------------

/// A policy manifest that GRANTS the Dreamer's Auto request, mirroring the
/// landed `dreamer_promotion` fixture. ONE-1710 made `Auto` the universal
/// promotion request, so a promotion test must state the owner policy that
/// permits the write rather than observe a queue that no longer exists.
fn auto_permitting_manifest() -> Vec<u8> {
    let source_row = || {
        Value::Map(vec![
            (Value::from("max_auto_sensitivity"), Value::from(3_u64)),
            (Value::from("receipted"), Value::Boolean(true)),
            (Value::from("warned"), Value::Boolean(true)),
        ])
    };
    let manifest = Value::Map(vec![
        (Value::from("schema_version"), Value::from("1.1")),
        (Value::from("pack_id"), Value::from("cmt4-lifecycle-test")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from("defaults"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
        (Value::from("rules"), Value::Array(Vec::new())),
        (
            Value::from("actor_ceilings"),
            Value::Array(
                ["agent", "human", "first_party", "system"]
                    .into_iter()
                    .map(|actor_class| {
                        Value::Map(vec![
                            (Value::from("actor_class"), Value::from(actor_class)),
                            (Value::from("ceiling"), Value::from("auto")),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            Value::from("source_trust"),
            Value::Map(
                [
                    ClaimSource::UserStated,
                    ClaimSource::Observed,
                    ClaimSource::Inferred,
                    ClaimSource::Imported,
                    ClaimSource::ToolOutput,
                    ClaimSource::Generated,
                ]
                .into_iter()
                .map(|source| (Value::from(source.as_str()), source_row()))
                .collect(),
            ),
        ),
        (
            Value::from("signature"),
            Value::Map(vec![
                (Value::from("alg"), Value::from("ed25519")),
                (Value::from("key_id"), Value::from("cmt4-test")),
                (Value::from("sig"), Value::from("cmt4-test-signature")),
            ]),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &manifest).expect("encode the policy manifest");
    out
}

/// A Dreamer run plus one admissible witness TURN.
struct WitnessFixture {
    run: DreamerRunContext,
    turn: EntityId,
}

fn witness(vault: &Vault) -> Result<WitnessFixture> {
    let id = crate::gate::default_policy_manifest_id().expect("default policy manifest id");
    crate::test_util::put_policy_manifest_bytes(vault, id, &auto_permitting_manifest())?;

    let agent = crate::test_util::entity(0x61);
    let conversation = crate::test_util::entity(0x62);
    let turn = crate::test_util::entity(0x63);
    vault.put_entity(&agent, ENTITY_TYPE_PERSON, time(1, 1), 1, b"dreamer")?;
    vault.put_entity(
        &conversation,
        ENTITY_TYPE_SESSION,
        time(1, 1),
        1,
        b"session",
    )?;
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![
            (Value::from("txt"), Value::from("the document went out")),
            (Value::from("spkr"), Value::from("user")),
        ]),
    )
    .expect("turn body");
    vault
        .batch()
        .put(&turn, ENTITY_TYPE_TURN, time(5, 5), 5, &body)
        .edge(&turn, EdgeKind::ChildOf, &conversation, 1.0)
        .commit()?;

    Ok(WitnessFixture {
        run: DreamerRunContext {
            run_id: "run-cmt4".to_owned(),
            attempt_id: crate::attempt_queue::AttemptId::now(),
            agent_actor: WriteActor::new(agent, EdgeActorClass::Agent),
            now_ms: 10_000,
        },
        turn,
    })
}

/// The witness path writes a durable, gated PROPOSAL and never a status.
///
/// ONE-1710 (ARCH-0067 §7) removed the approval queue this ticket's brief was
/// written against: `PromotionOutcome.pended` is STRUCTURALLY EMPTY, and a
/// write the gate does not grant `Auto` is rolled back into `rejected` rather
/// than converted into an owner-review row. The load-bearing claims survive
/// that change intact and are what this test pins: the proposal is durable and
/// gated, it carries `supersedes = None`, and the target commitment is still
/// `Open` afterwards because no status write happened anywhere on this path.
#[test]
fn dreamer_witness_pends_proposal_without_status_write() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let fixture = witness(&vault)?;
    let commitment = crate::test_util::entity(0x64);
    let proposal = crate::test_util::entity(0x65);
    parties.put_plain(&vault, &commitment, 300)?;

    let outcome = propose_commitment_fulfilled(
        &vault,
        &fixture.run,
        proposal,
        commitment,
        vec![fixture.turn],
        320,
    )?;
    assert_eq!(outcome.landed, vec![proposal]);
    assert!(
        outcome.pended.is_empty(),
        "ONE-1710: the promotion writer mints no approval-queue entry"
    );
    assert!(outcome.rejected.is_empty(), "{:?}", outcome.rejected);

    // Durable, gated, and readable as its own predicate.
    let body = vault.get_claim(&proposal)?.expect("proposal claim");
    assert_eq!(body.predicate, PREDICATE_COMMITMENT_FULFILLMENT_PROPOSAL);
    assert_eq!(body.subject, ClaimSubject::Entity(commitment));
    assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);

    // The target is untouched: no status write, no lifecycle receipt.
    assert_eq!(status(&vault, &commitment)?, CommitmentStatus::Open);
    assert!(receipts_for(&vault, &commitment)?.is_empty());
    // A proposal cannot close the live commitment: nothing supersedes it.
    assert!(
        vault
            .targets(&proposal, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn dreamer_witness_refuses_before_writing() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let parties = parties(&vault)?;
    let fixture = witness(&vault)?;
    let proposal = crate::test_util::entity(0x66);

    // 1. A target that does not exist.
    let missing = crate::test_util::entity(0x67);
    assert!(matches!(
        propose_commitment_fulfilled(
            &vault,
            &fixture.run,
            proposal,
            missing,
            vec![fixture.turn],
            320,
        ),
        Err(Error::EntityNotFound)
    ));

    // 2. A CLAIM that is not a commitment: the existing typed decode error.
    let stranger = crate::test_util::entity(0x68);
    let stranger_body = crate::claim::ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(parties.obligor),
        Value::from("not a commitment"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&stranger, &stranger_body, time(10, 20), 300)?;
    assert!(matches!(
        propose_commitment_fulfilled(
            &vault,
            &fixture.run,
            proposal,
            stranger,
            vec![fixture.turn],
            320,
        ),
        Err(Error::InvalidClaimBody(
            "claim predicate is not commitment.record"
        ))
    ));

    // 3. A terminal target.
    let terminal = crate::test_util::entity(0x69);
    parties.put_plain(&vault, &terminal, 300)?;
    vault.fulfill_commitment(&terminal, &parties.envelope, 310)?;
    assert!(matches!(
        propose_commitment_fulfilled(
            &vault,
            &fixture.run,
            proposal,
            terminal,
            vec![fixture.turn],
            320,
        ),
        Err(Error::InvalidClaimBody(
            "fulfillment proposal target is not an open commitment"
        ))
    ));

    // No proposal was written on any refusal.
    assert!(vault.get_raw(&proposal)?.is_none());
    Ok(())
}
