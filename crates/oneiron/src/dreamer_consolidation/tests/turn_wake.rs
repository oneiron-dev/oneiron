//! The turn wake against ARCH-0026's projector and shared-carrier lines: a
//! wake over material the projection holds writes nothing, new material is
//! queued once and held through a restart until its round applies, and a
//! TURN without its conversation edge waits parked instead of stopping later
//! turns.
use super::*;
use crate::attempt_queue::{ClaimAttempt, ClaimOutcome};
use crate::dreamer_runner::{CompleteDreamerAttempt, DreamerRunnerStore, FailDreamerAttempt};
use crate::dreamer_wake::WakeTurnSubject;

const OWNER: &str = "turn-wake-test";

/// Every Micro attempt row, in queue order.
fn micro_attempts(vault: &Vault) -> Result<Vec<crate::attempt_queue::AttemptRecord>> {
    Ok(AttemptQueue::new(vault)
        .list()?
        .into_iter()
        .filter(|row| row.kind == crate::DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND)
        .collect())
}

/// The TURNs each Micro attempt plans, attempt by attempt.
fn micro_rounds(vault: &Vault) -> Result<Vec<Vec<EntityId>>> {
    micro_attempts(vault)?
        .iter()
        .map(|row| {
            let payload = decode_dreamer_attempt_payload(&row.payload)?;
            Ok(decode_partition_payload(&payload.input)?.1)
        })
        .collect()
}

/// Claims the next Micro attempt as the Dreamer's runner would.
fn claim_micro(vault: &Vault, now: u64) -> Result<crate::attempt_queue::AttemptRecord> {
    match AttemptQueue::new(vault).claim_kind(
        crate::DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: OWNER.to_owned(),
            now,
        },
    )? {
        ClaimOutcome::Claimed(record) => Ok(record),
        other => panic!("expected a queued Micro attempt, got {other:?}"),
    }
}

/// Completes a claimed attempt through the Dreamer's own door, the
/// transaction that applies its projector round.
fn complete(vault: &Vault, record: &crate::attempt_queue::AttemptRecord, now: u64) -> Result<()> {
    DreamerRunnerStore::new(vault).complete(CompleteDreamerAttempt {
        id: record.id,
        lease_owner: OWNER.to_owned(),
        attempt_count: record.attempt_count,
        now,
    })?;
    Ok(())
}

fn reopen(dir: &tempfile::TempDir, vault: Vault) -> Vault {
    drop(vault);
    Vault::open(dir.path(), VaultConfig::device()).expect("reopen vault")
}

/// RD-26: "a wake with nothing new writes nothing". Before this build the
/// wake's image was a hash of the unread window's turn ids, so a turn that
/// only repeated held words still queued a round.
#[test]
fn a_wake_over_material_the_projection_holds_writes_nothing() -> Result<()> {
    let (_dir, vault) = open_vault();
    let at = vault.now_recorded_at();
    let session = seed_session(&vault, 7, at);
    let first = seed_turn(&vault, &session, "user", "I live in Kyoto. My sister is Mia.", at);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at)?);
    assert_eq!(micro_rounds(&vault)?, vec![vec![first]]);
    let record = claim_micro(&vault, at + 1)?;
    complete(&vault, &record, at + 2)?;

    // The same words again, punctuated and cased differently: held material.
    seed_turn(&vault, &session, "user", "i live in kyoto!", at + 3);
    assert!(!vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 3)?);
    assert_eq!(micro_attempts(&vault)?.len(), 1, "no round for held words");

    // A changed fact about the same person is new material: one round.
    let moved = seed_turn(&vault, &session, "user", "I moved to Osaka.", at + 4);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 4)?);
    assert_eq!(micro_rounds(&vault)?.len(), 2);
    assert_eq!(micro_rounds(&vault)?[1], vec![moved]);
    Ok(())
}

/// "A wake over new material writes once, and a restart between queue and
/// apply neither loses nor doubles it" (packet check). A round whose attempt
/// fails holds nothing, so the same words queue again.
#[test]
fn queued_material_survives_a_restart_once_and_applies_with_its_attempt() -> Result<()> {
    let (dir, vault) = open_vault();
    let at = vault.now_recorded_at();
    let session = seed_session(&vault, 8, at);
    let first = seed_turn(&vault, &session, "user", "Our offsite is in Sapporo.", at);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at)?);

    // Restart between queue and apply: the round is still queued, its
    // material still held, and a repeat of it queues nothing new.
    let vault = reopen(&dir, vault);
    assert_eq!(micro_rounds(&vault)?, vec![vec![first]]);
    seed_turn(&vault, &session, "user", "Our offsite is in Sapporo.", at + 1);
    assert!(!vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 1)?);
    assert_eq!(micro_attempts(&vault)?.len(), 1, "not doubled");

    // The round applies when its attempt completes, and stays applied.
    let record = claim_micro(&vault, at + 2)?;
    complete(&vault, &record, at + 3)?;
    let vault = reopen(&dir, vault);
    seed_turn(&vault, &session, "user", "our offsite is in sapporo", at + 4);
    assert!(!vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 4)?);
    assert_eq!(micro_attempts(&vault)?.len(), 1);

    // A round that fails is not declared current: its words are new again.
    let second = seed_turn(&vault, &session, "user", "The budget is fixed.", at + 5);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 5)?);
    let record = claim_micro(&vault, at + 6)?;
    DreamerRunnerStore::new(&vault).fail(FailDreamerAttempt {
        id: record.id,
        lease_owner: OWNER.to_owned(),
        attempt_count: record.attempt_count,
        reason: "fixture failure".to_owned(),
        now: at + 7,
    })?;
    let again = seed_turn(&vault, &session, "user", "The budget is fixed.", at + 8);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 8)?);
    let rounds = micro_rounds(&vault)?;
    assert_eq!(rounds.len(), 3);
    assert_eq!(rounds[1], vec![second]);
    assert_eq!(rounds[2], vec![again]);
    Ok(())
}

/// ARCH-0026 (#1353 follow-up): "A TURN with no conversation edge stops the
/// window at that turn, so later turns wait." It now waits parked on the
/// shared carrier: the later turn's wake plans it, and the parked TURN is
/// planned under its own conversation once its edge lands.
#[test]
fn a_turn_without_its_conversation_edge_does_not_block_a_later_turns_wake() -> Result<()> {
    let (_dir, vault) = open_vault();
    let at = vault.now_recorded_at();
    let session = seed_session(&vault, 9, at);
    let orphan = EntityId::now();
    vault
        .batch()
        .put(
            &orphan,
            ENTITY_TYPE_TURN,
            occurred(at),
            at,
            &turn_body("user", "My manager is Ren.", None),
        )
        .commit()?;
    let later = seed_turn(&vault, &session, "user", "I start at Acme on Monday.", at + 1);

    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 1)?);
    assert_eq!(micro_rounds(&vault)?, vec![vec![later]]);
    // Nothing new: the parked TURN neither counts nor plans.
    assert!(!vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 2)?);

    vault
        .batch()
        .edge(&orphan, EdgeKind::ChildOf, &session, 1.0)
        .commit()?;
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 3)?);
    assert_eq!(micro_rounds(&vault)?, vec![vec![later], vec![orphan]]);
    Ok(())
}
