//! The turn wake against ARCH-0026's projector and shared-carrier lines: a
//! wake over material the projection holds writes nothing, new material is
//! queued once and held from the moment its round applies, through a
//! restart, and a TURN without its conversation edge waits parked instead of
//! stopping later turns. Sol's projector repros close the file.
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
    let first = seed_turn(
        &vault,
        &session,
        "user",
        "I live in Kyoto. My sister is Mia.",
        at,
    );
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at)?);
    assert_eq!(micro_rounds(&vault)?, vec![vec![first]]);
    let record = claim_micro(&vault, at + 1)?;
    complete(&vault, &record, at + 2)?;

    // The same words again, punctuated and cased differently: held material.
    seed_turn(
        &vault,
        &session,
        "user",
        "i live in kyoto! my sister is mia",
        at + 3,
    );
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
/// apply neither loses nor doubles it" (packet check): the attempt is still
/// queued after the restart and its window is never planned again. Once it
/// completes, its words are held through another restart. A round whose
/// attempt fails held nothing, so the same words queue again.
#[test]
fn queued_material_survives_a_restart_once_and_applies_with_its_attempt() -> Result<()> {
    let (dir, vault) = open_vault();
    let at = vault.now_recorded_at();
    let session = seed_session(&vault, 8, at);
    let first = seed_turn(&vault, &session, "user", "Our offsite is in Sapporo.", at);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at)?);

    // Restart between queue and apply: the attempt is still queued, and the
    // window it planned is read, so no wake plans it again.
    let vault = reopen(&dir, vault);
    assert_eq!(micro_rounds(&vault)?, vec![vec![first]]);
    assert!(!vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 1)?);
    assert_eq!(micro_attempts(&vault)?.len(), 1, "not doubled");

    // The round applies when its attempt completes, and stays applied.
    let record = claim_micro(&vault, at + 2)?;
    complete(&vault, &record, at + 3)?;
    let vault = reopen(&dir, vault);
    seed_turn(
        &vault,
        &session,
        "user",
        "our offsite is in sapporo",
        at + 4,
    );
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
    let later = seed_turn(
        &vault,
        &session,
        "user",
        "I start at Acme on Monday.",
        at + 1,
    );

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

/// Sol R1 (P1): every statement a partition's applied rounds ever held stayed
/// held, so a return to an earlier value (Kyoto, Osaka, Kyoto) was consumed
/// as already projected. Only the partition's latest round holds.
#[test]
fn a_return_to_an_earlier_value_is_new_material() -> Result<()> {
    let (_dir, vault) = open_vault();
    let at = vault.now_recorded_at();
    let session = seed_session(&vault, 10, at);
    let kyoto = seed_turn(&vault, &session, "user", "I live in Kyoto.", at);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at)?);
    complete(&vault, &claim_micro(&vault, at + 1)?, at + 2)?;
    let osaka = seed_turn(&vault, &session, "user", "I live in Osaka.", at + 3);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 3)?);
    complete(&vault, &claim_micro(&vault, at + 4)?, at + 5)?;

    let back = seed_turn(&vault, &session, "user", "I live in Kyoto.", at + 6);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 6)?);
    assert_eq!(
        micro_rounds(&vault)?,
        vec![vec![kyoto], vec![osaka], vec![back]]
    );
    Ok(())
}

/// Sol R1 (P1 ×2): a repeat of a queued round's words was consumed against
/// the pending round, so a round lost before it applied (cancelled while
/// landing at a crash, or its source erased) stranded the repeat behind the
/// watermark. A queued round holds nothing: the repeat queues its own round,
/// which outlives the first source's erasure.
#[test]
fn a_repeat_while_its_round_is_queued_queues_its_own_round() -> Result<()> {
    let (_dir, vault) = open_vault();
    let at = vault.now_recorded_at();
    let session = seed_session(&vault, 11, at);
    let first = seed_turn(&vault, &session, "user", "My manager is Ren.", at);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at)?);
    let repeat = seed_turn(&vault, &session, "user", "My manager is Ren.", at + 1);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 1)?);
    assert_eq!(micro_rounds(&vault)?, vec![vec![first], vec![repeat]]);

    vault
        .delete_room_record_unchecked_for_test(&first, crate::deletion::DeleteReason::UserDelete)?;
    let queued: Vec<_> = micro_attempts(&vault)?
        .into_iter()
        .filter(|row| row.state == crate::attempt_queue::AttemptState::Queued)
        .map(|row| {
            let payload = decode_dreamer_attempt_payload(&row.payload)?;
            Ok(decode_partition_payload(&payload.input)?.1)
        })
        .collect::<Result<_>>()?;
    assert!(
        queued.contains(&vec![repeat]),
        "the repeat's round is still queued"
    );
    Ok(())
}

/// Sol R1 (P1, and the P2 batch-delete bypass): a repeat consumed against an
/// applied round had nothing left once that round's source was erased. The
/// erasure, here through the public batch delete, puts the repeat back on
/// the shared carrier, so the next wake reads it as new.
#[test]
fn erasing_the_source_a_repeat_rode_on_reads_the_repeat_again() -> Result<()> {
    let (_dir, vault) = open_vault();
    let at = vault.now_recorded_at();
    let session = seed_session(&vault, 12, at);
    let first = seed_turn(&vault, &session, "user", "My manager is Ren.", at);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at)?);
    complete(&vault, &claim_micro(&vault, at + 1)?, at + 2)?;
    let repeat = seed_turn(&vault, &session, "user", "my manager is Ren", at + 3);
    assert!(!vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 3)?);

    vault.batch().delete(&first).commit()?;
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 4)?);
    assert_eq!(micro_rounds(&vault)?, vec![vec![first], vec![repeat]]);
    Ok(())
}

/// One user turn witnessed into `conversation` by `person`.
fn witness_into(
    vault: &Vault,
    person: EntityId,
    conversation: EntityId,
    messages: Vec<crate::memory::WitnessMessage>,
) -> EntityId {
    let turn = EntityId::now();
    vault
        .memory(person, EdgeActorClass::Human)
        .witness(&crate::memory::WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            messages,
            occurred_at: 10,
        })
        .expect("witnessed turn");
    turn
}

/// Sol R1 (P1): the projector held a system interleave's words, which no
/// consolidation branch reads, so the user later saying them was suppressed
/// as already projected. Statements come from the branch's own text.
#[test]
fn words_a_branch_never_reads_are_never_held() -> Result<()> {
    use super::witnessed_turns::{allow_system_rows, message};
    use crate::memory::WitnessAuthor;
    let (_dir, vault) = open_vault();
    let person = EntityId::from_bytes([0x71; 16])?;
    vault.put_entity(&person, ENTITY_TYPE_PERSON, occurred(1), 1, b"witness")?;
    allow_system_rows(&vault, person)?;
    let conversation = EntityId::from_bytes([0x72; 16])?;
    let thanks = witness_into(
        &vault,
        person,
        conversation,
        vec![
            message(0, WitnessAuthor::User, "Thanks.", true),
            message(1, WitnessAuthor::System, "My manager is Ren.", true),
        ],
    );
    let at = vault.now_recorded_at();
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at)?);
    complete(&vault, &claim_micro(&vault, at + 1)?, at + 2)?;

    let said = witness_into(
        &vault,
        person,
        conversation,
        vec![message(0, WitnessAuthor::User, "My manager is Ren.", true)],
    );
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 3)?);
    assert_eq!(micro_rounds(&vault)?, vec![vec![thanks], vec![said]]);
    Ok(())
}

/// Sol R1 (P1): a round held every statement of its partition, the screen's
/// skipped turns included, so the rescan door found a skipped turn's words
/// already projected. A round holds only the turns its attempt was given.
#[test]
fn a_turn_the_screen_skipped_is_not_held_by_the_round_that_left_it_out() -> Result<()> {
    use crate::dreamer_prefilter::{PrefilterConfig, PrefilterWeights, reopen_prefilter_rescan};
    let (_dir, vault) = open_vault();
    let weights = PrefilterWeights {
        len: 1.0,
        ttr: 0.0,
        entity_density: 0.0,
        novelty: 0.0,
        role: 0.0,
    };
    vault.set_prefilter_config(PrefilterConfig {
        enabled: true,
        threshold: 0.1,
        weights,
    })?;
    let at = vault.now_recorded_at();
    let session = seed_session(&vault, 13, at);
    let kept = seed_turn(
        &vault,
        &session,
        "user",
        "Alice moved to Osaka yesterday.",
        at,
    );
    let skipped = seed_turn(&vault, &session, "user", "Budget doubled.", at);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at)?);
    assert_eq!(micro_rounds(&vault)?, vec![vec![kept]]);
    complete(&vault, &claim_micro(&vault, at + 1)?, at + 2)?;

    vault.set_prefilter_config(PrefilterConfig {
        enabled: false,
        threshold: 0.1,
        weights,
    })?;
    reopen_prefilter_rescan(&vault, DreamerConsolidationScope::Micro, at)?;
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 3)?);
    let rounds = micro_rounds(&vault)?;
    assert_eq!(rounds.len(), 2);
    assert!(rounds[1].contains(&skipped));
    Ok(())
}

/// Sol R1 (P1): the public enqueue left an edge-less turn out and reported
/// success, but the complete-second watermark its callers settle with parks
/// nothing, so the turn was stranded behind it. The public door refuses it.
#[test]
fn the_public_enqueue_refuses_a_turn_without_its_conversation_edge() -> Result<()> {
    let (_dir, vault) = open_vault();
    let at = vault.now_recorded_at();
    let session = seed_session(&vault, 14, at);
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
    seed_turn(
        &vault,
        &session,
        "user",
        "I start at Acme on Monday.",
        at + 1,
    );
    let scope = DreamerConsolidationScope::Micro;
    let watermark = read_watermark(&vault, scope)?;
    let scan = scan_dirty_turns(&vault, scope, &watermark, 10)?;
    assert!(scan.iter().any(|turn| turn.turn_id == orphan));
    assert!(enqueue_partition_attempts(&vault, scope, &scan, &watermark, "run", at + 2).is_err());
    assert!(micro_attempts(&vault)?.is_empty());
    Ok(())
}

/// Sol R1 (P1): a TURN whose `txt` moved into its document read as no text,
/// so the sieve flagged nothing and the projector found no material, and the
/// due wake consumed the turn unplanned. Both read the logical body.
#[cfg(feature = "sync")]
#[test]
fn a_turn_whose_text_lives_in_its_document_is_sieved_and_planned() -> Result<()> {
    use crate::entity_doc::{DocAuthorization, TextField};
    let (_dir, vault) = open_vault();
    let at = vault.now_recorded_at();
    let session = seed_session(&vault, 15, at);
    let turn = seed_turn(&vault, &session, "user", "Alice arrives tomorrow.", at);
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    crate::test_util::bind_test_owner(&vault, owner);
    let authenticated = vault.authenticate_owner(
        owner,
        "principal:turn-wake-test",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault.migrate_entity_text(
        &turn,
        &TextField::MapField("txt".into()),
        crate::write_envelope::WriteActor::new(owner, EdgeActorClass::Human),
        &DocAuthorization::Owner(&authenticated),
    )?;

    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 1)?);
    assert_eq!(micro_rounds(&vault)?, vec![vec![turn]]);
    let kinds: Vec<_> = vault
        .sieve_queue(16)?
        .into_iter()
        .filter(|span| span.turn == turn)
        .map(|span| span.kind)
        .collect();
    assert!(kinds.contains(&crate::dreamer_wake::SpanKind::Date));
    assert!(kinds.contains(&crate::dreamer_wake::SpanKind::Name));
    Ok(())
}

/// Sol R2 (P1): a round queued again under its key after its attempt
/// completed (the same batch replayed with new words) was marked applied by
/// a repeated completion report of the old attempt, so a repeat of the new
/// words was consumed while the new attempt was still queued.
#[test]
fn a_repeated_completion_report_never_applies_a_newer_round_under_its_key() -> Result<()> {
    use crate::attempt_queue::{CompleteAttempt, CompleteOutcome};
    use crate::dreamer_prefilter::reopen_prefilter_rescan;
    let (_dir, vault) = open_vault();
    let at = vault.now_recorded_at();
    let session = seed_session(&vault, 16, at);
    let turn = seed_turn(&vault, &session, "user", "I live in Kyoto.", at);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at)?);
    let first = claim_micro(&vault, at + 1)?;
    complete(&vault, &first, at + 2)?;

    // The same row, rewritten under its own key, and read again.
    vault
        .batch()
        .put(
            &turn,
            ENTITY_TYPE_TURN,
            occurred(at),
            at,
            &turn_body("user", "I live in Osaka.", None),
        )
        .commit()?;
    reopen_prefilter_rescan(&vault, DreamerConsolidationScope::Micro, at)?;
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 3)?);
    let attempts = micro_attempts(&vault)?;
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].dedupe_key, attempts[1].dedupe_key);

    let report = AttemptQueue::new(&vault).complete(CompleteAttempt {
        id: first.id,
        lease_owner: OWNER.to_owned(),
        attempt_count: first.attempt_count,
        now: at + 4,
    })?;
    assert!(matches!(report, CompleteOutcome::AlreadyCompleted(_)));
    let repeat = seed_turn(&vault, &session, "user", "I live in Osaka.", at + 5);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 5)?);
    assert_eq!(micro_rounds(&vault)?[2], vec![repeat]);
    Ok(())
}

/// Sol R2 (P1): erasing one turn of a queued batch retired its round but
/// left the batch's other turns behind the watermark, and the attempt could
/// no longer read its batch. The other live turns go back on the carrier.
#[test]
fn erasing_one_turn_of_a_queued_batch_plans_the_others_again() -> Result<()> {
    let (_dir, vault) = open_vault();
    let at = vault.now_recorded_at();
    let session = seed_session(&vault, 17, at);
    let erased = seed_turn(&vault, &session, "user", "My manager is Ren.", at);
    let kept = seed_turn(&vault, &session, "user", "Our offsite is in Sapporo.", at);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at)?);
    assert_eq!(micro_rounds(&vault)?, vec![vec![erased, kept]]);

    vault.batch().delete(&erased).commit()?;
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 1)?);
    assert_eq!(micro_rounds(&vault)?[1], vec![kept]);
    Ok(())
}

/// Sol R2 (P1, and R1's same-key re-put P2): a turn rewritten under its own
/// key after its round was queued left the round holding the old words,
/// and left the sieve's spans of the old words queued. The round holds only
/// while its turns read as they did, and the re-put owes the sieve a read.
#[test]
fn a_turn_rewritten_under_its_own_key_unbinds_its_round_and_is_sieved_again() -> Result<()> {
    let (_dir, vault) = open_vault();
    let at = vault.now_recorded_at();
    let session = seed_session(&vault, 18, at);
    let turn = seed_turn(&vault, &session, "user", "I live in Kyoto.", at);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at)?);
    let kyoto = |span: &crate::dreamer_wake::SieveSpan| (span.start, span.end) == (10, 15);
    assert!(
        vault
            .sieve_queue(64)?
            .iter()
            .any(|span| span.turn == turn && kyoto(span))
    );

    vault
        .batch()
        .put(
            &turn,
            ENTITY_TYPE_TURN,
            occurred(at),
            at,
            &turn_body("user", "We moved to Osaka last year.", None),
        )
        .commit()?;
    complete(&vault, &claim_micro(&vault, at + 1)?, at + 2)?;
    let repeat = seed_turn(&vault, &session, "user", "I live in Kyoto.", at + 3);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 3)?);
    assert_eq!(micro_rounds(&vault)?[1], vec![repeat]);
    assert!(
        !vault
            .sieve_queue(64)?
            .iter()
            .any(|span| span.turn == turn && kyoto(span))
    );
    Ok(())
}

/// Sol R2 and R3 (P1): the latest round held every statement of its batch,
/// so Kyoto then Osaka in one batch held Kyoto too, and a later return to
/// Kyoto was consumed. A text comparison cannot order statements, so only
/// the batch's latest turn holds.
#[test]
fn a_value_superseded_inside_one_batch_is_new_material_again() -> Result<()> {
    let (_dir, vault) = open_vault();
    let at = vault.now_recorded_at();
    let session = seed_session(&vault, 19, at);
    let kyoto = seed_turn(&vault, &session, "user", "I live in Kyoto.", at);
    let osaka = seed_turn(&vault, &session, "user", "I live in Osaka.", at + 1);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 1)?);
    assert_eq!(micro_rounds(&vault)?, vec![vec![kyoto, osaka]]);
    complete(&vault, &claim_micro(&vault, at + 2)?, at + 3)?;

    let back = seed_turn(&vault, &session, "user", "I live in Kyoto.", at + 4);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 4)?);
    assert_eq!(micro_rounds(&vault)?[1], vec![back]);
    Ok(())
}

/// Engine ruling on Sol R2's batched reversal: only the held turn's whole
/// statement set said again is held. Part of it is new material, since a
/// text comparison cannot tell what the rest of the held turn changed.
#[test]
fn part_of_the_held_words_is_new_material() -> Result<()> {
    let (_dir, vault) = open_vault();
    let at = vault.now_recorded_at();
    let session = seed_session(&vault, 20, at);
    let first = seed_turn(
        &vault,
        &session,
        "user",
        "I live in Kyoto. My sister is Mia.",
        at,
    );
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at)?);
    complete(&vault, &claim_micro(&vault, at + 1)?, at + 2)?;

    let part = seed_turn(&vault, &session, "user", "i live in kyoto!", at + 3);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 3)?);
    assert_eq!(micro_rounds(&vault)?, vec![vec![first], vec![part]]);
    Ok(())
}

/// Engine ruling on Sol R2's batched reversal: a repeat rides the held turn
/// as of its wake. A turn between the two that is queued later, here a
/// parked turn whose conversation edge lands, may have changed the value the
/// repeat returned to, so the repeat is planned again.
#[test]
fn a_repeat_is_planned_again_when_a_turn_before_it_is_queued_later() -> Result<()> {
    let (_dir, vault) = open_vault();
    let at = vault.now_recorded_at();
    let session = seed_session(&vault, 21, at);
    let kyoto = seed_turn(&vault, &session, "user", "I live in Kyoto.", at);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at)?);
    complete(&vault, &claim_micro(&vault, at + 1)?, at + 2)?;
    let parked = EntityId::now();
    vault
        .batch()
        .put(
            &parked,
            ENTITY_TYPE_TURN,
            occurred(at + 3),
            at + 3,
            &turn_body("user", "I live in Osaka.", None),
        )
        .commit()?;
    let back = seed_turn(&vault, &session, "user", "I live in Kyoto.", at + 4);
    assert!(!vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 4)?);

    vault
        .batch()
        .edge(&parked, EdgeKind::ChildOf, &session, 1.0)
        .commit()?;
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 5)?);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 6)?);
    assert_eq!(
        micro_rounds(&vault)?,
        vec![vec![kyoto], vec![parked], vec![back]]
    );
    Ok(())
}

/// Sol R3 (P1): a held turn rewritten after its round was queued, then
/// rewritten back after its attempt completed on the changed words, read as
/// it did when queued, so its round held words its attempt never read and a
/// return to them was consumed. Publishing a held turn's words ends its hold
/// for good.
#[test]
fn a_held_turn_rewritten_and_restored_holds_nothing() -> Result<()> {
    let (_dir, vault) = open_vault();
    let at = vault.now_recorded_at();
    let session = seed_session(&vault, 22, at);
    let turn = seed_turn(&vault, &session, "user", "I live in Kyoto.", at);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at)?);
    let rewrite = |text: &str| {
        vault
            .batch()
            .put(
                &turn,
                ENTITY_TYPE_TURN,
                occurred(at),
                at,
                &turn_body("user", text, None),
            )
            .commit()
    };
    rewrite("I live in Osaka.")?;
    complete(&vault, &claim_micro(&vault, at + 1)?, at + 2)?;
    rewrite("I live in Kyoto.")?;

    let back = seed_turn(&vault, &session, "user", "I live in Kyoto.", at + 3);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 3)?);
    assert_eq!(micro_rounds(&vault)?[1], vec![back]);
    Ok(())
}

/// Sol R4 and R5 (P1): a repeat rode the held turn, and the held turn
/// itself was queued again with changed words (a finalized stream
/// continuation keeps its TURN row and re-dirties it; a re-put can also move
/// its key back), but only material between the two keys the repeat
/// recorded released it, so its return to the old words was never read
/// after the change. The repeated turn queued again, under any key,
/// releases it too.
#[test]
fn a_repeat_is_planned_again_when_the_turn_it_repeated_is_queued_again() -> Result<()> {
    let (_dir, vault) = open_vault();
    let at = vault.now_recorded_at();
    let session = seed_session(&vault, 23, at);
    let held = seed_turn(&vault, &session, "user", "I live in Kyoto.", at);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at)?);
    complete(&vault, &claim_micro(&vault, at + 1)?, at + 2)?;
    let back = seed_turn(&vault, &session, "user", "I live in Kyoto.", at + 3);
    assert!(!vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 3)?);

    // New words on the held turn, re-put under an earlier key and
    // re-dirtied as a finalized stream continuation re-dirties its turn.
    vault
        .batch()
        .put(
            &held,
            ENTITY_TYPE_TURN,
            occurred(at - 5),
            at - 5,
            &turn_body("user", "I live in Kyoto. I moved to Osaka.", None),
        )
        .commit()?;
    vault.with_write_txn(|txn| {
        crate::dreamer_consolidation::redirty::redirty_turn_in_txn(&vault, txn, &held)
    })?;
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 4)?);
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 5)?);
    assert_eq!(
        micro_rounds(&vault)?,
        vec![vec![held], vec![held], vec![back]]
    );
    Ok(())
}

/// Sol R4 (P1): a turn consumed as a repeat kept riding after one of its
/// MESSAGEs was erased, though what it still says is only part of the held
/// turn's words, which is new material. A rider that loses a MESSAGE is read
/// again.
#[test]
fn a_repeat_that_loses_a_message_is_read_again() -> Result<()> {
    use super::witnessed_turns::{allow_system_rows, message};
    use crate::memory::WitnessAuthor;
    let (_dir, vault) = open_vault();
    let person = EntityId::from_bytes([0x73; 16])?;
    vault.put_entity(&person, ENTITY_TYPE_PERSON, occurred(1), 1, b"witness")?;
    allow_system_rows(&vault, person)?;
    let conversation = EntityId::from_bytes([0x74; 16])?;
    let said = || {
        vec![
            message(0, WitnessAuthor::User, "I live in Kyoto.", true),
            message(1, WitnessAuthor::User, "I moved to Osaka.", true),
        ]
    };
    let held = witness_into(&vault, person, conversation, said());
    let at = vault.now_recorded_at();
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at)?);
    complete(&vault, &claim_micro(&vault, at + 1)?, at + 2)?;
    let again = said();
    let moved = EntityId::from_hex(again[1].id.as_deref().expect("message id"))?;
    let back = witness_into(&vault, person, conversation, again);
    assert!(!vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 3)?);

    vault
        .delete_room_record_unchecked_for_test(&moved, crate::deletion::DeleteReason::UserDelete)?;
    assert!(vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, at + 4)?);
    assert_eq!(micro_rounds(&vault)?, vec![vec![held], vec![back]]);
    Ok(())
}
