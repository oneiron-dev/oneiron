//! Review round 2 (REVIEW-9956): a turn's claim and its answer stay one
//! holder's. A leader answers an unaddressed turn only on the claim it holds,
//! even through the live DAG reply door, which takes no claim (finding 2). A
//! name or a task keeps no claim for a holder the witness would refuse
//! (finding 3). An answer seals its claim against another machine's
//! concurrent takeover, in either order (finding 1). Each of these four is
//! red at the round-1 head 995d059b623.
//!
//! The own review of round 2 added the two erased-claim tests: the seal
//! writes no live copy of a claim back over its erased form (FIX 4870). Both
//! are green at 995d059b623, which had no seal, and red at the round-2 head
//! 33a9d1322fe.

use oneiron::conversation_dag::{AddressMode, AppendRecord};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::{EdgeActorClass, EntityId, MemoryError, TimeRange, WriteActor};

use super::{Fixture, TestResult, claimed_by, claimed_receipt, generation};

/// `agent`'s reply to owen's trunk turn `asked` through the DAG's thread
/// reply door, which answers `asked` and takes no claim. Returns the
/// record's id, or the door's refusal.
fn dag_reply(
    fixture: &Fixture,
    agent: EntityId,
    asked: EntityId,
) -> TestResult<Result<EntityId, MemoryError>> {
    let now = fixture.vault.now_recorded_at();
    let input = AppendRecord {
        conversation: fixture.room,
        parent: None,
        reply_to: Some(asked),
        quote: None,
        address: AddressMode::Broadcast,
        recipients: vec![],
        advance: false,
        kind: ENTITY_TYPE_TURN,
        containing_turn: None,
        occurred: TimeRange {
            start: now,
            end: now,
        },
        learned_at: now,
        body: rmp_serde::to_vec_named(&serde_json::json!({"txt": "answer"}))?,
        text: vec![],
        session: None,
        actor: WriteActor::new(agent, EdgeActorClass::Agent),
        thread_audience: None,
    };
    Ok(fixture
        .vault
        .reply_in_thread(&fixture.agent(agent), asked, &input)
        .map(|appended| appended.id))
}

/// REVIEW-9956 round 2, finding 2: owen claims his own turn that names no
/// agent, so he holds it. The leader's live DAG reply to it is refused: the
/// leader answers such a turn only on the claim it holds.
///
/// Green on main (the turn speaks to no agent there); red at the round-1
/// head, where the reply lands past owen's claim.
#[test]
fn a_leaders_dag_reply_needs_the_turns_claim() -> TestResult {
    let fixture = Fixture::open()?;
    let asked = fixture.owen_speaks(serde_json::json!({}))?;
    let held = fixture
        .owen()
        .rooms_claim(fixture.room, asked, fixture.vault.now_recorded_at())?;
    assert!(
        claimed_by(&held, fixture.owen),
        "owen holds his own turn: {held:?}"
    );
    let replied = dag_reply(&fixture, fixture.lead, asked)?;
    assert!(
        replied.is_err(),
        "the leader's DAG reply lands past owen's claim: {replied:?}"
    );
    Ok(())
}

/// REVIEW-9956 round 2, finding 3: a name keeps no claim for a holder the
/// witness would refuse. owen's turn names `lead` and `other`; `lead` claims
/// it. The owner then makes `other` the leader and takes `lead` off the
/// roster, so `lead` stands in the room no more and its answer is refused.
/// `other`, named too, takes the claim over and answers.
///
/// Red on main and at the round-1 head: `other`'s claim settles HeldBy
/// `lead`'s, which its name kept.
#[test]
fn a_name_keeps_no_claim_for_a_holder_without_standing() -> TestResult {
    let fixture = Fixture::open()?;
    fixture
        .vault
        .bind_room_handle(fixture.room, "@lead", fixture.lead)?;
    let asked = fixture.owen_speaks(serde_json::json!({"room_mentions": ["@lead", "@other"]}))?;
    claimed_receipt(fixture.claim(fixture.lead, asked)?)?;
    fixture.replace_leader()?;
    let mut record = fixture
        .vault
        .project(fixture.project)?
        .ok_or("the project reads")?;
    record
        .roster
        .retain(|seated| *seated != fixture.lead.to_hex());
    fixture
        .vault
        .put_project(fixture.project, &record, fixture.vault.now_recorded_at())?;

    let taken = claimed_receipt(fixture.claim(fixture.other, asked)?)?;
    assert_eq!(taken.actor, fixture.other.to_hex(), "other holds the turn");
    assert_eq!(generation(&taken)?, 1, "other's claim took lead's over");
    assert!(
        fixture.reply(fixture.lead, asked).is_err(),
        "lead's late answer is refused"
    );
    let answer = fixture.reply(fixture.other, asked)?;
    assert!(
        fixture.landed(answer, fixture.other)?,
        "other's answer lands"
    );
    Ok(())
}

/// REVIEW-9956 round 2, finding 1, this vault answered first: `lead` claims
/// and answers owen's turn, and the owner then makes `other` the leader.
/// Another machine, which had not seen the answer, carries `other`'s
/// takeover of `lead`'s claim. The answered claim stands, and `other` finds
/// the turn held.
///
/// Red at the round-1 head: the carried takeover replaces the answered
/// claim, by its higher generation.
#[cfg(oneiron_test_support)]
#[test]
fn an_answered_claim_stands_over_a_carried_takeover() -> TestResult {
    use oneiron::test_doors::room_turn_claims::{held_claim, merge_replicated_claim};
    use oneiron::workspace_roster::{RoomClaimOutcome, RoomClaimReceipt};

    let fixture = Fixture::open()?;
    let asked = fixture.owen_speaks(serde_json::json!({}))?;
    let answered = claimed_receipt(fixture.claim(fixture.lead, asked)?)?;
    fixture.reply(fixture.lead, asked)?;
    fixture.replace_leader()?;

    let mut carried = serde_json::to_value(&answered)?;
    carried["actor"] = serde_json::json!(fixture.other.to_hex());
    carried["receipt_ref"] = serde_json::json!("rooms.claim:replica-takeover");
    carried["at"] = serde_json::json!(answered.at + 1);
    carried["generation"] = serde_json::json!(1);
    let carried: RoomClaimReceipt = serde_json::from_value(carried)?;
    merge_replicated_claim(&fixture.vault, &carried)?;
    assert_eq!(
        held_claim(&fixture.vault, asked)?,
        Some(answered.clone()),
        "the answered claim still holds the turn"
    );
    assert_eq!(
        fixture.claim(fixture.other, asked)?,
        RoomClaimOutcome::HeldBy(answered),
        "other finds the answered turn held"
    );
    Ok(())
}

/// REVIEW-9956 round 2, finding 1, this vault took over first: `lead`
/// claims owen's turn, the owner makes `other` the leader, and `other`
/// takes the claim over here. Another machine, which had not seen the
/// takeover, carries `lead`'s answer with `lead`'s claim. The answer seals
/// `lead`'s claim, which holds the turn again, and `other` finds it held.
///
/// Red at the round-1 head: the response merge reads no carried claim, so
/// `other`'s takeover keeps holding a turn `lead` answered.
#[cfg(oneiron_test_support)]
#[test]
fn a_carried_answer_restores_the_claim_it_answered() -> TestResult {
    use oneiron::test_doors::room_turn_claims::{held_claim, merge_replicated_answer};
    use oneiron::workspace_roster::RoomClaimOutcome;

    let fixture = Fixture::open()?;
    let asked = fixture.owen_speaks(serde_json::json!({}))?;
    let answered = claimed_receipt(fixture.claim(fixture.lead, asked)?)?;
    fixture.replace_leader()?;
    let taken = claimed_receipt(fixture.claim(fixture.other, asked)?)?;
    assert_eq!(
        taken.actor,
        fixture.other.to_hex(),
        "other took the turn over"
    );

    merge_replicated_answer(
        &fixture.vault,
        fixture.room,
        asked,
        EntityId::now(),
        fixture.lead,
        fixture.vault.now_recorded_at(),
        std::slice::from_ref(&answered),
    )?;
    assert_eq!(
        held_claim(&fixture.vault, asked)?,
        Some(answered.clone()),
        "lead's answered claim holds the turn again"
    );
    assert_eq!(
        fixture.claim(fixture.other, asked)?,
        RoomClaimOutcome::HeldBy(answered),
        "other finds the answered turn held"
    );
    Ok(())
}

/// The erased form of `receipt`, as a machine that erased its actor carries
/// it: the same receipt, naming no one.
#[cfg(oneiron_test_support)]
fn erased_copy(
    receipt: &oneiron::workspace_roster::RoomClaimReceipt,
) -> oneiron::workspace_roster::RoomClaimReceipt {
    let mut erased = receipt.clone();
    erased.actor = oneiron::receipt::ERASED_CALL_IDENTITY.to_owned();
    erased
}

/// REVIEW-9956 round 2, own review (FIX 4870): `lead` claims and answers
/// owen's turn. Another machine carries the erased form of `lead`'s claim,
/// which stands here, as the erased form wins where copies meet. A third
/// machine still carries the live copy of that receipt: the answer seals no
/// live copy back over the erased form.
///
/// Red at the round-2 head 33a9d1322fe: the claim merge's seal writes the
/// live copy back, since `lead` spoke the held answer.
#[cfg(oneiron_test_support)]
#[test]
fn an_answer_seals_no_live_copy_over_an_erased_claim() -> TestResult {
    use oneiron::test_doors::room_turn_claims::{held_claim, merge_replicated_claim};

    let fixture = Fixture::open()?;
    let asked = fixture.owen_speaks(serde_json::json!({}))?;
    let answered = claimed_receipt(fixture.claim(fixture.lead, asked)?)?;
    fixture.reply(fixture.lead, asked)?;
    let erased = erased_copy(&answered);
    assert_eq!(
        merge_replicated_claim(&fixture.vault, &erased)?,
        "Written",
        "the erased form of the claim stands"
    );
    merge_replicated_claim(&fixture.vault, &answered)?;
    assert_eq!(
        held_claim(&fixture.vault, asked)?,
        Some(erased),
        "the live copy of an erased claim changes nothing"
    );
    Ok(())
}

/// REVIEW-9956 round 2, own review (FIX 4870): `lead` claims owen's turn,
/// and another machine's erased form of that claim stands here. A third
/// machine carries `lead`'s answer with the live copy of the claim: the
/// answer seals no live copy back over the erased form.
///
/// Red at the round-2 head 33a9d1322fe: the response merge leaves the
/// erased form out and writes the live copy as the answered claim.
#[cfg(oneiron_test_support)]
#[test]
fn a_carried_answer_seals_no_live_copy_over_an_erased_claim() -> TestResult {
    use oneiron::test_doors::room_turn_claims::{
        held_claim, merge_replicated_answer, merge_replicated_claim,
    };

    let fixture = Fixture::open()?;
    let asked = fixture.owen_speaks(serde_json::json!({}))?;
    let answered = claimed_receipt(fixture.claim(fixture.lead, asked)?)?;
    let erased = erased_copy(&answered);
    assert_eq!(
        merge_replicated_claim(&fixture.vault, &erased)?,
        "Written",
        "the erased form of the claim stands"
    );
    merge_replicated_answer(
        &fixture.vault,
        fixture.room,
        asked,
        EntityId::now(),
        fixture.lead,
        fixture.vault.now_recorded_at(),
        std::slice::from_ref(&answered),
    )?;
    assert_eq!(
        held_claim(&fixture.vault, asked)?,
        Some(erased),
        "the carried answer seals no live copy over the erased claim"
    );
    Ok(())
}
