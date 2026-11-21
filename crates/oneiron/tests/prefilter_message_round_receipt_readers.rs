//! Who reads the prefilter receipts of a MESSAGE-screened round.
//!
//! A round whose screen asked for a TURN's words from its MESSAGE rows marks
//! every receipt it writes (`read_message_rows = "true"`). The vault owner
//! reads them on this device; an agent, bound to a read credential or not,
//! reads none, a page refills past them, and no caller off this device reads
//! one. The receipts of a round that asked for no MESSAGE words stay
//! readable, as before.
//!
//! Each reader assertion names the round's receipts by the `round` field
//! they carry, never by the mark, so it also fails at a commit that writes
//! no mark.
//!
//! - `the_owner_reads_every_receipt_of_a_message_screened_round`: red at
//!   9dbd7e2bb6ed (no receipt carries the mark), green from 682f1addda21.
//! - `an_agent_reads_no_receipt_of_a_message_screened_round`: red at
//!   9dbd7e2bb6ed (the bound agent reads the skip of the TURN it reads and
//!   the rollup; the unbound agent reads all three), green from 682f1addda21.
//! - `a_page_refills_past_owner_only_receipts`: red at 9dbd7e2bb6ed (the
//!   first page of one holds the MESSAGE-screened round's rollup), green
//!   from 682f1addda21.
//! - `a_caller_off_this_device_reads_no_receipt_of_a_message_screened_round`:
//!   red at b0771d74f5e0 (the owner off this device reads all three), green
//!   from 7347a13d4bf7.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test prefilter_message_round_receipt_readers`.
#![cfg(oneiron_test_support)]

use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::claim::CallerLocality;
use oneiron::dreamer_consolidation::{
    ConsolidationWatermark, WorkingSetTurn, advance_watermark, enqueue_partition_attempts,
};
use oneiron::dreamer_prefilter::{
    PREFILTER_DECISION_SKIP, PREFILTER_OUTCOME_SCREENED, PrefilterConfig,
};
use oneiron::memory::MemoryReceipt;
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::extraction_inputs::{set_extraction_prefilter, witness_extraction_turns};
use oneiron::test_support::test_host_issuer;
use oneiron::{
    DreamerConsolidationScope, EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault,
    read_watermark, scan_dirty_turns, screen_turn_inputs,
};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU8, Ordering};

/// Returns a fixture or assertion error without hiding its source.
type PrefilterMessageRoundTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// A thin TURN's words: one filler word, far below a 1.0 threshold.
const THIN_WORDS: &str = "ok";

/// The prefilter receipt `fields` keys, as literals: the `FIELD_PREFILTER_*`
/// constants (`crates/oneiron/src/store/receipt_row.rs`) are crate-private.
/// What the screen ruled: `skip` on a turn row, `screened` on a rollup.
const DECISION: &str = "decision";
/// The round a receipt belongs to, lower hex; on every prefilter receipt.
const ROUND: &str = "round";
/// The screened TURN, lower hex; skip receipts only.
const TURN: &str = "turn";
/// How many TURNs the round scanned, as a plain integer; rollups only.
const SCANNED: &str = "scanned";
/// How many TURNs the round kept, as a plain integer; rollups only.
const PASSED: &str = "passed";
/// How many TURNs the round screened out, as a plain integer; rollups only.
const SKIPPED: &str = "skipped";
/// `true` on every receipt of a round whose screen asked for MESSAGE words;
/// absent on a round that asked for none.
const READ_MESSAGE_ROWS: &str = "read_message_rows";

/// The one receipt kind every page of this file asks for.
const EXTRACTION_KIND: &str = "extraction";

/// When the inline round's receipts occurred, in Unix seconds: the older round.
const INLINE_ROUND_AT: u64 = 20;
/// When the MESSAGE-screened round's receipts occurred: the newer round.
const MESSAGE_ROUND_AT: u64 = 30;

/// The challenge the credential proofs sign, as a transport challenge does.
const CHALLENGE: &[u8] = b"oneiron-request:prefilter-message-round-readers";

/// Scans the Micro dirty set the way the consolidation door does, and returns
/// the scan with the watermark it was read under.
fn scan_micro_turns(
    vault: &Vault,
) -> PrefilterMessageRoundTestResult<(ConsolidationWatermark, Vec<WorkingSetTurn>)> {
    let watermark = read_watermark(vault, DreamerConsolidationScope::Micro)?;
    let scan = scan_dirty_turns(vault, DreamerConsolidationScope::Micro, &watermark, 10)?;
    Ok((watermark, scan))
}

/// Returns the prefilter's Extraction receipts split into skips and rollups,
/// by decision, from the engine's own unscreened read.
fn prefilter_receipts(
    vault: &Vault,
) -> PrefilterMessageRoundTestResult<(Vec<ReceiptRecord>, Vec<ReceiptRecord>)> {
    let mut skips = Vec::new();
    let mut rollups = Vec::new();
    for receipt in vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Extraction))? {
        match receipt.fields.get(DECISION).map(String::as_str) {
            Some(PREFILTER_DECISION_SKIP) => skips.push(receipt),
            Some(PREFILTER_OUTCOME_SCREENED) => rollups.push(receipt),
            other => panic!("a prefilter receipt decides skip or screened, found {other:?}"),
        }
    }
    Ok((skips, rollups))
}

/// Seeds one conversation row the inline TURNs below hang under.
fn seed_inline_conversation(vault: &Vault) -> PrefilterMessageRoundTestResult<EntityId> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        ENTITY_TYPE_CONVERSATION,
        TimeRange { start: 1, end: 1 },
        1,
        b"\x80",
    )?;
    Ok(id)
}

/// Seeds one admissible dirty TURN carrying its own words, with the
/// conversation edge the partition planner requires.
fn seed_inline_turn(
    vault: &Vault,
    conversation: &EntityId,
    learned_at: u64,
) -> PrefilterMessageRoundTestResult<EntityId> {
    let turn = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("spkr"), rmpv::Value::from("user")),
            (rmpv::Value::from("txt"), rmpv::Value::from(THIN_WORDS)),
        ]),
    )
    .map_err(|error| format!("the turn body encodes: {error}"))?;
    vault
        .batch()
        .put(
            &turn,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        )
        .edge(&turn, EdgeKind::ChildOf, conversation, 1.0)
        .commit()?;
    Ok(turn)
}

/// The next credential slip id, distinct for every credential this file mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The live `agent` credential the fixture's host mints `holder`, held to
/// `records`, verified as a transport verifies it. The issuer is the one
/// that rooted the fixture vault: a rooted vault recognizes no other host.
fn agent_credential(
    vault: &Vault,
    holder: EntityId,
    records: BTreeSet<String>,
) -> PrefilterMessageRoundTestResult<VerifiedSlip> {
    let issuer: HostSlipIssuer = test_host_issuer();
    let root = vault.ensure_host_root_slip(&issuer)?;
    let mut claims = root.claims;
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some("agent".to_owned());
    claims.records = records;
    let slip = vault.mint_capability_slip(&issuer, claims)?;
    let binding = issuer.binding_proof(&slip, CHALLENGE)?;
    Ok(vault.verify_capability_slip(&issuer.public_key(), &slip, CHALLENGE, &binding)?)
}

/// Puts one PERSON row the agent handle below binds as `Agent`.
fn put_agent_person(vault: &Vault) -> PrefilterMessageRoundTestResult<EntityId> {
    let agent = EntityId::now();
    vault.put_entity(
        &agent,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"the agent who reads receipts",
    )?;
    Ok(agent)
}

/// Whether a served `vault.receipts` row carries the MESSAGE-screened mark.
fn carries_the_mark(receipt: &MemoryReceipt) -> bool {
    receipt.fields.get(READ_MESSAGE_ROWS).map(String::as_str) == Some("true")
}

/// How many of the served `receipts` belong to `round`, by their `round` field.
fn count_of_round(receipts: &[MemoryReceipt], round: &str) -> usize {
    receipts
        .iter()
        .filter(|receipt| receipt.fields.get(ROUND).map(String::as_str) == Some(round))
        .count()
}

/// The `round` field of the skip receipt that names `turn`.
fn round_of_skip(skips: &[ReceiptRecord], turn: &EntityId) -> String {
    let wanted = turn.to_hex();
    let Some(skip) = skips
        .iter()
        .find(|skip| skip.fields.get(TURN) == Some(&wanted))
    else {
        panic!("a round skipped TURN {wanted}");
    };
    let Some(round) = skip.fields.get(ROUND) else {
        panic!("a skip receipt names its round: {}", skip.receipt_id);
    };
    round.clone()
}

/// Scans the two dirty TURNs `what` names, checks the screen skips both at
/// the stored threshold, and enqueues them as one round whose receipts occur
/// at `now`; returns the scan with the watermark it was read under.
fn skip_one_round(
    vault: &Vault,
    what: &str,
    run_id: &str,
    now: u64,
) -> PrefilterMessageRoundTestResult<(ConsolidationWatermark, Vec<WorkingSetTurn>)> {
    let policy = vault.prefilter_config()?;
    let (watermark, scan) = scan_micro_turns(vault)?;
    assert_eq!(scan.len(), 2, "the scan holds the two {what} TURNs");
    let inputs: Vec<(WorkingSetTurn, Option<String>)> = scan
        .iter()
        .map(|turn| (*turn, Some(THIN_WORDS.to_owned())))
        .collect();
    let expected = screen_turn_inputs(&policy, &inputs, &BTreeSet::new());
    for entry in &expected.verdicts {
        assert!(
            !entry.verdict.pass,
            "a perfect threshold skips the {what} TURN"
        );
    }
    enqueue_partition_attempts(
        vault,
        DreamerConsolidationScope::Micro,
        &scan,
        &watermark,
        run_id,
        now,
    )?;
    Ok((watermark, scan))
}

/// The two seeded rounds: their TURNs in scan order, and each round's id as
/// its receipts name it.
struct TwoRounds {
    /// The inline TURNs of the round whose screen asked for no MESSAGE words.
    inline_turns: Vec<EntityId>,
    /// The chat TURNs of the round whose screen asked for MESSAGE words.
    chat_turns: Vec<EntityId>,
    /// The `round` field of the inline round's three receipts.
    inline_round: String,
    /// The `round` field of the MESSAGE-screened round's three receipts.
    message_round: String,
}

/// Seeds the inline round older and the MESSAGE-screened round newer, both
/// skipped whole under a 1.0 threshold: two skips and one rollup each.
fn seed_two_rounds(vault: &Vault) -> PrefilterMessageRoundTestResult<TwoRounds> {
    set_extraction_prefilter(
        vault,
        &PrefilterConfig {
            threshold: 1.0,
            ..PrefilterConfig::default()
        },
    )?;
    assert_eq!(
        vault.prefilter_config()?.threshold,
        1.0,
        "the door stores the perfect threshold"
    );
    let conversation = seed_inline_conversation(vault)?;
    let inline_turns = vec![
        seed_inline_turn(vault, &conversation, 5)?,
        seed_inline_turn(vault, &conversation, 6)?,
    ];
    let (_, scan) = skip_one_round(vault, "inline", "run-inline", INLINE_ROUND_AT)?;
    let Some(last_learned) = scan.iter().map(|turn| turn.learned_at).max() else {
        panic!("the inline scan holds two TURNs, so a last learned second");
    };
    advance_watermark(vault, DreamerConsolidationScope::Micro, last_learned, &scan)?;
    let chat_turns = witness_extraction_turns(vault, &[THIN_WORDS, THIN_WORDS])?.turns;
    skip_one_round(vault, "chat", "run-chat", MESSAGE_ROUND_AT)?;
    let (skips, rollups) = prefilter_receipts(vault)?;
    assert_eq!(skips.len(), 4, "both rounds skip their two TURNs");
    assert_eq!(rollups.len(), 2, "both rounds roll up");
    let inline_round = round_of_skip(&skips, &inline_turns[0]);
    let message_round = round_of_skip(&skips, &chat_turns[0]);
    assert_ne!(inline_round, message_round, "the two rounds differ");
    for receipt in skips.iter().chain(&rollups) {
        let round = receipt.fields.get(ROUND);
        assert!(
            round == Some(&inline_round) || round == Some(&message_round),
            "every prefilter receipt belongs to a seeded round: {}",
            receipt.receipt_id
        );
    }
    Ok(TwoRounds {
        inline_turns,
        chat_turns,
        inline_round,
        message_round,
    })
}

/// On this device the owner reads every receipt of a MESSAGE-screened round:
/// two skips and the rollup, each with the mark, and no receipt of the
/// inline round carries it.
#[test]
fn the_owner_reads_every_receipt_of_a_message_screened_round() -> PrefilterMessageRoundTestResult<()>
{
    let dir = tempfile::tempdir()?;
    let vault = open_dreamer_vault(dir.path(), "owen")?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let rounds = seed_two_rounds(&vault)?;
    let (skips, rollups) = prefilter_receipts(&vault)?;
    for receipt in skips.iter().chain(&rollups) {
        let of_message_round = receipt.fields.get(ROUND) == Some(&rounds.message_round);
        assert_eq!(
            receipt.fields.get(READ_MESSAGE_ROWS).map(String::as_str),
            of_message_round.then_some("true"),
            "exactly the MESSAGE-screened round's receipts carry the mark: {}",
            receipt.receipt_id
        );
    }
    let Some(rollup) = rollups
        .iter()
        .find(|rollup| rollup.fields.get(ROUND) == Some(&rounds.message_round))
    else {
        panic!("the MESSAGE-screened round rolls up");
    };
    assert_eq!(
        rollup.fields.get(SCANNED).map(String::as_str),
        Some("2"),
        "the rollup counts its two scanned TURNs"
    );
    assert_eq!(
        rollup.fields.get(PASSED).map(String::as_str),
        Some("0"),
        "the rollup counts no kept TURN"
    );
    assert_eq!(
        rollup.fields.get(SKIPPED).map(String::as_str),
        Some("2"),
        "the rollup counts its two skipped TURNs"
    );
    let page = vault.memory(owner, EdgeActorClass::Human).receipts_page(
        100,
        &[EXTRACTION_KIND.to_owned()],
        None,
    )?;
    assert_eq!(
        count_of_round(&page.receipts, &rounds.message_round),
        3,
        "the owner reads all three receipts of the MESSAGE-screened round: {:?}",
        page.receipts
    );
    assert_eq!(page.receipts.len(), 6, "the owner reads both rounds");
    for receipt in &page.receipts[..3] {
        assert!(
            carries_the_mark(receipt),
            "the newer round is the marked one, and the owner's page keeps the mark: {receipt:?}"
        );
    }
    Ok(())
}

/// An agent reads no receipt of a MESSAGE-screened round, bound or unbound,
/// yet still reads the inline round's receipts it may read.
#[test]
fn an_agent_reads_no_receipt_of_a_message_screened_round() -> PrefilterMessageRoundTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_dreamer_vault(dir.path(), "owen")?;
    vault.ensure_embedded_owner_actor()?;
    let agent = put_agent_person(&vault)?;
    let rounds = seed_two_rounds(&vault)?;
    let kinds = &[EXTRACTION_KIND.to_owned()];
    let readable = BTreeSet::from([
        rounds.chat_turns[1].to_hex(),
        rounds.inline_turns[1].to_hex(),
    ]);
    let proof = agent_credential(&vault, agent, readable)?;
    let bound = vault
        .memory(agent, EdgeActorClass::Agent)
        .with_read_proof(&proof);
    let page = bound.receipts_page(100, kinds, None)?;
    assert_eq!(
        count_of_round(&page.receipts, &rounds.message_round),
        0,
        "LEAK: an agent bound to a credential that reads one of the round's TURNs reads a receipt of the MESSAGE-screened round: {:?}",
        page.receipts
    );
    assert_eq!(
        page.receipts.len(),
        2,
        "the bound agent keeps the inline round's skip of the TURN it reads, and its rollup: {:?}",
        page.receipts
    );
    let wanted = rounds.inline_turns[1].to_hex();
    let mut saw_skip = false;
    let mut saw_rollup = false;
    for receipt in &page.receipts {
        if receipt.outcome.as_str() == PREFILTER_DECISION_SKIP {
            assert_eq!(
                receipt.fields.get(TURN).map(String::as_str),
                Some(wanted.as_str()),
                "the bound skip names the readable TURN"
            );
            saw_skip = true;
        } else {
            assert_eq!(
                receipt.outcome.as_str(),
                PREFILTER_OUTCOME_SCREENED,
                "the other bound receipt is the inline round's rollup"
            );
            saw_rollup = true;
        }
    }
    assert!(
        saw_skip && saw_rollup,
        "the bound agent keeps a skip and a rollup"
    );
    let unbound = vault.memory(agent, EdgeActorClass::Agent);
    let page = unbound.receipts_page(100, kinds, None)?;
    assert_eq!(
        count_of_round(&page.receipts, &rounds.message_round),
        0,
        "LEAK: an agent bound to no credential reads a receipt of the MESSAGE-screened round: {:?}",
        page.receipts
    );
    assert_eq!(
        count_of_round(&page.receipts, &rounds.inline_round),
        3,
        "the unbound agent still reads the inline round: {:?}",
        page.receipts
    );
    Ok(())
}

/// A page refills past the owner-only receipts: each readable receipt comes
/// once, newest first, with a cursor that continues and then ends.
#[test]
fn a_page_refills_past_owner_only_receipts() -> PrefilterMessageRoundTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_dreamer_vault(dir.path(), "owen")?;
    vault.ensure_embedded_owner_actor()?;
    let agent = put_agent_person(&vault)?;
    let rounds = seed_two_rounds(&vault)?;
    let readable = BTreeSet::from([
        rounds.chat_turns[1].to_hex(),
        rounds.inline_turns[1].to_hex(),
    ]);
    let proof = agent_credential(&vault, agent, readable)?;
    let bound = vault
        .memory(agent, EdgeActorClass::Agent)
        .with_read_proof(&proof);
    let kinds = &[EXTRACTION_KIND.to_owned()];
    let first = bound.receipts_page(1, kinds, None)?;
    assert_eq!(
        count_of_round(&first.receipts, &rounds.message_round),
        0,
        "LEAK: the first page holds a receipt of the MESSAGE-screened round: {:?}",
        first.receipts
    );
    assert_eq!(
        first.receipts.len(),
        1,
        "a page of one refills to one readable"
    );
    assert_eq!(
        first.receipts[0].outcome.as_str(),
        PREFILTER_OUTCOME_SCREENED,
        "the newest readable receipt is the inline round's rollup"
    );
    let Some(after) = first.next_after.clone() else {
        panic!("a page with one more readable receipt behind it carries a cursor");
    };
    let second = bound.receipts_page(1, kinds, Some(after.as_str()))?;
    assert_eq!(
        second.receipts.len(),
        1,
        "the cursor continues to the last readable"
    );
    assert_eq!(
        second.receipts[0].outcome.as_str(),
        PREFILTER_DECISION_SKIP,
        "the last readable receipt is the inline round's skip"
    );
    let wanted = rounds.inline_turns[1].to_hex();
    assert_eq!(
        second.receipts[0].fields.get(TURN).map(String::as_str),
        Some(wanted.as_str()),
        "the skip names the readable TURN"
    );
    assert!(second.next_after.is_none(), "the end carries no cursor");
    let both = bound.receipts_page(2, kinds, None)?;
    assert_eq!(
        both.receipts.len(),
        2,
        "a page of two holds both readable receipts"
    );
    assert_eq!(
        both.receipts[0].receipt_ref, first.receipts[0].receipt_ref,
        "a wider page starts where the narrow one did"
    );
    assert_eq!(
        both.receipts[1].receipt_ref, second.receipts[0].receipt_ref,
        "a wider page ends where the narrow one did"
    );
    assert!(both.next_after.is_none(), "a full page ends with no cursor");
    Ok(())
}

/// The owner off this device reads no receipt of a MESSAGE-screened round,
/// and the page refills to the inline round's receipts, which may leave.
#[test]
fn a_caller_off_this_device_reads_no_receipt_of_a_message_screened_round()
-> PrefilterMessageRoundTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_dreamer_vault(dir.path(), "owen")?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let rounds = seed_two_rounds(&vault)?;
    let kinds = &[EXTRACTION_KIND.to_owned()];
    let on_device = vault.memory(owner, EdgeActorClass::Human);
    let page = on_device.receipts_page(100, kinds, None)?;
    assert_eq!(
        count_of_round(&page.receipts, &rounds.message_round),
        3,
        "on this device the owner reads the MESSAGE-screened round: {:?}",
        page.receipts
    );
    assert_eq!(
        count_of_round(&page.receipts, &rounds.inline_round),
        3,
        "on this device the owner reads the inline round: {:?}",
        page.receipts
    );
    let off_device = vault
        .memory(owner, EdgeActorClass::Human)
        .at(CallerLocality::OffDevice);
    let page = off_device.receipts_page(100, kinds, None)?;
    assert_eq!(
        count_of_round(&page.receipts, &rounds.message_round),
        0,
        "LEAK: off this device the owner reads a receipt of the MESSAGE-screened round: {:?}",
        page.receipts
    );
    assert_eq!(
        count_of_round(&page.receipts, &rounds.inline_round),
        3,
        "the off-device page refills to the inline round: {:?}",
        page.receipts
    );
    Ok(())
}
