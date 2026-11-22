//! A verb hook's receipt tail holds no receipt of a MESSAGE-screened prefilter round
//! (FIX PREFILTER-OWNER-ONLY-RECEIPT-REACHES-VERB-HOOK-TAIL, #10286).
//!
//! A round whose screen asked for a TURN's words from its MESSAGE rows marks its receipts,
//! and such a receipt is the vault owner's alone on this device. A verb hook is not that
//! reader: on the owner's own call too, both post hooks of the call must see none of that
//! round's receipts, and still all three of the older round whose TURNs carried their own
//! words, so the tail refills past the receipts it leaves out.
//!
//! Each assertion names a round's receipts by their `round` field, which every commit
//! writes, never by the mark: the test fails at 682f1addda21, where the tail of the owner's
//! call holds the three marked receipts whole, and passes from b0771d74f5e0 on.
//!
//! Run:
//! ```sh
//! RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features \
//!     --test prefilter_message_round_hook_tail
//! ```
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_consolidation::{
    ConsolidationWatermark, WorkingSetTurn, advance_watermark, enqueue_partition_attempts,
};
use oneiron::dreamer_prefilter::{
    PREFILTER_DECISION_SKIP, PREFILTER_OUTCOME_SCREENED, PrefilterConfig,
};
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use oneiron::runtime_hooks::{
    HookBodyRun, HookBodyRuntime, HookRunContext, InvocationId, VerbCall, VerbDomain,
};
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::{HookActorClass, PackInstallDisposition};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::extraction_inputs::{set_extraction_prefilter, witness_extraction_turns};
use oneiron::{
    DreamerConsolidationScope, EdgeKind, EntityId, TimeRange, Vault, read_watermark,
    scan_dirty_turns, screen_turn_inputs,
};
use oneiron_keystore::MemoryKeystore;
use serde_json::{Value, json};

/// The result of a fixture step in this test.
type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// A thin TURN's words: one filler word, far below a 1.0 threshold.
const THIN_WORDS: &str = "ok";
/// What the screen ruled: `skip` on a turn row, `screened` on a rollup.
const DECISION: &str = "decision";
/// The round a receipt belongs to, lower hex; on every prefilter receipt.
const ROUND: &str = "round";
/// The screened TURN, lower hex; skip receipts only.
const TURN: &str = "turn";

/// The read verb the two hooks run after.
const VERB: &str = "vault.claims.list";
/// The owner's test pack name.
const PACK: &str = "example.prefiltertail";
/// How far ahead of the wall clock the inline round's receipts occur, in
/// seconds. The tail is the eight newest receipts of the whole family, and
/// the pack install, the witness writes and the owner's call write receipts
/// at the wall clock: an hour ahead, the two rounds are the family's newest
/// however slow the host is.
const INLINE_ROUND_AHEAD_SECS: u64 = 3_600;
/// The same for the MESSAGE-screened round: one second after the inline
/// round, so its receipts take the tail's first places where none is cut.
const MESSAGE_ROUND_AHEAD_SECS: u64 = 3_601;
/// The input JSON captured for each hook body run.
static HOOK_INPUTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// The pack manifest declaring both post hooks.
const PACK_MD: &str = "---
name: example.prefiltertail
description: Two vault.claims.list post hooks answering Continue.
version: 1.0.0
kind: capability
hooks: [\"post-first\", \"post-second\"]
---
A pack whose two post hooks run on one call.
";

/// The higher-priority post hook selector.
const POST_FIRST_HOOK_MD: &str = "---
name: post-first
version: 1.0.0
verbs: [\"vault.claims.list\"]
phase: post
priority: 10
budget_ms: 1000
blocking: false
outcomes: [\"continue\"]
---
First post hook: answers Continue.
";

/// The lower-priority post hook selector.
const POST_SECOND_HOOK_MD: &str = "---
name: post-second
version: 1.0.0
verbs: [\"vault.claims.list\"]
phase: post
priority: 0
budget_ms: 1000
blocking: false
outcomes: [\"continue\"]
---
Second post hook: answers Continue.
";

/// The body installed for both hooks.
const CONTINUE_BODY_JS: &str = "return { kind: \"continue\" };\n";

/// A hook runtime that records each input and answers Continue without reading any rows.
struct ContinueRuntime;

impl HookBodyRuntime for ContinueRuntime {
    /// Captures the JSON the chain projected for this hook body.
    fn run_hook(
        &self,
        _body: &str,
        input_json: &str,
        _context: &mut HookRunContext,
        _read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
    ) -> oneiron::Result<HookBodyRun> {
        HOOK_INPUTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(input_json.to_owned());
        Ok(HookBodyRun {
            outcome_json: r#"{"kind":"continue"}"#.to_owned(),
            fuel_used: None,
            host_calls: 1,
        })
    }
}

/// Installs the owner's capability pack and checks that it bound both post hooks.
fn put_verb_pack(vault: &Vault, owner_proof: &AuthenticatedOwner) -> TestResult<()> {
    let files = vec![
        HubFile::new("PACK.md", PACK_MD),
        HubFile::new("hooks/post-first/HOOK.md", POST_FIRST_HOOK_MD),
        HubFile::new("hooks/post-first/body.js", CONTINUE_BODY_JS),
        HubFile::new("hooks/post-second/HOOK.md", POST_SECOND_HOOK_MD),
        HubFile::new("hooks/post-second/body.js", CONTINUE_BODY_JS),
    ];
    let disposition = vault.put_pack(owner_proof, files)?;
    let PackInstallDisposition::Installed(receipt) = disposition else {
        panic!("FIXTURE: the owner installs the hook pack: {disposition:?}");
    };
    assert_eq!(
        receipt.pack_name, PACK,
        "FIXTURE: the owner installs this pack"
    );
    let bindings = vault
        .pack_hook_bindings()?
        .into_iter()
        .filter(|(_, binding)| binding.pack == PACK)
        .count();
    assert_eq!(bindings, 2, "FIXTURE: the pack binds both post hooks");
    Ok(())
}

/// Runs the canonical pre and post chains for one owner read with the given result.
fn run_verb_call_with(vault: &Vault, actor: EntityId, result: Value) -> TestResult<InvocationId> {
    let invocation = InvocationId::mint();
    let call = VerbCall {
        verb: VERB.to_owned(),
        invocation,
        actor,
        class: HookActorClass::Human,
        scope: None,
        board_epoch: None,
        turn: None,
        domain: VerbDomain::Read,
        reader: None,
    };
    let check = |_: &Value| -> std::result::Result<(), String> { Ok(()) };
    let pre = vault.pre_verb_hooks(call, json!({}), &check)?;
    let Ok(pre) = pre else {
        panic!(
            "FIXTURE: the pre chain passes with no pre hook: {:?}",
            pre.err()
        );
    };
    let post = vault.post_verb_hooks(pre, result)?;
    let Ok(_) = post else {
        panic!(
            "FIXTURE: the post chain admits both Continues: {:?}",
            post.err()
        );
    };
    Ok(invocation)
}

/// Returns one receipt tail for each hook body run of this invocation.
fn tails_of(invocation: InvocationId) -> TestResult<Vec<Vec<Value>>> {
    let want = invocation.to_hex();
    let inputs = HOOK_INPUTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut tails = Vec::new();
    for input in &*inputs {
        let input: Value = serde_json::from_str(input)?;
        if input.get("invocation").and_then(Value::as_str) == Some(want.as_str()) {
            let tail = input
                .get("receipt_tail")
                .and_then(Value::as_array)
                .ok_or("FIXTURE: the hook input carries a receipt_tail array")?;
            tails.push(tail.clone());
        }
    }
    Ok(tails)
}

/// Counts the JSON receipts of `round` without looking at the MESSAGE-screened mark.
fn count_of_round(tail: &[Value], round: &str) -> usize {
    tail.iter()
        .filter(|receipt| receipt.pointer("/fields/round").and_then(Value::as_str) == Some(round))
        .count()
}

/// Scans the Micro dirty set the way the consolidation door does, and returns
/// the scan with the watermark it was read under.
fn scan_micro_turns(vault: &Vault) -> TestResult<(ConsolidationWatermark, Vec<WorkingSetTurn>)> {
    let watermark = read_watermark(vault, DreamerConsolidationScope::Micro)?;
    let scan = scan_dirty_turns(vault, DreamerConsolidationScope::Micro, &watermark, 10)?;
    Ok((watermark, scan))
}

/// Returns the prefilter's Extraction receipts split into skips and rollups,
/// by decision, from the engine's own unscreened read.
fn prefilter_receipts(vault: &Vault) -> TestResult<(Vec<ReceiptRecord>, Vec<ReceiptRecord>)> {
    let mut skips = Vec::new();
    let mut rollups = Vec::new();
    for receipt in vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Extraction))? {
        match receipt.fields.get(DECISION).map(String::as_str) {
            Some(PREFILTER_DECISION_SKIP) => skips.push(receipt),
            Some(PREFILTER_OUTCOME_SCREENED) => rollups.push(receipt),
            other => {
                return Err(format!(
                    "a prefilter receipt decides skip or screened, found {other:?}"
                )
                .into());
            }
        }
    }
    Ok((skips, rollups))
}

/// Seeds one conversation row the inline TURNs below hang under.
fn seed_inline_conversation(vault: &Vault) -> TestResult<EntityId> {
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
) -> TestResult<EntityId> {
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
) -> TestResult<(ConsolidationWatermark, Vec<WorkingSetTurn>)> {
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
fn seed_two_rounds(
    vault: &Vault,
    inline_round_at: u64,
    message_round_at: u64,
) -> TestResult<TwoRounds> {
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
    let (_, scan) = skip_one_round(vault, "inline", "run-inline", inline_round_at)?;
    let Some(last_learned) = scan.iter().map(|turn| turn.learned_at).max() else {
        panic!("the inline scan holds two TURNs, so a last learned second");
    };
    advance_watermark(vault, DreamerConsolidationScope::Micro, last_learned, &scan)?;
    let chat_turns = witness_extraction_turns(vault, &[THIN_WORDS, THIN_WORDS])?.turns;
    skip_one_round(vault, "chat", "run-chat", message_round_at)?;
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

/// Neither post hook sees a MESSAGE-screened receipt on the owner's own call.
/// Both still see every receipt of the inline round.
#[test]
fn a_verb_hook_tail_holds_no_receipt_of_a_message_screened_round_on_the_owners_call()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let vault = open_dreamer_vault(directory.path(), "owen")?;
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.install_hook_runtime(Arc::new(ContinueRuntime))?;
    vault.prepare_install_signing()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let owner_proof =
        vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    put_verb_pack(&vault, &owner_proof)?;

    // testkit-lint: allow(wall-clock) the rounds must sort after receipts written at wall time
    let wall = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let rounds = seed_two_rounds(
        &vault,
        wall + INLINE_ROUND_AHEAD_SECS,
        wall + MESSAGE_ROUND_AHEAD_SECS,
    )?;
    let invocation = run_verb_call_with(&vault, owner, json!({"rows": []}))?;
    let tails = tails_of(invocation)?;
    assert_eq!(
        tails.len(),
        2,
        "FIXTURE: both post hooks ran on the owner's call"
    );
    for (index, tail) in tails.iter().enumerate() {
        assert_eq!(
            count_of_round(tail, &rounds.message_round),
            0,
            "LEAK: post hook {index} sees a receipt of the MESSAGE-screened round \
             (TURNs {:?}): {tail:?}",
            rounds.chat_turns,
        );
        assert_eq!(
            count_of_round(tail, &rounds.inline_round),
            3,
            "MISSING: post hook {index} must still see all of the inline round's receipts \
             (TURNs {:?}) past the round it leaves out: {tail:?}",
            rounds.inline_turns,
        );
    }
    Ok(())
}
