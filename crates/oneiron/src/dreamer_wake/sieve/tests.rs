//! The sieve against the packet's checks (gate 3, ARCH-0026 Continuous): a
//! turn chunk with a date and a name gets both flags and queues them by
//! score; a restart keeps the queue and the cursor and reads nothing twice;
//! saved oneiroNER tags stand in for the rule names, and a save that lands
//! after the sieve read the turn owes it a new read. Then the review's
//! repros: what the Dreamer may not read, a long turn read across passes,
//! and grants written while turns wait.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::*;
use crate::edge::EdgeActorClass;
use crate::memory::extraction::{EncoderInput, EncoderOutput, ExtractionEncoder, NerSpan};
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::ports::ManualClock;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::tagging::{TaggingMarkerConfig, TaggingMode, TaggingReconciler};
use crate::temporal::TimeRange;
use crate::{ModelId, VaultConfig};

const NOW: u64 = 1_790_000_000;
const ROOM: &str = "52525252525252525252525252525252";

fn witness(vault: &Vault, turn_ref: &str, text: &str) -> EntityId {
    witness_with(vault, turn_ref, text, NOW, None)
}

fn witness_with(
    vault: &Vault,
    turn_ref: &str,
    text: &str,
    occurred_at: u64,
    metadata: Option<serde_json::Value>,
) -> EntityId {
    let message = WitnessMessage {
        id: None,
        author: WitnessAuthor::User,
        message_type: "text".into(),
        content: text.into(),
        metadata,
        is_visible: true,
        order: 0,
    };
    witness_messages(vault, turn_ref, occurred_at, vec![message])
}

/// A visible user MESSAGE with the id `id`.
fn message(
    id: &str,
    text: &str,
    order: u32,
    metadata: Option<serde_json::Value>,
) -> WitnessMessage {
    WitnessMessage {
        id: Some(id.to_owned()),
        author: WitnessAuthor::User,
        message_type: "text".into(),
        content: text.into(),
        metadata,
        is_visible: true,
        order,
    }
}

fn witness_messages(
    vault: &Vault,
    turn_ref: &str,
    occurred_at: u64,
    messages: Vec<WitnessMessage>,
) -> EntityId {
    let speaker = EntityId::from_bytes([0x21; 16]).expect("speaker id");
    if vault.get(&speaker).expect("speaker read").is_none() {
        vault
            .put_entity(
                &speaker,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&serde_json::json!({ "name": "speaker" })).expect("body"),
            )
            .expect("speaker");
    }
    let turn = WitnessTurn {
        conversation_ref: ROOM.into(),
        turn_ref: Some(turn_ref.to_owned()),
        occurred_at,
        messages,
    };
    vault
        .memory(speaker, EdgeActorClass::Human)
        .witness(&turn)
        .expect("witness");
    EntityId::from_hex(turn_ref).expect("turn id")
}

/// Lets the Dreamer read the MESSAGE rows of `space`, under grant id
/// `[id; 16]`.
fn grant_messages_read(vault: &Vault, id: u8, space: EntityId) {
    use crate::access_grant::{
        AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
    };
    let dreamer = vault.dreamer_authority().expect("dreamer").entity_ref();
    vault
        .create_access_grant(
            &EntityId::from_bytes([id; 16]).expect("grant id"),
            &AccessGrant {
                principal_ref: dreamer,
                scope: AccessGrantScope::Messages { space_ref: space },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: 1,
                revoked_at: None,
                expires_at: Some(u64::MAX),
                authority_scope: crate::federation::scope_codec::read_preset(),
            },
        )
        .expect("grant");
}

/// Runs passes from `now` until one leaves no work; returns how many ran.
fn drain(vault: &Vault, now: u64) -> u64 {
    let mut passes = 0;
    while vault.sieve_pass(now + passes).expect("pass").more {
        passes += 1;
        assert!(passes < 1_000, "the sieve never settles");
    }
    passes + 1
}

/// A fake oneiroNER tagger: each word it knows is a `PERSON`. It names the
/// served `stack` beside its checkpoint when it has one.
struct Names {
    model: ModelId,
    known: Vec<&'static str>,
    stack: Option<&'static str>,
}

impl ExtractionEncoder for Names {
    fn model_id(&self) -> &ModelId {
        &self.model
    }
    fn locality(&self) -> crate::embed::EmbedderLocality {
        crate::embed::EmbedderLocality::OnDevice
    }
    fn infer(&self, input: &EncoderInput) -> crate::Result<EncoderOutput> {
        let mut spans = Vec::new();
        for (message, each) in input.messages.iter().enumerate() {
            for name in &self.known {
                if let Some(start) = each.text.find(name) {
                    spans.push(NerSpan {
                        message,
                        start,
                        end: start + name.len(),
                        label: "PERSON".to_owned(),
                        confidence: 0.9,
                    });
                }
            }
        }
        Ok(EncoderOutput {
            spans,
            links: Vec::new(),
            vad: None,
            context_links: Vec::new(),
            speaker_links: Vec::new(),
            stack_sha16: self.stack.map(str::to_owned),
        })
    }
}

fn open(path: &std::path::Path, tagging: bool) -> Arc<Vault> {
    let mut config = VaultConfig::device();
    config.store_clock = ManualClock::new(NOW).bundle();
    if tagging {
        config.tagging = Some(
            TaggingMarkerConfig::new("0123456789abcdef")
                .expect("checkpoint")
                .with_labels(BTreeMap::from([("PERSON".to_owned(), ENTITY_TYPE_PERSON)]))
                .with_mode(TaggingMode::Save),
        );
    }
    Arc::new(Vault::open(path, config).expect("open vault"))
}

/// Every queued span of `turn` as (kind, its words, its origin's tag),
/// in text order.
fn flags(vault: &Vault, turn: &EntityId, text: &str) -> Vec<(SpanKind, String, &'static str)> {
    let mut spans: Vec<_> = vault
        .sieve_queue(usize::MAX)
        .expect("queue")
        .spans
        .into_iter()
        .filter(|span| span.turn == *turn)
        .collect();
    spans.sort_by_key(|span| span.start);
    spans
        .iter()
        .map(|span| {
            let origin = match span.origin {
                SpanOrigin::Rule { .. } => "rule",
                SpanOrigin::SavedTag { .. } => "tag",
            };
            (
                span.kind,
                text[span.start as usize..span.end as usize].to_owned(),
                origin,
            )
        })
        .collect()
}

#[test]
fn a_turn_with_a_date_and_a_name_queues_both_by_score_and_a_restart_reads_nothing_twice() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), false);
    let text = "We met Alice Smith on October 12, 2026.";
    let turn = witness(&vault, "71717171717171717171717171717171", text);

    let pass = vault.sieve_pass(NOW).expect("pass");
    assert_eq!((pass.turns_read, pass.spans_queued), (1, 2));
    assert_eq!(
        flags(&vault, &turn, text),
        vec![
            (SpanKind::Name, "Alice Smith".to_owned(), "rule"),
            (SpanKind::Date, "October 12, 2026".to_owned(), "rule"),
        ]
    );
    let queue = vault.sieve_queue(usize::MAX).expect("queue").spans;
    assert_eq!(queue[0].kind, SpanKind::Date, "the surer date leads");
    assert!(queue.windows(2).all(|pair| pair[0].score >= pair[1].score));
    // No model rung has run: every span waits on the novelty question.
    assert!(
        queue
            .iter()
            .all(|span| span.owed.contains(&SieveRung::Novelty))
    );

    drop(vault);
    let vault = open(dir.path(), false);
    assert_eq!(vault.sieve_queue(usize::MAX).expect("queue").spans, queue);
    assert_eq!(
        vault.sieve_pass(NOW + 1).expect("pass"),
        SievePass::default()
    );
    assert_eq!(vault.sieve_queue(usize::MAX).expect("queue").spans, queue);

    // The cursor stood: a new turn is the only thing the next pass reads.
    let next = "Ken joins next week.";
    let later = witness(&vault, "72727272727272727272727272727272", next);
    let pass = vault.sieve_pass(NOW + 2).expect("pass");
    assert_eq!(pass.turns_read, 1);
    assert_eq!(
        flags(&vault, &later, next),
        vec![
            (SpanKind::Name, "Ken".to_owned(), "rule"),
            (SpanKind::Date, "next week".to_owned(), "rule"),
        ]
    );
    let uncertain = vault
        .sieve_queue(usize::MAX)
        .expect("queue")
        .spans
        .into_iter()
        .find(|span| span.turn == later && span.kind == SpanKind::Name)
        .expect("the opening name");
    assert_eq!(uncertain.band, SpanBand::Uncertain);
    assert_eq!(uncertain.owed, vec![SieveRung::Novelty, SieveRung::Typing]);
    assert_eq!(vault.sieve_queue(usize::MAX).expect("queue").spans.len(), 4);
}

#[test]
fn saved_tags_stand_in_for_the_rule_names_once_the_tagger_saves_them() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let text = "Ada met Mirela on 2026-10-12.";
    let turn = witness(&vault, "73737373737373737373737373737373", text);

    // No tags yet: the rules name both.
    vault.sieve_pass(NOW).expect("pass");
    assert_eq!(
        flags(&vault, &turn, text),
        vec![
            (SpanKind::Name, "Ada".to_owned(), "rule"),
            (SpanKind::Name, "Mirela".to_owned(), "rule"),
            (SpanKind::Date, "2026-10-12".to_owned(), "rule"),
        ]
    );

    // The tagger saves its tags after the sieve read the turn: the save owes
    // the turn a read, and its names now come from the tag set alone.
    let tagger: Arc<dyn ExtractionEncoder> = Arc::new(Names {
        model: "fixture/names@v1".parse().expect("model id"),
        known: vec!["Mirela"],
        stack: None,
    });
    TaggingReconciler::new(Arc::clone(&vault), tagger)
        .expect("reconciler")
        .drain_once()
        .expect("drain");
    assert!(vault.turn_tags(&turn).expect("tags").is_some());
    let pass = vault.sieve_pass(NOW + 1).expect("pass");
    assert_eq!((pass.turns_read, pass.spans_retired), (1, 3));
    assert_eq!(
        flags(&vault, &turn, text),
        vec![
            (SpanKind::Name, "Mirela".to_owned(), "tag"),
            (SpanKind::Date, "2026-10-12".to_owned(), "rule"),
        ]
    );
    // Read once: the next pass finds nothing owed.
    assert_eq!(
        vault.sieve_pass(NOW + 2).expect("pass"),
        SievePass::default()
    );
}

/// CodeRabbit (#1418): the version of a tag set left the served stack out,
/// so the tags a head swap saved at the same checkpoint read as the set the
/// sieve had read, and its spans went on indexing the old set's mentions. A
/// head swap is another derivation: its save owes the turn a read, and the
/// names come from the new set.
#[test]
fn a_head_swap_at_one_checkpoint_reads_the_new_tags_names() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let text = "Ada met Mirela on 2026-10-12.";
    let turn = witness(&vault, "74747474747474747474747474747474", text);
    let tag = |stack: &'static str, known: Vec<&'static str>| {
        let tagger: Arc<dyn ExtractionEncoder> = Arc::new(Names {
            model: "fixture/names@v1".parse().expect("model id"),
            known,
            stack: Some(stack),
        });
        TaggingReconciler::new(Arc::clone(&vault), tagger)
            .expect("reconciler")
            .drain_once()
            .expect("drain");
        vault.turn_tags(&turn).expect("tags").expect("saved tags")
    };
    let before = tag("aaaaaaaaaaaaaaaa", vec!["Mirela"]);
    vault.sieve_pass(NOW).expect("pass");
    assert_eq!(
        flags(&vault, &turn, text),
        vec![
            (SpanKind::Name, "Mirela".to_owned(), "tag"),
            (SpanKind::Date, "2026-10-12".to_owned(), "rule"),
        ]
    );

    // The served head swaps at the same checkpoint and the turn is tagged
    // again: the same input, tagger, save path and parameters.
    vault
        .with_write_txn(|txn| crate::tagging::mark_turn_in_txn(&vault, txn, turn))
        .expect("mark");
    let after = tag("bbbbbbbbbbbbbbbb", vec!["Ada"]);
    assert_eq!(vault.sieve_pass(NOW + 1).expect("pass").turns_read, 1);
    assert_eq!(
        flags(&vault, &turn, text),
        vec![
            (SpanKind::Name, "Ada".to_owned(), "tag"),
            (SpanKind::Date, "2026-10-12".to_owned(), "rule"),
        ]
    );
    assert_eq!(
        crate::tagging::DerivationEnvelope {
            stack: before.envelope.stack.clone(),
            ..after.envelope.clone()
        },
        before.envelope,
        "only the stack differs"
    );
    assert_ne!(
        read::envelope_digest(&before.envelope),
        read::envelope_digest(&after.envelope)
    );
}

/// Astra-1418 (P2): a new turn that claims a time behind the sieve's cursor
/// was never read: the forward scan starts past the cursor, and the late
/// sweep reads only the cursor's own second. A new TURN is owed its first
/// read where it is written, and a restart keeps that.
#[test]
fn a_new_turn_dated_behind_the_cursor_is_read() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), false);
    witness(
        &vault,
        "74747474747474747474747474747474",
        "Ken joins next week.",
    );
    vault.sieve_pass(NOW).expect("pass");
    let text = "We met Alice Smith on October 12, 2026.";
    let late = witness_with(
        &vault,
        "75757575757575757575757575757575",
        text,
        NOW - 1_000,
        None,
    );

    drop(vault);
    let vault = open(dir.path(), false);
    let pass = vault.sieve_pass(NOW + 1).expect("pass");
    assert_eq!(pass.turns_read, 1);
    assert_eq!(
        flags(&vault, &late, text),
        vec![
            (SpanKind::Name, "Alice Smith".to_owned(), "rule"),
            (SpanKind::Date, "October 12, 2026".to_owned(), "rule"),
        ]
    );
}

/// Astra-1418 (P2): the sieve read MESSAGE rows unscoped, so a private row
/// and a relationship row the Dreamer holds no grant for gave spans. The
/// sieve reads what the Dreamer may read, and a grant written later owes
/// the waiting turn a read.
#[test]
fn words_the_dreamer_may_not_read_give_no_span_until_a_grant_lets_it() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), false);
    let space = EntityId::from_bytes([0x5a; 16]).expect("space id");
    let text = "We met Alice Smith on October 12, 2026.";
    let private = witness_with(
        &vault,
        "76767676767676767676767676767676",
        text,
        NOW,
        Some(serde_json::json!({"scope": {"private": true}})),
    );
    let related = witness_with(
        &vault,
        "77777777777777777777777777777777",
        text,
        NOW,
        Some(serde_json::json!({"rel": space.to_hex()})),
    );
    vault.sieve_pass(NOW).expect("pass");
    assert!(flags(&vault, &private, text).is_empty());
    assert!(flags(&vault, &related, text).is_empty());

    grant_messages_read(&vault, 0x5b, space);
    let pass = vault.sieve_pass(NOW + 1).expect("pass");
    assert_eq!(pass.turns_read, 1);
    assert_eq!(flags(&vault, &related, text).len(), 2);
    assert!(flags(&vault, &private, text).is_empty());
}

/// Astra-1418 (P2): one turn's flood of dates and katakana names was read
/// whole in the wake's write transaction, every name checked against every
/// date. Overlaps are found in one ordered sweep, and a pass reads at most
/// the policy row's bytes (32 KiB shipped): the turn reads on pass after
/// pass, and a restart between passes neither loses a span nor queues one
/// twice.
#[test]
fn a_flood_is_read_pass_after_pass_within_the_bound() {
    const BOUND: u32 = 32 * 1024;
    let dir = tempfile::tempdir().expect("dir");
    let mut vault = open(dir.path(), false);
    let text = "アリス 2026-10-12 ".repeat(20_000);
    let turn = witness(&vault, "78787878787878787878787878787878", &text);
    let spans_of = |vault: &Vault| -> Vec<(u32, u32)> {
        let mut spans: Vec<_> = vault
            .sieve_queue(usize::MAX)
            .expect("queue")
            .spans
            .into_iter()
            .filter(|span| span.turn == turn)
            .map(|span| (span.start, span.end))
            .collect();
        spans.sort_unstable();
        spans
    };
    let mut passes = 0;
    loop {
        let before = spans_of(&vault);
        let pass = vault.sieve_pass(NOW + passes).expect("pass");
        let after = spans_of(&vault);
        let read: Vec<_> = after
            .iter()
            .filter(|span| before.binary_search(span).is_err())
            .collect();
        if let (Some(first), Some(last)) = (read.first(), read.last()) {
            assert!(
                last.1 - first.0 <= BOUND,
                "pass {passes} read past the bound"
            );
        }
        passes += 1;
        if passes == 3 {
            drop(vault);
            vault = open(dir.path(), false);
        }
        if !pass.more {
            break;
        }
    }
    assert!(passes > 2, "the flood takes more than one pass");
    let spans = spans_of(&vault);
    assert_eq!(spans.len(), 40_000);
    assert!(spans.windows(2).all(|pair| pair[0].1 <= pair[1].0));
}

/// Sol R10 (P2): a turn re-read with the same readable words returned
/// before it noted a newly withheld MESSAGE, so a grant written later never
/// read that MESSAGE. The wait for a grant is noted on every read.
#[test]
fn a_message_withheld_beside_unchanged_words_is_read_once_a_grant_lets_it() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), false);
    let space = EntityId::from_bytes([0x5c; 16]).expect("space id");
    let turn_ref = "79797979797979797979797979797979";
    let (first, second) = (
        "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a",
        "7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b",
    );
    let turn = witness_messages(
        &vault,
        turn_ref,
        NOW,
        vec![message(first, "We met Alice.", 0, None)],
    );
    drain(&vault, NOW);
    witness_messages(
        &vault,
        turn_ref,
        NOW,
        vec![message(
            second,
            "Bob arrives tomorrow.",
            1,
            Some(serde_json::json!({"rel": space.to_hex()})),
        )],
    );
    drain(&vault, NOW + 10);
    let second = EntityId::from_hex(second).expect("message id");
    let of_second = |vault: &Vault| {
        vault
            .sieve_queue(usize::MAX)
            .expect("queue")
            .spans
            .into_iter()
            .filter(|span| span.turn == turn && span.source == second)
            .count()
    };
    assert_eq!(of_second(&vault), 0, "the Dreamer may not read it yet");

    grant_messages_read(&vault, 0x5d, space);
    drain(&vault, NOW + 20);
    assert_eq!(of_second(&vault), 2, "Bob and tomorrow, once granted");
}

/// Sol R10 and R11 (P2): a cut at a word end split a date the rules read
/// across it and reset the sentence a name runs in; a window that saw no
/// close read inline code as prose; a cut inside a word gave the next
/// segment a word edge, and so a date, the text does not have; a cut in the
/// line that closes a fence left the fence open; a cut forced by a long word
/// split a short date inside it, and the rest of a long run read as a name.
/// A long text is read in segments that end where no word or span the rules
/// see runs across, or, inside an extent too long to be a span, where no
/// shorter one does, and carry the sentence, the code and the word or run
/// they end in, so each text below reads as a short one would.
#[test]
fn a_long_text_is_cut_where_no_span_runs_across() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), false);
    let (date, name) = (SpanKind::Date, SpanKind::Name);
    let cases = [
        (
            "x ".repeat(16_380) + "January 12, 2026.",
            vec![(date, "January 12, 2026")],
        ),
        (
            "x ".repeat(16_381) + "Alice Smith arrives.",
            vec![(name, "Alice Smith")],
        ),
        (
            format!(
                "```\n{}```\nCarol arrives.",
                "Alice Smith met Bob.\n".repeat(400)
            ),
            vec![(name, "Carol")],
        ),
        (
            "```\nx\n```".to_owned() + &" ".repeat(5_000) + "\nAlice arrives.",
            vec![(name, "Alice")],
        ),
        ("x".repeat(4_096) + "2026-10-12 " + &"x".repeat(600), vec![]),
        // An inline code span closes within 256 bytes or is plain text, in a
        // short text and in a long one alike.
        (
            "`".to_owned() + &"x ".repeat(200) + "Alice 2026-10-12`",
            vec![(name, "Alice"), (date, "2026-10-12")],
        ),
        (
            "`".to_owned() + &"x ".repeat(2_500) + "Alice 2026-10-12`",
            vec![(name, "Alice"), (date, "2026-10-12")],
        ),
        (
            "x ".repeat(2_040) + "`Alice 2026-10-12` Bob arrives. " + &"x ".repeat(2_000),
            vec![(name, "Bob")],
        ),
        // The rest of a word a cut splits opens no name, and a date reads
        // a word edge only where the text has one.
        (
            "x".repeat(4_095) + "-Alice arrives. " + &"x ".repeat(400),
            vec![],
        ),
        (
            "a_".repeat(2_048) + "2026-10-12 ok. " + &"x ".repeat(400),
            vec![],
        ),
        // A cut inside a word too long to be a name splits no date in it,
        // and a run too long to be a name gives none, not even its rest.
        (
            "A".repeat(4_090) + "-2026-10-12 " + &"x ".repeat(300),
            vec![(date, "2026-10-12")],
        ),
        (
            "ア".repeat(1_366) + "、アリス。" + &"x ".repeat(1_000),
            vec![(name, "アリス")],
        ),
        (
            "Aa ".repeat(1_400) + "x Bob arrives. " + &"x ".repeat(300),
            vec![(name, "Bob")],
        ),
    ];
    let turns: Vec<EntityId> = cases
        .iter()
        .enumerate()
        .map(|(index, (text, _))| {
            let turn_ref = format!("{:02x}", 0x80 + index).repeat(16);
            witness(&vault, &turn_ref, text)
        })
        .collect();
    drain(&vault, NOW);
    for ((text, expected), turn) in cases.iter().zip(&turns) {
        let expected: Vec<_> = expected
            .iter()
            .map(|(kind, words)| (*kind, (*words).to_owned(), "rule"))
            .collect();
        assert_eq!(flags(&vault, turn, text), expected, "{}", &text[..40]);
    }
    let name = vault
        .sieve_queue(usize::MAX)
        .expect("queue")
        .spans
        .into_iter()
        .find(|span| span.turn == turns[1])
        .expect("the name");
    assert_eq!(
        name.origin,
        SpanOrigin::Rule {
            rules: RULES_VERSION,
            class: RuleClass::Name,
        }
    );
}

/// Sol R10 (P2): a word with no space in it ran past the bound whole. A
/// segment cuts such a word at the segment size and drops what runs across
/// the cut, so every pass stays within the bound, and the read goes on to
/// what follows the word.
#[test]
fn a_word_with_no_space_is_read_within_the_bound() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), false);
    let text = "アリス".repeat(20_000) + " Alice arrives.";
    let turn = witness(&vault, "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", &text);
    let mut passes = 1;
    while vault.sieve_pass(NOW + passes).expect("pass").more {
        passes += 1;
    }
    assert!(passes > 2, "the word takes more than one pass");
    assert_eq!(
        flags(&vault, &turn, &text),
        vec![(SpanKind::Name, "Alice".to_owned(), "rule")]
    );
}

/// Sol R11 (P2): a grant that let the sieve read a long turn ended the
/// pass that cut its read with no work left, so a caller draining the sieve
/// stopped with the turn half read.
#[test]
fn a_grant_that_opens_a_long_turn_keeps_the_pass_going() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), false);
    let space = EntityId::from_bytes([0x5f; 16]).expect("space id");
    let text = "アリス 2026-10-12 ".repeat(20_000);
    let turn = witness_with(
        &vault,
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        &text,
        NOW,
        Some(serde_json::json!({"rel": space.to_hex()})),
    );
    let now = NOW + drain(&vault, NOW);
    let spans = |vault: &Vault| {
        vault
            .sieve_queue(usize::MAX)
            .expect("queue")
            .spans
            .into_iter()
            .filter(|span| span.turn == turn)
            .count()
    };
    assert_eq!(spans(&vault), 0);

    grant_messages_read(&vault, 0x60, space);
    assert!(
        vault.sieve_pass(now).expect("pass").more,
        "the read the grant opened goes on"
    );
    drain(&vault, now + 1);
    assert_eq!(spans(&vault), 40_000);
}

/// Sol R11 (P2): a read that went on in a MESSAGE kept reading it after the
/// MESSAGE left its TURN, so the turn queued words it no longer holds. A read
/// goes on only in a MESSAGE that is still part of the turn. The batch door
/// refuses to move a room MESSAGE's PartOf edge, so the edge is torn below
/// that door, as a membership change from any other path would leave it.
#[test]
fn a_message_taken_out_of_its_turn_is_not_read_on() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), false);
    let id = "8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e";
    let text = "x ".repeat(16_400) + "Alice arrives.";
    let turn = witness_messages(
        &vault,
        "8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f",
        NOW,
        vec![message(id, &text, 0, None)],
    );
    assert!(
        vault.sieve_pass(NOW).expect("pass").more,
        "the bound cut it"
    );
    let message = EntityId::from_hex(id).expect("message id");
    let torn = vault
        .with_write_txn(|txn| {
            crate::ports::EdgeStoreStaging::port_remove_edge_rows(
                &vault.store,
                txn,
                &message,
                crate::edge::EdgeKind::PartOf,
                &turn,
            )
        })
        .expect("edge");
    assert!(torn, "the edge existed");
    drain(&vault, NOW + 1);
    assert!(flags(&vault, &turn, &text).is_empty());
}

/// Sol R12 and Wonder R12 (P2): a read that went on past a MESSAGE kept the
/// spans it read there after the Dreamer lost its grant to read it, and
/// settled the turn whole. A read settles only when the turn still holds
/// every chunk it passed and the Dreamer may still read each; else the turn
/// is read again whole. Sol R13 (P2): the check runs once, as the read
/// settles, not on every pass the read goes on.
#[test]
fn a_grant_revoked_behind_a_read_takes_back_what_the_read_passed() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), false);
    let space = EntityId::from_bytes([0x5d; 16]).expect("space id");
    grant_messages_read(&vault, 0x61, space);
    let (first, second) = (
        "6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a",
        "6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b",
    );
    let long = "x ".repeat(16_400) + "Bob arrives.";
    let turn = witness_messages(
        &vault,
        "6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c",
        NOW,
        vec![
            message(
                first,
                "Alice arrives.",
                0,
                Some(serde_json::json!({"rel": space.to_hex()})),
            ),
            message(second, &long, 1, None),
        ],
    );
    assert!(
        vault.sieve_pass(NOW).expect("pass").more,
        "the bound cut it"
    );
    vault
        .revoke_access_grant(&EntityId::from_bytes([0x61; 16]).expect("grant id"), NOW)
        .expect("revoke");
    drain(&vault, NOW + 1);
    let second = EntityId::from_hex(second).expect("message id");
    let sources: Vec<EntityId> = vault
        .sieve_queue(usize::MAX)
        .expect("queue")
        .spans
        .into_iter()
        .filter(|span| span.turn == turn)
        .map(|span| span.source)
        .collect();
    assert_eq!(
        sources,
        vec![second],
        "only Bob, from the message it may read"
    );
}

/// Astra-1418b (P2): a turn read whole kept serving the spans of a MESSAGE
/// after the grant that let the Dreamer read it was revoked: the retry
/// sweep walks only withheld turns, and the queue served what it held. The
/// queue serves a span only while the Dreamer may read its source; the span
/// stays queued, and a later grant serves it again with no new read.
#[test]
fn a_revoked_grant_takes_its_spans_out_of_what_the_queue_serves() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), false);
    let space = EntityId::from_bytes([0x66; 16]).expect("space id");
    grant_messages_read(&vault, 0x62, space);
    let id = "6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e";
    let text = "Alice arrives tomorrow.";
    let turn = witness_messages(
        &vault,
        "6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d",
        NOW,
        vec![message(
            id,
            text,
            0,
            Some(serde_json::json!({"rel": space.to_hex()})),
        )],
    );
    let mut now = NOW + drain(&vault, NOW) + 1;
    let served = |vault: &Vault| -> Vec<SieveSpan> {
        vault
            .sieve_queue(usize::MAX)
            .expect("queue")
            .spans
            .into_iter()
            .filter(|span| span.turn == turn)
            .collect()
    };
    let read = served(&vault);
    assert_eq!(read.len(), 2, "Alice and tomorrow");

    vault
        .revoke_access_grant(&EntityId::from_bytes([0x62; 16]).expect("grant id"), NOW)
        .expect("revoke");
    now += drain(&vault, now) + 1;
    assert!(served(&vault).is_empty(), "no span, ref, range or digest");
    let queue = vault.sieve_queue(usize::MAX).expect("queue");
    assert_eq!(queue.skipped.unreadable, 2);

    grant_messages_read(&vault, 0x63, space);
    assert_eq!(vault.sieve_pass(now).expect("pass").turns_read, 0);
    assert_eq!(served(&vault), read, "served again, not read again");
}

/// Sol R15 (P2): a TURN whose own body carries its words was served on its
/// liveness alone, so its spans stayed served after the owner's policy took
/// the Dreamer's read away. The sieve asks the Dreamer's gate for the TURN
/// as a branch does: a TURN it may not read gives no span until the owner
/// grants the read, and one it may no longer read keeps its spans queued,
/// unserved, until the read is granted again, with no new read.
#[test]
fn a_turn_the_dreamer_may_not_read_gives_and_serves_no_span_of_its_words() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), false);
    crate::test_util::seeded_without_dreamer_rows(&vault).expect("seed");
    let turn = EntityId::from_hex("6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c").expect("turn id");
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![
            ("txt".into(), "Alice arrives tomorrow.".into()),
            ("spkr".into(), "user".into()),
        ]),
    )
    .expect("turn body");
    vault
        .put_entity(
            &turn,
            crate::registry::ENTITY_TYPE_TURN,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
            &body,
        )
        .expect("turn");
    let served = |vault: &Vault| -> Vec<SieveSpan> {
        vault
            .sieve_queue(usize::MAX)
            .expect("queue")
            .spans
            .into_iter()
            .filter(|span| span.turn == turn)
            .collect()
    };
    let mut now = NOW + drain(&vault, NOW) + 1;
    assert!(served(&vault).is_empty(), "the Dreamer may not read it");
    assert_eq!(
        vault.sieve_queue(usize::MAX).expect("queue").skipped,
        SieveSkipped::default(),
        "no span was queued to pass over"
    );

    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("owner");
    assert!(vault.grant_dreamer_weave(&owner, now).expect("weave grant"));
    now += drain(&vault, now) + 1;
    let read = served(&vault);
    assert_eq!(read.len(), 2, "Alice and tomorrow");
    assert!(
        read.iter().all(|span| span.source == turn),
        "the TURN's words"
    );

    crate::test_util::withhold_dreamer_read(&vault).expect("withhold");
    now += drain(&vault, now) + 1;
    assert!(served(&vault).is_empty(), "no span, ref, range or digest");
    let queue = vault.sieve_queue(usize::MAX).expect("queue");
    assert_eq!(queue.skipped.unreadable, 2);

    assert!(
        vault
            .grant_dreamer_weave(&owner, now)
            .expect("weave grant again")
    );
    assert_eq!(vault.sieve_pass(now).expect("pass").turns_read, 0);
    assert_eq!(served(&vault), read, "served again, not read again");
}

/// Sol R11 and R12 (P2): the owner's grant that gives the Dreamer back its
/// read writes a policy manifest, not an access grant, so the turns the
/// sieve withheld waited for a grant that never came. A policy manifest a
/// write puts moves the sieve's retries on as a grant does.
#[test]
fn the_owners_weave_grant_reads_the_turns_the_dreamer_could_not() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), false);
    crate::test_util::seeded_without_dreamer_rows(&vault).expect("seed");
    let text = "We met Alice on 2026-10-12.";
    let turn = witness(&vault, "6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d", text);
    let now = NOW + drain(&vault, NOW);
    assert!(
        flags(&vault, &turn, text).is_empty(),
        "the Dreamer may not read it"
    );
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("owner");
    assert!(vault.grant_dreamer_weave(&owner, now).expect("weave grant"));
    drain(&vault, now);
    assert_eq!(
        flags(&vault, &turn, text),
        vec![
            (SpanKind::Name, "Alice".to_owned(), "rule"),
            (SpanKind::Date, "2026-10-12".to_owned(), "rule"),
        ]
    );
}

/// Sol R12 and its rulings (P2): a fence whose line opened past a window's
/// end, a phrase the character before a segment read as a word of its own,
/// a chain of overlapping dates, and a long run of number words read
/// differently a segment at a time than in one window. A segment keeps
/// every span that starts in it, and each rule reads on in the next from
/// where it stood, so each text below reads span for span as one window
/// reads it.
#[test]
fn a_long_text_reads_a_segment_at_a_time_as_in_one_window() {
    let rules = super::rules::Rules::new();
    let fence = " ".repeat(5_000) + "```\nAlice 2026-10-12\n```\nBob arrives.";
    let phrase = "x".repeat(4_095) + "a few days ago " + &"x ".repeat(300);
    let texts = [
        fence.clone(),
        phrase.clone(),
        "May 5 June 6 July 7 ".repeat(300),
        "1/2/3/4 ".repeat(1_000),
        "2026年10月12日".repeat(400),
        "one ".repeat(1_025) + "days ago " + &"x ".repeat(300),
        "last week, next Tuesday and 3 days ago ".repeat(300),
        "A".repeat(4_090) + "-2026-10-12 " + &"x ".repeat(300),
        "ア".repeat(1_366) + "、アリス。" + &"x ".repeat(1_000),
        "Aa ".repeat(1_400) + "x Bob arrives. " + &"x ".repeat(300),
        "x".repeat(4_095) + "-Alice arrives. " + &"x ".repeat(400),
        "a_".repeat(2_048) + "2026-10-12 ok. " + &"x ".repeat(400),
        "`Alice` and Bob ".repeat(1_000),
        "Alice Smith met Bob on May 5. ".repeat(500),
    ];
    for text in &texts {
        let whole = rules.read_whole(text);
        assert_eq!(
            rules.read_segmented(text),
            whole,
            "{}",
            text.chars().take(16).collect::<String>()
        );
    }
    let read = |text: &str| -> Vec<String> {
        rules
            .read_segmented(text)
            .iter()
            .map(|span| text[span.start..span.end].to_owned())
            .collect()
    };
    assert_eq!(read(&fence), ["Bob"]);
    assert_eq!(read(&phrase), ["few days ago"]);
}

/// Sol R13 (P2): the character before a segment read `.5` as a number the
/// text does not hold there, and the bounded phrase steps read the end of a
/// long count as a count of its own (`one days ago` out of 1,025 `one`s).
/// The sieve flags the phrases the query reader reads in the whole text, no
/// longer than a step ([`crate::temporal::temporal_phrase_spans`], the
/// rule's 256 bytes), and reads past a longer one whole: in one window or
/// many. The texts after the repros are drawn from the grammar's words,
/// gaps around a step's bound and a window's reach, long counts and long
/// words, from a fixed seed.
#[test]
fn the_sieve_reads_the_phrases_the_query_reader_reads() {
    let rules = super::rules::Rules::new();
    let mut texts = vec![
        "x".repeat(4_095) + ".5 days ago " + &"x ".repeat(300),
        "one ".repeat(1_025) + "days ago " + &"x ".repeat(300),
        ("last".to_owned() + &" ".repeat(300) + "3 days ago, ").repeat(40),
    ];
    let words: Vec<&str> = "last past this next a an couple few half several of one twenty \
        hundred thousand and 3 1,000 .5 day days weeks minute second ago night morning \
        yesterday today recent x the"
        .split_whitespace()
        .collect();
    let mut seed: u64 = 0x5eed;
    let mut below = |bound: usize| {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from(seed >> 33).expect("31 bits") % bound
    };
    for _ in 0..48 {
        let mut text = String::new();
        while text.len() < 12_000 {
            match below(16) {
                0 => text.push_str(&"one ".repeat(below(1_200))),
                1 => text.push_str(&" ".repeat(below(700))),
                2 => text.push_str(&"x".repeat(below(3_000))),
                _ => {}
            }
            text.push_str(words[below(words.len())]);
            text.push_str([" ", " ", ", ", ". ", "-"][below(5)]);
        }
        texts.push(text);
    }
    let dates = |spans: Vec<super::rules::RuleSpan>| -> Vec<(usize, usize, bool)> {
        spans
            .iter()
            .map(|span| {
                let resolved = span.class == super::rules::RuleClass::RelativeDate;
                (span.start, span.end, resolved)
            })
            .collect()
    };
    for text in &texts {
        let phrases: Vec<(usize, usize, bool)> = crate::temporal::temporal_phrase_spans(text)
            .into_iter()
            .filter(|phrase| phrase.end - phrase.start <= 256)
            .map(|phrase| (phrase.start, phrase.end, phrase.resolved))
            .collect();
        let head: String = text.chars().take(24).collect();
        assert_eq!(dates(rules.read_whole(text)), phrases, "whole: {head}");
        assert_eq!(
            dates(rules.read_segmented(text)),
            phrases,
            "segmented: {head}"
        );
    }
    assert_eq!(
        dates(rules.read_segmented(&texts[0])),
        [(4_096, 4_106, true)]
    );
    assert!(rules.read_segmented(&texts[1]).is_empty());
}

/// Sol R10 (P2): every grant written put each withheld turn back in the
/// owed list, ahead of a new turn with a higher id, so grants written
/// before each pass kept a new turn from ever being read. A grant moves an
/// epoch on, and the withheld turns are read again on what a pass leaves.
#[test]
fn grants_written_while_turns_wait_never_hold_a_new_turn_back() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), false);
    let private = Some(serde_json::json!({"scope": {"private": true}}));
    for index in 0..64_u8 {
        let turn_ref = format!("5e{index:030x}");
        witness_with(
            &vault,
            &turn_ref,
            "We met Alice Smith.",
            NOW,
            private.clone(),
        );
    }
    let mut now = NOW + drain(&vault, NOW);
    let text = "Bob arrives tomorrow.";
    let turn = witness(&vault, "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", text);
    let space = EntityId::from_bytes([0x9e; 16]).expect("space id");
    for grant in 0..3_u8 {
        // Not 0xa1 on: the system agent definitions hold those ids.
        grant_messages_read(&vault, 0xc0 + grant, space);
        vault.sieve_pass(now).expect("pass");
        now += 1;
        assert_eq!(
            flags(&vault, &turn, text),
            vec![
                (SpanKind::Name, "Bob".to_owned(), "rule"),
                (SpanKind::Date, "tomorrow".to_owned(), "rule"),
            ],
            "grant {grant}"
        );
    }
    drain(&vault, now);
    let queue = vault.sieve_queue(usize::MAX).expect("queue").spans;
    assert!(queue.iter().all(|span| span.turn == turn));
}
