//! The Dreamer's sieve reads a TURN's words into spans, and a rung quotes a
//! span's words as its evidence. The sieve reads only the words a door that
//! releases a turn's words gives (ARCH-0069 #readers-followups-open, "the
//! Dreamer sieve's TURN reads"; census L6-30 item d): a message stored while
//! the owner's write-door scan was off, whose words or whose body the write
//! door now refuses, gives no span. The turn's other words still give theirs.
//!
//! Public crate surface only: the owner's scan switch, a witnessed turn,
//! `Vault::sieve_pass` and `Vault::sieve_queue`.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test sieve_secret_body_release`.

use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_model::SecretScanMode;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A 12-word recovery phrase with a valid checksum: the write door refuses it.
const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
/// Ordinary words with a name and a date, each a span the sieve's rules read.
const CLEAN: &str = "We met Owen Hart on October 12, 2026.";
/// A name and a date, then the phrase, in the message's own words.
const WORDS_REFUSED: &str = "We met Yuki Mori on October 13, 2026: legal winner thank year wave sausage worth useful legal winner thank yellow";
/// A name and a date in the words; the phrase rides the body's metadata.
const BODY_REFUSED: &str = "We met Lena Ito on October 14, 2026.";

fn message(
    id: EntityId,
    text: &str,
    order: u32,
    metadata: Option<serde_json::Value>,
) -> WitnessMessage {
    WitnessMessage {
        id: Some(id.to_hex()),
        author: WitnessAuthor::User,
        message_type: "text".to_owned(),
        content: text.to_owned(),
        parts: None,
        metadata,
        is_visible: true,
        order,
        quote: None,
    }
}

#[test]
fn a_message_the_write_door_refuses_gives_the_sieve_no_span() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
    let at = vault.now_recorded_at();
    // The owner's scan off: the phrase is stored as written.
    vault.set_secret_scan_mode(&owner, SecretScanMode::Off, at)?;

    let turn = EntityId::now();
    let clean = EntityId::now();
    let words_refused = EntityId::now();
    let body_refused = EntityId::now();
    vault
        .memory(owner_id, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            occurred_at: at,
            messages: vec![
                message(clean, CLEAN, 0, None),
                message(words_refused, WORDS_REFUSED, 1, None),
                message(
                    body_refused,
                    BODY_REFUSED,
                    2,
                    Some(serde_json::json!({ "memo": PHRASE })),
                ),
            ],
            assertions: Default::default(),
        })?;

    let mut passes = 0_u64;
    while vault.sieve_pass(vault.now_recorded_at() + passes)?.more {
        passes += 1;
        assert!(passes < 1_000, "the sieve never settles");
    }
    let spans: Vec<_> = vault
        .sieve_queue(usize::MAX)?
        .spans
        .into_iter()
        .filter(|span| span.turn == turn)
        .collect();
    let of = |source: EntityId| spans.iter().filter(|span| span.source == source).count();

    // The fixture: the sieve read the turn, and its clean words give spans.
    assert!(
        of(clean) > 0,
        "the turn's clean words still give spans: {spans:?}"
    );
    assert_eq!(
        of(words_refused),
        0,
        "a message whose words the write door refuses gave the sieve spans: {spans:?}"
    );
    assert_eq!(
        of(body_refused),
        0,
        "a message whose body the write door refuses gave the sieve spans: {spans:?}"
    );
    Ok(())
}
