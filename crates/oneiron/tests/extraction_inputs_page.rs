//! Pages one queued Meso extraction attempt's TURNs under the caller's live read.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_inputs_page`.
#![cfg(oneiron_test_support)]

use oneiron::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptBinding};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::define_agent;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::narrow_steward_grant_to_project;
use oneiron::test_doors::dreamer_attempt_binding::enqueue_strength_attempt;
use oneiron::test_doors::extraction_inputs::{
    append_extraction_turn_words, enqueue_admitted_extraction_attempt, enqueue_extraction_attempt,
    settle_extraction_rows_in_project, witness_extraction_turns,
};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::{AttemptId, EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;

/// Returns a fixture or assertion error without hiding its source.
type ExtractionInputsPageTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// The inputs page verb under test, invoked by name with plain JSON, so this
/// file compiles while the handler is still missing and fails at runtime on
/// the unknown verb.
const EXTRACTION_INPUTS_PAGE_VERB: &str = "vault.consolidation.extraction.inputs.page";

/// The evidence spans verb an extraction attempt reads its words through.
const EVIDENCE_SPANS_VERB: &str = "vault.evidence.spans";

/// The commit verb no extraction attempt admits.
const DERIVE_COMMIT_VERB: &str = "vault.derive.commit";

/// The conflicts page verb no extraction attempt admits.
const CONFLICTS_PAGE_VERB: &str = "vault.consolidation.conflicts.page";

/// The queue clock every enqueue and admission here runs at, in seconds.
const QUEUE_NOW: u64 = 1_000;

/// Opens a vault the way the conflicts page test does: the Dreamer fixture
/// vault, reopened owned, with engine machines provisioned and the embedded
/// owner ensured.
fn open_extraction_inputs_vault(dir: &tempfile::TempDir) -> ExtractionInputsPageTestResult<Vault> {
    drop(open_dreamer_vault(dir.path(), "owen")?);
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    Ok(vault)
}

/// Returns the attempt id as the page names it: its bytes as lowercase hex.
fn extraction_attempt_hex(id: AttemptId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Reads the extraction inputs page for `attempt` through `binding`.
fn read_bound_extraction_page(
    binding: &DreamerAttemptBinding,
    attempt: &str,
    cursor: Option<String>,
    limit: Option<u32>,
) -> MemoryResult<Value> {
    binding
        .invoke(
            EXTRACTION_INPUTS_PAGE_VERB,
            json!({"attempt": attempt, "cursor": cursor, "limit": limit}),
            None,
        )
        .map(|answer| answer["value"].clone())
}

/// Reads evidence spans for `source` through `binding`, at `version` when one
/// is named and over `ranges`.
fn read_bound_spans(
    binding: &DreamerAttemptBinding,
    source: EntityId,
    version: Option<Value>,
    ranges: Value,
) -> MemoryResult<Value> {
    binding
        .invoke(
            EVIDENCE_SPANS_VERB,
            json!({"source": source.to_hex(), "version": version, "ranges": ranges}),
            None,
        )
        .map(|answer| answer["value"].clone())
}

/// Reads the extraction inputs page for `attempt` as `actor` of `class`
/// through the public SDK.
fn read_public_extraction_page(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    attempt: &str,
) -> MemoryResult<Value> {
    invoke(
        &vault.memory(actor, class),
        EXTRACTION_INPUTS_PAGE_VERB,
        json!({"attempt": attempt}),
    )
    .map(|answer| answer["value"].clone())
}

/// Asserts that `pin` is one lowercase 64-character hex digest.
fn assert_extraction_digest(pin: &Value) {
    let pin = pin.as_str().unwrap_or_else(|| panic!("a pin is a string"));
    assert_eq!(pin.len(), 64);
    assert!(
        pin.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}

/// Asserts that `revision` is a `blake3:` ref with a 64-character hex digest.
fn assert_extraction_revision(revision: &Value) {
    let revision = revision
        .as_str()
        .unwrap_or_else(|| panic!("a revision is a string"));
    let digest = revision
        .strip_prefix("blake3:")
        .unwrap_or_else(|| panic!("a revision names blake3"));
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}

/// Binds `admitted` in `vault` and returns the live extraction binding.
fn bind_extraction(
    vault: &Arc<Vault>,
    admitted: &DreamerAdmittedAttempt,
) -> ExtractionInputsPageTestResult<DreamerAttemptBinding> {
    Ok(vault.bind_dreamer_attempt(admitted)?)
}

/// The bound Dreamer pages its partition's three TURNs in queued order, each
/// with its conversation, partition, role, learned time and source version,
/// and the effective policy with its pin, and its bound evidence serves each
/// turn's current words.
#[test]
fn the_bound_dreamer_pages_its_partition_turns_with_version_pins()
-> ExtractionInputsPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_inputs_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let words = [
        "call me owen",
        "yuki likes tea",
        "reach owen at owen@example.com",
    ];
    let witnessed = witness_extraction_turns(&vault, &words)?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let attempt = extraction_attempt_hex(id);
    let page = read_bound_extraction_page(&binding, &attempt, None, None)?;
    assert_eq!(page["attempt"], attempt);
    assert_eq!(page["scope"], "meso");
    assert!(page["policy"]["prefilter"].is_object());
    assert!(page["policy"]["selection"].is_object());
    assert!(page["policy"]["key_rules"].is_object());
    assert_eq!(page["policy"]["prefilter"]["enabled"], false);
    assert_extraction_digest(&page["policy_pin"]);
    let turns = page["turns"]
        .as_array()
        .unwrap_or_else(|| panic!("turns is an array"));
    assert_eq!(turns.len(), 3);
    let mut partitions = BTreeSet::new();
    for (index, served) in turns.iter().enumerate() {
        assert_eq!(served["turn"], witnessed.turns[index].to_hex());
        assert_eq!(served["conversation"], witnessed.conversation.to_hex());
        assert!(served["world"].is_null());
        assert!(served["facet"].is_null());
        assert_extraction_digest(&served["partition"]);
        partitions.insert(served["partition"].as_str().unwrap_or("").to_owned());
        assert_eq!(served["role"], "user");
        assert_eq!(
            served["learned_at"],
            json!(10u64.saturating_add(index as u64))
        );
        let version = &served["version"];
        assert_eq!(version["entity"], witnessed.turns[index].to_hex());
        assert_extraction_revision(&version["revision"]);
        assert_extraction_revision(
            version
                .get("projection")
                .unwrap_or_else(|| panic!("a TURN version pins its projection")),
        );
    }
    assert_eq!(partitions.len(), 1, "one conversation plans one partition");
    assert!(page["next"].is_null());
    for (index, turn) in witnessed.turns.iter().enumerate() {
        let version = turns[index]["version"].clone();
        let spans = read_bound_spans(&binding, *turn, Some(version), json!([]))?;
        assert_eq!(spans["status"], "current");
        let served = spans["spans"]
            .as_array()
            .unwrap_or_else(|| panic!("spans is an array"));
        assert_eq!(served.len(), 1);
        assert_eq!(served[0]["text"], words[index]);
    }
    Ok(())
}

/// A TURN outside the Dreamer's Steward grant is absent whole: the page names
/// it nowhere, and its bound words are withheld.
#[test]
fn a_turn_outside_the_dreamer_grant_is_absent_and_its_words_withheld()
-> ExtractionInputsPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_inputs_vault(&dir)?);
    let actor = dreamer(&vault)?;
    let witnessed = witness_extraction_turns(
        &vault,
        &[
            "call me owen",
            "yuki likes tea",
            "reach owen at owen@example.com",
        ],
    )?;
    let outside = witnessed.turns[2];
    let project = EntityId::now();
    settle_extraction_rows_in_project(&vault, &[outside, witnessed.messages[2]], project)?;
    let grant = stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    narrow_steward_grant_to_project(&vault, grant, oneiron::claim::default_project_id())?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id), None, None)?;
    let turns = page["turns"]
        .as_array()
        .unwrap_or_else(|| panic!("turns is an array"));
    assert_eq!(turns.len(), 2);
    assert_eq!(turns[0]["turn"], witnessed.turns[0].to_hex());
    assert_eq!(turns[1]["turn"], witnessed.turns[1].to_hex());
    assert!(!page.to_string().contains(&outside.to_hex()));
    assert!(page["next"].is_null());
    let withheld = read_bound_spans(&binding, outside, None, json!([]))?;
    assert_eq!(withheld["status"], "withheld");
    assert!(withheld["version"].is_null());
    assert!(
        withheld["spans"]
            .as_array()
            .unwrap_or_else(|| panic!("spans is an array"))
            .is_empty()
    );
    Ok(())
}

/// A TURN that moved since its served version serves no words at the old
/// version: the bound spans answer moved with the current version and no
/// bytes.
#[test]
fn a_moved_turn_serves_no_words_at_its_old_version() -> ExtractionInputsPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_inputs_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let witnessed = witness_extraction_turns(&vault, &["call me owen"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id), None, None)?;
    let served = page["turns"]
        .as_array()
        .unwrap_or_else(|| panic!("turns is an array"));
    assert_eq!(served.len(), 1);
    let old = served[0]["version"].clone();
    append_extraction_turn_words(
        &vault,
        witnessed.conversation,
        witnessed.turns[0],
        "and yuki joins owen",
    )?;
    let moved = read_bound_spans(&binding, witnessed.turns[0], Some(old.clone()), json!([]))?;
    assert_eq!(moved["status"], "moved");
    assert!(!moved["version"].is_null());
    assert_ne!(moved["version"], old);
    assert!(
        moved["spans"]
            .as_array()
            .unwrap_or_else(|| panic!("spans is an array"))
            .is_empty()
    );
    Ok(())
}

/// Each facet refuses the other's verbs: a strength binding refuses the
/// extraction page and evidence, and an extraction binding refuses commits
/// and the conflicts page.
#[test]
fn other_facets_and_other_verbs_are_refused() -> ExtractionInputsPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_inputs_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let witnessed = witness_extraction_turns(&vault, &["call me owen"])?;
    let (extraction_id, extraction_admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let extraction = bind_extraction(&vault, &extraction_admitted)?;
    let strength_admitted = enqueue_strength_attempt(&vault, extraction_id, QUEUE_NOW)?;
    let strength = vault.bind_dreamer_attempt(&strength_admitted)?;
    let attempt = extraction_attempt_hex(extraction_id);
    let Err(page) = read_bound_extraction_page(&strength, &attempt, None, None) else {
        panic!("a strength binding refuses the extraction page");
    };
    assert_eq!(page.code, MEMORY_CODE_FORBIDDEN);
    assert!(page.message.contains("does not admit"));
    let Err(spans) = read_bound_spans(&strength, witnessed.turns[0], None, json!([])) else {
        panic!("a strength binding refuses evidence spans");
    };
    assert_eq!(spans.code, MEMORY_CODE_FORBIDDEN);
    assert!(spans.message.contains("does not admit"));
    let Err(commit) = extraction.invoke(
        DERIVE_COMMIT_VERB,
        json!({"items": [], "sources": []}),
        None,
    ) else {
        panic!("an extraction binding refuses commits");
    };
    assert_eq!(commit.code, MEMORY_CODE_FORBIDDEN);
    assert!(commit.message.contains("does not admit"));
    let Err(conflicts) = extraction.invoke(CONFLICTS_PAGE_VERB, json!({}), None) else {
        panic!("an extraction binding refuses the conflicts page");
    };
    assert_eq!(conflicts.code, MEMORY_CODE_FORBIDDEN);
    assert!(conflicts.message.contains("does not admit"));
    Ok(())
}

/// The bound page reads its own attempt only: with two Meso conversations
/// queued, it serves the bound attempt's TURNs and refuses the other's
/// attempt.
#[test]
fn the_bound_page_reads_its_own_attempt_only() -> ExtractionInputsPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_inputs_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let first = witness_extraction_turns(&vault, &["call me owen", "owen likes coffee"])?;
    let second = witness_extraction_turns(&vault, &["call me yuki", "yuki likes tea"])?;
    let (first_id, first_admitted) =
        enqueue_admitted_extraction_attempt(&vault, &first.turns, QUEUE_NOW)?;
    let second_id = enqueue_extraction_attempt(&vault, &second.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &first_admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(first_id), None, None)?;
    let turns = page["turns"]
        .as_array()
        .unwrap_or_else(|| panic!("turns is an array"));
    assert_eq!(turns.len(), 2);
    assert_eq!(turns[0]["turn"], first.turns[0].to_hex());
    assert_eq!(turns[1]["turn"], first.turns[1].to_hex());
    let served = page.to_string();
    for turn in &second.turns {
        assert!(!served.contains(&turn.to_hex()));
    }
    assert!(!served.contains(&second.conversation.to_hex()));
    let Err(other) =
        read_bound_extraction_page(&binding, &extraction_attempt_hex(second_id), None, None)
    else {
        panic!("a bound page refuses another attempt");
    };
    assert_eq!(other.code, MEMORY_CODE_FORBIDDEN);
    assert!(other.message.contains("own attempt"));
    Ok(())
}

/// A reader without a live Steward read is refused, while the owner reads the
/// queued TURNs.
#[test]
fn a_reader_without_a_live_steward_read_is_refused_and_the_owner_reads()
-> ExtractionInputsPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_inputs_vault(&dir)?);
    let witnessed =
        witness_extraction_turns(&vault, &["call me owen", "reach owen at owen@example.com"])?;
    let id = enqueue_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let attempt = extraction_attempt_hex(id);
    let agent = define_agent(&vault)?;
    let Err(refused) = read_public_extraction_page(&vault, agent, EdgeActorClass::Agent, &attempt)
    else {
        panic!("a reader without a live Steward read is refused");
    };
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN);
    let owner = vault.ensure_embedded_owner_actor()?;
    let page = read_public_extraction_page(&vault, owner, EdgeActorClass::Human, &attempt)?;
    let turns = page["turns"]
        .as_array()
        .unwrap_or_else(|| panic!("turns is an array"));
    assert_eq!(turns.len(), 2);
    assert_eq!(turns[0]["turn"], witnessed.turns[0].to_hex());
    assert_eq!(turns[1]["turn"], witnessed.turns[1].to_hex());
    assert!(page["next"].is_null());
    Ok(())
}

/// Bounded pages walk every TURN once, in queued order, and the last page
/// carries no cursor.
#[test]
fn the_pages_walk_every_turn_once() -> ExtractionInputsPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_inputs_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let witnessed = witness_extraction_turns(
        &vault,
        &[
            "call me owen",
            "yuki likes tea",
            "reach owen at owen@example.com",
            "owen and yuki plan tea",
        ],
    )?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let attempt = extraction_attempt_hex(id);
    let expected: Vec<String> = witnessed.turns.iter().map(|turn| turn.to_hex()).collect();
    let mut seen = BTreeSet::new();
    let mut ordered = Vec::new();
    let mut cursor = None;
    for index in 0..4 {
        let page = read_bound_extraction_page(&binding, &attempt, cursor.clone(), Some(1))?;
        let turns = page["turns"]
            .as_array()
            .unwrap_or_else(|| panic!("turns is an array"));
        assert_eq!(turns.len(), 1);
        let served = turns[0]["turn"]
            .as_str()
            .unwrap_or_else(|| panic!("the turn is a string"))
            .to_owned();
        assert!(seen.insert(served.clone()), "each TURN is served once");
        ordered.push(served.clone());
        let next = page["next"].clone();
        assert_eq!(next.is_null(), index == 3);
        if index < 3 {
            assert_eq!(next, json!(format!("extraction-turns:{served}")));
            cursor = next.as_str().map(str::to_owned);
        }
    }
    assert_eq!(seen, expected.iter().cloned().collect::<BTreeSet<_>>());
    assert_eq!(ordered, expected);
    let resumed = read_bound_extraction_page(
        &binding,
        &attempt,
        Some(format!("extraction-turns:{}", expected[0])),
        None,
    )?;
    let turns = resumed["turns"]
        .as_array()
        .unwrap_or_else(|| panic!("turns is an array"));
    let rest: Vec<String> = turns
        .iter()
        .map(|turn| {
            turn["turn"]
                .as_str()
                .unwrap_or_else(|| panic!("the turn is a string"))
                .to_owned()
        })
        .collect();
    assert_eq!(rest, expected[1..].to_vec());
    assert!(resumed["next"].is_null());
    Ok(())
}
