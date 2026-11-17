//! The `self.board.*` doors keep the agent-managed board layout promises
//! (BOARD-LAYOUT = A, owner ruling 2026-11-03; canon
//! `oneiron/agents/oneiron-arch-0067-context-board-v1.md:386`). Every layout
//! call enters through `oneiron_testkit::door::invoke`, the generated verb
//! dispatch every transport shares. Rendered board text has no verb, so the
//! tests that show what a staged layout does to a board lay the layout the door
//! answered over hand-built sections with the public pure seams
//! (`apply_board_layout`, `assemble_memories_sections`, `render_board_block`).
//!
//! - `layout_changes_wait_in_one_pending_batch` (:386 "Layout changes apply on
//!   the next turn in one batch"): fold, filter and size each add to one pending
//!   batch, `replace` swaps the whole batch, and no call touches the live layout.
//! - `a_fold_line_is_rebuilt_from_live_rows` (:386 "A folded line is a live
//!   engine summary rebuilt from typed state every turn"; :41 "a projection,
//!   never a store"): a staged fold carries no counts, and the same staged fold
//!   counts 2 rows over two live rows and 3 over three.
//! - `shares_stay_within_the_cap` (:386 "section sizes as shares of that cap,
//!   never summing past it"): shares up to 100 stage; one share or a sum past
//!   100 is refused and leaves the batch as it was.
//! - `each_actor_lays_out_only_its_own_board` (:386 "The layout persists per
//!   agent"; `crates/oneiron/src/verbs/board_layout.rs:5` "keyed by the
//!   handle's actor, never by a field naming someone else").
//! - `pinned_rows_are_never_folded_or_shed` (:48 "PINNED ... is never
//!   budget-shed", :386 "PINNED and the legend never fold"): a share of 0 and a
//!   fold keep the pinned floor, and a cap of 0 sheds snippets but renders it.
//! - `a_malformed_or_unbound_board_act_is_refused`: an actor the vault does not
//!   hold, a class its entity does not admit, and malformed bodies.
//!
//! Not in this file: the owner's default and override layouts (set through
//! `Vault::set_board_layout_settings`, an owner settings act, not a
//! `self.board` row) and activation at the next turn (the HTTP TURN writer and
//! a native run's render activate the batch; no in-process door reaches it).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test self_board_doors`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::context_board::{
    BoardBlockHeader, BoardBudgetRequest, BoardFrame, BoardLayout, BoardLegend, BoardSection,
    MEMORIES_SECTION_VERSION_V4, MemoriesBudget, MemoriesSection, MemoryRow, MemorySlot,
    MemorySource, MemoryTier, SHED_ORDER, SectionPolicy, ShedRank, apply_board_layout,
    assemble_memories_sections, render_board_block,
};
use oneiron::memory::Memory;
use oneiron::registry::{ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_PERSON};
use oneiron::{
    EdgeActorClass, EntityId, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, TimeRange, Vault,
    VaultConfig,
};
use oneiron_testkit::door;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const PINNED_TEXT: &str = "the pinned text that must survive";
const SNIPPET_TEXT: &str = "a sheddable snippet about lunch plans";

/// A seeded vault, opened as most hosts and tests open one
/// (gate_pins_authority_rechecks.rs's `Fixture::open`).
fn open_vault() -> TestResult<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    Ok((dir, vault))
}

/// A second PERSON of the vault, bound as an agent: PERSON admits the agent
/// class (`crates/oneiron-store/src/write_envelope/provenance/actor_substrate.rs`).
fn agent_person(vault: &Vault) -> TestResult<EntityId> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"an agent of the vault",
    )?;
    Ok(id)
}

fn read_layout(caller: &Memory<'_>) -> TestResult<Value> {
    Ok(door::invoke(caller, "self.board.layout", json!({}))?)
}

fn stage(caller: &Memory<'_>, verb: &str, body: Value) -> TestResult<Value> {
    Ok(door::invoke(caller, verb, body)?)
}

fn refused(caller: &Memory<'_>, verb: &str, body: Value) -> TestResult<(String, String)> {
    let Err(err) = door::invoke(caller, verb, body.clone()) else {
        return Err(format!("{verb} {body} was not refused").into());
    };
    Ok((err.code.to_string(), err.message.to_string()))
}

fn assert_bad(caller: &Memory<'_>, verb: &str, body: Value) -> TestResult {
    let (code, message) = refused(caller, verb, body.clone())?;
    assert_eq!(code, MEMORY_CODE_BAD_REQUEST, "{verb} {body}: {message}");
    Ok(())
}

/// A TASKS section of `rows` live rows, as its producer would build it.
fn tasks_section(rows: &[&str]) -> TestResult<BoardSection> {
    Ok(BoardSection::new(
        "TASKS",
        Vec::new(),
        rows.iter().map(|row| (*row).to_owned()).collect(),
        vec![format!("count: {}", rows.len())],
        SectionPolicy {
            pinned: false,
            shed_rank: Some(ShedRank::TasksToCounts),
        },
    )?)
}

fn memory_row(row_index: usize, tier: MemoryTier, snippet: &str) -> MemoryRow {
    MemoryRow {
        row_index,
        slot: MemorySlot::Claims,
        source: MemorySource::Result,
        id: EntityId::now().to_hex(),
        short_id: format!("m{row_index}"),
        content_hash: format!("{row_index:02x}"),
        entity_type: ENTITY_TYPE_ASSET_TEXT,
        asset_ref: None,
        score: 1.0,
        claim_source: None,
        world: None,
        world_unproven: false,
        tier,
        snippet: Some(snippet.to_owned()),
        hook: None,
        room_pin: None,
        source_revision: None,
        question: None,
        fiction: false,
        constraint: false,
    }
}

/// One MEMORIES pull: a PINNED row and a snippet row, in no world.
fn memories() -> MemoriesSection {
    MemoriesSection {
        version: MEMORIES_SECTION_VERSION_V4.to_owned(),
        budget: MemoriesBudget::default(),
        rows: vec![
            memory_row(0, MemoryTier::Pinned, PINNED_TEXT),
            memory_row(1, MemoryTier::Snippet, SNIPPET_TEXT),
        ],
        companion: None,
        disclosure: None,
    }
}

#[test]
fn layout_changes_wait_in_one_pending_batch() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = door::owner(&vault)?;
    let before = read_layout(&owner)?;
    assert_eq!(
        before,
        json!({"live": {}}),
        "a fresh actor reads the empty default"
    );

    let folded = stage(
        &owner,
        "self.board.fold",
        json!({"section": "tasks", "note": "sweep first"}),
    )?;
    assert_eq!(
        folded["live"],
        json!({}),
        "a fold waits for the turn: {folded}"
    );
    assert_eq!(
        folded["pending"]["sections"]["tasks"]["fold"]["note"], "sweep first",
        "{folded}"
    );
    let filtered = stage(
        &owner,
        "self.board.filter",
        json!({"section": "tasks", "filter": {"who": {"kind": "mine"}, "status": ["running"]}}),
    )?;
    assert_eq!(filtered["live"], json!({}), "{filtered}");
    let sized = stage(
        &owner,
        "self.board.size",
        json!({"section": "memories", "share_pct": 30}),
    )?;
    assert_eq!(sized["live"], json!({}), "{sized}");
    // One batch: the size joined the fold and the filter staged before it.
    let tasks = &sized["pending"]["sections"]["tasks"];
    assert_eq!(tasks["fold"]["note"], "sweep first", "{sized}");
    assert_eq!(
        tasks["filter"],
        json!({"who": {"kind": "mine"}, "status": ["running"]}),
        "{sized}"
    );
    assert_eq!(
        sized["pending"]["sections"]["memories"],
        json!({"share_pct": 30}),
        "{sized}"
    );
    assert_eq!(
        read_layout(&owner)?,
        sized,
        "the read answers the staged batch"
    );

    let unfolded = stage(&owner, "self.board.unfold", json!({"section": "tasks"}))?;
    assert!(
        unfolded["pending"]["sections"]["tasks"]
            .get("fold")
            .is_none(),
        "{unfolded}"
    );
    assert_eq!(unfolded["live"], json!({}), "{unfolded}");

    let replaced = stage(
        &owner,
        "self.board.replace",
        json!({"layout": {"sections": {"inbox": {"share_pct": 10}}}}),
    )?;
    assert_eq!(
        replaced,
        json!({"live": {}, "pending": {"sections": {"inbox": {"share_pct": 10}}}}),
        "replace swaps the whole batch"
    );
    assert_eq!(read_layout(&owner)?, replaced);
    Ok(())
}

#[test]
fn a_fold_line_is_rebuilt_from_live_rows() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = door::owner(&vault)?;
    let folded = stage(
        &owner,
        "self.board.fold",
        json!({"section": "tasks", "note": "sweep first"}),
    )?;
    assert_eq!(
        folded["pending"]["sections"]["tasks"]["fold"],
        json!({"note": "sweep first"}),
        "a staged fold carries no counts of its own: {folded}"
    );
    let layout: BoardLayout = serde_json::from_value(folded["pending"].clone())?;

    let two = tasks_section(&["t1 running one", "t2 queued two"])?;
    let laid = apply_board_layout(std::slice::from_ref(&two), &layout, 10_000);
    assert_eq!(laid.folded, vec!["tasks".to_owned()]);
    let line = laid.sections[0].header_line();
    assert!(laid.sections[0].is_folded(), "{line}");
    assert!(line.starts_with("TASKS 2 · open:"), "{line}");
    assert!(line.ends_with("· note: sweep first"), "{line}");

    let three = tasks_section(&["t1 running one", "t2 queued two", "t3 done three"])?;
    let laid = apply_board_layout(std::slice::from_ref(&three), &layout, 10_000);
    let line = laid.sections[0].header_line();
    assert!(line.starts_with("TASKS 3 · open:"), "{line}");

    assert_eq!(
        read_layout(&owner)?["pending"],
        folded["pending"],
        "a render stores nothing back"
    );
    Ok(())
}

#[test]
fn shares_stay_within_the_cap() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = door::owner(&vault)?;
    stage(
        &owner,
        "self.board.size",
        json!({"section": "tasks", "share_pct": 60}),
    )?;
    let full = stage(
        &owner,
        "self.board.size",
        json!({"section": "memories", "share_pct": 40}),
    )?;
    assert_eq!(
        full["pending"],
        json!({"sections": {"memories": {"share_pct": 40}, "tasks": {"share_pct": 60}}}),
        "shares may fill the cap exactly"
    );

    assert_bad(
        &owner,
        "self.board.size",
        json!({"section": "memories", "share_pct": 50}),
    )?;
    assert_bad(
        &owner,
        "self.board.size",
        json!({"section": "inbox", "share_pct": 1}),
    )?;
    assert_bad(
        &owner,
        "self.board.replace",
        json!({"layout": {"sections": {"tasks": {"share_pct": 60}, "memories": {"share_pct": 50}}}}),
    )?;
    assert_eq!(
        read_layout(&owner)?,
        full,
        "a refused share leaves the batch as it was"
    );

    let resized = stage(
        &owner,
        "self.board.size",
        json!({"section": "tasks", "share_pct": 50}),
    )?;
    let regrown = stage(
        &owner,
        "self.board.size",
        json!({"section": "inbox", "share_pct": 10}),
    )?;
    assert_eq!(resized["pending"]["sections"]["tasks"]["share_pct"], 50);
    assert_eq!(
        regrown["pending"],
        json!({"sections": {
            "inbox": {"share_pct": 10},
            "memories": {"share_pct": 40},
            "tasks": {"share_pct": 50}
        }})
    );
    Ok(())
}

#[test]
fn each_actor_lays_out_only_its_own_board() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = door::owner(&vault)?;
    let agent_id = agent_person(&vault)?;
    let agent = vault.memory(agent_id, EdgeActorClass::Agent);

    stage(
        &owner,
        "self.board.filter",
        json!({"section": "tasks", "filter": {"status": ["failed"]}}),
    )?;
    assert_eq!(
        read_layout(&agent)?,
        json!({"live": {}}),
        "the owner's batch is not the agent's"
    );

    let own = stage(
        &agent,
        "self.board.size",
        json!({"section": "memories", "share_pct": 20}),
    )?;
    assert_eq!(
        own["pending"],
        json!({"sections": {"memories": {"share_pct": 20}}}),
        "the agent's batch starts from its own layout: {own}"
    );
    let owner_view = read_layout(&owner)?;
    assert_eq!(
        owner_view["pending"],
        json!({"sections": {"tasks": {"filter": {"status": ["failed"]}}}}),
        "the agent's size never reaches the owner's batch: {owner_view}"
    );

    // A second handle of the same actor reads the same stored batch.
    let again = vault.memory(agent_id, EdgeActorClass::Agent);
    assert_eq!(read_layout(&again)?, own);
    Ok(())
}

#[test]
fn pinned_rows_are_never_folded_or_shed() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = door::owner(&vault)?;
    let sections = assemble_memories_sections(&memories())?;
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].name(), "MEMORIES world=unscoped");
    assert!(
        sections[0]
            .pinned_rows()
            .iter()
            .any(|row| row.contains("tier=PINNED") && row.contains(PINNED_TEXT)),
        "{:?}",
        sections[0].pinned_rows()
    );
    assert!(
        sections[0]
            .detail_rows()
            .iter()
            .any(|row| row.contains(SNIPPET_TEXT)),
        "{:?}",
        sections[0].detail_rows()
    );

    // A share of 0 is a literal zero: the section fits to its count line and
    // keeps its pinned floor.
    let sized = stage(
        &owner,
        "self.board.size",
        json!({"section": "memories", "share_pct": 0}),
    )?;
    let layout: BoardLayout = serde_json::from_value(sized["pending"].clone())?;
    let laid = apply_board_layout(&sections, &layout, 10_000);
    assert_eq!(laid.fitted, vec!["memories".to_owned()]);
    assert!(
        laid.sections[0]
            .pinned_rows()
            .iter()
            .any(|row| row.contains(PINNED_TEXT)),
        "{:?}",
        laid.sections[0].pinned_rows()
    );
    assert_eq!(laid.sections[0].detail_rows(), ["count: 2".to_owned()]);

    // A fold folds the snippets to one line; the pinned floor stays.
    let folded = stage(&owner, "self.board.fold", json!({"section": "memories"}))?;
    let layout: BoardLayout = serde_json::from_value(folded["pending"].clone())?;
    let laid = apply_board_layout(&sections, &layout, 10_000);
    assert!(laid.sections[0].is_folded());
    assert!(laid.sections[0].detail_rows().is_empty());
    assert!(
        laid.sections[0]
            .pinned_rows()
            .iter()
            .any(|row| row.contains(PINNED_TEXT)),
        "{:?}",
        laid.sections[0].pinned_rows()
    );

    // A cap of 0 runs the whole shed ladder: snippets go, PINNED renders.
    let header = BoardBlockHeader {
        epoch: 1,
        scope: "world-set".to_owned(),
    };
    let legend = BoardLegend::canonical();
    let render = render_board_block(
        &BoardFrame {
            header: &header,
            legend: &legend,
            sections: &sections,
            you: None,
            changes: None,
        },
        BoardBudgetRequest {
            harness_default_tok: 10_000,
            caller_limit_tok: Some(0),
            explicit_override_tok: None,
        },
    )?;
    assert!(render.text.contains(PINNED_TEXT), "{}", render.text);
    assert!(!render.text.contains(SNIPPET_TEXT), "{}", render.text);
    assert!(
        render.shed.applied.contains(&ShedRank::MemoriesSnippets),
        "{:?}",
        render.shed.applied
    );
    assert!(
        render.shed.floor_exceeds_cap,
        "the pinned floor renders past the cap"
    );
    let rank = |wanted: ShedRank| SHED_ORDER.iter().position(|rank| *rank == wanted);
    assert!(rank(ShedRank::MemoriesSnippets) < rank(ShedRank::TasksToCounts));
    Ok(())
}

#[test]
fn a_malformed_or_unbound_board_act_is_refused() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = door::owner(&vault)?;

    // An actor the vault does not hold stages nothing; nor does a PERSON bound
    // as the system class.
    let ghost = vault.memory(EntityId::now(), EdgeActorClass::Agent);
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let system = vault.memory(owner_id, EdgeActorClass::System);
    for (verb, body) in [
        ("self.board.fold", json!({"section": "tasks"})),
        ("self.board.unfold", json!({"section": "tasks"})),
        (
            "self.board.size",
            json!({"section": "tasks", "share_pct": 10}),
        ),
        (
            "self.board.filter",
            json!({"section": "tasks", "filter": {"status": ["running"]}}),
        ),
        (
            "self.board.replace",
            json!({"layout": {"sections": {"tasks": {"share_pct": 10}}}}),
        ),
    ] {
        for caller in [&ghost, &system] {
            let (code, message) = refused(caller, verb, body.clone())?;
            assert_eq!(code, MEMORY_CODE_FORBIDDEN, "{verb}: {message}");
        }
    }

    let keep65: Vec<String> = (0..65).map(|_| EntityId::now().to_hex()).collect();
    let mut sections33 = serde_json::Map::new();
    for index in 0..33 {
        sections33.insert(format!("k{index:02}"), json!({}));
    }
    let malformed = [
        ("self.board.layout", json!({"section": "tasks"})),
        ("self.board.layout", json!("tasks")),
        ("self.board.fold", json!({"section": "tasks", "pin": true})),
        ("self.board.fold", json!({"section": 12345})),
        (
            "self.board.fold",
            json!({"section": "tasks", "keep": ["not hex"]}),
        ),
        ("self.board.fold", json!({"section": "!!"})),
        ("self.board.fold", json!({"section": ""})),
        ("self.board.fold", json!({"section": "9lives"})),
        (
            "self.board.fold",
            json!({"section": "tasks", "note": "x".repeat(513)}),
        ),
        (
            "self.board.fold",
            json!({"section": "tasks", "keep": keep65}),
        ),
        (
            "self.board.unfold",
            json!({"section": "tasks", "note": "x"}),
        ),
        ("self.board.unfold", json!({"section": "has space"})),
        (
            "self.board.size",
            json!({"section": "tasks", "share_pct": 10, "weight": 1}),
        ),
        (
            "self.board.size",
            json!({"section": "tasks", "share_pct": "lots"}),
        ),
        (
            "self.board.size",
            json!({"section": "tasks", "share_pct": 300}),
        ),
        (
            "self.board.size",
            json!({"section": "tasks", "share_pct": 101}),
        ),
        (
            "self.board.filter",
            json!({"section": "tasks", "who": "mine"}),
        ),
        (
            "self.board.filter",
            json!({"section": "tasks", "filter": "mine"}),
        ),
        (
            "self.board.filter",
            json!({"section": "tasks", "filter": {"who": {"kind": "everyone"}}}),
        ),
        (
            "self.board.filter",
            json!({"section": "tasks", "filter": {"who": {"kind": "class", "class": "Human"}}}),
        ),
        (
            "self.board.filter",
            json!({"section": "tasks", "filter": {"status": ["Running"]}}),
        ),
        (
            "self.board.filter",
            json!({"section": "tasks", "filter": {"status": ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9"]}}),
        ),
        ("self.board.replace", json!({"layout": {}, "batch": 1})),
        (
            "self.board.replace",
            json!({"layout": {"sections": {"Tasks": {}}}}),
        ),
        (
            "self.board.replace",
            json!({"layout": {"sections": sections33}}),
        ),
    ];
    for (verb, body) in malformed {
        assert_bad(&owner, verb, body)?;
    }
    assert_eq!(
        read_layout(&owner)?,
        json!({"live": {}}),
        "no refused act staged a batch"
    );
    Ok(())
}
