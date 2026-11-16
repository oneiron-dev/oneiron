//! graph_fs doors: the nine read-only rows read through the verb dispatch and write nothing.
//!
//! Proves P1 of canon `oneiron/code-in-oneiron.md:104`: "the lens is the nine
//! read-only graph_fs rows, reached through the verb-call import". Every row is
//! scope Read (`scripts/sdk/verbs/graph_fs.*.json:7`), served below only a
//! scoped read lane (`crates/oneiron/src/memory/graph_fs_doors/mod.rs`), so
//! the owner reads each row and no call adds a claim, entity, or receipt row.
//!
//! Proves the gate behind P2 ("verb-call is first-party-only
//! (crates/oneiron/wit/code-run.wit:88-110; NON_WRITE_IMPORTS,
//! crates/oneiron/src/store/sandbox_contract.rs:263-274), so today a foreign
//! or untrusted guest reads no graph_fs row"): the Foreign and Untrusted
//! sandbox contracts link no verb-table import and no import named for a
//! row, while the first-party contract links `self.verbs.call`. A guest run
//! end to end needs a real host (a QuickJS component and a model), so this
//! file proves the link-time gate a guest's call would meet.
//!
//! It uses no cfg door. Run: `cargo test --locked -p oneiron --all-features --test
//! graph_fs_doors`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::code_sandbox::{SandboxBoundaryContract, SandboxGuestTier, SandboxImportClass};
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, Memory};
use oneiron::receipt::ReceiptQuery;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::verbs::AgentVerb;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault,
};
use oneiron_testkit::{TestVault, door};
use serde_json::{Value, json};

/// The nine graph_fs rows, in canon order.
const GRAPH_FS_ROWS: [&str; 9] = [
    "graph_fs.cat",
    "graph_fs.find",
    "graph_fs.grep",
    "graph_fs.head",
    "graph_fs.ls",
    "graph_fs.readdir",
    "graph_fs.read_file",
    "graph_fs.read_link",
    "graph_fs.wc",
];

/// The verb-call import that carries every row to a guest.
const VERB_CALL_IMPORT: &str = "self.verbs.call";

/// First person's body: three lines, carrying the grep token.
const BODY_FIRST: &str =
    "graph-fs doors first line greptoken-alpha\nsecond line here\nthird line here\n";
/// Second person's body: one line, no token.
const BODY_SECOND: &str = "second body without the marker\n";
/// The token only the first body holds.
const GREP_TOKEN: &str = "greptoken-alpha";

/// One test's vault: the copy owns its temp dir, the open vault borrows it.
struct GraphFixture {
    test_vault: TestVault,
    vault: Vault,
}

impl GraphFixture {
    /// An empty vault, opened owned so every door can run, with its embedded
    /// owner present so calls have a live owner to act as.
    fn open_named(seed_name: &str) -> Self {
        let test_vault = TestVault::seeded(seed_name, |_, _| Ok(())).expect("seed an empty vault");
        let vault = test_vault.open_owned().expect("open the vault owned");
        vault
            .ensure_embedded_owner_actor()
            .expect("ensure the embedded owner");
        Self { test_vault, vault }
    }

    /// The agent principal `name` acts as (no grants minted for it).
    fn agent_named(&self, name: &str) -> EntityId {
        self.vault
            .ensure_agent_principal(name)
            .expect("ensure the agent principal")
    }
}

/// Two people with text bodies and one claim about the first; answers
/// (first person, second person, claim).
fn seed_two_people_and_claim(vault: &Vault) -> (EntityId, EntityId, EntityId) {
    let at = TimeRange { start: 1, end: 1 };
    let first = EntityId::now();
    vault
        .put_entity(&first, ENTITY_TYPE_PERSON, at, 1, BODY_FIRST.as_bytes())
        .expect("put the first person");
    let second = EntityId::now();
    vault
        .put_entity(&second, ENTITY_TYPE_PERSON, at, 1, BODY_SECOND.as_bytes())
        .expect("put the second person");
    let claim = EntityId::now();
    let body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(first),
        rmpv::Value::from("claim about the first person"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("build the claim body");
    vault
        .put_claim(&claim, &body, at, 1)
        .expect("put the claim");
    (first, second, claim)
}

/// The live-head mount every row input carries.
fn live_head_mount() -> Value {
    json!({"ref": {"kind": "live_head"}})
}

/// The path `row` addresses (and echoes) over the seeded tree: `person_hex`
/// is the first person's hex, `claim_hex` the claim's.
fn path_echo_for(row: &str, person_hex: &str, claim_hex: &str) -> String {
    match row {
        "graph_fs.cat" | "graph_fs.read_file" | "graph_fs.head" | "graph_fs.wc" => {
            format!("/entities/{person_hex}/body")
        }
        "graph_fs.ls" | "graph_fs.readdir" => format!("/entities/{person_hex}"),
        "graph_fs.find" | "graph_fs.grep" => "/entities".to_owned(),
        "graph_fs.read_link" => format!("/[[claim:{claim_hex}]]"),
        _ => panic!("unknown graph_fs row: {row}"),
    }
}

/// The input for `row` over the seeded tree.
fn input_for_row(row: &str, person_hex: &str, claim_hex: &str) -> Value {
    let mount = live_head_mount();
    let echoed = path_echo_for(row, person_hex, claim_hex);
    match row {
        "graph_fs.cat" | "graph_fs.read_file" | "graph_fs.wc" => {
            json!({"mount": mount, "path": echoed})
        }
        "graph_fs.head" => json!({"mount": mount, "path": echoed, "lines": 2}),
        "graph_fs.ls" | "graph_fs.readdir" => json!({"mount": mount, "path": echoed}),
        "graph_fs.find" => json!({"mount": mount, "path": echoed}),
        "graph_fs.grep" => json!({
            "mount": mount, "path": echoed,
            "pattern": GREP_TOKEN, "recursive": true,
        }),
        "graph_fs.read_link" => json!({"mount": mount, "path": echoed}),
        _ => panic!("unknown graph_fs row: {row}"),
    }
}

/// Every receipt (id and outcome) of every kind, in receipt-id order: the
/// receipt rows a call may have kept.
fn receipt_rows_in(vault: &Vault) -> Vec<String> {
    let mut rows = vault
        .receipts(ReceiptQuery::new(100))
        .expect("query receipts");
    rows.sort_by_key(|row| row.receipt_id.clone());
    rows.into_iter()
        .map(|row| format!("{} {}", row.receipt_id, row.outcome))
        .collect()
}

/// The lens reading itself: the entity and claim listings plus the first
/// body, as stable text. Any new entity or claim row would change it.
fn lens_reading_with(caller: &Memory<'_>, person_hex: &str) -> Vec<String> {
    let mount = live_head_mount();
    let body_path = format!("/entities/{person_hex}/body");
    let entity_path = format!("/entities/{person_hex}");
    let mut reading = Vec::new();
    for (verb, path) in [
        ("graph_fs.ls", "/entities"),
        ("graph_fs.ls", entity_path.as_str()),
        ("graph_fs.ls", "/claims/by-id"),
        ("graph_fs.cat", body_path.as_str()),
    ] {
        let input = json!({"mount": mount.clone(), "path": path});
        let answer: Value = door::invoke(caller, verb, input)
            .unwrap_or_else(|error| panic!("{verb} {path} answers: {error:?}"));
        reading.push(format!(
            "{verb} {path} {encoding} {plan} {output}",
            encoding = answer["encoding"].as_str().unwrap_or("?"),
            plan = answer["plan"].as_str().unwrap_or("?"),
            output = answer["output"].as_str().unwrap_or("?"),
        ));
    }
    reading
}

/// The stable fields of one row's answer: content and echoes, never the
/// sealed per-call cursor or receipt.
fn stable_answer_of(row: &str, answer: &Value) -> String {
    if row == "graph_fs.readdir" {
        let mut entries: Vec<String> = answer["entries"]
            .as_array()
            .unwrap_or_else(|| panic!("{row} answers entries: {answer}"))
            .iter()
            .map(|entry| {
                format!(
                    "{name}:{kind}",
                    name = entry["name"].as_str().unwrap_or("?"),
                    kind = entry["kind"].as_str().unwrap_or("?"),
                )
            })
            .collect();
        entries.sort();
        return format!(
            "{} {}",
            answer["path"].as_str().unwrap_or("?"),
            entries.join(",")
        );
    }
    if row == "graph_fs.read_link" {
        return format!(
            "{}>{}",
            answer["path"].as_str().unwrap_or("?"),
            answer["target"].as_str().unwrap_or("?"),
        );
    }
    format!(
        "{}|{}|{}|{}",
        answer["path"].as_str().unwrap_or("?"),
        answer["output"].as_str().unwrap_or("?"),
        answer["encoding"].as_str().unwrap_or("?"),
        answer["plan"].as_str().unwrap_or("?"),
    )
}

/// Every graph_fs row is a facade Read row: invokable by name, and marked
/// non-writing at the dispatch layer.
fn assert_row_is_facade_read(row: &str) {
    let verb = AgentVerb::from_name(row).unwrap_or_else(|| panic!("{row} is a verb row"));
    assert!(
        verb.is_facade(),
        "{row} is a facade row, so invoke reaches it"
    );
    assert!(
        !verb.writes(),
        "{row} is scope Read, so the dispatch marks it non-writing"
    );
}

/// The owner's answer for `row` carries the seeded tree: echoes, shape, and
/// (where the source fixes it) content.
fn assert_owner_answer(row: &str, answer: &Value, person_hex: &str, claim_hex: &str, echoed: &str) {
    assert_eq!(
        answer["mount"]["ref"]["kind"].as_str(),
        Some("live_head"),
        "{row} echoes the live-head mount: {answer}"
    );
    assert_eq!(
        answer["path"].as_str(),
        Some(echoed),
        "{row} echoes its input path: {answer}"
    );
    match row {
        "graph_fs.cat" | "graph_fs.read_file" => {
            assert_eq!(
                answer["output"].as_str(),
                Some(BODY_FIRST),
                "{row} serves the stored body bytes"
            );
            assert_eq!(
                answer["encoding"].as_str(),
                Some("utf8"),
                "{row} serves text as utf8"
            );
        }
        "graph_fs.head" => {
            let output = answer["output"]
                .as_str()
                .unwrap_or_else(|| panic!("{row} outputs text"));
            assert!(
                output.contains("first line"),
                "{row} keeps the first lines: {output}"
            );
            assert!(
                output.contains("second line"),
                "{row} keeps the first lines: {output}"
            );
            assert!(
                !output.contains("third line"),
                "{row} stops after two lines: {output}"
            );
        }
        "graph_fs.wc" => {
            let expected = format!(
                "{lines} {words} {bytes} {echoed}\n",
                lines = BODY_FIRST.lines().count(),
                words = BODY_FIRST.split_whitespace().count(),
                bytes = BODY_FIRST.len(),
            );
            assert_eq!(
                answer["output"].as_str(),
                Some(expected.as_str()),
                "{row} counts the stored body: {answer}"
            );
            assert_eq!(
                answer["encoding"].as_str(),
                Some("utf8"),
                "{row} counts as text"
            );
        }
        "graph_fs.ls" => {
            let output = answer["output"]
                .as_str()
                .unwrap_or_else(|| panic!("{row} outputs text"));
            assert!(output.contains("body"), "{row} lists the body: {output}");
        }
        "graph_fs.find" => {
            let output = answer["output"]
                .as_str()
                .unwrap_or_else(|| panic!("{row} outputs text"));
            assert!(
                output.contains(person_hex),
                "{row} walks the seeded person: {output}"
            );
        }
        "graph_fs.grep" => {
            let output = answer["output"]
                .as_str()
                .unwrap_or_else(|| panic!("{row} outputs text"));
            assert!(
                output.contains(GREP_TOKEN),
                "{row} matches the token: {output}"
            );
        }
        "graph_fs.readdir" => {
            let entries = answer["entries"]
                .as_array()
                .unwrap_or_else(|| panic!("{row} answers entries: {answer}"));
            assert!(!entries.is_empty(), "{row} lists the entity: {answer}");
            assert!(
                entries.iter().any(|entry| {
                    entry["name"].as_str() == Some("body") && entry["kind"].as_str() == Some("file")
                }),
                "{row} lists the body as a file: {answer}"
            );
        }
        "graph_fs.read_link" => {
            assert_eq!(
                answer["target"].as_str(),
                Some(format!("/claims/{claim_hex}").as_str()),
                "{row} resolves the claim link: {answer}"
            );
        }
        _ => panic!("unknown graph_fs row: {row}"),
    }
    if row != "graph_fs.readdir" && row != "graph_fs.read_link" {
        assert!(
            matches!(answer["plan"].as_str(), Some("pushdown") | Some("walk")),
            "{row} names its plan: {answer}"
        );
    }
}

/// Every graph_fs row reads through the verb dispatch and writes nothing:
/// the owner reads the seeded tree on each row, a grantless agent's calls
/// keep nothing whatever the read gate answers, and a refused call keeps
/// nothing either.
#[test]
fn every_graph_fs_row_reads_and_writes_nothing() {
    let fixture = GraphFixture::open_named("graph-fs-doors-read");
    let seeded = seed_two_people_and_claim(&fixture.vault);
    let person_hex = seeded.0.to_hex();
    let claim_hex = seeded.2.to_hex();
    let owner = door::owner(&fixture.vault).expect("the owner caller");
    let stranger = fixture.vault.memory(
        fixture.agent_named("graph-fs-doors-stranger"),
        EdgeActorClass::Agent,
    );
    for row in GRAPH_FS_ROWS {
        assert_row_is_facade_read(row);
    }
    let receipts_before = receipt_rows_in(&fixture.vault);
    let lens_before = lens_reading_with(&owner, &person_hex);
    let mut first_answers = Vec::new();
    for row in GRAPH_FS_ROWS {
        let echoed = path_echo_for(row, &person_hex, &claim_hex);
        let answer: Value = door::invoke(&owner, row, input_for_row(row, &person_hex, &claim_hex))
            .unwrap_or_else(|error| panic!("{row} answers the owner: {error:?}"));
        assert_owner_answer(row, &answer, &person_hex, &claim_hex, &echoed);
        first_answers.push(stable_answer_of(row, &answer));
    }
    for row in GRAPH_FS_ROWS {
        let echoed = path_echo_for(row, &person_hex, &claim_hex);
        let input = input_for_row(row, &person_hex, &claim_hex);
        if let Ok(answer) = door::invoke(&stranger, row, input) {
            assert_eq!(
                answer["path"].as_str(),
                Some(echoed.as_str()),
                "{row} echoes one path for any caller"
            );
        }
    }
    let mount = live_head_mount();
    let refused = door::invoke(
        &owner,
        "graph_fs.grep",
        json!({"mount": mount, "path": "/entities", "pattern": "", "recursive": true}),
    )
    .expect_err("an empty pattern is refused");
    assert_eq!(
        refused.code, MEMORY_CODE_BAD_REQUEST,
        "the empty-pattern refusal code"
    );
    assert_eq!(
        refused.message, "grep needs a pattern",
        "the empty-pattern refusal message"
    );
    assert_eq!(
        receipt_rows_in(&fixture.vault),
        receipts_before,
        "reads and the one refusal keep no receipt row"
    );
    assert_eq!(
        lens_reading_with(&owner, &person_hex),
        lens_before,
        "reads and the one refusal keep no claim or entity row"
    );
    for (index, first) in first_answers.iter().enumerate() {
        let row = GRAPH_FS_ROWS[index];
        let answer: Value = door::invoke(&owner, row, input_for_row(row, &person_hex, &claim_hex))
            .unwrap_or_else(|error| panic!("{row} answers again: {error:?}"));
        assert_eq!(
            &stable_answer_of(row, &answer),
            first,
            "{row} reads the same twice"
        );
    }
}

/// The verb-call import is first-party-only: the Foreign and Untrusted
/// contracts link neither it, nor any verb-table import, nor an import named
/// for a row, so no guest call reaches any of the nine rows. The first-party
/// contract links it.
#[test]
fn foreign_and_untrusted_guests_link_no_graph_fs_row() {
    for tier in [SandboxGuestTier::Foreign, SandboxGuestTier::Untrusted] {
        let contract = SandboxBoundaryContract::for_tier(tier);
        assert_eq!(contract.tier(), tier, "the contract is {tier:?}'s");
        assert!(
            tier.requires_zero_write_imports(),
            "{tier:?} takes no write imports"
        );
        assert!(
            contract.has_proposal_delta_channel(),
            "{tier:?} writes by proposal only"
        );
        let names: Vec<&str> = contract
            .linked_imports()
            .iter()
            .map(|import| import.name())
            .collect();
        assert!(
            !names.contains(&VERB_CALL_IMPORT),
            "{tier:?} links no verb-call import: {names:?}"
        );
        assert!(
            contract
                .linked_imports()
                .iter()
                .all(|import| import.class() != SandboxImportClass::VerbTable),
            "{tier:?} links no verb-table import: {names:?}"
        );
        for row in GRAPH_FS_ROWS {
            assert!(
                !names.iter().any(|name| name.contains(row)),
                "{tier:?} links no import named for {row}: {names:?}"
            );
        }
    }
    let first_party = SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer);
    assert!(
        !first_party.tier().requires_zero_write_imports(),
        "the first-party tier links its imports"
    );
    assert!(
        first_party
            .linked_imports()
            .iter()
            .any(|import| import.name() == VERB_CALL_IMPORT),
        "the first-party tier links the verb-call import"
    );
}
