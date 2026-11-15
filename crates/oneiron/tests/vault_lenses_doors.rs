//! The `vault.lenses.*` doors keep the lens promises (ruling L4-23 = A: each
//! test proves a promise at its public door). Every verb call enters through
//! `oneiron_testkit::door::invoke`, the generated verb dispatch every
//! transport shares. Seven of the ten rows answer in-process; `select`,
//! `resolve` and `result_set.action` act on a server's held card and answer
//! the host-only refusal on an embedded vault (their served custody is the
//! server's `api/facade/lens_selection_doors.rs`, their engine entry is
//! pinned by `tests/lens_result_set_selection.rs`).
//!
//! - P2 `oneiron/agents/oneiron-arch-0062-booking-loop-v1.md:314`: "the
//!   widget lens is a CODE artifact with intent-senior regeneration". No
//!   widget lens ships on main; the test pins the generic mechanism every
//!   lens uses: a proposal is a `CODE_ARTIFACT` row holding the frozen tree,
//!   its authored intent is kept beside it, and a lens pack carries that
//!   intent by default, because the intent is the recipe a regeneration
//!   reruns. The rerun itself (`Vault::regenerate_lens_on_upgrade`,
//!   `Memory::lenses_enact_regeneration`) has no verb.
//! - P3 `oneiron/surfaces/oneiron-arch-0048-genui-protocol.md:61`: "never
//!   HTML or JS, and one trusted render_instrument draws the result". The
//!   door half: an atom kind outside the closed kit (`html`) and a self.ui
//!   action id naming a script capability are refused before anything
//!   lands. The renderer half (`render_instrument`) answers no lens verb.
//! - Owner: `activate` and `deactivate` are the owner's (`host_door_proof:
//!   owner`); an agent is refused both and the slot keeps its selection.
//! - Refusals: an unknown field is refused on all ten rows, and the three
//!   host rows refuse a well-formed body as host-only.
//!
//! Not in this file: arch-0062:34 "an unauthenticated render whose reach is
//! pack verbs" is the booking page's public route, not a `vault.lenses` row
//! (no lens verb renders without a caller); ND-027 is not on main.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test vault_lenses_doors`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_MODEL_UNAVAILABLE, Memory,
    MemoryError,
};
use oneiron::{EdgeActorClass, Vault, VaultConfig};
use oneiron_testkit::door;
use serde_json::{Value, json};

/// A 32-hex id nothing is stored under.
const SOME_ID: &str = "019a7218240070008000000000000001";
/// A 64-hex hash nothing is stored under.
const SOME_HASH: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// A seeded vault this process owns (the writer lease), as an embedded host
/// opens it (`tests/gate_pins_authority_rechecks.rs` opens it the same way).
/// Its open installs the engine's weave lens pack Active
/// (`skill_hub/pack_catalog/lenses.rs` `seed_weave_lens_pack_in_txn`).
fn owned_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("a tempdir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("an owned open");
    (dir, vault)
}

fn provision_machines(vault: &Vault) {
    let _issuer = oneiron::test_support::provision_engine_machines(vault);
}

#[track_caller]
fn refused(result: Result<Value, MemoryError>, what: &str) -> MemoryError {
    match result {
        Err(error) => error,
        Ok(value) => panic!("{what} was answered, want a refusal: {value}"),
    }
}

#[track_caller]
fn answered(result: Result<Value, MemoryError>, what: &str) -> Value {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{what} was refused: {error:?}"),
    }
}

/// The weave pack's slot as the owner reads its install: the pack name, its
/// one skill and the content hash it is Active at.
struct Slot {
    pack: String,
    skill: String,
    content: String,
}

fn weave_slot(owner: &Memory<'_>) -> Slot {
    let install = answered(
        door::invoke(owner, "vault.packs.get", json!({"name": "oneiron.weave"})),
        "packs.get oneiron.weave",
    );
    assert_eq!(
        install["status"],
        json!("active"),
        "the weave pack is Active: {install}"
    );
    Slot {
        pack: install["pack_name"].as_str().expect("pack_name").to_owned(),
        skill: install["skills"][0].as_str().expect("one skill").to_owned(),
        content: install["content_hash"]
            .as_str()
            .expect("content_hash")
            .to_owned(),
    }
}

/// The smallest tree at this vault's stamps (kit 3, apps contract 1): one
/// closed `throbber` atom.
fn throbber_tree() -> Value {
    json!({
        "kit_version": 3,
        "apps_contract_version": 1,
        "root": {
            "id": "root",
            "atom": {"kind": "throbber", "props": {"label": "loading"}},
            "fallbackText": "loading"
        }
    })
}

fn propose_body(slot: &Slot, intent: &str) -> Value {
    json!({
        "slot": {"pack_name": slot.pack, "skill_id": slot.skill},
        "pack_content_hash": slot.content,
        "compiled": throbber_tree(),
        "intent_prompt": intent
    })
}

fn list_row(owner: &Memory<'_>, lens_ref: &str) -> Value {
    let page = answered(
        door::invoke(owner, "vault.lenses.list", json!({"with_compiled": true})),
        "lenses.list",
    );
    page["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|row| row["lens_ref"] == json!(lens_ref))
        .cloned()
        .unwrap_or_else(|| panic!("list names {lens_ref}: {page}"))
}

/// A result-set action event from card `c` whose action id is `action_id`.
fn result_set_action(action_id: &str) -> Value {
    json!({
        "event": {
            "action": {"cardId": "c", "elementId": "e", "actionId": action_id, "occurredAt": 1},
            "selection": {"mode": "all_within_filter"}
        },
        "selected": [],
        "idempotencyKey": "k"
    })
}

/// P2. A proposal is a CODE_ARTIFACT row holding the frozen tree; list names
/// the same revision; the lens pack carries the authored intent by default,
/// and an explicit empty choice carries none.
/// Red proof: `oneiron-authority/src/share_travel.rs:93` the lens pack's
/// default travel no longer names the intent prompt (`-red1`).
#[test]
fn a_proposed_lens_is_a_code_row_whose_intent_travels_with_it() {
    let (_dir, vault) = owned_vault();
    provision_machines(&vault);
    let owner = door::owner(&vault).expect("the owner");
    let slot = weave_slot(&owner);
    let intent = "Draw a loading card.";

    let receipt = answered(
        door::invoke(&owner, "vault.lenses.propose", propose_body(&slot, intent)),
        "propose",
    );
    assert_eq!(receipt["approval"], json!("proposed"), "{receipt}");
    assert_eq!(receipt["pack_name"], json!(slot.pack));
    let lens_ref = receipt["lens_ref"].as_str().expect("lens_ref").to_owned();
    let compiled_hash = receipt["compiled_hash"]
        .as_str()
        .expect("compiled_hash")
        .to_owned();

    let row = answered(
        door::invoke(&owner, "vault.get", json!({"entity_ref": lens_ref})),
        "vault.get the lens row",
    );
    assert_eq!(
        row["value"]["kind"],
        json!("CODE_ARTIFACT"),
        "the lens is a CODE row: {row}"
    );

    let listed = list_row(&owner, &lens_ref);
    assert_eq!(listed["state"], json!("proposed"), "{listed}");
    assert_eq!(listed["mounted"], json!(false), "{listed}");
    assert_eq!(listed["compiled_hash"], json!(compiled_hash), "{listed}");
    assert_eq!(listed["skill_id"], json!(slot.skill), "{listed}");
    assert_eq!(listed["pack_content_hash"], json!(slot.content), "{listed}");
    assert_eq!(listed["compiled"]["kit_version"], json!(3), "{listed}");
    assert_eq!(
        listed["compiled"]["root"]["atom"]["kind"],
        json!("throbber"),
        "{listed}"
    );

    let export = answered(
        door::invoke(
            &owner,
            "vault.lenses.export_pack",
            json!({"lens_ref": lens_ref}),
        ),
        "export_pack (default travel)",
    );
    let file: Value = serde_json::from_str(export["pack_json"].as_str().expect("pack_json"))
        .expect("a pack file");
    assert_eq!(file["compiled_hash"], json!(compiled_hash), "{file}");
    assert_eq!(file["compiled"]["root"]["id"], json!("root"), "{file}");
    assert_eq!(
        file["born_with"]["intent_prompt"],
        json!(intent),
        "the recipe travels: {file}"
    );
    assert_eq!(export["receipt"]["lens_ref"], json!(lens_ref));
    assert_ne!(
        export["receipt"]["prompt_ref"],
        json!(lens_ref),
        "the intent is its own row"
    );
    assert_eq!(
        export["receipt"]["travelled"],
        json!(["intent_prompt"]),
        "{export}"
    );

    let bare = answered(
        door::invoke(
            &owner,
            "vault.lenses.export_pack",
            json!({"lens_ref": lens_ref, "travel": {"born_with": []}}),
        ),
        "export_pack (nothing travels)",
    );
    let file: Value =
        serde_json::from_str(bare["pack_json"].as_str().expect("pack_json")).expect("a pack file");
    assert_eq!(bare["receipt"]["travelled"], json!([]), "{bare}");
    assert!(
        file["born_with"]["intent_prompt"].is_null(),
        "the choice is kept: {file}"
    );
}

/// P3. An atom kind outside the closed kit and a self.ui action id that
/// names a script capability are refused at the door; a closed tree lands.
/// Red proof: `oneiron-lens-wire/src/lens/validate.rs:190` the forbidden
/// capability check is skipped (`-red2`): the `script` id decodes and
/// reaches the host-only refusal.
#[test]
fn a_lens_carries_no_html_and_no_script_capability() {
    let (_dir, vault) = owned_vault();
    provision_machines(&vault);
    let owner = door::owner(&vault).expect("the owner");
    let slot = weave_slot(&owner);

    let mut html = propose_body(&slot, "An html card.");
    html["compiled"]["root"]["atom"] = json!({"kind": "html", "props": {"body": "<b>hi</b>"}});
    let error = refused(
        door::invoke(&owner, "vault.lenses.propose", html),
        "an html atom",
    );
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST, "{error:?}");

    for action_id in ["script", "runJavascript", "eval"] {
        let error = refused(
            door::invoke(
                &owner,
                "vault.lenses.result_set.action",
                result_set_action(action_id),
            ),
            action_id,
        );
        assert_eq!(
            error.code, MEMORY_CODE_BAD_REQUEST,
            "{action_id}: {error:?}"
        );
    }
    // The same event with a plain id decodes and meets the host-only refusal.
    let error = refused(
        door::invoke(
            &owner,
            "vault.lenses.result_set.action",
            result_set_action("archive"),
        ),
        "archive",
    );
    assert_eq!(error.code, MEMORY_CODE_MODEL_UNAVAILABLE, "{error:?}");

    let page = answered(door::invoke(&owner, "vault.lenses.list", json!({})), "list");
    assert_eq!(page["rows"], json!([]), "nothing refused landed: {page}");
    let receipt = answered(
        door::invoke(
            &owner,
            "vault.lenses.propose",
            propose_body(&slot, "A loading card."),
        ),
        "a closed tree",
    );
    assert_eq!(receipt["approval"], json!("proposed"), "{receipt}");
}

/// Owner. The owner selects a slot's lens; an agent is refused selecting and
/// clearing it and the slot keeps the owner's selection; the owner clears it.
/// Red proof: `oneiron/src/memory/owner_door.rs:85` the embedded owner
/// door's refusal answers NOT_FOUND (`-red1`).
#[test]
fn only_the_owner_selects_or_clears_a_lens_slot() {
    let (_dir, vault) = owned_vault();
    let agent = oneiron::test_doors::coach::define_agent(&vault).expect("an agent");
    provision_machines(&vault);
    let owner = door::owner(&vault).expect("the owner");
    let agent = vault.memory(agent, EdgeActorClass::Agent);
    let slot = weave_slot(&owner);

    let receipt = answered(
        door::invoke(
            &owner,
            "vault.lenses.propose",
            propose_body(&slot, "Owner slot."),
        ),
        "propose",
    );
    let lens_ref = receipt["lens_ref"].as_str().expect("lens_ref").to_owned();
    let compiled_hash = receipt["compiled_hash"]
        .as_str()
        .expect("compiled_hash")
        .to_owned();
    let select = json!({"lens_ref": lens_ref, "compiled_hash": compiled_hash});
    let clear = json!({
        "slot": {"pack_name": slot.pack, "skill_id": slot.skill},
        "expected_active_ref": lens_ref
    });

    let active = answered(
        door::invoke(&owner, "vault.lenses.activate", select.clone()),
        "owner activate",
    );
    assert_eq!(active["decision"], json!("activated"), "{active}");
    assert!(
        active["previous_ref"].is_null(),
        "an empty slot had none: {active}"
    );
    let listed = list_row(&owner, &lens_ref);
    assert_eq!(
        (listed["state"].clone(), listed["mounted"].clone()),
        (json!("active"), json!(true))
    );

    let mut again = select.clone();
    again["expected_active_ref"] = json!(lens_ref);
    for (verb, body) in [
        ("vault.lenses.activate", again),
        ("vault.lenses.deactivate", clear.clone()),
    ] {
        let error = refused(door::invoke(&agent, verb, body), verb);
        assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{verb}: {error:?}");
        assert!(
            error.message.contains("is the vault owner's"),
            "{verb}: {error:?}"
        );
    }
    let listed = list_row(&owner, &lens_ref);
    assert_eq!(
        listed["state"],
        json!("active"),
        "the refusals changed nothing: {listed}"
    );

    let cleared = answered(
        door::invoke(&owner, "vault.lenses.deactivate", clear),
        "owner deactivate",
    );
    assert_eq!(cleared["decision"], json!("deactivated"), "{cleared}");
    let listed = list_row(&owner, &lens_ref);
    assert_eq!(
        (listed["state"].clone(), listed["mounted"].clone()),
        (json!("proposed"), json!(false))
    );
}

/// Refusals. A well-formed body plus one unknown field is refused on all ten
/// rows before any lookup; the three host rows refuse a well-formed body as
/// host-only.
/// Red proof: `oneiron-verb-wire/src/lens/proposal.rs:28`
/// `deny_unknown_fields` deleted on `LensListRequest` (`-red2`).
#[test]
fn a_malformed_or_host_only_lens_act_is_refused() {
    let (_dir, vault) = owned_vault();
    provision_machines(&vault);
    let owner = door::owner(&vault).expect("the owner");
    let slot = Slot {
        pack: "oneiron.weave".to_owned(),
        skill: SOME_ID.to_owned(),
        content: SOME_HASH.to_owned(),
    };
    let select = json!({"cardId": "c", "atomId": "a", "handle": "h"});
    let resolve = json!({"cardId": "c", "selectionRef": "s"});
    let action = result_set_action("archive");
    let rows = [
        (
            "vault.lenses.activate",
            json!({"lens_ref": SOME_ID, "compiled_hash": SOME_HASH}),
        ),
        (
            "vault.lenses.deactivate",
            json!({"slot": {"pack_name": "oneiron.weave", "skill_id": SOME_ID}, "expected_active_ref": SOME_ID}),
        ),
        ("vault.lenses.default", json!({"title": "t"})),
        ("vault.lenses.export_pack", json!({"lens_ref": SOME_ID})),
        ("vault.lenses.list", json!({})),
        ("vault.lenses.propose", propose_body(&slot, "x")),
        (
            "vault.lenses.propose_from_pack",
            json!({"pack_name": "oneiron.weave", "lens": "weave-report"}),
        ),
        ("vault.lenses.resolve", resolve.clone()),
        ("vault.lenses.result_set.action", action.clone()),
        ("vault.lenses.select", select.clone()),
    ];
    for (verb, mut body) in rows {
        body["zzz"] = json!(1);
        let error = refused(door::invoke(&owner, verb, body), verb);
        assert_eq!(
            error.code, MEMORY_CODE_BAD_REQUEST,
            "{verb} + unknown field: {error:?}"
        );
    }
    for (verb, body) in [
        ("vault.lenses.select", select),
        ("vault.lenses.resolve", resolve),
        ("vault.lenses.result_set.action", action),
    ] {
        let error = refused(door::invoke(&owner, verb, body), verb);
        assert_eq!(
            error.code, MEMORY_CODE_MODEL_UNAVAILABLE,
            "{verb}: {error:?}"
        );
    }
}
