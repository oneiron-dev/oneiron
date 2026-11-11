//! ROLES-CHECKIN P2.2, piece 2d (ruling R2; Engine rulings PR2-SPLIT = B and
//! P22-SHAPE Q3, Q5-Q7 = A): the wait per person rung and canon's table
//! "When nobody answers", on a clock the test moves (never a sleep).
//!
//! - A person rung waits 24 hours: at 23:59 it stays, at 24:00 it climbs,
//!   one rung per tick, and the next rung's wait starts at its entry.
//! - The Owner's `check_in` row sets the wait per act class and per scope;
//!   the narrower scope wins. The asker may lengthen it, never shorten it.
//! - A holder's extension is receipted and never passes the asker's `until`.
//! - At `until` the ask lets go and no answer lands.
//! - A rung with no verified holder is skipped at once, naming the missing
//!   link; a rung of agents does not wait.
//! - The chain's end: an undoable `AskWhenUnsure` act with an undo plan
//!   proceeds with it; any other act holds; a delay window passes in silence
//!   and an objection holds it.
//!
//! On #7090's head this file does not build: there is no pending check-in,
//! no `check_in` policy row and no `test_doors::check_in`.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_rung_waits`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/fixture.rs"]
mod fixture;

use fixture::{DAY, DIGEST, Fixture, HOUR, T0, people, request};
use oneiron::EntityId;
use oneiron::check_in::{
    ActClass, CheckInMode, CheckInScope, CheckInTransition, DelayWindowOpen, HolderAnswer,
    HolderKind, PendingState, Rung, RungHolder, RungMembers, WaitReason, WaitSource,
};
use oneiron::test_doors::check_in::{FixedChain, advance, answer, extend, object, open};

/// A chain of one person on each rung.
fn three_people(fixture: &Fixture) -> (FixedChain, [EntityId; 3]) {
    let (grantor, _) = fixture.person();
    let (holder, _) = fixture.person();
    let (owner, _) = fixture.person();
    let chain = FixedChain::default()
        .with(Rung::Grantor, people(&[grantor]))
        .with(Rung::ChainHolders, people(&[holder]))
        .with(Rung::Owner, people(&[owner]));
    (chain, [grantor, holder, owner])
}

#[test]
fn a_person_rung_stays_at_23_59_and_climbs_at_24_00() {
    let fixture = Fixture::open();
    let (chain, [grantor, holder, _]) = three_people(&fixture);
    let opened = open(
        &fixture.vault,
        request(EntityId::now(), ActClass::Spawn),
        &chain,
    )
    .expect("open");

    fixture.at(T0 + DAY - 60);
    assert_eq!(
        advance(&fixture.vault, &opened.id, &chain).expect("tick"),
        None
    );
    assert_eq!(
        fixture.row(&opened.id).current_rung().unwrap().rung,
        Rung::Grantor
    );

    fixture.at(T0 + DAY);
    assert_eq!(
        advance(&fixture.vault, &opened.id, &chain).expect("tick"),
        Some(CheckInTransition::Climbed(Rung::ChainHolders))
    );
    let row = fixture.row(&opened.id);
    let rung = row.current_rung().unwrap();
    assert_eq!(rung.rung, Rung::ChainHolders);
    assert_eq!(rung.holders[0].principal, holder);
    assert_eq!(rung.due_at(), T0 + 2 * DAY);
    assert!(
        row.rungs[0]
            .holders
            .iter()
            .any(|pinned| pinned.principal == grantor)
    );
    assert_eq!(
        fixture.outcomes(&opened.id),
        ["opened", "climbed", "climbed"]
    );
}

#[test]
fn at_the_due_instant_the_climb_wins_over_the_lower_rungs_answer() {
    let fixture = Fixture::open();
    let (grantor, proof) = fixture.person();
    let (holder, _) = fixture.person();
    let chain = FixedChain::default()
        .with(Rung::Grantor, people(&[grantor]))
        .with(Rung::ChainHolders, people(&[holder]));
    let opened = open(
        &fixture.vault,
        request(EntityId::now(), ActClass::Spawn),
        &chain,
    )
    .expect("open");
    fixture.at(T0 + DAY);
    assert!(
        answer(
            &fixture.vault,
            &proof,
            &opened.id,
            &DIGEST,
            HolderAnswer::Approve
        )
        .is_err(),
        "the grantor's wait has ended at 24:00"
    );
    assert_eq!(fixture.row(&opened.id).state, PendingState::Open);
}

#[test]
fn a_late_tick_climbs_one_rung_and_the_next_wait_starts_at_its_entry() {
    let fixture = Fixture::open();
    let (chain, _) = three_people(&fixture);
    let opened = open(
        &fixture.vault,
        request(EntityId::now(), ActClass::Spawn),
        &chain,
    )
    .expect("open");

    fixture.at(T0 + 5 * DAY);
    assert_eq!(
        advance(&fixture.vault, &opened.id, &chain).expect("tick"),
        Some(CheckInTransition::Climbed(Rung::ChainHolders))
    );
    let rung = fixture.row(&opened.id).current_rung().unwrap().clone();
    assert_eq!(rung.entered_at, T0 + 5 * DAY);
    assert_eq!(
        rung.due_at(),
        T0 + 6 * DAY,
        "its holders get their whole wait"
    );
    assert_eq!(
        advance(&fixture.vault, &opened.id, &chain).expect("tick"),
        None,
        "one rung per tick"
    );
}

#[test]
fn an_exhausted_chain_holds_an_act_that_may_not_proceed_on_silence() {
    let fixture = Fixture::open();
    let (chain, _) = three_people(&fixture);
    let opened = open(
        &fixture.vault,
        request(EntityId::now(), ActClass::MemberRemove),
        &chain,
    )
    .expect("open");
    for (day, expected) in [
        (1, CheckInTransition::Climbed(Rung::ChainHolders)),
        (2, CheckInTransition::Climbed(Rung::Owner)),
        (3, CheckInTransition::Held),
    ] {
        fixture.at(T0 + day * DAY);
        assert_eq!(
            advance(&fixture.vault, &opened.id, &chain).expect("tick"),
            Some(expected)
        );
    }
    assert_eq!(
        fixture.row(&opened.id).state,
        PendingState::Held { at: T0 + 3 * DAY }
    );
    assert_eq!(
        fixture.outcomes(&opened.id),
        ["opened", "climbed", "climbed", "climbed", "held"]
    );
    fixture.at(T0 + 9 * DAY);
    assert_eq!(
        advance(&fixture.vault, &opened.id, &chain).expect("tick"),
        None
    );
}

#[test]
fn an_exhausted_chain_proceeds_with_the_undo_only_for_an_undoable_unsure_act() {
    let fixture = Fixture::open();
    let (owner, _) = fixture.person();
    let chain = FixedChain::default().with(Rung::Owner, people(&[owner]));
    let unsure = |undo_plan: Option<&str>, mode: CheckInMode| {
        let mut ask = request(EntityId::now(), ActClass::ReversibleWork);
        ask.mode = mode;
        ask.reason = WaitReason::Unsure;
        ask.undo_plan = undo_plan.map(str::to_owned);
        open(&fixture.vault, ask, &chain).expect("open").id
    };
    let proceeds = unsure(Some("undo:restore-version"), CheckInMode::AskWhenUnsure);
    let no_plan = unsure(None, CheckInMode::AskWhenUnsure);
    let always = unsure(Some("undo:restore-version"), CheckInMode::AlwaysAsk);

    fixture.at(T0 + DAY);
    let tick = |id: EntityId| advance(&fixture.vault, &id, &chain).expect("tick");
    assert_eq!(tick(proceeds), Some(CheckInTransition::ProceedWithUndo));
    assert_eq!(
        tick(no_plan),
        Some(CheckInTransition::Held),
        "no undo: it holds"
    );
    assert_eq!(
        tick(always),
        Some(CheckInTransition::Held),
        "AlwaysAsk holds"
    );
    assert_eq!(
        fixture.row(&proceeds).state,
        PendingState::ProceedWithUndo {
            at: T0 + DAY,
            undo_plan: "undo:restore-version".to_owned(),
        }
    );
    let receipt = fixture.receipts(&proceeds).pop().expect("receipt");
    assert_eq!(receipt.outcome, "proceed_with_undo");
    assert_eq!(receipt.fields["undo_plan"], "undo:restore-version");
}

#[test]
fn a_rung_with_no_verified_holder_is_skipped_at_once_with_its_missing_link() {
    let fixture = Fixture::open();
    let (holder, _) = fixture.person();
    let chain = FixedChain::default()
        .with(
            Rung::Grantor,
            RungMembers::Missing("spawn parent principal".to_owned()),
        )
        .with(Rung::ChainHolders, people(&[holder]));
    let opened = open(
        &fixture.vault,
        request(EntityId::now(), ActClass::Spawn),
        &chain,
    )
    .expect("open");

    assert_eq!(opened.rungs.len(), 2);
    assert_eq!(
        opened.rungs[0].skipped.as_deref(),
        Some("spawn parent principal")
    );
    let rung = opened.current_rung().unwrap();
    assert_eq!(rung.rung, Rung::ChainHolders);
    assert_eq!(
        rung.due_at(),
        T0 + DAY,
        "the wait starts when the ask enters"
    );
    assert_eq!(
        fixture.outcomes(&opened.id),
        ["opened", "skipped", "climbed"]
    );
    let skipped = &fixture.receipts(&opened.id)[1];
    assert_eq!(skipped.fields["rung"], "grantor");
    assert_eq!(skipped.fields["missing_link"], "spawn parent principal");
}

#[test]
fn a_rung_of_agents_does_not_wait() {
    let fixture = Fixture::open();
    let (owner, _) = fixture.person();
    let agent = RungHolder {
        principal: EntityId::now(),
        kind: HolderKind::Agent,
    };
    let chain = FixedChain::default()
        .with(Rung::Grantor, RungMembers::Holders(vec![agent]))
        .with(Rung::Owner, people(&[owner]));
    let opened = open(
        &fixture.vault,
        request(EntityId::now(), ActClass::Spawn),
        &chain,
    )
    .expect("open");
    let rung = opened.current_rung().unwrap();
    assert_eq!(rung.wait, None, "no wait is ruled for an agent rung (R2)");
    assert_eq!(rung.due_at(), T0);
    assert_eq!(
        advance(&fixture.vault, &opened.id, &chain).expect("tick"),
        Some(CheckInTransition::Climbed(Rung::Owner)),
        "the agent rung is due at once; this chain names no chain holders, so the ask \
         passes that rung and reaches the Owner"
    );
}

#[test]
fn the_owner_row_sets_the_wait_per_act_class_and_per_scope() {
    let fixture = Fixture::open();
    let (holder, _) = fixture.person();
    fixture.install_check_in_row(serde_json::json!({
        "version": 1,
        "rung_wait": [
            {"row_ref": "spawn-anywhere", "act_class": "spawn", "secs": 2 * HOUR},
            {"row_ref": "project-launch", "project_ref": "project-launch", "secs": 3 * DAY},
        ],
    }));
    let chain = FixedChain::default().with(Rung::Grantor, people(&[holder]));
    let wait_of = |act: ActClass, project: Option<&str>| {
        let mut ask = request(EntityId::now(), act);
        ask.scope = CheckInScope {
            world_ref: None,
            project_ref: project.map(str::to_owned),
        };
        let opened = open(&fixture.vault, ask, &chain).expect("open");
        opened
            .current_rung()
            .unwrap()
            .wait
            .clone()
            .expect("a person rung")
    };

    let spawn = wait_of(ActClass::Spawn, None);
    assert_eq!(spawn.secs, 2 * HOUR);
    assert_eq!(
        spawn.floor.source,
        WaitSource::Row("spawn-anywhere".to_owned())
    );
    let in_project = wait_of(ActClass::Spawn, Some("project-launch"));
    assert_eq!(in_project.secs, 3 * DAY, "the narrower scope wins");
    assert_eq!(
        in_project.floor.source,
        WaitSource::Row("project-launch".to_owned())
    );
    let delete = wait_of(ActClass::Delete, None);
    assert_eq!(delete.secs, DAY);
    assert_eq!(delete.floor.source, WaitSource::ShippedDefault);
}

#[test]
fn a_check_in_row_with_a_zero_wait_is_refused() {
    let fixture = Fixture::open();
    let policy = serde_json::json!({
        "schema_version": "1.2",
        "pack_id": "check-in-rung-waits",
        "pack_version": "1.0.0",
        "min_engine_version": "0.0.0",
        "defaults": {},
        "rules": [],
        "actor_ceilings": [],
        "check_in": {"version": 1, "rung_wait": [{"row_ref": "none", "secs": 0}]},
    });
    assert!(fixture.try_install(&policy).is_err());
}

#[test]
fn the_asker_may_lengthen_the_wait_but_not_shorten_it() {
    let fixture = Fixture::open();
    let (holder, _) = fixture.person();
    let chain = FixedChain::default().with(Rung::Grantor, people(&[holder]));
    let mut longer = request(EntityId::now(), ActClass::Spawn);
    longer.asker_wait_secs = Some(2 * DAY);
    let opened = open(&fixture.vault, longer, &chain).expect("open");
    let wait = opened.current_rung().unwrap().wait.clone().unwrap();
    assert_eq!(wait.secs, 2 * DAY);
    assert_eq!(wait.floor.secs, DAY, "the floor stays the class's wait");
    assert_eq!(opened.current_rung().unwrap().due_at(), T0 + 2 * DAY);

    let mut shorter = request(EntityId::now(), ActClass::Spawn);
    shorter.asker_wait_secs = Some(DAY - 1);
    assert!(
        open(&fixture.vault, shorter, &chain).is_err(),
        "below the floor without a policy holder"
    );
}

#[test]
fn a_holders_extension_is_receipted_and_never_passes_until() {
    let fixture = Fixture::open();
    let (grantor, proof) = fixture.person();
    let (_, outsider) = fixture.person();
    let (holder, _) = fixture.person();
    let chain = FixedChain::default()
        .with(Rung::Grantor, people(&[grantor]))
        .with(Rung::ChainHolders, people(&[holder]));
    let mut ask = request(EntityId::now(), ActClass::Spawn);
    ask.until = Some(T0 + 3 * DAY);
    let opened = open(&fixture.vault, ask, &chain).expect("open");
    let id = opened.id;

    assert!(
        extend(&fixture.vault, &proof, &id, T0 + DAY - 1).is_err(),
        "shorter"
    );
    assert!(
        extend(&fixture.vault, &outsider, &id, T0 + 2 * DAY).is_err(),
        "not pinned"
    );
    assert!(
        extend(&fixture.vault, &proof, &id, T0 + 4 * DAY).is_err(),
        "past until"
    );
    let extended = extend(&fixture.vault, &proof, &id, T0 + 2 * DAY).expect("extend");
    let extension = extended.current_rung().unwrap().extension.unwrap();
    assert_eq!(extension.until, T0 + 2 * DAY);
    assert_eq!(extension.by, Some(grantor));
    let receipt = fixture.receipts(&id).pop().unwrap();
    assert_eq!(receipt.outcome, "extended");
    assert_eq!(receipt.fields["by"], grantor.to_hex());
    assert_eq!(receipt.fields["due_at"], (T0 + 2 * DAY).to_string());

    fixture.at(T0 + DAY);
    assert_eq!(advance(&fixture.vault, &id, &chain).expect("tick"), None);
    fixture.at(T0 + 2 * DAY);
    assert_eq!(
        advance(&fixture.vault, &id, &chain).expect("tick"),
        Some(CheckInTransition::Climbed(Rung::ChainHolders))
    );
}

#[test]
fn at_until_the_ask_lets_go_and_no_answer_lands() {
    let fixture = Fixture::open();
    let (grantor, proof) = fixture.person();
    let chain = FixedChain::default().with(Rung::Grantor, people(&[grantor]));
    let mut ask = request(EntityId::now(), ActClass::Spawn);
    ask.until = Some(T0 + 12 * HOUR);
    let opened = open(&fixture.vault, ask, &chain).expect("open");
    assert_eq!(opened.next_due_at(), Some(T0 + 12 * HOUR));

    fixture.at(T0 + 12 * HOUR);
    assert!(
        answer(
            &fixture.vault,
            &proof,
            &opened.id,
            &DIGEST,
            HolderAnswer::Approve
        )
        .is_err(),
        "at until, let-go wins over an answer"
    );
    assert_eq!(
        advance(&fixture.vault, &opened.id, &chain).expect("tick"),
        Some(CheckInTransition::LetGo)
    );
    assert_eq!(
        fixture.row(&opened.id).state,
        PendingState::LetGo { at: T0 + 12 * HOUR }
    );
    assert_eq!(fixture.row(&opened.id).next_due_at(), None);
    assert!(
        answer(
            &fixture.vault,
            &proof,
            &opened.id,
            &DIGEST,
            HolderAnswer::Approve
        )
        .is_err()
    );
    assert_eq!(
        fixture.outcomes(&opened.id),
        ["opened", "climbed", "let_go"]
    );
}

#[test]
fn a_delay_window_passes_in_silence_and_an_objection_holds_it() {
    let fixture = Fixture::open();
    let (owner, _) = fixture.person();
    let (objector, _) = fixture.person();
    let chain = FixedChain::default().with(Rung::Owner, people(&[owner]));
    let windowed = || {
        let mut ask = request(EntityId::now(), ActClass::OutboundSend);
        ask.delay_window = Some(DelayWindowOpen {
            notice_at: T0,
            ends_at: T0 + 7 * DAY,
        });
        open(&fixture.vault, ask, &chain).expect("open").id
    };
    let silent = windowed();
    let objected = windowed();
    object(&fixture.vault, &objected, objector).expect("objection");

    fixture.at(T0 + DAY);
    for id in [silent, objected] {
        assert_eq!(
            advance(&fixture.vault, &id, &chain).expect("tick"),
            Some(CheckInTransition::AwaitsWindow),
            "the chain is exhausted; the window's end decides"
        );
    }
    fixture.at(T0 + 7 * DAY - 1);
    assert_eq!(
        advance(&fixture.vault, &silent, &chain).expect("tick"),
        None
    );
    fixture.at(T0 + 7 * DAY);
    assert_eq!(
        advance(&fixture.vault, &silent, &chain).expect("tick"),
        Some(CheckInTransition::WindowPassed)
    );
    assert_eq!(
        advance(&fixture.vault, &objected, &chain).expect("tick"),
        Some(CheckInTransition::ObjectionHeld)
    );
    assert_eq!(
        fixture.row(&silent).state,
        PendingState::WindowPassed { at: T0 + 7 * DAY }
    );
    assert_eq!(
        fixture.row(&objected).state,
        PendingState::ObjectionHeld { at: T0 + 7 * DAY }
    );
}
