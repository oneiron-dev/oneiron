//! ROLES-CHECKIN P2.2, piece 2c (ARCH-0082 #ladder; Engine ruling P22-SHAPE
//! Q3, Q4 and Q9 = A): the ladder from verified records.
//!
//! On a shared vault whose roster is an Owner, two Admins, a Deputy and a
//! Member, an agent asks under a delegate grant the first Admin minted:
//!
//! - rung 2 asks that Admin (the grant's `delegated_by`), rung 3 the other
//!   Admin (every other holder of the grantor's role, not the Deputy or the
//!   Member), rung 4 the Owner;
//! - only a holder pinned on the current rung answers, as themself;
//! - a holder whose own check-in for the act would wait, or whose grant does
//!   not admit the verb, is not asked: the rung is skipped, naming why;
//! - a holder whose grant does not cover the effect's world is not asked, and
//!   once its grant is narrowed away from that world it no longer answers or
//!   extends (review round 1 of #7112);
//! - an Owner who minted the grant is asked once, not again at rung 4;
//! - a grant ref that names another principal's grant finds no grantor.
//!
//! With the test's chain: an agent holder's verdict answers when the ask
//! enters its rung, and with no verdict the agent passes the ask up at once.
//!
//! On P2.2a's head this file does not build: there are no `_verified` doors
//! and no agent verdicts.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_ladder`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/fixture.rs"]
mod fixture;
#[path = "check_in/ladder.rs"]
mod ladder;

use fixture::{DIGEST, Fixture, T0, request};
use ladder::{DELEGATE_TTL, Ladder};
use oneiron::EntityId;
use oneiron::check_in::{
    ActClass, CheckInTransition, HolderAnswer, HolderKind, PendingCheckIn, PendingState, Rung,
    RungHolder, RungMembers,
};
use oneiron::test_doors::check_in::{
    FixedChain, advance, answer_verified, extend_verified, narrow_grant_worlds, open,
};

fn person(principal: EntityId) -> RungHolder {
    RungHolder {
        principal,
        kind: HolderKind::Person,
    }
}

fn agents(ids: &[EntityId]) -> RungMembers {
    RungMembers::Holders(
        ids.iter()
            .map(|&principal| RungHolder {
                principal,
                kind: HolderKind::Agent,
            })
            .collect(),
    )
}

/// The current rung and the holders pinned there.
fn pinned(row: &PendingCheckIn) -> (Rung, Vec<RungHolder>) {
    let entry = row.current_rung().expect("a rung");
    (entry.rung, entry.holders.clone())
}

/// The missing links of the skipped rungs, in order.
fn skipped(row: &PendingCheckIn) -> Vec<(Rung, String)> {
    row.rungs
        .iter()
        .filter_map(|entry| entry.skipped.clone().map(|link| (entry.rung, link)))
        .collect()
}

#[test]
fn the_ladder_asks_the_grantor_then_the_other_holders_of_its_role_then_the_owner() {
    let l = Ladder::new();
    let row = l.open(l.ask(l.delegate, ActClass::MemberAdd, "org:add-member"));
    assert_eq!(
        pinned(&row),
        (Rung::Grantor, vec![person(l.first_admin.0)]),
        "rung 2 is the Admin who minted the agent's delegate grant"
    );

    assert_eq!(
        l.climb(&row.id),
        Some(CheckInTransition::Climbed(Rung::ChainHolders))
    );
    assert_eq!(
        pinned(&l.fx.row(&row.id)),
        (Rung::ChainHolders, vec![person(l.second_admin.0)]),
        "rung 3 is every other Admin: not the grantor, the Deputy or the Member"
    );

    assert_eq!(
        l.climb(&row.id),
        Some(CheckInTransition::Climbed(Rung::Owner))
    );
    assert_eq!(
        pinned(&l.fx.row(&row.id)),
        (Rung::Owner, vec![person(l.owner.0)])
    );
    assert_eq!(
        l.fx.outcomes(&row.id),
        ["opened", "climbed", "climbed", "climbed"]
    );
}

#[test]
fn only_a_holder_pinned_on_the_current_rung_answers_and_as_themself() {
    let l = Ladder::new();
    let row = l.open(l.ask(l.delegate, ActClass::MemberAdd, "org:add-member"));
    for (_, proof) in [&l.member, &l.deputy, &l.second_admin, &l.owner] {
        assert!(
            answer_verified(&l.fx.vault, proof, &row.id, &DIGEST, HolderAnswer::Approve).is_err(),
            "a holder not pinned on rung 2 does not answer"
        );
    }
    let answered = answer_verified(
        &l.fx.vault,
        &l.first_admin.1,
        &row.id,
        &DIGEST,
        HolderAnswer::Approve,
    )
    .expect("the grantor answers");
    assert_eq!(
        answered.state,
        PendingState::Answered {
            answer: HolderAnswer::Approve,
            by: Some(l.first_admin.0),
            rung: Rung::Grantor,
            at: T0,
        }
    );
}

#[test]
fn a_holder_whose_own_check_in_would_wait_is_not_asked() {
    // An Admin's own outbound send always asks (ARCH-0082's role table), so
    // neither Admin may approve the agent's; the Owner's goes.
    let l = Ladder::new();
    let row = l.open(l.ask(l.delegate, ActClass::OutboundSend, "write"));
    let why = "no holder whose live grant and own check-in admit the act".to_owned();
    assert_eq!(
        skipped(&row),
        [(Rung::Grantor, why.clone()), (Rung::ChainHolders, why)]
    );
    assert_eq!(pinned(&row), (Rung::Owner, vec![person(l.owner.0)]));
    assert_eq!(
        l.fx.outcomes(&row.id),
        ["opened", "skipped", "skipped", "climbed"]
    );
}

#[test]
fn a_holder_whose_grant_does_not_admit_the_verb_is_not_asked() {
    let l = Ladder::new();
    let row = l.open(l.ask(
        l.delegate,
        ActClass::ReversibleWork,
        "vault.not_granted.verb",
    ));
    assert_eq!(
        skipped(&row)
            .into_iter()
            .map(|(rung, _)| rung)
            .collect::<Vec<_>>(),
        [Rung::Grantor, Rung::ChainHolders]
    );
    assert_eq!(
        pinned(&row),
        (Rung::Owner, vec![person(l.owner.0)]),
        "the Owner holds every power"
    );
}

#[test]
fn an_owner_who_minted_the_askers_grant_is_asked_once() {
    let l = Ladder::new();
    let delegate =
        l.fx.vault
            .create_federation_delegate(&l.owner.1, l.owner_grant, l.agent, T0, T0 + DELEGATE_TTL)
            .expect("the Owner's delegate grant");
    let row = l.open(l.ask(delegate, ActClass::MemberAdd, "org:add-member"));
    assert_eq!(pinned(&row), (Rung::Grantor, vec![person(l.owner.0)]));

    assert_eq!(l.climb(&row.id), Some(CheckInTransition::Held));
    let row = l.fx.row(&row.id);
    assert_eq!(
        skipped(&row),
        [
            (
                Rung::ChainHolders,
                "no other live holder of the grantor's role this ask has not already asked"
                    .to_owned()
            ),
            (
                Rung::Owner,
                "no live owner this ask has not already asked".to_owned()
            ),
        ]
    );
    assert_eq!(
        l.fx.outcomes(&row.id),
        ["opened", "climbed", "skipped", "skipped", "held"]
    );
}

#[test]
fn a_grant_ref_naming_another_principals_grant_finds_no_grantor() {
    let l = Ladder::new();
    let row = l.open(l.ask(l.first_admin_grant, ActClass::MemberAdd, "org:add-member"));
    let why = "the asker's grant is not a live grant naming the asker".to_owned();
    assert_eq!(
        skipped(&row),
        [(Rung::Grantor, why.clone()), (Rung::ChainHolders, why)]
    );
    assert_eq!(pinned(&row), (Rung::Owner, vec![person(l.owner.0)]));
}

#[test]
fn an_agent_holders_verdict_answers_when_the_ask_enters_its_rung() {
    let fx = Fixture::open();
    let (asker, holder) = (EntityId::now(), EntityId::now());
    let chain = FixedChain::default()
        .with(Rung::Grantor, agents(&[holder]))
        .with_verdict(holder, HolderAnswer::Deny);
    let row = open(&fx.vault, request(asker, ActClass::Spawn), &chain).expect("open");
    assert_eq!(
        row.state,
        PendingState::Answered {
            answer: HolderAnswer::Deny,
            by: Some(holder),
            rung: Rung::Grantor,
            at: T0,
        }
    );
    assert_eq!(fx.outcomes(&row.id), ["opened", "climbed", "answered"]);
}

#[test]
fn an_agent_holder_with_no_verdict_passes_the_ask_up_at_once() {
    let fx = Fixture::open();
    let (asker, holder) = (EntityId::now(), EntityId::now());
    let (next, _) = fx.person();
    let chain = FixedChain::default()
        .with(Rung::Grantor, agents(&[holder]))
        .with(Rung::ChainHolders, fixture::people(&[next]));
    let row = open(&fx.vault, request(asker, ActClass::Spawn), &chain).expect("open");
    assert_eq!(row.state, PendingState::Open);
    assert_eq!(
        advance(&fx.vault, &row.id, &chain).expect("advance"),
        Some(CheckInTransition::Climbed(Rung::ChainHolders)),
        "at the same instant"
    );
}

#[test]
fn a_holder_whose_grant_does_not_cover_the_effects_world_neither_is_asked_nor_answers() {
    let l = Ladder::new();
    let (world_a, world_b) = (EntityId::now(), EntityId::now());
    let ask_in = |world: EntityId| {
        let mut ask = l.ask(l.delegate, ActClass::MemberAdd, "org:add-member");
        ask.scope.world_ref = Some(world.to_hex());
        l.open(ask)
    };

    let row = ask_in(world_b);
    assert_eq!(
        l.climb(&row.id),
        Some(CheckInTransition::Climbed(Rung::ChainHolders))
    );
    assert_eq!(
        pinned(&l.fx.row(&row.id)),
        (Rung::ChainHolders, vec![person(l.second_admin.0)]),
        "the second Admin's grant covers every world"
    );
    narrow_grant_worlds(&l.fx.vault, l.second_admin_grant, &[world_a]).expect("narrow");
    let due = l.fx.row(&row.id).current_rung().expect("a rung").due_at();
    assert!(
        answer_verified(
            &l.fx.vault,
            &l.second_admin.1,
            &row.id,
            &DIGEST,
            HolderAnswer::Approve
        )
        .is_err(),
        "a grant narrowed to world A approves nothing in world B"
    );
    assert!(
        extend_verified(&l.fx.vault, &l.second_admin.1, &row.id, due + fixture::DAY).is_err(),
        "nor gives it more time"
    );
    assert_eq!(l.fx.row(&row.id).state, PendingState::Open);

    let row = ask_in(world_b);
    assert_eq!(
        l.climb(&row.id),
        Some(CheckInTransition::Climbed(Rung::Owner))
    );
    let row = l.fx.row(&row.id);
    assert_eq!(
        skipped(&row),
        [(
            Rung::ChainHolders,
            "no holder whose live grant and own check-in admit the act".to_owned()
        )],
        "no other Admin covers world B"
    );
    assert_eq!(pinned(&row), (Rung::Owner, vec![person(l.owner.0)]));

    let row = ask_in(world_a);
    assert_eq!(
        l.climb(&row.id),
        Some(CheckInTransition::Climbed(Rung::ChainHolders))
    );
    assert_eq!(
        pinned(&l.fx.row(&row.id)),
        (Rung::ChainHolders, vec![person(l.second_admin.0)]),
        "its grant still covers world A"
    );
}
