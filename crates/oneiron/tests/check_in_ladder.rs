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

use fixture::{DIGEST, Fixture, T0, request};
use oneiron::EntityId;
use oneiron::check_in::{
    ActClass, CheckInTransition, HolderAnswer, HolderKind, OpenPendingCheckIn, PendingCheckIn,
    PendingState, Rung, RungHolder, RungMembers,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole, InitialSharedMember};
use oneiron::test_doors::check_in::{
    FixedChain, FixedVerdicts, advance, advance_verified, answer_verified, open, open_verified,
};

/// The shared vault's id.
const SHARED: u64 = 42;
/// A delegate grant's lifetime, inside the 90-day cap.
const DELEGATE_TTL: u64 = 30 * fixture::DAY;

struct Ladder {
    fx: Fixture,
    owner: (EntityId, AuthenticatedOwner),
    first_admin: (EntityId, AuthenticatedOwner),
    second_admin: (EntityId, AuthenticatedOwner),
    deputy: (EntityId, AuthenticatedOwner),
    member: (EntityId, AuthenticatedOwner),
    owner_grant: EntityId,
    first_admin_grant: EntityId,
    agent: EntityId,
    /// The agent's delegate grant, minted by the first Admin.
    delegate: EntityId,
}

impl Ladder {
    fn new() -> Self {
        let fx = Fixture::open();
        let owner_id = fx.vault.ensure_embedded_owner_actor().expect("owner");
        let owner = (owner_id, fx.owner());
        let first_admin = fx.person();
        let second_admin = fx.person();
        let deputy = fx.person();
        let member = fx.person();
        let roster = [
            (first_admin.0, FederationGrantRole::Admin),
            (second_admin.0, FederationGrantRole::Admin),
            (deputy.0, FederationGrantRole::Deputy),
            (member.0, FederationGrantRole::Member),
        ]
        .map(|(member_ref, role)| InitialSharedMember {
            member_ref,
            role: Some(role),
        });
        let creation = fx
            .vault
            .initialize_shared_vault(&owner.1, SHARED, None, &roster, T0)
            .expect("shared vault");
        let owner_grant = EntityId::from_hex(&creation.grant_refs[0]).expect("owner grant id");
        let mut accepted = Vec::new();
        for (_, proof) in [&first_admin, &second_admin, &deputy, &member] {
            let invitations = fx
                .vault
                .shared_invitations(proof, SHARED)
                .expect("invitations");
            assert_eq!(invitations.len(), 1, "one founding invitation each");
            let receipt = fx
                .vault
                .accept_shared_invitation(proof, SHARED, &invitations[0].id)
                .expect("accept");
            accepted.push(receipt.grants);
        }
        let first_admin_grant = EntityId::from_hex(&accepted[0][0]).expect("admin grant id");
        let (agent, _) = fx
            .vault
            .get_seeded_agent_definition_by_logical_id("sys.team_lead")
            .expect("seeded agents")
            .expect("sys.team_lead");
        let delegate = fx
            .vault
            .create_federation_delegate(
                &first_admin.1,
                first_admin_grant,
                agent,
                T0,
                T0 + DELEGATE_TTL,
            )
            .expect("delegate grant");
        Self {
            fx,
            owner,
            first_admin,
            second_admin,
            deputy,
            member,
            owner_grant,
            first_admin_grant,
            agent,
            delegate,
        }
    }

    /// The agent's ask for `act` through `verb`, under the grant `grant`.
    fn ask(&self, grant: EntityId, act: ActClass, verb: &str) -> OpenPendingCheckIn {
        OpenPendingCheckIn {
            grant_ref: grant.to_hex(),
            verb: verb.to_owned(),
            ..request(self.agent, act)
        }
    }

    fn open(&self, ask: OpenPendingCheckIn) -> PendingCheckIn {
        open_verified(&self.fx.vault, ask, &FixedVerdicts::default()).expect("open")
    }

    /// Moves the clock to the current rung's end and makes the one
    /// transition due there.
    fn climb(&self, id: &EntityId) -> Option<CheckInTransition> {
        let due = self.fx.row(id).current_rung().expect("a rung").due_at();
        self.fx.at(due);
        advance_verified(&self.fx.vault, id, &FixedVerdicts::default()).expect("advance")
    }
}

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
