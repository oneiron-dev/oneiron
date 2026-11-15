//! The ladder fixture of the check-in tests (ROLES-CHECKIN P2.2c, used by
//! `check_in_ladder.rs` and `check_in_waiter_resume.rs`): a shared vault whose
//! roster is an Owner, two Admins, a Deputy and a Member, and the seeded agent
//! `sys.team_lead` asking under a delegate grant the first Admin minted.
#![allow(dead_code)]

use oneiron::EntityId;
use oneiron::check_in::{ActClass, CheckInTransition, OpenPendingCheckIn, PendingCheckIn};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole, InitialSharedMember};
use oneiron::test_doors::check_in::{FixedVerdicts, advance_verified, open_verified};

use crate::fixture::{self, Fixture, T0, request};

/// The shared vault's id.
pub(crate) const SHARED: u64 = 42;
/// A delegate grant's lifetime, inside the 90-day cap.
pub(crate) const DELEGATE_TTL: u64 = 30 * fixture::DAY;

pub(crate) struct Ladder {
    pub(crate) fx: Fixture,
    pub(crate) owner: (EntityId, AuthenticatedOwner),
    pub(crate) first_admin: (EntityId, AuthenticatedOwner),
    pub(crate) second_admin: (EntityId, AuthenticatedOwner),
    pub(crate) deputy: (EntityId, AuthenticatedOwner),
    pub(crate) member: (EntityId, AuthenticatedOwner),
    pub(crate) owner_grant: EntityId,
    pub(crate) first_admin_grant: EntityId,
    pub(crate) second_admin_grant: EntityId,
    pub(crate) agent: EntityId,
    /// The agent's delegate grant, minted by the first Admin.
    pub(crate) delegate: EntityId,
}

impl Ladder {
    pub(crate) fn new() -> Self {
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
        let second_admin_grant = EntityId::from_hex(&accepted[1][0]).expect("admin grant id");
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
            second_admin_grant,
            agent,
            delegate,
        }
    }

    /// The agent's ask for `act` through `verb`, under the grant `grant`.
    pub(crate) fn ask(&self, grant: EntityId, act: ActClass, verb: &str) -> OpenPendingCheckIn {
        OpenPendingCheckIn {
            grant_ref: grant.to_hex(),
            verb: verb.to_owned(),
            ..request(self.agent, act)
        }
    }

    pub(crate) fn open(&self, ask: OpenPendingCheckIn) -> PendingCheckIn {
        open_verified(&self.fx.vault, ask, &FixedVerdicts::default()).expect("open")
    }

    /// Moves the clock to the current rung's end and makes the one
    /// transition due there.
    pub(crate) fn climb(&self, id: &EntityId) -> Option<CheckInTransition> {
        let due = self.fx.row(id).current_rung().expect("a rung").due_at();
        self.fx.at(due);
        advance_verified(&self.fx.vault, id, &FixedVerdicts::default()).expect("advance")
    }

    /// The same vault, closed and opened again on the same clock: the roster,
    /// grants and pending rows stay. The proofs were minted on the closed
    /// vault.
    pub(crate) fn reopen(self) -> Self {
        let Self {
            fx,
            owner,
            first_admin,
            second_admin,
            deputy,
            member,
            owner_grant,
            first_admin_grant,
            second_admin_grant,
            agent,
            delegate,
        } = self;
        Self {
            fx: fx.reopen(),
            owner,
            first_admin,
            second_admin,
            deputy,
            member,
            owner_grant,
            first_admin_grant,
            second_admin_grant,
            agent,
            delegate,
        }
    }
}
