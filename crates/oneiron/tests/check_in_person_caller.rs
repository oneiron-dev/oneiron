//! FIX CHECK-IN-PERSON-CALLER-NO-GRANT (Engine rulings CHECKIN-PERSON-GRANT
//! and CHECKIN-PERSON-POWER = A, 17 Nov 00:0x and 03:32): a person's live
//! membership row stands for the Grant on the check-in ladder.
//!
//! - A Member's own ask opens: `vault.check_in.preflight` and
//!   `vault.check_in.open` read the Member's row, its roster role's cell for
//!   the act class gives the power, and an outbound send (the Member's cell
//!   asks) waits under that row. Rung 2 asks who added the member: the
//!   inviter of their accepted invitation, here the Owner who founded the
//!   shared vault.
//! - A Deputy whose role holds the act answers the Member it invited: the
//!   Deputy's own outbound send asks only when unsure, so it may answer.
//! - A grantor whose cell for the act only proposes cannot answer, and the
//!   ask climbs to the Owner: a Member an Admin invited, whom the Owner then
//!   made a Deputy, asks an erase; the Admin's erase cell is propose.
//! - A Deputy's own door ask (a member remove) asks the Owner who added the
//!   Deputy on rung 2, where main skipped rungs 2 and 3 as missing links.
//!
//! On main every person call to the two verbs but the owner's is refused
//! FORBIDDEN, and the door ask's rungs 2 and 3 are skipped.
//!
//! The vault is rooted, and a rooted vault admits only a writer its
//! authority log binds, so each person's acts run while the fixture binds the
//! host key to that person (`Org::as_person`, as check_in_membership_effects.rs
//! does).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_person_caller`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::check_in::{PendingCheckIn, Rung};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::{EdgeActorClass, EntityId, Error, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

const SHARED: u64 = 44;
const PREFLIGHT: &str = "vault.check_in.preflight";
const OPEN: &str = "vault.check_in.open";
const ANSWER: &str = "vault.check_in.answer";
/// `outbound_send`: a Member's and an Admin's cell asks, a Deputy's asks
/// when unsure.
const SEND: &str = "connector.call";
/// `spawn`: a Member's cell asks when unsure.
const SPAWN: &str = "self.agents.spawn";
/// A `read` verb.
const READ: &str = "vault.gate.decision.get";
/// `erase`: a Deputy's cell asks, an Admin's proposes.
const ERASE: &str = "vault.records.erase_confirm";

struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    deputy: EntityId,
    admin: EntityId,
    member: EntityId,
}

fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// `member` accepts its pending invitation to the shared vault at `role`.
fn accept(vault: &Vault, member: EntityId, role: Role) {
    let member_proof = proof(vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == role)
        .expect("the invitation");
    vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("the member accepts");
}

/// The digest of one effect, 64 hex.
fn digest(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

impl Org {
    /// A rooted vault whose shared vault holds the owner, a Deputy, an Admin
    /// and a Member, each of whom accepted the founding invitation.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
        let [deputy, admin, member] = std::array::from_fn(|_| EntityId::now());
        for id in [deputy, admin, member] {
            person(&vault, id);
        }
        let founding = |member_ref, role| InitialSharedMember {
            member_ref,
            role: Some(role),
        };
        vault
            .initialize_shared_vault(
                &proof(&vault, owner),
                SHARED,
                None,
                &[
                    founding(owner, Role::Owner),
                    founding(deputy, Role::Deputy),
                    founding(admin, Role::Admin),
                    founding(member, Role::Member),
                ],
                1,
            )
            .expect("a shared vault with a Deputy, an Admin and a Member");
        accept(&vault, deputy, Role::Deputy);
        accept(&vault, admin, Role::Admin);
        accept(&vault, member, Role::Member);
        Self {
            _dir: dir,
            vault,
            issuer,
            owner,
            deputy,
            admin,
            member,
        }
    }

    /// Runs `act` with the host key bound to `person`, then binds the key
    /// back to the owner: a rooted vault admits only a bound writer, and the
    /// host key holds one live binding.
    fn as_person<T>(&self, person: EntityId, act: impl FnOnce() -> T) -> T {
        bind_host_actor(&self.vault, &self.issuer, person, "human")
            .expect("the host key bound to the person for its act");
        let answer = act();
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("the owner's binding again");
        answer
    }

    /// `person` calls `verb` with `input`, as themself.
    fn call(&self, person: EntityId, verb: &str, input: Value) -> MemoryResult<Value> {
        self.as_person(person, || {
            invoke(
                &self.vault.memory(person, EdgeActorClass::Human),
                verb,
                input,
            )
        })
    }

    /// `person`'s ask for `verb`'s act over the effect `byte` names.
    fn ask(&self, person: EntityId, verb: &str, check_in: &str, byte: u8) -> Value {
        self.call(
            person,
            check_in,
            json!({ "verb": verb, "effect_digest": digest(byte) }),
        )
        .unwrap_or_else(|error| panic!("{check_in} of {verb} answers: {error:?}"))
    }

    /// A newcomer `inviter` adds at `role`, who accepts.
    fn invited_by(&self, inviter: EntityId, role: Role) -> EntityId {
        let newcomer = EntityId::now();
        person(&self.vault, newcomer);
        let inviter_proof = proof(&self.vault, inviter);
        self.as_person(inviter, || {
            self.vault
                .add_shared_member(&inviter_proof, SHARED, newcomer, Some(role))
        })
        .expect("the inviter adds the newcomer");
        accept(&self.vault, newcomer, role);
        newcomer
    }

    /// The pending check-in an open's answer names.
    fn row(&self, opened: &Value) -> PendingCheckIn {
        let handle = opened["handle"]["handle"].as_str().expect("a handle");
        self.vault
            .pending_check_in(&EntityId::from_hex(handle).expect("a check-in id"))
            .expect("read the check-in")
            .expect("the check-in is stored")
    }

    /// `person` approves the ask `opened` names, over the effect it waits on.
    fn approves(&self, person: EntityId, opened: &Value) -> MemoryResult<Value> {
        let row = self.row(opened);
        let effect: String = row
            .effect_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        self.call(
            person,
            ANSWER,
            json!({
                "handle": row.id.to_hex(),
                "answer": "approve",
                "effect_digest": effect,
            }),
        )
    }

    /// `member`'s live membership row on the shared vault.
    fn membership_row(&self, member: EntityId) -> EntityId {
        self.vault
            .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
            .expect("grants")
            .into_iter()
            .find(|id| {
                let Some(body) = self.vault.get(id).expect("grant row") else {
                    return false;
                };
                oneiron::federation::decode_federation_grant_body(&body)
                    .is_ok_and(|grant| grant.member_ref == member && grant.role != Role::Delegate)
            })
            .expect("the member's membership row")
    }
}

/// Each rung the ask entered: the rung, whether it was skipped, and who it
/// pinned.
fn rungs(row: &PendingCheckIn) -> Vec<(Rung, bool, Vec<EntityId>)> {
    row.rungs
        .iter()
        .map(|entry| {
            (
                entry.rung,
                entry.skipped.is_some(),
                entry
                    .holders
                    .iter()
                    .map(|holder| holder.principal)
                    .collect(),
            )
        })
        .collect()
}

#[test]
fn a_members_own_ask_opens_under_their_membership_row_and_asks_who_added_them() {
    let org = Org::new();
    let read = org.ask(org.member, READ, PREFLIGHT, 0x11);
    assert_eq!(
        (read["outcome"].as_str(), read["reason"].as_str()),
        (Some("go"), Some("read")),
        "a Member's read goes on the power alone: {read}"
    );
    let spawn = org.ask(org.member, SPAWN, PREFLIGHT, 0x12);
    assert_eq!(
        (spawn["outcome"].as_str(), spawn["reason"].as_str()),
        (Some("go"), Some("sure")),
        "a Member asks when unsure on a spawn, and a person's own act is sure: {spawn}"
    );
    let preflight = org.ask(org.member, SEND, PREFLIGHT, 0x13);
    assert_eq!(
        (
            preflight["outcome"].as_str(),
            preflight["reason"].as_str(),
            preflight["act_class"].as_str(),
        ),
        (Some("wait"), Some("always_ask"), Some("outbound_send")),
        "a Member's outbound send always asks: {preflight}"
    );
    assert!(preflight["handle"].is_null(), "preflight opens nothing");

    let opened = org.ask(org.member, SEND, OPEN, 0x13);
    assert_eq!(
        (
            opened["outcome"].as_str(),
            opened["handle"]["state"].as_str(),
            opened["handle"]["rung"].as_str(),
        ),
        (Some("wait"), Some("open"), Some("grantor")),
        "the Member's ask opens and enters rung 2: {opened}"
    );
    let row = org.row(&opened);
    assert_eq!(
        (row.asker, row.grant_ref.clone()),
        (org.member, org.membership_row(org.member).to_hex()),
        "the ask is the Member's, under their membership row"
    );
    assert_eq!(
        rungs(&row),
        [(Rung::Grantor, false, vec![org.owner])],
        "rung 2 asks who added the Member: the Owner who founded the shared vault"
    );
    let settled = org.approves(org.owner, &opened).expect("the Owner answers");
    assert_eq!(
        (settled["rung"].as_str(), settled["eligible"].as_str()),
        (Some("grantor"), Some("approved")),
        "{settled}"
    );

    let stranger = EntityId::now();
    person(&org.vault, stranger);
    let refused = org
        .call(
            stranger,
            PREFLIGHT,
            json!({ "verb": SEND, "effect_digest": digest(0x14) }),
        )
        .expect_err("a person with no membership row is refused");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
}

#[test]
fn a_deputy_whose_role_holds_the_act_answers_the_member_it_invited() {
    let org = Org::new();
    let newcomer = org.invited_by(org.deputy, Role::Member);
    let opened = org.ask(newcomer, SEND, OPEN, 0x21);
    assert_eq!(
        (
            opened["outcome"].as_str(),
            opened["handle"]["rung"].as_str()
        ),
        (Some("wait"), Some("grantor")),
        "{opened}"
    );
    assert_eq!(
        rungs(&org.row(&opened)),
        [(Rung::Grantor, false, vec![org.deputy])],
        "rung 2 asks the Deputy who added the Member"
    );
    let early = org
        .approves(org.owner, &opened)
        .expect_err("the Owner is not pinned on rung 2");
    assert_eq!(early.code, MEMORY_CODE_FORBIDDEN, "{early:?}");
    let settled = org
        .approves(org.deputy, &opened)
        .expect("the Deputy's own outbound send asks only when unsure, so it answers");
    assert_eq!(
        (settled["rung"].as_str(), settled["eligible"].as_str()),
        (Some("grantor"), Some("approved")),
        "{settled}"
    );
}

#[test]
fn a_grantor_whose_cell_only_proposes_the_act_passes_the_ask_up_to_the_owner() {
    let org = Org::new();
    let newcomer = org.invited_by(org.admin, Role::Member);
    org.vault
        .change_shared_member_role(
            &proof(&org.vault, org.owner),
            SHARED,
            newcomer,
            Role::Deputy,
            None,
        )
        .expect("the Owner makes the newcomer a Deputy");
    let opened = org.ask(newcomer, ERASE, OPEN, 0x31);
    assert_eq!(
        (opened["outcome"].as_str(), opened["reason"].as_str()),
        (Some("wait"), Some("always_ask")),
        "a Deputy's erase always asks: {opened}"
    );
    let row = org.row(&opened);
    assert_eq!(
        rungs(&row),
        [
            (Rung::Grantor, true, Vec::new()),
            (Rung::ChainHolders, true, Vec::new()),
            (Rung::Owner, false, vec![org.owner]),
        ],
        "the Admin who added the newcomer may only propose an erase, and no other Admin \
         holds the role, so the ask climbs to the Owner"
    );
    assert_eq!(
        row.rungs[0].skipped.as_deref(),
        Some("no holder whose live grant and own check-in admit the act"),
        "rung 2 names the Admin's missing power"
    );
    let settled = org.approves(org.owner, &opened).expect("the Owner answers");
    assert_eq!(
        (settled["rung"].as_str(), settled["eligible"].as_str()),
        (Some("owner"), Some("approved")),
        "{settled}"
    );
}

#[test]
fn a_deputys_door_ask_first_asks_the_owner_who_added_them() {
    let org = Org::new();
    let deputy = proof(&org.vault, org.deputy);
    let id = match org.as_person(org.deputy, || {
        org.vault
            .remove_shared_member(&deputy, SHARED, org.member, None)
    }) {
        Err(Error::CheckInPending(id)) => id,
        other => panic!("a Deputy's remove waits on a check-in: {other:?}"),
    };
    let row = org
        .vault
        .pending_check_in(&EntityId::from_hex(&id).expect("a check-in id"))
        .expect("read the check-in")
        .expect("the check-in is stored");
    assert_eq!(
        rungs(&row),
        [(Rung::Grantor, false, vec![org.owner])],
        "the Deputy's membership row names who added them, and rung 2 asks that Owner"
    );
}
