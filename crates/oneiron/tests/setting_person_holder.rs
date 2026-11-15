//! DESIGN 15-setting-primitive 1.2 steps 3 and 4 (AUTH-1 = A; Engine RULING 21:39
//! SETTING-DIALS-PURPOSE-DEFAULTS-POWERS = A): a person holder of a key, and a person's ask.
//! - a person who holds DEC-0005's policy power over a `policy` key (an Admin whose Owner-minted
//!   `policy.change` grant names the key's policy target) moves its value rows both ways at once,
//!   and the change row names the membership grant the power stands on;
//! - a member without that power asks: the change waits on a check-in under the member's own
//!   membership grant, and once the Owner approves it, the same change applies once;
//! - a person holder never pins, and over a row the owner set makes no widening: it tightens the
//!   owner's row and asks to loosen it; on a key that reads one row it keeps clear of the owner's
//!   row;
//! - an Owner's person door, and a person on a personal vault, are refused as before.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_person_holder`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::check_in::HolderAnswer;
use oneiron::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::llm::purpose_default_grant_target;
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use oneiron::setting::{
    ChangeDirection, SetSetting, SetSettingOutcome, Setter, SettingCaller, SettingMode,
    SettingScope,
};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::setting::{set_setting_as_person, setting_change};
use oneiron::{EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

const SHARED: u64 = 42;
const CAP: &str = "test.policy_cap";
const NUMBER: &str = "test.policy_number";

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

/// A shared vault whose roster holds its embedded owner as Owner and an Admin who accepted its
/// founding invitation.
struct Shared {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
    admin: EntityId,
    admin_proof: AuthenticatedOwner,
}

impl Shared {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let admin = EntityId::now();
        person(&vault, admin);
        vault
            .initialize_shared_vault(
                &proof(&vault, owner),
                SHARED,
                None,
                &[
                    InitialSharedMember {
                        member_ref: owner,
                        role: Some(Role::Owner),
                    },
                    InitialSharedMember {
                        member_ref: admin,
                        role: Some(Role::Admin),
                    },
                ],
                1,
            )
            .expect("a shared vault with an Admin");
        let admin_proof = proof(&vault, admin);
        let invitation = vault
            .shared_invitations(&admin_proof, SHARED)
            .expect("the Admin's invitations")
            .into_iter()
            .find(|open| open.role == Role::Admin)
            .expect("the Admin's founding invitation");
        vault
            .accept_shared_invitation(&admin_proof, SHARED, &invitation.id)
            .expect("the Admin accepts");
        let owner_proof = proof(&vault, owner);
        Self {
            vault,
            _dir: dir,
            owner_proof,
            admin,
            admin_proof,
        }
    }

    /// The Owner's `policy.change` grant to the Admin, naming the inference defaults' vault-scope
    /// target: the policy power `test.policy_cap` and `test.policy_number` name.
    fn give_policy_power(&self) {
        let bound = GrantBound::action(
            ActorBound::new(self.admin.to_hex())
                .expect("actor bound")
                .with_actor_class("human")
                .expect("a person's bound"),
            ActionClass::new("policy.change").expect("action class"),
            ActionEnvelope::new(["owner_policy_rows".to_owned()])
                .expect("envelope")
                .with_target(purpose_default_grant_target())
                .expect("the exact target"),
        )
        .expect("the policy.change bound");
        self.vault
            .create_standing_grant(&self.owner_proof, bound)
            .expect("the Owner mints the policy.change grant");
    }

    /// The Admin's membership grant rows.
    fn admin_grants(&self) -> Vec<EntityId> {
        self.vault
            .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
            .expect("grants")
            .into_iter()
            .filter(|id| {
                self.vault
                    .get(id)
                    .expect("grant row")
                    .and_then(|body| oneiron::federation::decode_federation_grant_body(&body).ok())
                    .is_some_and(|grant| {
                        grant.member_ref == self.admin && grant.role == Role::Admin
                    })
            })
            .collect()
    }

    fn as_admin(&self, request: SetSetting) -> oneiron::Result<SetSettingOutcome> {
        set_setting_as_person(&self.vault, &self.admin_proof, request)
    }

    fn as_owner(&self, request: SetSetting) -> SetSettingOutcome {
        self.vault
            .set_setting(SettingCaller::Owner(&self.owner_proof), request)
            .expect("the owner's change applies")
    }

    /// The Owner approves the check-in `outcome` waits on.
    fn owner_approves(&self, outcome: &SetSettingOutcome) -> EntityId {
        let id = check_in_of(outcome);
        let row = self
            .vault
            .pending_check_in(&id)
            .expect("read")
            .expect("the pending check-in");
        oneiron::test_doors::check_in::answer_verified(
            &self.vault,
            &self.owner_proof,
            &id,
            &row.effect_digest,
            HolderAnswer::Approve,
        )
        .expect("the Owner approves");
        id
    }
}

fn value(key: &str, value: Value) -> SetSetting {
    SetSetting::vault_value(key, value)
}

fn check_in_of(outcome: &SetSettingOutcome) -> EntityId {
    match outcome {
        SetSettingOutcome::Pending { check_in } => {
            EntityId::from_hex(check_in).expect("a check-in id")
        }
        SetSettingOutcome::Applied { .. } => panic!("the change waits: {outcome:?}"),
    }
}

/// The change row an applied `outcome` wrote.
fn change_of(vault: &Vault, outcome: &SetSettingOutcome) -> oneiron::setting::SettingChange {
    let SetSettingOutcome::Applied {
        sequence: Some(sequence),
        ..
    } = outcome
    else {
        panic!("the change applies and writes a row: {outcome:?}");
    };
    setting_change(vault, *sequence)
        .expect("the change stream reads")
        .expect("the change stands")
}

fn applied_value(outcome: &SetSettingOutcome) -> &Value {
    match outcome {
        SetSettingOutcome::Applied { value, .. } => value,
        SetSettingOutcome::Pending { .. } => panic!("the change applies: {outcome:?}"),
    }
}

#[test]
fn a_policy_holder_moves_a_policy_key_both_ways_and_the_change_names_its_grant() {
    let fx = Shared::new();
    fx.give_policy_power();
    let grants = fx.admin_grants();
    assert!(!grants.is_empty(), "the Admin holds a membership grant");

    let looser = fx
        .as_admin(value(CAP, json!(20)))
        .expect("the policy holder widens the cap");
    assert_eq!(applied_value(&looser), &json!(20), "{looser:?}");
    let change = change_of(&fx.vault, &looser);
    assert_eq!(change.by, Some(fx.admin));
    assert_eq!(change.direction, Some(ChangeDirection::Looser));
    let Setter::Holder { grant } = change.setter else {
        panic!("the change names the holder's grant: {:?}", change.setter);
    };
    assert!(
        grants.contains(&grant),
        "the change names the Admin's membership grant: {grant:?} not in {grants:?}"
    );

    let tighter = fx
        .as_admin(value(CAP, json!(5)))
        .expect("the policy holder narrows the cap");
    let change = change_of(&fx.vault, &tighter);
    assert_eq!(change.direction, Some(ChangeDirection::Tighter));
    assert!(matches!(change.setter, Setter::Holder { .. }), "{change:?}");

    let project = EntityId::now();
    let below = fx
        .as_admin(SetSetting {
            scope: SettingScope::Project(project),
            ..value(CAP, json!(3))
        })
        .expect("the policy holder sets a row at a scope the key admits");
    assert!(matches!(
        change_of(&fx.vault, &below).setter,
        Setter::Holder { .. }
    ));

    // The power names one target: an owner key stays the owner's, so the holder asks for it.
    let owner_key = fx
        .as_admin(value("test.owner_number", json!(1)))
        .expect("a member asks for a change of an owner key");
    assert!(
        matches!(owner_key, SetSettingOutcome::Pending { .. }),
        "{owner_key:?}"
    );
}

#[test]
fn a_member_without_the_policy_power_asks_and_the_owners_approval_applies_it_once() {
    let fx = Shared::new();
    let grants = fx.admin_grants();

    let pending = fx
        .as_admin(value(CAP, json!(20)))
        .expect("a member who holds no policy power asks");
    let id = check_in_of(&pending);
    let row = fx
        .vault
        .pending_check_in(&id)
        .expect("read")
        .expect("the pending check-in");
    assert_eq!(row.asker, fx.admin);
    assert_eq!(row.verb, "vault.settings.set");
    assert!(
        grants.iter().any(|grant| grant.to_hex() == row.grant_ref),
        "the ask stands on the member's own membership grant: {} not in {grants:?}",
        row.grant_ref
    );
    let again = fx
        .as_admin(value(CAP, json!(20)))
        .expect("the same change finds its open ask");
    assert_eq!(check_in_of(&again), id, "one ask per change");

    fx.owner_approves(&pending);
    let approved = SetSetting {
        check_in_ref: Some(id),
        ..value(CAP, json!(20))
    };
    let applied = fx
        .as_admin(approved.clone())
        .expect("the approved change applies");
    assert_eq!(applied_value(&applied), &json!(20));
    let change = change_of(&fx.vault, &applied);
    assert_eq!(change.setter, Setter::Approved { check_in: id });
    assert_eq!(change.by, Some(fx.admin));

    let spent = fx.as_admin(approved);
    assert!(spent.is_err(), "an approval applies once: {spent:?}");
}

#[test]
fn a_policy_holder_never_pins_and_over_the_owners_row_only_tightens() {
    let fx = Shared::new();
    fx.give_policy_power();

    // A key that reads one row: with no owner's row the holder sets it.
    let set = fx
        .as_admin(value(NUMBER, json!(3)))
        .expect("the holder sets a key that reads one row");
    assert!(matches!(
        change_of(&fx.vault, &set).setter,
        Setter::Holder { .. }
    ));
    fx.as_owner(value(NUMBER, json!(9)));
    let over = fx
        .as_admin(value(NUMBER, json!(4)))
        .expect("over the owner's row the holder asks");
    assert!(
        matches!(over, SetSettingOutcome::Pending { .. }),
        "{over:?}"
    );

    // A key whose rows meet: over the owner's row the holder tightens, and asks to loosen.
    fx.as_owner(value(CAP, json!(10)));
    let tighter = fx
        .as_admin(value(CAP, json!(6)))
        .expect("the holder tightens the owner's row");
    assert!(matches!(
        change_of(&fx.vault, &tighter).setter,
        Setter::Holder { .. }
    ));
    fx.as_owner(value(CAP, json!(10)));
    let looser = fx
        .as_admin(value(CAP, json!(20)))
        .expect("the holder asks to loosen the owner's row");
    assert!(
        matches!(looser, SetSettingOutcome::Pending { .. }),
        "{looser:?}"
    );

    let pin = fx
        .as_admin(SetSetting {
            mode: SettingMode::Pin,
            ..value(CAP, json!(1))
        })
        .expect("a pin is the owner's: the holder asks");
    assert!(matches!(pin, SetSettingOutcome::Pending { .. }), "{pin:?}");
}

#[test]
fn an_owners_person_door_and_a_person_on_a_personal_vault_are_refused_as_before() {
    let dir = tempfile::tempdir().expect("tempdir");
    let personal = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let owner = personal.ensure_embedded_owner_actor().expect("owner");
    let refused = set_setting_as_person(&personal, &proof(&personal, owner), value(CAP, json!(20)))
        .expect_err("a personal vault has no member who asks");
    assert!(
        format!("{refused:?}").contains("a person sets only"),
        "{refused:?}"
    );

    let fx = Shared::new();
    let refused = set_setting_as_person(&fx.vault, &fx.owner_proof, value(CAP, json!(20)))
        .expect_err("an Owner changes the key through the owner's door, never by an ask");
    assert!(
        format!("{refused:?}").contains("a person sets only"),
        "{refused:?}"
    );
}
