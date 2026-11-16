//! The owner-key move a device confirms (row HOSTED-OWNER-MOVE-TWO-PHASE;
//! Engine RULING OWNERKEY-HOSTED-MOVE-NEXT-STEP = A, ANSWER
//! OWNERKEY-TWO-PHASE-SIGNER = A). A managed host holds no owner key, so a
//! move that ends an owner-key holder's keys is refused there and its shared
//! act stays pending, naming the act and the executor's next step. The
//! executing Owner's device takes the act's plan, signs each `RevokeDevice`
//! itself with their enrolled owner key as the primary signer, and the server
//! lands those rows with the move in the act's one writer. Removal, demotion
//! and an Owner's own leave all go this way.
//!
//! The device here is an independent signing key, outside this install,
//! through [`sign_owner_key_move`]; the last two tests run the device door on
//! an install that holds the owner's key, the last one through the three
//! verbs' JSON (`vault.shared.owner_key_move_plan`,
//! `vault.shared.owner_key_move_sign`, `vault.shared.execute` with
//! `owner_key_revokes`). Every test is new with the plan and
//! confirm doors (red on the base, #9057, by not compiling); the base-API pin
//! is `owner_key_move_proof.rs`'s refusal test (`enrol_owner_device`, `act:`).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_key_move_two_phase`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityKey, AuthorityLogEntry, AuthorityOp, HostSlipIssuer,
    MachineRole, OWNER_KEY_MOVE_NO_HELD_KEY, OWNER_KEY_MOVE_NOT_PLANNED, OWNER_KEY_MOVE_NOT_SYNCED,
    OWNER_KEY_MOVE_PLAN_STALE, OWNER_KEY_MOVE_SIGNER_NOT_EXECUTORS, OwnerKeyEnrollment,
    OwnerKeyMovePlan, OwnerKeyMoveSigner, authority_entry_hash, decode_authority_log_entry_body,
    encode_authority_log_entry_body, sign_owner_key_move,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_support::bind_host_owner;
use oneiron::{EntityId, ErrorKind, HostingPrivacyPosture, Vault, VaultConfig};

const SHARED: u64 = 46;
/// The seed of the owner's own owner key, on a device of theirs.
const OWNER_SEED: u8 = 7;
/// The seed of the co-Owner's owner key, on a device of theirs.
const CO_OWNER_SEED: u8 = 9;
/// The seed of the co-Owner's second owner key.
const CO_OWNER_SECOND_SEED: u8 = 11;
/// The seed of a third Owner's owner key.
const THIRD_OWNER_SEED: u8 = 13;

fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    id
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

fn public(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

/// The rows a device that holds `key` signs for `plan`, as it sends them.
fn sign(plan: &OwnerKeyMovePlan, key: &SigningKey) -> Vec<Vec<u8>> {
    sign_owner_key_move(plan, public(key), |transcript| {
        Ok(key.sign(transcript).to_bytes().to_vec())
    })
    .expect("the device signs the plan")
    .iter()
    .map(|row| encode_authority_log_entry_body(row).expect("a row body"))
    .collect()
}

fn reason_codes(error: oneiron::Error) -> Vec<String> {
    oneiron::memory::MemoryError::from(error).reason_codes
}

/// A shared vault as a managed host serves it: the Hosted posture, rooted
/// under the host's custodial root (which proves for no owner), the embedded
/// owner bound by it, and a second Owner the owner added.
struct Hosted {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    co_owner: EntityId,
}

fn hosted() -> Hosted {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let vault = Vault::open(dir.path(), config).expect("hosted vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    vault
        .initialize_shared_vault(
            &proof(&vault, owner),
            SHARED,
            None,
            &[InitialSharedMember {
                member_ref: owner,
                role: Some(Role::Owner),
            }],
            1,
        )
        .expect("a shared vault");
    let hosted = Hosted {
        _dir: dir,
        co_owner: owner,
        vault,
        issuer,
        owner,
    };
    let co_owner = hosted.add_owner();
    Hosted { co_owner, ..hosted }
}

impl Hosted {
    /// The owner adds a new person as an Owner; answers them.
    fn add_owner(&self) -> EntityId {
        let added = person(&self.vault);
        let owner_proof = proof(&self.vault, self.owner);
        let act = self
            .vault
            .propose_add_owner(&owner_proof, SHARED, added)
            .expect("the owner starts add_owner");
        self.vault
            .execute_completed_shared_act(&owner_proof, &act.id, Some(&self.issuer))
            .expect("add_owner runs at once");
        added
    }

    /// `starter` starts the removal of `target`, who leaves; answers the
    /// act's id.
    fn propose_removal(&self, starter: EntityId, target: EntityId) -> String {
        self.vault
            .propose_remove_owner(
                &proof(&self.vault, starter),
                SHARED,
                target,
                None,
                None,
                false,
            )
            .expect("an Owner starts remove_owner")
            .id
    }

    /// `executor` runs `act` under the host's issuer, with no confirm.
    fn run(&self, executor: EntityId, act: &str) -> oneiron::Result<()> {
        self.vault
            .execute_completed_shared_act(&proof(&self.vault, executor), act, Some(&self.issuer))
            .map(|_| ())
    }

    /// The plan `executor`'s device confirms `act` with.
    fn plan(&self, executor: EntityId, act: &str) -> OwnerKeyMovePlan {
        self.vault
            .owner_key_move_plan(&proof(&self.vault, executor), act, Some(&self.issuer))
            .expect("the act's plan")
    }

    /// `executor` runs `act` with their device's `rows`.
    fn confirm(&self, executor: EntityId, act: &str, rows: &[Vec<u8>]) -> oneiron::Result<()> {
        self.vault
            .execute_completed_shared_act_with_owner_key_revokes(
                &proof(&self.vault, executor),
                act,
                Some(&self.issuer),
                rows,
            )
            .map(|_| ())
    }

    /// `person` enrols an owner signing key of a device of theirs, made from
    /// `seed`, with this host's root as its predecessor. This install never
    /// holds it. Answers the key.
    fn enrol_device_key(&self, person: EntityId, seed: u8) -> SigningKey {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let public_key = public(&key);
        let machine = self
            .vault
            .prepare_install_signing()
            .expect("this install's machine");
        let authority = ActAuthority::Owner(proof(&self.vault, person), ActSurface::ThisInstall);
        let challenge = self
            .vault
            .owner_key_enrollment_challenge_as(&authority, machine, &public_key)
            .expect("the enrolment challenge");
        let input = OwnerKeyEnrollment {
            machine,
            public_key,
            proof: key.sign(&challenge).to_bytes().to_vec(),
        };
        self.vault
            .enrol_owner_signing_key_as_host(&authority, input, &self.issuer)
            .expect("an Owner enrols an owner key of their own");
        key
    }

    fn key_is_live(&self, public_key: [u8; 32]) -> bool {
        self.vault
            .enrolled_owner_keys()
            .expect("the enrolled keys")
            .into_iter()
            .find(|key| key.public_key == public_key)
            .expect("the key is listed")
            .live
    }

    /// The stored `RevokeDevice` row that ends `public_key`.
    fn revoke_of(&self, public_key: [u8; 32]) -> AuthorityLogEntry {
        let revoked = AuthorityKey::Ed25519(public_key);
        self.vault
            .export_signed_authority_history()
            .expect("the signed history")
            .iter()
            .map(|bytes| decode_authority_log_entry_body(bytes).expect("a row"))
            .find(|row| {
                matches!(&row.op, AuthorityOp::RevokeDevice { revoked_key } if *revoked_key == revoked)
            })
            .expect("the key's revoke is stored")
    }
}

/// The owner removes the co-Owner, and both hold an owner key on a device.
/// The plain run is refused, naming the act and the step "confirm on your
/// device"; the plan names the co-Owner's key and the owner's own; the
/// owner's device signs the revoke as its primary signer, and the confirmed
/// run lands it with the removal. A second confirm answers the same receipt.
#[test]
fn a_hosted_removal_lands_when_the_executors_device_confirms_it() {
    let hosted = hosted();
    let owner_key = hosted.enrol_device_key(hosted.owner, OWNER_SEED);
    let co_key = hosted.enrol_device_key(hosted.co_owner, CO_OWNER_SEED);
    let act = hosted.propose_removal(hosted.owner, hosted.co_owner);

    let refusal = hosted
        .run(hosted.owner, &act)
        .expect_err("no owner key on this install proves the revoke");
    assert_eq!(refusal.kind(), ErrorKind::OwnerKeyRequired, "{refusal}");
    assert_eq!(
        reason_codes(refusal),
        vec![
            "owner_key_required".to_owned(),
            "next_step:confirm_on_owner_device".to_owned(),
            format!("member:{}", hosted.co_owner.to_hex()),
            format!("act:{act}"),
        ],
        "the refusal names the step, the member and the act"
    );
    assert!(hosted.key_is_live(public(&co_key)), "nothing moved yet");

    let plan = hosted.plan(hosted.owner, &act);
    assert_eq!(plan.member, hosted.co_owner, "{plan:?}");
    assert_eq!(plan.revoked, vec![public(&co_key)], "{plan:?}");
    assert_eq!(
        plan.signers
            .iter()
            .map(|signer| signer.public_key)
            .collect::<Vec<_>>(),
        vec![public(&owner_key)],
        "only the executor's own key may sign: {plan:?}"
    );
    let rows = sign(&plan, &owner_key);
    hosted
        .confirm(hosted.owner, &act, &rows)
        .expect("the confirmed removal runs");

    assert!(
        !hosted.key_is_live(public(&co_key)),
        "the removal ends the co-Owner's key"
    );
    assert!(
        hosted.key_is_live(public(&owner_key)),
        "the confirming key stays live"
    );
    let revoke = hosted.revoke_of(public(&co_key));
    assert_eq!(
        revoke.signer.public_key,
        AuthorityKey::Ed25519(public(&owner_key)),
        "the owner's device key signs the revoke as its primary signer"
    );
    assert!(revoke.cosigns.is_empty(), "{revoke:?}");
    hosted
        .confirm(hosted.owner, &act, &rows)
        .expect("a second confirm answers the same receipt");
}

/// The co-Owner leaves: a removal naming themselves, which they start and
/// run. Their device confirms it with one of their two keys, which ends the
/// other first and itself last, on the other's revoke.
#[test]
fn an_owners_own_leave_is_confirmed_on_their_device_and_ends_its_key_last() {
    let hosted = hosted();
    let confirming = hosted.enrol_device_key(hosted.co_owner, CO_OWNER_SEED);
    let other = hosted.enrol_device_key(hosted.co_owner, CO_OWNER_SECOND_SEED);
    let act = hosted.propose_removal(hosted.co_owner, hosted.co_owner);

    let refusal = hosted
        .run(hosted.co_owner, &act)
        .expect_err("no owner key on this install proves the leave");
    assert!(
        reason_codes(refusal).contains(&"next_step:confirm_on_owner_device".to_owned()),
        "the leaver confirms on their device"
    );
    let plan = hosted.plan(hosted.co_owner, &act);
    hosted
        .confirm(hosted.co_owner, &act, &sign(&plan, &confirming))
        .expect("the confirmed leave runs");

    assert!(
        !hosted.key_is_live(public(&confirming)),
        "the leave ends it"
    );
    assert!(!hosted.key_is_live(public(&other)), "the leave ends it");
    let own = hosted.revoke_of(public(&confirming));
    let first = hosted.revoke_of(public(&other));
    assert_eq!(
        own.parent_hashes,
        vec![authority_entry_hash(&first).expect("a hash")],
        "the confirming key's own revoke comes last, on the other's"
    );
    assert_eq!(own.seq, first.seq + 1, "one key's chain");
}

/// The owner hands ownership to a new person and keeps Admin: a demotion
/// that ends the owner's key. Their device confirms it with that key, whose
/// self-revoke lands with the handover.
#[test]
fn a_demotion_by_transfer_is_confirmed_the_same_way() {
    let hosted = hosted();
    let owner_key = hosted.enrol_device_key(hosted.owner, OWNER_SEED);
    let gainer = person(&hosted.vault);
    let act = hosted
        .vault
        .propose_transfer_ownership(
            &proof(&hosted.vault, hosted.owner),
            SHARED,
            gainer,
            Some(Role::Admin),
        )
        .expect("the owner starts transfer_ownership")
        .id;

    let refusal = hosted
        .run(hosted.owner, &act)
        .expect_err("no owner key on this install proves the demotion");
    assert!(
        reason_codes(refusal).contains(&"next_step:confirm_on_owner_device".to_owned()),
        "the owner confirms on their device"
    );
    let plan = hosted.plan(hosted.owner, &act);
    assert_eq!(plan.member, hosted.owner, "{plan:?}");
    hosted
        .confirm(hosted.owner, &act, &sign(&plan, &owner_key))
        .expect("the confirmed demotion runs");

    assert!(
        !hosted.key_is_live(public(&owner_key)),
        "the demotion ends the owner's key"
    );
}

/// Two removals planned at once: once the second lands, the owner key's
/// sequence has moved past the first plan's, so the first is refused as
/// stale and writes nothing; planned again, it lands.
#[test]
fn a_plan_gone_stale_writes_nothing_and_a_new_plan_lands() {
    let hosted = hosted();
    let third = hosted.add_owner();
    let owner_key = hosted.enrol_device_key(hosted.owner, OWNER_SEED);
    let co_key = hosted.enrol_device_key(hosted.co_owner, CO_OWNER_SEED);
    let third_key = hosted.enrol_device_key(third, THIRD_OWNER_SEED);
    let first_act = hosted.propose_removal(hosted.owner, hosted.co_owner);
    let second_act = hosted.propose_removal(hosted.owner, third);
    let first_plan = hosted.plan(hosted.owner, &first_act);
    let second_plan = hosted.plan(hosted.owner, &second_act);
    hosted
        .confirm(hosted.owner, &second_act, &sign(&second_plan, &owner_key))
        .expect("the second removal runs");
    assert!(!hosted.key_is_live(public(&third_key)));

    let stale = hosted
        .confirm(hosted.owner, &first_act, &sign(&first_plan, &owner_key))
        .expect_err("the owner key's sequence moved past the first plan");
    assert!(
        stale.to_string().contains(OWNER_KEY_MOVE_PLAN_STALE),
        "{stale}"
    );
    assert!(hosted.key_is_live(public(&co_key)), "nothing was written");

    let replanned = hosted.plan(hosted.owner, &first_act);
    hosted
        .confirm(hosted.owner, &first_act, &sign(&replanned, &owner_key))
        .expect("the new plan lands");
    assert!(!hosted.key_is_live(public(&co_key)));
}

/// A key enrolled for the member after the plan is one the plan's rows do
/// not end: the confirm is stale and writes nothing; the new plan ends both.
#[test]
fn a_key_enrolled_for_the_member_after_the_plan_makes_it_stale() {
    let hosted = hosted();
    let owner_key = hosted.enrol_device_key(hosted.owner, OWNER_SEED);
    let co_key = hosted.enrol_device_key(hosted.co_owner, CO_OWNER_SEED);
    let act = hosted.propose_removal(hosted.owner, hosted.co_owner);
    let plan = hosted.plan(hosted.owner, &act);
    let later = hosted.enrol_device_key(hosted.co_owner, CO_OWNER_SECOND_SEED);

    let stale = hosted
        .confirm(hosted.owner, &act, &sign(&plan, &owner_key))
        .expect_err("the plan misses a key");
    assert!(
        stale.to_string().contains(OWNER_KEY_MOVE_PLAN_STALE),
        "{stale}"
    );
    assert!(hosted.key_is_live(public(&co_key)), "nothing was written");

    let replanned = hosted.plan(hosted.owner, &act);
    assert_eq!(replanned.revoked.len(), 2, "{replanned:?}");
    hosted
        .confirm(hosted.owner, &act, &sign(&replanned, &owner_key))
        .expect("the new plan lands");
    assert!(!hosted.key_is_live(public(&co_key)));
    assert!(!hosted.key_is_live(public(&later)));
}

/// Only the executing Owner's own enrolled key confirms: the removed
/// member's key and another Owner's key are refused, writing nothing, and
/// the device's signer refuses a key its plan does not name.
#[test]
fn a_key_that_is_not_the_executors_own_is_refused() {
    let hosted = hosted();
    let third = hosted.add_owner();
    hosted.enrol_device_key(hosted.owner, OWNER_SEED);
    let co_key = hosted.enrol_device_key(hosted.co_owner, CO_OWNER_SEED);
    let third_key = hosted.enrol_device_key(third, THIRD_OWNER_SEED);
    let act = hosted.propose_removal(hosted.owner, hosted.co_owner);
    let plan = hosted.plan(hosted.owner, &act);

    let unnamed = sign_owner_key_move(&plan, public(&co_key), |_| Ok(vec![0; 64]))
        .expect_err("the plan does not name the member's key");
    assert!(
        unnamed.to_string().contains(OWNER_KEY_MOVE_NOT_PLANNED),
        "{unnamed}"
    );
    for key in [&co_key, &third_key] {
        let mut forged = plan.clone();
        forged.signers = vec![OwnerKeyMoveSigner {
            public_key: public(key),
            seq: 1,
        }];
        let refused = hosted
            .confirm(hosted.owner, &act, &sign(&forged, key))
            .expect_err("a key that is not the executor's own");
        assert_eq!(refused.kind(), ErrorKind::AuthorityRefused, "{refused}");
        assert!(
            refused
                .to_string()
                .contains(OWNER_KEY_MOVE_SIGNER_NOT_EXECUTORS),
            "{refused}"
        );
        assert!(hosted.key_is_live(public(&co_key)), "nothing was written");
    }
}

/// Rows on parents this log does not hold, and a row whose signature does
/// not verify, are refused, writing nothing.
#[test]
fn tampered_and_forged_rows_are_refused() {
    let hosted = hosted();
    let owner_key = hosted.enrol_device_key(hosted.owner, OWNER_SEED);
    let co_key = hosted.enrol_device_key(hosted.co_owner, CO_OWNER_SEED);
    let act = hosted.propose_removal(hosted.owner, hosted.co_owner);
    let plan = hosted.plan(hosted.owner, &act);

    let mut elsewhere = plan.clone();
    elsewhere.parents = vec![[0x5a; 32]];
    let refused = hosted
        .confirm(hosted.owner, &act, &sign(&elsewhere, &owner_key))
        .expect_err("parents this log does not hold");
    assert!(
        refused.to_string().contains(OWNER_KEY_MOVE_PLAN_STALE),
        "{refused}"
    );
    assert!(hosted.key_is_live(public(&co_key)), "nothing was written");

    let forged: Vec<Vec<u8>> = sign_owner_key_move(&plan, public(&owner_key), |_| Ok(vec![7; 64]))
        .expect("rows with a signature that does not verify")
        .iter()
        .map(|row| encode_authority_log_entry_body(row).expect("a row body"))
        .collect();
    hosted
        .confirm(hosted.owner, &act, &forged)
        .expect_err("a forged signature");
    assert!(hosted.key_is_live(public(&co_key)), "nothing was written");
}

/// The device door on an install that holds the owner's key: it checks the
/// plan against its own copy and signs it with that key. A plan whose keys
/// this copy does not show, or that names none of the keys it holds, is
/// refused.
#[test]
fn the_device_door_signs_the_plan_with_the_key_this_install_holds() {
    let hosted = hosted();
    let co_key = hosted.enrol_device_key(hosted.co_owner, CO_OWNER_SEED);
    let held = hosted
        .vault
        .enrol_device_owner_signing_key(
            &ActAuthority::Owner(proof(&hosted.vault, hosted.owner), ActSurface::ThisInstall),
            &hosted.issuer,
        )
        .expect("the owner enrols this install's owner signing key")
        .public_key;
    let act = hosted.propose_removal(hosted.owner, hosted.co_owner);
    let plan = hosted.plan(hosted.owner, &act);
    let device = ActAuthority::Owner(proof(&hosted.vault, hosted.owner), ActSurface::ThisInstall);

    let mut unsynced = plan.clone();
    unsynced.revoked.push([0x33; 32]);
    let refused = hosted
        .vault
        .sign_owner_key_move_as(&device, &unsynced)
        .expect_err("a key this copy does not show");
    assert!(
        refused.to_string().contains(OWNER_KEY_MOVE_NOT_SYNCED),
        "{refused}"
    );
    let mut unheld = plan.clone();
    unheld.signers.clear();
    let refused = hosted
        .vault
        .sign_owner_key_move_as(&device, &unheld)
        .expect_err("no key this install holds is named");
    assert!(
        refused.to_string().contains(OWNER_KEY_MOVE_NO_HELD_KEY),
        "{refused}"
    );

    let rows = hosted
        .vault
        .sign_owner_key_move_as(&device, &plan)
        .expect("the device door signs the plan");
    hosted
        .confirm(hosted.owner, &act, &rows)
        .expect("the confirmed removal runs");
    assert!(!hosted.key_is_live(public(&co_key)));
    assert_eq!(
        hosted.revoke_of(public(&co_key)).signer.public_key,
        AuthorityKey::Ed25519(held),
        "the held key signs as primary"
    );
}

/// The three verbs carry the move as JSON: the server's plan
/// (`vault.shared.owner_key_move_plan`, byte fields in hex) goes to the
/// device as it is, the rows the device signs
/// (`vault.shared.owner_key_move_sign`) go back to `vault.shared.execute` as
/// they are, and the confirmed run lands the removal. An execute input with
/// no rows field is the plain run, whose refusal names the act and the step;
/// a plan field that is not its 64 lowercase hex is a bad request.
#[test]
fn the_verbs_carry_the_plan_and_the_confirm_as_json() {
    use oneiron::memory::MEMORY_CODE_BAD_REQUEST;
    use oneiron::task_verb::sdk::{
        self, SharedActExecuteRequest, SharedActRequest, SharedOwnerKeyMoveSignRequest,
    };
    use serde_json::json;

    let hosted = hosted();
    let co_key = hosted.enrol_device_key(hosted.co_owner, CO_OWNER_SEED);
    let act = hosted.propose_removal(hosted.owner, hosted.co_owner);
    let executor = proof(&hosted.vault, hosted.owner);

    let plain: SharedActExecuteRequest =
        serde_json::from_value(json!({ "act_id": act })).expect("an input with no rows field");
    assert!(plain.owner_key_revokes.is_empty());
    assert_eq!(
        serde_json::to_value(&plain).expect("the input as JSON"),
        json!({ "act_id": act }),
        "no rows, no field"
    );
    let refused = sdk::execute_shared_act(&hosted.vault, &executor, Some(&hosted.issuer), plain)
        .expect_err("the plain run needs an owner key the executor holds");
    assert_eq!(
        refused.reason_codes,
        vec![
            "owner_key_required".to_owned(),
            "next_step:enrol_owner_device".to_owned(),
            format!("member:{}", hosted.co_owner.to_hex()),
            format!("act:{act}"),
        ],
        "the verb's refusal names the step, the member and the act"
    );

    let held = hosted
        .vault
        .enrol_device_owner_signing_key(
            &ActAuthority::Owner(proof(&hosted.vault, hosted.owner), ActSurface::ThisInstall),
            &hosted.issuer,
        )
        .expect("the owner enrols this install's owner signing key")
        .public_key;
    let plan = sdk::plan_shared_owner_key_move(
        &hosted.vault,
        &executor,
        Some(&hosted.issuer),
        SharedActRequest {
            act_id: act.clone(),
        },
    )
    .expect("the plan verb answers the plan");
    assert_eq!(plan.member, hosted.co_owner.to_hex(), "{plan:?}");
    assert_eq!(
        plan.revoked,
        vec![oneiron_hex::encode(&public(&co_key))],
        "{plan:?}"
    );
    assert_eq!(
        plan.signers
            .iter()
            .map(|signer| signer.public_key.clone())
            .collect::<Vec<_>>(),
        vec![oneiron_hex::encode(&held)],
        "{plan:?}"
    );

    let mut malformed = plan.clone();
    malformed.authority_vault_id.push_str("00");
    let refused = sdk::sign_shared_owner_key_move(
        &hosted.vault,
        &executor,
        SharedOwnerKeyMoveSignRequest { plan: malformed },
    )
    .expect_err("33 bytes are no authority vault id");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");

    let sign_input: SharedOwnerKeyMoveSignRequest = serde_json::from_value(
        json!({ "plan": serde_json::to_value(&plan).expect("the plan as JSON") }),
    )
    .expect("the device reads the plan the server answered");
    let confirm = sdk::sign_shared_owner_key_move(&hosted.vault, &executor, sign_input)
        .expect("the device signs the plan");
    assert_eq!(confirm.owner_key_revokes.len(), 1, "{confirm:?}");

    let confirmed: SharedActExecuteRequest = serde_json::from_value(json!({
        "act_id": act,
        "owner_key_revokes": serde_json::to_value(&confirm).expect("the confirm as JSON")["owner_key_revokes"],
    }))
    .expect("execute reads the device's rows");
    sdk::execute_shared_act(&hosted.vault, &executor, Some(&hosted.issuer), confirmed)
        .expect("the confirmed removal runs");
    assert!(!hosted.key_is_live(public(&co_key)));
    assert_eq!(
        hosted.revoke_of(public(&co_key)).signer.public_key,
        AuthorityKey::Ed25519(held),
        "the held key signs as primary"
    );
}
