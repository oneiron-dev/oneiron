#![cfg(oneiron_test_support)]
//! OPUS-T0-F gate pins, PR 6 (Engine NOTE 13 Nov 02:19): green pins for
//! eight authority, custody and grant gates of OPUS-TRIAGECENSUS's census
//! (census/TRIAGE.md, class GAP-PASSES: real callers pass these gates
//! today, and no running test drove them from a door). Each test drives
//! the door a real caller uses, with that caller's inputs, through the
//! gate, and reads the write back. A pin that goes red is a live refusal
//! of a real caller (GAP-BROKEN).
//!
//! Each test name starts with the census ids, so `-- g253_` runs one gate's
//! pin.
//!
//! - G124 `guard_actor_delete`: an ordinary PERSON's delete passes the
//!   base-actor guard.
//! - G126 `owner_choice_landing`: the owner's consolidation home pick lands.
//! - G161 `refuse_revoked_use_in_txn` and G200
//!   `record_custody_change_in_txn`: the owner's rewrap of a live portable
//!   secret is recorded and enacted.
//! - G184 `bind_person_credential`: a person's own human slip binds to
//!   their proof.
//! - G188 `live_federation_grant_in`: the owner sets a live federation
//!   grant's travel.
//! - G253 `require_sight_in_txn`: the owner seated in a room saves its talk.
//! - G260 `redeem_secret_grant_at_door`: a door grant redeems at its door.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test gate_pins_authority_custody_grants`.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{
    ActSurface, AuthorityVaultId, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineOwnership,
    MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::{ConversationBody, ConversationKind};
use oneiron::dreamer_runner::{
    ConsolidationHomePickRequest, consolidation_home_as, consolidation_home_pick_as,
};
use oneiron::inquiry::InquiryEdgeRequest;
use oneiron::off_record::{OffRecordBackendClass, OffRecordNoticeAct};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::{
    CustodyClass, CustodyPlan, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::secret_lease::{
    NoSecretHostDelivery, SecretGrantCaller, SecretGrantRef, SecretGrantTarget,
};
use oneiron::share_travel::{BornWithField, TravelChoice};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::steward;
use oneiron::world_keys::OwnerWorkStatus;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed, so a red
/// pin names its door and the refusal's own words.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

const fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// An owned vault with a device keystore and install signing, its embedded
/// owner PERSON and that owner's proof (tests/gate_pins_put_pipeline.rs).
struct Owned {
    _dir: tempfile::TempDir,
    vault: Vault,
    actor: EntityId,
    owner: AuthenticatedOwner,
}

fn owned() -> TestResult<Owned> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).map_err(at("open owned"))?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .map_err(at("install signing"))?;
    let actor = vault
        .ensure_embedded_owner_actor()
        .map_err(at("embedded owner"))?;
    let owner = vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .map_err(at("owner proof"))?;
    Ok(Owned {
        _dir: dir,
        vault,
        actor,
        owner,
    })
}

/// A vault whose owner acts have a carrier: its engine machines, device
/// keystore and this install's machine profile, as a host provisions them
/// (`test_doors::steward::open_owner_carrier_vault`), and the owner's proof.
struct Carrier {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: AuthenticatedOwner,
}

fn carrier() -> TestResult<Carrier> {
    let dir = tempfile::tempdir()?;
    let vault = steward::open_owner_carrier_vault(dir.path()).map_err(at("open the carrier"))?;
    let owner = steward::owner(&vault).map_err(at("owner proof"))?;
    Ok(Carrier {
        _dir: dir,
        vault,
        owner,
    })
}

#[test]
fn g124_an_ordinary_persons_delete_passes_the_base_actor_guard() -> TestResult {
    let owned = owned()?;
    let person = EntityId::now();
    owned
        .vault
        .put_entity(&person, ENTITY_TYPE_PERSON, range(1), 1, b"yuki")
        .map_err(at("put the PERSON"))?;
    assert!(
        owned
            .vault
            .delete_entity(&person)
            .map_err(at("delete the PERSON"))?
    );
    assert!(owned.vault.is_deleted_shell(&person)?);
    Ok(())
}

#[test]
fn g126_the_owners_consolidation_home_pick_lands() -> TestResult {
    let carrier = carrier()?;
    // The facade's `vault.consolidation.home.pick` (coordination_doors.rs).
    let receipt = consolidation_home_pick_as(
        &carrier.vault,
        &carrier.owner,
        ActSurface::ThisInstall,
        ConsolidationHomePickRequest {
            node_id: Some("7".to_owned()),
            seen: None,
        },
    )
    .map_err(at("the owner's home pick"))?;
    assert_eq!(receipt.pick.as_deref(), Some("7"));
    let view = consolidation_home_as(&carrier.vault, &carrier.owner)
        .map_err(at("read the consolidation home"))?;
    assert_eq!(view.pick.as_deref(), Some("7"));
    Ok(())
}

/// When the owner's custody acts in these pins happen.
const CUSTODY_AT: u64 = 1_780_000_000;

#[test]
fn g161_g200_the_owners_rewrap_of_a_live_portable_secret_lands() -> TestResult {
    let carrier = carrier()?;
    let vault = &carrier.vault;
    // A serving install enrols unanswered and is no custody candidate until
    // the owner answers that it is his, as the owner's machine route
    // (machine_routes.rs) does with `set_machine_role`.
    let this_install = vault
        .local_machine()
        .map_err(at("read this install"))?
        .ok_or("fixture: this install has no machine id")?
        .id;
    vault
        .set_machine_role(
            &carrier.owner,
            ActSurface::ThisInstall,
            this_install,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .map_err(at("the owner answers this install is his"))?;
    // Registered after that answer, so the value is portable.
    vault
        .register_secret_as_owner(
            &carrier.owner,
            &OwnerSecretRegistration {
                name: "owen-deploy",
                class: CustodyClass::CustodyPortable,
                device_only: false,
                rung: CustodyTier::T1Leased,
                bindings: vec![RequestedBinding {
                    effector: "deploy".to_owned(),
                    tier_ceiling: None,
                    scopes: vec!["read".to_owned()],
                }],
                manifest: None,
                value: b"pin-value",
            },
            CUSTODY_AT,
        )
        .map_err(at("register the portable secret"))?;
    let view = vault
        .secret_custody_view(&carrier.owner, "owen-deploy")
        .map_err(at("read the custody view"))?;
    let machine = view
        .candidates
        .iter()
        .find(|candidate| candidate.this_install)
        .map(|candidate| candidate.permit.machine)
        .ok_or("fixture: this install is no custody candidate")?;
    assert_eq!(machine, this_install);
    // The owner route's rewrap (owner/secrets.rs): this install holds it,
    // and the plan permits this install.
    let work = vault
        .rewrap_secret_as_owner(
            &carrier.owner,
            ActSurface::ThisInstall,
            "owen-deploy",
            &CustodyPlan {
                holder: None,
                recipients: vec![machine],
            },
            CUSTODY_AT + 1,
        )
        .map_err(at("the owner's rewrap"))?;
    assert!(
        work.kept_here.is_none(),
        "the rewrap was kept on this install"
    );
    let receipt = work.work.ok_or("the rewrap recorded no owner work")?;
    assert!(
        matches!(receipt.status, OwnerWorkStatus::Enacted),
        "the rewrap is not enacted"
    );
    assert_eq!(receipt.executor, Some(machine));
    Ok(())
}

/// A fresh slip id from two UUIDv7 stamps.
fn slip_id() -> [u8; 32] {
    let first = EntityId::now();
    let second = EntityId::now();
    let mut id = [0_u8; 32];
    id[..16].copy_from_slice(first.as_bytes());
    id[16..].copy_from_slice(second.as_bytes());
    id
}

#[test]
fn g184_a_persons_own_human_slip_binds_to_their_proof() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default()).map_err(at("open"))?;
    let yuki = EntityId::now();
    vault
        .put_entity(&yuki, ENTITY_TYPE_PERSON, range(1), 1, b"yuki")
        .map_err(at("put the PERSON"))?;
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // yuki's own human slip, cut from the host root and verified on her
    // binding (tests/esign_audit_document_admission.rs).
    let root = vault
        .ensure_host_root_slip(&issuer)
        .map_err(at("host root"))?;
    let mut claims = root.claims;
    claims.slip_id = slip_id();
    claims.holder_ref = yuki.to_hex();
    claims.actor_class = Some("human".to_owned());
    let slip = vault
        .mint_capability_slip(&issuer, claims)
        .map_err(at("mint the slip"))?;
    let challenge = b"gate-pins-g184";
    let binding = issuer
        .binding_proof(&slip, challenge)
        .map_err(at("binding proof"))?;
    let verified = vault
        .verify_capability_slip(&issuer.public_key(), &slip, challenge, &binding)
        .map_err(at("verify the slip"))?;
    // The facade's person door (shared_act_doors.rs `person`, then
    // code_wait_doors.rs `as_person`): her proof carries the request's slip,
    // then binds it as her person credential.
    let person = vault
        .authenticate_owner(yuki, &yuki.to_hex(), true, GateDecisionId::now())
        .map_err(at("the person's proof"))?;
    let person = vault
        .bind_request_credential(person, verified.clone())
        .map_err(at("bind the request slip"))?;
    let bound = vault
        .bind_person_credential(person, verified.clone())
        .map_err(at("bind the person credential"))?;
    assert_eq!(bound.revalidate_person(&vault)?, yuki);
    // The proof now holds a person credential: a second one is refused.
    assert!(vault.bind_person_credential(bound, verified).is_err());
    Ok(())
}

/// A company vault no fixture opens: the edge mints before any pact.
const UNOPENED_COMPANY: AuthorityVaultId = [0xac; 32];

#[test]
fn g188_the_owner_sets_a_live_grants_travel() -> TestResult {
    // A vault rooted under its own host, its engine machines and install
    // profile provisioned and its owner bound (tests/inquiry_edge.rs).
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device()).map_err(at("open"))?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer =
        HostSlipIssuer::from_seed(&[0x51; HOST_ISSUER_SEED_BYTES]).map_err(at("host issuer"))?;
    vault
        .ensure_host_root_slip(&issuer)
        .map_err(at("host root"))?;
    vault
        .provision_engine_machine_identities(&issuer)
        .map_err(at("engine machines"))?;
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .map_err(at("install profile"))?;
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(at("embedded owner"))?;
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).map_err(at("bind owner"))?;
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .map_err(at("owner proof"))?;
    let edge = vault
        .mint_inquiry_edge(
            &proof,
            &InquiryEdgeRequest::member_defaults(UNOPENED_COMPANY, "Acme"),
        )
        .map_err(at("mint the federation grant"))?;
    // The owner route `POST /v1/owner/federation/grant-travel`.
    let choice = TravelChoice {
        born_with: BTreeSet::from([BornWithField::Why]),
    };
    let set = vault
        .set_federation_grant_travel_as(
            &proof,
            ActSurface::ThisInstall,
            &edge.grant,
            Some(choice.clone()),
            None,
            vault.now_recorded_at(),
        )
        .map_err(at("set the grant's travel"))?;
    assert_eq!(set.map(|travel| travel.travel), Some(choice.clone()));
    let stored = vault
        .federation_grant_travel(&edge.grant)?
        .ok_or("the grant's travel is not stored")?;
    assert_eq!(stored.travel, choice);
    Ok(())
}

#[test]
fn g253_the_owner_seated_in_a_room_saves_its_talk() -> TestResult {
    let owned = owned()?;
    let room = EntityId::now();
    owned
        .vault
        .create_conversation(
            room,
            &ConversationBody {
                kind: ConversationKind::Group,
                member_ids: vec![owned.actor],
                ..Default::default()
            },
            WriteActor::new(owned.actor, EdgeActorClass::Human),
            owned.vault.now_recorded_at(),
        )
        .map_err(at("create the room"))?;
    let rooms = owned.vault.off_record_session_vault();
    let session = rooms
        .enter_in_room_as(
            "owen-room-pin",
            OffRecordBackendClass::Local,
            room,
            &owned.owner,
        )
        .map_err(at("enter the room off record"))?;
    // The room route's save (off_record_rooms.rs `room_save`).
    let saved = session
        .save_talk_as(&owned.owner)
        .map_err(at("save the room's talk"))?;
    // No turn was staged, so none is saved; the save itself is the act.
    assert!(saved.is_empty());
    let record = session
        .record_for(owned.actor)
        .map_err(at("read the session record"))?;
    assert!(
        record.notices.iter().any(|notice| {
            matches!(notice.act, OffRecordNoticeAct::SavedTalk)
                && notice.by == *owned.actor.as_bytes()
        }),
        "no SavedTalk notice by the owner among {} notices",
        record.notices.len()
    );
    Ok(())
}

#[test]
fn g260_a_door_grant_redeems_at_its_door() -> TestResult {
    let owned = owned()?;
    let vault = &owned.vault;
    vault
        .register_secret_as_owner(
            &owned.owner,
            &OwnerSecretRegistration {
                name: "owen-slack",
                class: CustodyClass::CustodyPortable,
                device_only: false,
                rung: CustodyTier::T1Leased,
                bindings: vec![RequestedBinding {
                    // The effector of the `slack.auth_test` operation.
                    effector: "connector:slack".to_owned(),
                    tier_ceiling: None,
                    scopes: vec!["read".to_owned()],
                }],
                manifest: None,
                value: b"xoxb-pin-value",
            },
            CUSTODY_AT,
        )
        .map_err(at("register the secret"))?;
    let caller = SecretGrantCaller::of(&vault.memory(owned.actor, EdgeActorClass::Human), None)
        .map_err(at("the grant's caller"))?;
    let target = SecretGrantTarget::Operation {
        name: "slack.auth_test".to_owned(),
    };
    let minted = vault
        .mint_secret_grant_for_name(
            &caller,
            "owen-slack",
            target.clone(),
            None,
            None,
            &mut NoSecretHostDelivery,
        )
        .map_err(at("mint the door grant"))?;
    let grant = SecretGrantRef::new(minted.grant.grant_id, caller.holder());
    // The send's own door: the value reaches the closure and nothing else.
    let mut sent = Vec::new();
    let redeemed = vault
        .redeem_secret_grant_at_door(&grant, &target, &mut |value: &[u8]| {
            sent = value.to_vec();
            Ok(())
        })
        .map_err(at("redeem the grant at its door"))?;
    assert_eq!(sent, b"xoxb-pin-value");
    assert_eq!(redeemed.grant_id, minted.grant.grant_id);
    assert_eq!(redeemed.generation, minted.grant.generation);
    assert_eq!(redeemed.effector, "connector:slack");
    Ok(())
}
