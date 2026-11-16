//! UNBUILT-06 PR 3: Engine ANSWER UNBUILT06-PR2-UNHELD-ROLE-DOORS = A
//! (16 Nov 15:52). Four proofs cover private-thread POLICY delete, private-thread
//! audience edits (including a walk-in and a seated member's own edit), group
//! mail changes (without holding reads), and decline of a Steward's member ask.
//! Each proves (a) Admin goes with org.two_admin off, (b) Owner turns it on,
//! (c) Admin refuses with two_admin_hold and changes nothing, and (d) Owner goes.
//! On #8482's committed head (0027f5855d7), without the PR 3 library changes,
//! step (c) fails: the Admin's act succeeds. All other assertions use that head's
//! existing behavior.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test two_admin_role_doors`
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrantRole as Role, InitialSharedMember, MemberAskChange, MemberAskStatus,
};
use oneiron::mail_pack::{
    MailCopySetting, MailProvider, MailSourceConnectRequest, MailSourceKind,
    MailSourceMembersRequest, MailSourceSettingsRequest, install_mail_calendar_pack_embedded,
};
use oneiron::memory::{
    MemoryError, MemoryResult, TWO_ADMIN_HOLD_REASON_CODE, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::{SECRET_CUSTODY_SCHEMA_VERSION, decode_secret_custody_body};
use oneiron::setting::{SetSetting, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::test_support::{bind_host_actor, bind_host_owner, provision_engine_machines};
use oneiron::workspace_roster::{
    PrivateThreadDeleteRequest, ProjectRecord, ThreadAudienceAddRequest, ThreadAudienceHistory,
    ThreadAudienceReceipt, ThreadAudienceRemoveRequest,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

const SHARED: u64 = 47;

struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    admin: EntityId,
    member: EntityId,
    steward: EntityId,
    /// Home room of a project whose roster is the Member alone.
    member_room: EntityId,
    /// Home room of a project whose roster seats the Admin and the Member.
    seated_room: EntityId,
}

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

// Project home rooms seat their leader and roster; no Admin seat is implied.
fn project_home_room(vault: &Vault, owner: EntityId, roster: &[EntityId]) -> EntityId {
    let root = vault.root_project().expect("root project");
    let project = EntityId::now();
    let mut record = ProjectRecord::new(project, Some(root), root, owner).expect("project");
    record.roster.extend(roster.iter().map(EntityId::to_hex));
    vault
        .put_project(project, &record, vault.now_recorded_at())
        .expect("put project");
    EntityId::from_hex(&record.home_room).expect("home room")
}

fn assert_held(err: &MemoryError) {
    assert!(
        err.reason_codes
            .iter()
            .any(|code| code == TWO_ADMIN_HOLD_REASON_CODE),
        "the refusal must name the two-admin rule: {err:?}"
    );
}

impl Org {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let [admin, member, steward] = std::array::from_fn(|_| person(&vault));
        // A child project put before the host root slip takes the implicit
        // birth. Once the vault is rooted, a new child project needs an
        // owner-signed birth (`put_project` refuses "a new project requires
        // an owner-signed birth"), so both projects are put first.
        let member_room = project_home_room(&vault, owner, &[member]);
        let seated_room = project_home_room(&vault, owner, &[admin, member]);
        let issuer = provision_engine_machines(&vault);
        bind_host_owner(&vault, &issuer, owner).expect("owner binding");
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
                    founding(admin, Role::Admin),
                    founding(member, Role::Member),
                    founding(steward, Role::Steward),
                ],
                1,
            )
            .expect("shared vault");
        for (person, role) in [
            (admin, Role::Admin),
            (member, Role::Member),
            (steward, Role::Steward),
        ] {
            let invitee = proof(&vault, person);
            let invitation = vault
                .shared_invitations(&invitee, SHARED)
                .expect("invitations")
                .into_iter()
                .find(|open| open.role == role)
                .expect("founding invitation");
            vault
                .accept_shared_invitation(&invitee, SHARED, &invitation.id)
                .expect("accept");
        }
        Self {
            _dir: dir,
            vault,
            issuer,
            owner,
            admin,
            member,
            steward,
            member_room,
            seated_room,
        }
    }

    fn as_person<T>(&self, person: EntityId, act: impl FnOnce() -> T) -> T {
        bind_host_actor(&self.vault, &self.issuer, person, "human").expect("actor binding");
        let answer = act();
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("restore owner binding");
        answer
    }

    fn owner_sets(&self, key: &str, value: serde_json::Value) {
        self.vault
            .set_setting(
                SettingCaller::Owner(&proof(&self.vault, self.owner)),
                SetSetting::vault_value(key, value),
            )
            .expect("Owner sets the key");
    }

    /// The Owner's trunk turn in `room`, which every private thread opens on.
    fn trunk_turn(&self, room: EntityId) -> EntityId {
        let anchor = EntityId::now();
        self.speak(room, anchor, None, None);
        anchor
    }

    fn speak(
        &self,
        room: EntityId,
        turn: EntityId,
        anchor: Option<EntityId>,
        audience: Option<BTreeSet<EntityId>>,
    ) {
        let metadata = anchor.map(|anchor| json!({"room_thread_of": anchor.to_hex()}));
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .rooms_speak(&WitnessTurn {
                conversation_ref: room.to_hex(),
                turn_ref: Some(turn.to_hex()),
                thread_audience: audience,
                messages: vec![WitnessMessage {
                    id: Some(EntityId::now().to_hex()),
                    author: WitnessAuthor::User,
                    message_type: "text".into(),
                    content: "a room turn".into(),
                    parts: None,
                    metadata,
                    is_visible: true,
                    order: 0,
                    quote: None,
                }],
                occurred_at: self.vault.now_recorded_at(),
                assertions: Default::default(),
            })
            .expect("Owner speaks");
    }

    fn private_thread(&self, room: EntityId, anchor: EntityId, audience: &[EntityId]) -> EntityId {
        let root = EntityId::now();
        self.speak(
            room,
            root,
            Some(anchor),
            Some(audience.iter().copied().collect()),
        );
        root
    }

    fn audience(&self, room: EntityId, root: EntityId) -> Vec<String> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .rooms_get_thread(room, root)
            .expect("thread view")
            .expect("live thread")
            .audience
    }

    fn edit_audience(
        &self,
        by: EntityId,
        root: EntityId,
        target: EntityId,
        remove: bool,
    ) -> MemoryResult<ThreadAudienceReceipt> {
        self.as_person(by, || {
            let memory = self.vault.memory(by, EdgeActorClass::Human);
            if remove {
                memory.rooms_thread_audience_remove(&ThreadAudienceRemoveRequest {
                    thread_ref: root.to_hex(),
                    person_ref: target.to_hex(),
                })
            } else {
                memory.rooms_thread_audience_add(&ThreadAudienceAddRequest {
                    thread_ref: root.to_hex(),
                    person_ref: target.to_hex(),
                    history: ThreadAudienceHistory::Full,
                    check_in_ref: None,
                })
            }
        })
    }
}

// The custody fixture from mail_active_sources, with one explicit holder scope.
fn register_mail_credential(vault: &Vault, name: &str, scope: &str) {
    use rmpv::Value;
    let band = |min: u64, max: u64| {
        Value::Map(vec![("min".into(), min.into()), ("max".into(), max.into())])
    };
    let floor = Value::Map(vec![
        ("portable".into(), band(0, 2)),
        ("device_bound".into(), band(0, 2)),
        ("cross_vault".into(), band(0, 0)),
        ("rotation_max_age_secs".into(), Value::Nil),
        ("env_bindings".into(), Value::Map(vec![])),
    ]);
    let binding = Value::Map(vec![
        ("effector".into(), "connector:gmail".into()),
        ("tier_ceiling".into(), 0_u64.into()),
        ("scopes".into(), Value::Array(vec![scope.into()])),
    ]);
    let body = Value::Map(vec![
        (
            "schema_version".into(),
            u64::from(SECRET_CUSTODY_SCHEMA_VERSION).into(),
        ),
        ("name".into(), name.into()),
        ("class".into(), "custody-portable".into()),
        ("device_only".into(), false.into()),
        (
            "value_bytes".into(),
            Value::Binary(b"test-mail-token".to_vec()),
        ),
        ("status".into(), "active".into()),
        ("registered_at".into(), 1_u64.into()),
        ("rotated_at".into(), Value::Nil),
        ("rotation_generation".into(), 0_u64.into()),
        ("bindings".into(), Value::Array(vec![binding])),
        ("manifest_ref".into(), "".into()),
        ("declared_paths".into(), Value::Array(vec![])),
        ("policy_floor_snapshot".into(), floor),
        ("model_reveal_allowed".into(), true.into()),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body).expect("credential bytes");
    vault
        .register_secret(decode_secret_custody_body(&bytes).expect("credential body"))
        .expect("register credential");
}

#[test]
fn an_admins_policy_delete_of_a_private_thread_refuses_while_the_rule_is_on() {
    let org = Org::new();
    let room = org.member_room;
    let anchor = org.trunk_turn(room);
    let delete = |by, root: EntityId| {
        org.as_person(by, || {
            org.vault
                .memory(by, EdgeActorClass::Human)
                .rooms_thread_delete(&PrivateThreadDeleteRequest {
                    thread_ref: root.to_hex(),
                })
        })
    };
    let off = org.private_thread(room, anchor, &[org.owner]);
    assert!(
        delete(org.admin, off)
            .expect("Admin policy delete with rule off")
            .existed
    );
    assert!(org.vault.is_deleted_shell(&off).expect("deleted root"));

    org.owner_sets("org.two_admin", json!(true));
    let held = org.private_thread(room, anchor, &[org.owner]);
    let refusal = delete(org.admin, held).expect_err("Admin policy delete is held");
    assert_held(&refusal);
    assert!(
        !org.vault
            .is_deleted_shell(&held)
            .expect("root remains live")
    );
    assert!(
        delete(org.owner, held)
            .expect("Owner policy delete is never held")
            .existed
    );
    assert!(
        org.vault
            .is_deleted_shell(&held)
            .expect("Owner deleted root")
    );
}

#[test]
fn an_admins_audience_edit_of_a_private_thread_refuses_while_the_rule_is_on() {
    let org = Org::new();
    let room = org.member_room;
    let anchor = org.trunk_turn(room);
    let seated_room = org.seated_room;
    let seated_anchor = org.trunk_turn(seated_room);
    // Each operation uses its own thread: add another, remove another, walk in.
    for (target, remove) in [(org.member, false), (org.member, true), (org.admin, false)] {
        let seed = if remove {
            vec![org.owner, org.member]
        } else {
            vec![org.owner]
        };
        // A walk-in target is seated so the Owner can make the same add;
        // the Admin is outside this thread, and outside both for add/remove.
        let (room, anchor) = if target == org.admin {
            (seated_room, seated_anchor)
        } else {
            (room, anchor)
        };
        let off = org.private_thread(room, anchor, &seed);
        org.edit_audience(org.admin, off, target, remove)
            .expect("Admin edits with rule off");
        assert_eq!(org.audience(room, off).contains(&target.to_hex()), !remove);
    }

    let off_room_walk = org.private_thread(room, anchor, &[org.owner]);
    org.edit_audience(org.admin, off_room_walk, org.admin, false)
        .expect("Admin walks in without a room seat while the rule is off");
    assert!(
        org.audience(room, off_room_walk)
            .contains(&org.admin.to_hex())
    );

    org.owner_sets("org.two_admin", json!(true));
    for (target, remove) in [(org.member, false), (org.member, true), (org.admin, false)] {
        let seed = if remove {
            vec![org.owner, org.member]
        } else {
            vec![org.owner]
        };
        // A walk-in target is seated so the Owner can make the same add;
        // the Admin is outside this thread, and outside both for add/remove.
        let (room, anchor) = if target == org.admin {
            (seated_room, seated_anchor)
        } else {
            (room, anchor)
        };
        let held = org.private_thread(room, anchor, &seed);
        let before = org.audience(room, held);
        let refusal = org
            .edit_audience(org.admin, held, target, remove)
            .expect_err("outside Admin edit is held");
        assert_held(&refusal);
        assert_eq!(
            org.audience(room, held),
            before,
            "held edit changes no audience"
        );
        org.edit_audience(org.owner, held, target, remove)
            .expect("Owner makes the same edit");
        assert_eq!(org.audience(room, held).contains(&target.to_hex()), !remove);
    }

    let off_room_walk = org.private_thread(room, anchor, &[org.owner]);
    let before = org.audience(room, off_room_walk);
    assert_held(
        &org.edit_audience(org.admin, off_room_walk, org.admin, false)
            .expect_err("a held Admin cannot walk in without a room seat either"),
    );
    assert_eq!(org.audience(room, off_room_walk), before);

    let inside = org.private_thread(seated_room, seated_anchor, &[org.owner, org.admin]);
    org.edit_audience(org.admin, inside, org.member, false)
        .expect("an Admin in both audience and room edits as a member, even while held");
    assert!(
        org.audience(seated_room, inside)
            .contains(&org.member.to_hex())
    );
}

#[test]
fn an_admins_group_mail_change_refuses_while_the_rule_is_on() {
    let org = Org::new();
    install_mail_calendar_pack_embedded(&org.vault.memory(org.owner, EdgeActorClass::Human))
        .expect("Owner installs mail pack");
    register_mail_credential(&org.vault, "group-credential", "group-address");
    register_mail_credential(
        &org.vault,
        "member-credential",
        &format!("actor:{}", org.member.to_hex()),
    );
    let request = |address: &str, personal| MailSourceConnectRequest {
        provider: MailProvider::Google,
        kind: if personal {
            MailSourceKind::PersonalMailbox
        } else {
            MailSourceKind::GroupAddress
        },
        address: address.into(),
        provider_account: address.into(),
        custody_ref: if personal {
            "member-credential"
        } else {
            "group-credential"
        }
        .into(),
        members: if personal {
            vec![]
        } else {
            vec![org.member.to_hex()]
        },
        for_person: personal.then(|| org.member.to_hex()),
        channel_identity_ref: None,
        copy: None,
        on_provider_delete: None,
        calendar_details: None,
    };
    let connect = |by, input: &MailSourceConnectRequest| {
        org.as_person(by, || {
            org.vault
                .memory(by, EdgeActorClass::Human)
                .mail_sources_connect(input)
        })
    };
    let settings = |by, source: &str| {
        org.as_person(by, || {
            org.vault
                .memory(by, EdgeActorClass::Human)
                .mail_sources_settings_set(&MailSourceSettingsRequest {
                    source_ref: source.into(),
                    copy: Some(MailCopySetting::SearchOnly),
                    on_provider_delete: None,
                    calendar_details: None,
                    status: None,
                    own_addresses: None,
                })
        })
    };
    let readers = |by, source: &str| {
        org.as_person(by, || {
            org.vault
                .memory(by, EdgeActorClass::Human)
                .mail_sources_members_set(&MailSourceMembersRequest {
                    source_ref: source.into(),
                    members: vec![org.member.to_hex(), org.steward.to_hex()],
                })
        })
    };
    let list = |by| {
        org.as_person(by, || {
            org.vault
                .memory(by, EdgeActorClass::Human)
                .mail_sources_list()
        })
        .expect("list sources")
    };

    let off = connect(org.admin, &request("off-group@test.example", false))
        .expect("Admin connects group with rule off");
    assert!(!off.resumed);
    let off_person = connect(org.admin, &request("off-member@test.example", true))
        .expect("Admin connects another person's source with rule off");
    assert_eq!(off_person.source.owner_ref, Some(org.member.to_hex()));
    assert!(
        list(org.member)
            .iter()
            .any(|source| source.source_ref == off_person.source.source_ref)
    );
    assert_eq!(
        settings(org.admin, &off.source.source_ref)
            .expect("Admin settings with rule off")
            .copy,
        MailCopySetting::SearchOnly
    );
    let off_readers =
        readers(org.admin, &off.source.source_ref).expect("Admin readers with rule off");
    assert_eq!(off_readers.members.len(), 2);
    assert!(off_readers.members.contains(&org.steward.to_hex()));

    // A separate source stays in its original state for all held changes.
    let target = connect(org.owner, &request("target-group@test.example", false))
        .expect("target group")
        .source;
    let before_admin = list(org.admin);
    let before_member = list(org.member);
    let before_view = before_admin
        .iter()
        .find(|source| source.source_ref == target.source_ref)
        .expect("Admin manages a group they do not read");
    assert!(!before_view.reads);
    org.owner_sets("org.two_admin", json!(true));
    let new_group = request("held-group@test.example", false);
    let new_person = request("held-member@test.example", true);
    assert_held(&connect(org.admin, &new_group).expect_err("Admin group connect is held"));
    assert_held(&connect(org.admin, &new_person).expect_err("Admin for_person connect is held"));
    assert_held(
        &settings(org.admin, &target.source_ref).expect_err("Admin group settings are held"),
    );
    assert_held(&readers(org.admin, &target.source_ref).expect_err("Admin group readers are held"));
    assert_eq!(
        list(org.member),
        before_member,
        "no new personal source or changed readers/settings"
    );
    assert_eq!(
        list(org.admin),
        before_admin,
        "no new group source; a held Admin still lists/views the same group with unchanged settings/readers"
    );

    let group = connect(org.owner, &new_group).expect("Owner group connect with rule on");
    assert!(!group.resumed);
    assert!(
        list(org.admin)
            .iter()
            .any(|source| source.source_ref == group.source.source_ref)
    );
    let personal = connect(org.owner, &new_person).expect("Owner for_person connect with rule on");
    assert_eq!(personal.source.owner_ref, Some(org.member.to_hex()));
    assert!(
        list(org.member)
            .iter()
            .any(|source| source.source_ref == personal.source.source_ref)
    );
    assert_eq!(
        settings(org.owner, &target.source_ref)
            .expect("Owner settings with rule on")
            .copy,
        MailCopySetting::SearchOnly
    );
    let changed = readers(org.owner, &target.source_ref).expect("Owner readers with rule on");
    assert_eq!(changed.members.len(), 2);
    assert!(changed.members.contains(&org.steward.to_hex()));
}

#[test]
fn an_admins_decline_of_a_stewards_ask_refuses_while_the_rule_is_on() {
    let org = Org::new();
    let ask = || {
        org.as_person(org.steward, || {
            org.vault.ask_shared_member_change(
                &proof(&org.vault, org.steward),
                SHARED,
                MemberAskChange::Remove {
                    member: org.member.to_hex(),
                },
            )
        })
        .expect("Steward asks")
    };
    let decline = |by, id: &str| {
        org.as_person(by, || {
            org.vault
                .decline_shared_member_ask(&proof(&org.vault, by), id)
        })
    };
    let status = |id: &str| {
        org.vault
            .shared_member_asks(&proof(&org.vault, org.owner), SHARED)
            .expect("Owner lists asks")
            .into_iter()
            .find(|ask| ask.id == id)
            .expect("stored ask")
            .status
    };

    let off = ask();
    assert_eq!(off.status, MemberAskStatus::Open);
    decline(org.admin, &off.id).expect("Admin declines with rule off");
    assert_eq!(
        status(&off.id),
        MemberAskStatus::Declined {
            by: org.admin.to_hex()
        }
    );

    org.owner_sets("org.two_admin", json!(true));
    let held = ask();
    assert_ne!(held.id, off.id, "a separate ask after the first was closed");
    let refusal =
        MemoryError::from(decline(org.admin, &held.id).expect_err("Admin decline is held"));
    assert_held(&refusal);
    assert_eq!(
        status(&held.id),
        MemberAskStatus::Open,
        "held decline closes nothing"
    );
    decline(org.owner, &held.id).expect("Owner declines with rule on");
    assert_eq!(
        status(&held.id),
        MemberAskStatus::Declined {
            by: org.owner.to_hex()
        }
    );
}
