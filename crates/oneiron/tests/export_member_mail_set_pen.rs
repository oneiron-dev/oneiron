//! FIX 15416 slice 1, review of #7761 round 1 (P1 at
//! mail_pack/export_mailboxes.rs `mail_export_member_mail_set`): "Owners can
//! export members' mail" (`vault.mail.export_member_mail.set`) is changed by
//! the vault's Owner or an Admin in person. `manages_in` admits a pen (an
//! AGENT_DEF anchored to its PERSON) by its PERSON's standing, so a pen's
//! change turned the setting on, and the next whole-vault export carried
//! members' mail. A pen's change is an agent's act, not its PERSON's, as for
//! org compliance search (Engine ruling PEN-COMPLIANCE-SET = A): it is
//! refused `FORBIDDEN`, and nothing changes or is logged. A pen's call that
//! changes nothing answers the setting as it reads. The Owner's own change
//! still goes.
//!
//! The fixture is check_in_mail_compliance_effects.rs's: a rooted vault
//! whose host key the fixture binds to the pen for its call, then back to
//! the owner.
//!
//! Red on the slice 3 head 4bba43954b87 with this file added: the pen's
//! change is taken.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test export_member_mail_set_pen`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::mail_pack::{
    MailComplianceEventView, MailExportMemberMailSetRequest, MailExportMemberMailSettingView,
    mail_calendar_pack_files,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::subject_model::anchor_actor_subject;
use oneiron::test_doors::membership::stand_member_grant;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::verbs::{AgentDefinitionCreateRequest, create_agent_definition_as};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

const SHARED: u64 = 44;

struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    admin: EntityId,
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

impl Org {
    /// A rooted vault whose shared vault holds the owner and an Admin, who
    /// accepted, with the Mail & Calendar pack installed.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
        let admin = EntityId::now();
        person(&vault, admin);
        let member = |member_ref, role| InitialSharedMember {
            member_ref,
            role: Some(role),
        };
        vault
            .initialize_shared_vault(
                &proof(&vault, owner),
                SHARED,
                None,
                &[member(owner, Role::Owner), member(admin, Role::Admin)],
                1,
            )
            .expect("a shared vault with an Admin");
        let admin_proof = proof(&vault, admin);
        let invitation = vault
            .shared_invitations(&admin_proof, SHARED)
            .expect("invitations")
            .into_iter()
            .find(|open| open.role == Role::Admin)
            .expect("the founding invitation");
        vault
            .accept_shared_invitation(&admin_proof, SHARED, &invitation.id)
            .expect("the Admin accepts");
        vault
            .put_pack(&proof(&vault, owner), mail_calendar_pack_files())
            .expect("the Owner installs the Mail & Calendar pack");
        Self {
            _dir: dir,
            vault,
            issuer,
            owner,
            admin,
        }
    }

    /// A pen of `person`: an AGENT_DEF anchored to them, with its own
    /// Member grant, so the shared vault's content gate admits its write
    /// and `manages_in` reads its person's standing.
    fn pen_of(&self, person: EntityId, agent_id: &str) -> EntityId {
        let pen = EntityId::now();
        create_agent_definition_as(
            &self.vault,
            &proof(&self.vault, self.owner),
            AgentDefinitionCreateRequest {
                agent_def_ref: pen,
                definition: serde_json::from_value(json!({
                    "agent_id": agent_id,
                    "desc": "A person's pen agent",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("typed agent definition"),
            },
        )
        .expect("the Owner creates the pen's agent definition");
        anchor_actor_subject(
            &self.vault,
            pen,
            person,
            WriteActor::new(self.owner, EdgeActorClass::Human),
            self.vault.now_recorded_at(),
        )
        .expect("the pen is anchored to its person");
        stand_member_grant(&self.vault, pen, SHARED, Role::Member)
            .expect("the pen's own Member grant");
        pen
    }

    /// `pen`'s `vault.mail.export_member_mail.set`, with the host key bound
    /// to it as an agent for the call.
    fn pen_set(
        &self,
        pen: EntityId,
        enabled: bool,
    ) -> MemoryResult<MailExportMemberMailSettingView> {
        bind_host_actor(&self.vault, &self.issuer, pen, "agent")
            .expect("the host key bound to the pen for its change");
        let answer = self
            .vault
            .memory(pen, EdgeActorClass::Agent)
            .mail_export_member_mail_set(&MailExportMemberMailSetRequest { enabled });
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("the owner's binding again");
        answer
    }

    /// The Owner's own `vault.mail.export_member_mail.set`.
    fn owner_set(&self, enabled: bool) -> MemoryResult<MailExportMemberMailSettingView> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .mail_export_member_mail_set(&MailExportMemberMailSetRequest { enabled })
    }

    /// The compliance log, as the Owner reads it.
    fn log(&self) -> Vec<MailComplianceEventView> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .mail_compliance_log()
            .expect("the Owner reads the log")
    }
}

#[test]
fn a_pens_change_of_owners_export_members_mail_is_refused() {
    let org = Org::new();
    for (person, agent_id) in [(org.owner, "owner-pen"), (org.admin, "admin-pen")] {
        let pen = org.pen_of(person, agent_id);
        let unchanged = org
            .pen_set(pen, false)
            .expect("a pen's call that changes nothing answers the setting");
        assert!(
            !unchanged.enabled && unchanged.set_by_ref.is_none(),
            "a call that changes nothing records nothing: {unchanged:?}"
        );
        let refused = org
            .pen_set(pen, true)
            .expect_err("a pen's change is refused at the door");
        assert_eq!(
            refused.code.as_str(),
            MEMORY_CODE_FORBIDDEN,
            "refused as an agent's act: {refused:?}"
        );
    }
    assert!(org.log().is_empty(), "no pen's change was logged");
    let read = org
        .owner_set(false)
        .expect("the Owner's call that changes nothing");
    assert!(
        !read.enabled && read.set_by_ref.is_none(),
        "no pen turned the setting on: {read:?}"
    );

    let on = org.owner_set(true).expect("the Owner's own change");
    assert!(on.enabled, "the Owner turns it on in person: {on:?}");
    assert_eq!(
        on.set_by_ref,
        Some(org.owner.to_hex()),
        "the change names the Owner"
    );
}
