//! ROLES-CHECKIN P2.5, row 2k4b (ARCH-0082 #act-table "Disable a security
//! control (C)", #role-defaults and #owner-own-acts; Engine ruling
//! P25-SHAPE Q1 = A, 14 Nov 13:39): `vault.mail.compliance.set`, the door a
//! Deputy or an Admin already reaches by role, takes the writer judge (2i).
//!
//! - The Owner's change is never gated: it goes on their own proof, and the
//!   answer and the compliance log record that decision. A call that
//!   changes nothing records nothing.
//! - An Admin's change always asks: the door commits the pending check-in
//!   alone, changes and logs nothing, and answers `CHECK_IN_PENDING` naming
//!   it; a repeat names the same one. Before the Owner approves, or for
//!   another purpose, the named check-in runs nothing. Once approved, the
//!   call that names it turns the setting, spends it in the same writer and
//!   records it.
//! - The Owner may apply a Deputy's approved ask on their own proof: the
//!   decision names the Deputy as requester.
//!
//! The vault is rooted, and a rooted vault admits only a writer its
//! authority log binds. The host key holds one live binding, so each
//! member's change runs while the fixture binds the key to that member, and
//! the key goes back to the owner after (as check_in_membership_effects.rs
//! does).
//!
//! On the base (596ccd62145) this file does not build: the compliance
//! request has no `check_in_ref`, and its answer and log entries no
//! `check_in`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_mail_compliance_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::check_in::CheckInDecision;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::mail_pack::{
    MailComplianceEventKind, MailComplianceEventView, MailComplianceSetRequest,
    MailComplianceSettingView, mail_calendar_pack_files,
};
use oneiron::memory::{CHECK_IN_PENDING_REASON_PREFIX, MEMORY_CODE_CHECK_IN_PENDING, MemoryResult};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

const SHARED: u64 = 43;

struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    deputy: EntityId,
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

fn accept(vault: &Vault, member: EntityId, role: Role) {
    let member_proof = proof(vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == role)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("the member accepts");
}

impl Org {
    /// A rooted vault whose shared vault holds the owner, a Deputy and an
    /// Admin, each of whom accepted, with the Mail & Calendar pack installed.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
        let [deputy, admin] = std::array::from_fn(|_| EntityId::now());
        for id in [deputy, admin] {
            person(&vault, id);
        }
        let member = |member_ref, role| InitialSharedMember {
            member_ref,
            role: Some(role),
        };
        vault
            .initialize_shared_vault(
                &proof(&vault, owner),
                SHARED,
                None,
                &[
                    member(owner, Role::Owner),
                    member(deputy, Role::Deputy),
                    member(admin, Role::Admin),
                ],
                1,
            )
            .expect("a shared vault with a Deputy and an Admin");
        accept(&vault, deputy, Role::Deputy);
        accept(&vault, admin, Role::Admin);
        vault
            .put_pack(&proof(&vault, owner), mail_calendar_pack_files())
            .expect("the Owner installs the Mail & Calendar pack");
        Self {
            _dir: dir,
            vault,
            issuer,
            owner,
            deputy,
            admin,
        }
    }

    /// `person`'s `vault.mail.compliance.set`, with the host key bound to
    /// them for a member's call.
    fn set(
        &self,
        person: EntityId,
        enabled: bool,
        purpose: &str,
        check_in_ref: Option<&str>,
    ) -> MemoryResult<MailComplianceSettingView> {
        let request = MailComplianceSetRequest {
            enabled,
            purpose: purpose.to_owned(),
            check_in_ref: check_in_ref.map(str::to_owned),
        };
        let call = || {
            self.vault
                .memory(person, EdgeActorClass::Human)
                .mail_compliance_set(&request)
        };
        if person == self.owner {
            return call();
        }
        bind_host_actor(&self.vault, &self.issuer, person, "human")
            .expect("the host key bound to the member for their change");
        let answer = call();
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("the owner's binding again");
        answer
    }

    /// Whether compliance search is on, as the Owner reads it.
    fn enabled(&self) -> bool {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .mail_compliance_setting()
            .expect("the Owner reads the setting")
            .enabled
    }

    /// The compliance log, as the Owner reads it.
    fn log(&self) -> Vec<MailComplianceEventView> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .mail_compliance_log()
            .expect("the Owner reads the log")
    }

    /// The Owner approves pending check-in `id` over the effect it waits on,
    /// through `vault.check_in.answer`.
    fn owner_approves(&self, id: &str) {
        let row = self
            .vault
            .pending_check_in(&EntityId::from_hex(id).expect("a check-in id"))
            .expect("read the check-in")
            .expect("the check-in is stored");
        let digest: String = row
            .effect_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let settled = invoke(
            &self.vault.memory(self.owner, EdgeActorClass::Human),
            "vault.check_in.answer",
            json!({ "handle": id, "answer": "approve", "effect_digest": digest }),
        )
        .expect("the Owner answers");
        assert_eq!(
            settled["eligible"].as_str(),
            Some("approved"),
            "the Owner's approval makes the change eligible: {settled}"
        );
    }

    /// Whether check-in `id` is spent.
    fn spent(&self, id: &str) -> bool {
        self.vault
            .pending_check_in(&EntityId::from_hex(id).expect("a check-in id"))
            .expect("read the check-in")
            .expect("stored")
            .consumed_at
            .is_some()
    }
}

/// The check-in a waiting change names.
fn pending_id(result: MemoryResult<MailComplianceSettingView>) -> String {
    let refused = result.expect_err("the change waits on a check-in");
    assert_eq!(
        refused.code, MEMORY_CODE_CHECK_IN_PENDING,
        "the change waits: {refused:?}"
    );
    refused
        .reason_codes
        .first()
        .and_then(|code| code.strip_prefix(CHECK_IN_PENDING_REASON_PREFIX))
        .expect("the reason code names the check-in")
        .to_owned()
}

fn decision(
    role: &str,
    mode: Option<&str>,
    basis: &str,
    check_in: Option<&str>,
    requester: Option<EntityId>,
) -> CheckInDecision {
    CheckInDecision {
        act_class: "security_control_disable".to_owned(),
        role: role.to_owned(),
        mode: mode.map(str::to_owned),
        basis: basis.to_owned(),
        check_in: check_in.map(str::to_owned),
        requester: requester.map(|id| id.to_hex()),
    }
}

fn own_proof() -> CheckInDecision {
    decision("owner", None, "own_proof", None, None)
}

#[test]
fn the_owner_turns_compliance_search_on_and_off_on_their_own_proof() {
    let org = Org::new();

    let on = org
        .set(org.owner, true, "the quarterly audit", None)
        .expect("the Owner turns it on");
    assert!(on.enabled, "the setting reads on");
    assert_eq!(
        on.check_in,
        Some(own_proof()),
        "the Owner's change goes on their own proof"
    );
    let again = org
        .set(org.owner, true, "the quarterly audit", None)
        .expect("a repeat answers");
    assert_eq!(
        again.check_in, None,
        "a call that changes nothing records nothing"
    );
    let off = org
        .set(org.owner, false, "the audit closed", None)
        .expect("the Owner turns it off");
    assert!(!off.enabled, "the setting reads off");
    assert_eq!(off.check_in, Some(own_proof()));

    let kept: Vec<_> = org
        .log()
        .into_iter()
        .map(|entry| (entry.kind, entry.check_in))
        .collect();
    assert_eq!(
        kept,
        vec![
            (MailComplianceEventKind::Enabled, Some(own_proof())),
            (MailComplianceEventKind::Disabled, Some(own_proof())),
        ],
        "the log records each change's decision"
    );
}

#[test]
fn an_admins_change_waits_on_the_owner_and_runs_once_approved() {
    let org = Org::new();
    let purpose = "a records request";

    let first = pending_id(org.set(org.admin, true, purpose, None));
    assert!(!org.enabled(), "the waiting change turned nothing");
    assert!(org.log().is_empty(), "and logged nothing");
    assert_eq!(
        pending_id(org.set(org.admin, true, purpose, None)),
        first,
        "a repeat names the same check-in"
    );
    assert!(
        org.set(org.admin, true, purpose, Some(&first)).is_err(),
        "an unanswered check-in runs nothing"
    );

    org.owner_approves(&first);
    assert!(
        org.set(org.admin, true, "another purpose", Some(&first))
            .is_err(),
        "the approval covers the stated purpose only"
    );
    assert!(!org.spent(&first), "a refused call leaves it unspent");
    assert!(!org.enabled(), "and turned nothing");

    let on = org
        .set(org.admin, true, purpose, Some(&first))
        .expect("the approved change runs");
    let approved = decision("admin", Some("manual"), "approved", Some(&first), None);
    assert!(on.enabled, "the setting reads on");
    assert_eq!(
        on.check_in,
        Some(approved.clone()),
        "the answer names the check-in the change spent"
    );
    assert!(org.spent(&first), "the change spent it");
    let log = org.log();
    assert_eq!(log.len(), 1, "one change is logged");
    assert_eq!(
        (
            log[0].kind,
            log[0].by_ref.clone(),
            log[0].purpose.as_str(),
            log[0].check_in.clone()
        ),
        (
            MailComplianceEventKind::Enabled,
            Some(org.admin.to_hex()),
            purpose,
            Some(approved)
        ),
        "the log keeps who, why and the check-in"
    );
}

#[test]
fn the_owner_applies_a_deputys_approved_change() {
    let org = Org::new();
    org.set(org.owner, true, "the quarterly audit", None)
        .expect("the Owner turns it on");
    let purpose = "the audit closed";

    let ask = pending_id(org.set(org.deputy, false, purpose, None));
    org.owner_approves(&ask);
    assert!(
        org.set(org.owner, false, "another purpose", Some(&ask))
            .is_err(),
        "the ask covers the stated purpose only"
    );
    assert!(!org.spent(&ask), "a refused call leaves it unspent");
    assert!(org.enabled(), "and turned nothing");

    let off = org
        .set(org.owner, false, purpose, Some(&ask))
        .expect("the Owner applies the Deputy's approved ask");
    assert!(!off.enabled, "the setting reads off");
    assert_eq!(
        off.check_in,
        Some(decision(
            "owner",
            None,
            "own_proof",
            Some(&ask),
            Some(org.deputy)
        )),
        "the Owner's decision names the ask and its asker"
    );
    assert!(org.spent(&ask), "the Owner's change spent it");
    assert_eq!(
        org.set(org.deputy, false, purpose, Some(&ask))
            .expect("nothing is left to change")
            .check_in,
        None,
        "the Deputy's call finds the setting already off"
    );
}
