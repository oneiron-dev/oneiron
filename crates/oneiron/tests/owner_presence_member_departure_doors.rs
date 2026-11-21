//! The removal and leave doors read before they ask (row OWNER-CONFIRM-SHEET, PR 4b-3d1).
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, ActorBindingStatus, AuthorityKey, AuthorityOp, HostSlipIssuer,
    MachineRole, OwnerKeyEnrollment,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::{DevicePinRefusal, OwnerPresenceRefusal, RecordError, SecretError};
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember, MemberAskChange};
use oneiron::recovery::PassphraseCost;
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::member_departure_between::{
    leave_shared_vault_between, remove_shared_member_between, remove_shared_member_for_ask_between,
};
use oneiron::test_doors::passkey_vouch_limits::{SignedRow, append_signed_rows};
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::world_keys::DevicePin;
use oneiron::{EntityId, Error, TimeRange, Vault, VaultConfig};
use oneiron_authority::authority::ACTOR_CLASS_HUMAN;
use oneiron_keystore::{
    ManualPresenceClock, MemoryKeystore, PresenceError, PresenceGate, PresenceWindow,
    ScriptedPresence,
};

const SHARED: u64 = 48;
/// The device PIN: a passphrase, since nothing counts wrong tries but this process.
const PIN: &[u8] = b"quiet harbour lantern";

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

/// A scripted device prompt on `vault`: `answers` in order, a prompt past the script declined.
fn scripted_gate(
    vault: &Vault,
    answers: impl IntoIterator<Item = Result<(), PresenceError>>,
) -> Arc<ScriptedPresence> {
    let presence = Arc::new(ScriptedPresence::new(answers));
    let window = PresenceWindow::new(ManualPresenceClock::new(1_000_000, 1_000_000));
    let gate = PresenceGate::new(presence.clone(), window);
    vault.install_presence_gate(Arc::new(gate));
    presence
}

/// A rooted, self-hosted shared vault whose embedded owner the host root binds, with one
/// plain member. The host seed rests in this install's keystore, so a door given no issuer
/// loads the vault's own.
struct Departure {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    member: EntityId,
    keystore: Arc<MemoryKeystore>,
    _dir: tempfile::TempDir,
}

impl Departure {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        let keystore = Arc::new(MemoryKeystore::default());
        vault.install_device_keystore(keystore.clone());
        let issuer = vault.bootstrap_host_slip_issuer().expect("the host seed");
        vault.ensure_host_root_slip(&issuer).expect("the host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machines");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
        let member = person(&vault);
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
                        member_ref: member,
                        role: Some(Role::Member),
                    },
                ],
                1,
            )
            .expect("a shared vault");
        let invitation = vault
            .shared_invitations(&proof(&vault, member), SHARED)
            .expect("invitations")
            .into_iter()
            .find(|open| open.role == Role::Member)
            .expect("the founding invitation");
        vault
            .accept_shared_invitation(&proof(&vault, member), SHARED, &invitation.id)
            .expect("the member accepts");
        Self {
            vault,
            issuer,
            owner,
            member,
            keystore,
            _dir: dir,
        }
    }

    fn owner_proof(&self) -> AuthenticatedOwner {
        proof(&self.vault, self.owner)
    }

    fn member_proof(&self) -> AuthenticatedOwner {
        proof(&self.vault, self.member)
    }

    /// `person` joins the shared vault at `role`: the Owner invites them and they accept.
    fn join(&self, person: EntityId, role: Role) {
        self.vault
            .add_shared_member(&self.owner_proof(), SHARED, person, Some(role))
            .expect("the Owner invites the person");
        let invitation = self
            .vault
            .shared_invitations(&proof(&self.vault, person), SHARED)
            .expect("invitations")
            .into_iter()
            .find(|open| open.role == role)
            .expect("the invitation");
        self.vault
            .accept_shared_invitation(&proof(&self.vault, person), SHARED, &invitation.id)
            .expect("the invitee accepts");
    }

    /// The role `who` holds in the shared vault now, from its grant rows.
    fn role_of(&self, who: EntityId) -> Option<Role> {
        self.vault
            .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
            .expect("grants")
            .into_iter()
            .find_map(|id| {
                let body = self.vault.get(&id).expect("grant row")?;
                let grant = oneiron::federation::decode_federation_grant_body(&body).ok()?;
                (grant.member_ref == who && grant.role != Role::Delegate).then_some(grant.role)
            })
    }

    fn history(&self) -> Vec<Vec<u8>> {
        self.vault
            .export_signed_authority_history()
            .expect("the signed history")
    }

    /// The person a live `human` binding on `key` names, if any.
    fn bound_to(&self, key: &AuthorityKey) -> Option<EntityId> {
        self.vault
            .authority_fold()
            .expect("the fold")
            .actor_bindings
            .get(key)
            .filter(|binding| {
                binding.status == ActorBindingStatus::Active
                    && binding.actor_class == ACTOR_CLASS_HUMAN
            })
            .map(|binding| binding.actor_ref)
    }

    /// `person` enrols an owner signing key made from `seed`, with this host's root as
    /// predecessor; answers the signing key.
    fn enrol_device_key(&self, person: EntityId, seed: u8) -> SigningKey {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let public_key = key.verifying_key().to_bytes();
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

    /// The Owner enrols one more owner key, made from `seed`, and `signer`'s owner key signs
    /// a `human` binding of `person` on it: `person` then holds owner authority and no key.
    fn bound_key(&self, person: EntityId, signer: &SigningKey, seed: u8) -> AuthorityKey {
        let key = self.enrol_device_key(self.owner, seed);
        let bound = AuthorityKey::Ed25519(key.verifying_key().to_bytes());
        self.bind_on(&bound, person, signer);
        bound
    }

    /// `signer`'s owner key signs a `human` binding of `person` on `key`, which holds none
    /// yet; the fold counts it.
    fn bind_on(&self, key: &AuthorityKey, person: EntityId, signer: &SigningKey) {
        assert_eq!(self.bound_to(key), None, "{key:?} holds no binding yet");
        let counted = append_signed_rows(
            &self.vault,
            vec![SignedRow {
                op: AuthorityOp::BindActor {
                    authority_key: key.clone(),
                    actor_ref: person,
                    actor_class: ACTOR_CLASS_HUMAN.into(),
                    epoch: 1,
                },
                signer: AuthorityKey::Ed25519(signer.verifying_key().to_bytes()),
                cosigners: Vec::new(),
            }],
            |_, transcript| signer.sign(transcript).to_bytes().to_vec(),
        )
        .expect("the door stores the binding");
        assert_eq!(counted, vec![true], "the fold counts the binding");
        assert_eq!(self.bound_to(key), Some(person));
    }
}

/// An Owner's removal of a plain member who holds nothing asks nothing and lands.
#[test]
fn removing_a_member_who_holds_no_owner_authority_asks_nothing() {
    let dep = Departure::new();
    let presence = scripted_gate(&dep.vault, []);
    dep.vault
        .remove_shared_member(&dep.owner_proof(), SHARED, dep.member, None)
        .expect("the Owner removes a plain Member");
    assert_eq!(presence.prompts(), 0, "an ordinary removal shows no prompt");
    assert_eq!(dep.role_of(dep.member), None, "the member holds no role");
}

/// A plain member who holds nothing leaves without a prompt.
#[test]
fn a_member_who_holds_no_owner_authority_leaves_unasked() {
    let dep = Departure::new();
    let presence = scripted_gate(&dep.vault, []);
    dep.vault
        .leave_shared_vault(&dep.member_proof(), SHARED, None)
        .expect("the member leaves");
    assert_eq!(presence.prompts(), 0, "an ordinary leave shows no prompt");
    assert_eq!(dep.role_of(dep.member), None, "the member holds no role");
}

/// A refusal answered with no prompt: an error that is not the presence check's.
fn assert_refused_unasked<T: std::fmt::Debug>(answer: &oneiron::Result<T>, what: &str) {
    assert!(
        matches!(answer, Err(error) if !matches!(
            error,
            Error::Record(RecordError::OwnerPresenceRequired { .. })
        )),
        "{what} is refused by the door's own check: {answer:?}"
    );
}

/// A removal the door refuses on its read raises no prompt and stores nothing. Each target
/// holds owner authority, so each removal would ask as important if it passed the read.
#[test]
fn a_removal_refused_on_its_read_raises_no_prompt() {
    let dep = Departure::new();
    let holding = person(&dep.vault);
    dep.join(holding, Role::Member);
    let stranger = person(&dep.vault);
    let signer = dep.enrol_device_key(dep.owner, 7);
    let held = dep.bound_key(holding, &signer, 15);
    let strangers = dep.bound_key(stranger, &signer, 23);
    let history = dep.history();
    let presence = scripted_gate(&dep.vault, []);
    let vault = &dep.vault;
    assert_refused_unasked(
        &vault.remove_shared_member(&dep.owner_proof(), SHARED, stranger, None),
        "the removal of a person no grant names",
    );
    assert_refused_unasked(
        &vault.remove_shared_member(&dep.owner_proof(), SHARED, dep.owner, None),
        "the removal of an Owner",
    );
    assert_refused_unasked(
        &vault.remove_shared_member(&dep.member_proof(), SHARED, holding, None),
        "a removal by a Member, who holds no remove power",
    );
    assert_eq!(presence.prompts(), 0, "no refusal showed a prompt");
    assert_eq!(dep.history(), history, "the log holds the entries it held");
    assert_eq!(dep.role_of(holding), Some(Role::Member));
    assert_eq!(dep.role_of(dep.owner), Some(Role::Owner));
    assert_eq!(
        dep.bound_to(&held),
        Some(holding),
        "the member's binding stays"
    );
    assert_eq!(
        dep.bound_to(&strangers),
        Some(stranger),
        "the binding stays"
    );
    // The same member's removal by the Owner passes the read, and it asks.
    let asked = vault.remove_shared_member(&dep.owner_proof(), SHARED, holding, None);
    assert!(
        matches!(
            asked,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined
            }))
        ),
        "a removal that passes the read asks: {asked:?}"
    );
    assert_eq!(presence.prompts(), 1, "that removal showed one prompt");
}

/// A leave the door refuses on its read raises no prompt and stores nothing. Each person
/// holds owner authority, so each leave would ask as important if it passed the read.
#[test]
fn a_leave_refused_on_its_read_raises_no_prompt() {
    let dep = Departure::new();
    let stranger = person(&dep.vault);
    let signer = dep.enrol_device_key(dep.owner, 7);
    let strangers = dep.bound_key(stranger, &signer, 15);
    let history = dep.history();
    let presence = scripted_gate(&dep.vault, []);
    assert_refused_unasked(
        &dep.vault
            .leave_shared_vault(&dep.owner_proof(), SHARED, None),
        "an Owner's leave",
    );
    assert_refused_unasked(
        &dep.vault
            .leave_shared_vault(&proof(&dep.vault, stranger), SHARED, None),
        "the leave of a person who is no member",
    );
    assert_eq!(presence.prompts(), 0, "no refusal showed a prompt");
    assert_eq!(dep.history(), history, "the log holds the entries it held");
    assert_eq!(dep.role_of(dep.owner), Some(Role::Owner));
    assert_eq!(
        dep.bound_to(&strangers),
        Some(stranger),
        "the binding stays"
    );
}

/// An Owner applies a Steward's ask to remove a member after the Steward lost the role: the
/// door refuses on its read, before it asks. The member holds owner authority, so the
/// removal would ask as important if it passed the read.
#[test]
fn an_applied_ask_whose_steward_lost_the_role_raises_no_prompt() {
    let dep = Departure::new();
    let steward = person(&dep.vault);
    dep.join(steward, Role::Steward);
    let signer = dep.enrol_device_key(dep.owner, 7);
    let bound = dep.bound_key(dep.member, &signer, 15);
    let ask = dep
        .vault
        .ask_shared_member_change(
            &proof(&dep.vault, steward),
            SHARED,
            MemberAskChange::Remove {
                member: dep.member.to_hex(),
            },
        )
        .expect("the Steward's ask");
    dep.vault
        .change_shared_member_role(&dep.owner_proof(), SHARED, steward, Role::Member, None)
        .expect("the Owner makes the Steward a Member");
    let history = dep.history();
    let presence = scripted_gate(&dep.vault, []);
    assert_refused_unasked(
        &dep.vault
            .apply_shared_member_ask(&dep.owner_proof(), &ask.id, None),
        "an ask whose Steward lost the role",
    );
    assert_eq!(presence.prompts(), 0, "the refusal showed no prompt");
    assert_eq!(dep.history(), history, "the log holds the entries it held");
    assert_eq!(dep.role_of(dep.member), Some(Role::Member));
    assert_eq!(dep.bound_to(&bound), Some(dep.member), "the binding stays");
}

/// An Owner's removal for a Steward's ask that an applier declined after the apply read it
/// open: the door refuses on its read, before it asks. The member holds owner authority, so
/// the removal asks as important while the ask is open.
#[test]
fn a_removal_for_an_ask_declined_before_the_door_reads_raises_no_prompt() {
    let dep = Departure::new();
    let steward = person(&dep.vault);
    dep.join(steward, Role::Steward);
    let signer = dep.enrol_device_key(dep.owner, 7);
    let bound = dep.bound_key(dep.member, &signer, 15);
    let ask = dep
        .vault
        .ask_shared_member_change(
            &proof(&dep.vault, steward),
            SHARED,
            MemberAskChange::Remove {
                member: dep.member.to_hex(),
            },
        )
        .expect("the Steward's ask");
    let presence = scripted_gate(&dep.vault, []);
    // While the ask is open the removal passes the read, and it asks.
    let asked = remove_shared_member_for_ask_between(
        &dep.vault,
        &dep.owner_proof(),
        SHARED,
        dep.member,
        None,
        &ask.id,
        || {},
    );
    assert!(
        matches!(
            asked,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined
            }))
        ),
        "a removal for an open ask passes the read and asks: {asked:?}"
    );
    assert_eq!(presence.prompts(), 1, "that removal showed one prompt");
    dep.vault
        .decline_shared_member_ask(&dep.owner_proof(), &ask.id)
        .expect("an applier declines the ask");
    let history = dep.history();
    assert_refused_unasked(
        &remove_shared_member_for_ask_between(
            &dep.vault,
            &dep.owner_proof(),
            SHARED,
            dep.member,
            None,
            &ask.id,
            || {},
        ),
        "a removal for a declined ask",
    );
    assert_eq!(presence.prompts(), 1, "the refusal showed no prompt");
    assert_eq!(dep.history(), history, "the log holds the entries it held");
    assert_eq!(dep.role_of(dep.member), Some(Role::Member));
    assert_eq!(dep.bound_to(&bound), Some(dep.member), "the binding stays");
}

/// A Deputy's removal for a Steward's ask waits for an Owner's check-in while the ask is
/// open. Where an applier declines the ask after the door read it and before its write, the
/// write refuses the closed ask before the check-in judge, so no wait is filed.
#[test]
fn a_removal_for_an_ask_declined_after_the_door_read_it_files_no_check_in() {
    let dep = Departure::new();
    let steward = person(&dep.vault);
    dep.join(steward, Role::Steward);
    let deputy = person(&dep.vault);
    dep.join(deputy, Role::Deputy);
    let other = person(&dep.vault);
    dep.join(other, Role::Member);
    let ask_to_remove = |member: EntityId| {
        dep.vault
            .ask_shared_member_change(
                &proof(&dep.vault, steward),
                SHARED,
                MemberAskChange::Remove {
                    member: member.to_hex(),
                },
            )
            .expect("the Steward's ask")
    };
    let open = ask_to_remove(other);
    let declined = ask_to_remove(dep.member);
    let presence = scripted_gate(&dep.vault, []);
    let (owner_proof, deputy_proof) = (dep.owner_proof(), proof(&dep.vault, deputy));
    // A rooted vault admits only a bound writer, and the host key holds one live binding.
    bind_host_actor(&dep.vault, &dep.issuer, deputy, "human")
        .expect("the host key bound to the Deputy for its acts");
    let waits = remove_shared_member_for_ask_between(
        &dep.vault,
        &deputy_proof,
        SHARED,
        other,
        None,
        &open.id,
        || {},
    );
    let refused = remove_shared_member_for_ask_between(
        &dep.vault,
        &deputy_proof,
        SHARED,
        dep.member,
        None,
        &declined.id,
        || {
            dep.vault
                .decline_shared_member_ask(&owner_proof, &declined.id)
                .expect("the Owner declines the ask after the door read it");
        },
    );
    bind_host_owner(&dep.vault, &dep.issuer, dep.owner).expect("the owner's binding again");
    assert!(
        matches!(waits, Err(Error::CheckInPending(_))),
        "a Deputy's removal for an open ask waits for an Owner: {waits:?}"
    );
    assert!(
        matches!(&refused, Err(error) if !matches!(error, Error::CheckInPending(_))),
        "the write refuses the declined ask before the check-in judge: {refused:?}"
    );
    assert_eq!(presence.prompts(), 0, "neither removal showed a prompt");
    assert_eq!(
        dep.role_of(other),
        Some(Role::Member),
        "a waiting removal changes nothing"
    );
    assert_eq!(
        dep.role_of(dep.member),
        Some(Role::Member),
        "the member still holds their role"
    );
}

/// Removing a member who holds a binding asks, and a declined confirm stores nothing.
#[test]
fn removing_a_member_who_holds_owner_authority_asks_and_a_declined_confirm_stores_nothing() {
    let dep = Departure::new();
    let first = dep.enrol_device_key(dep.owner, 7);
    let second = dep.enrol_device_key(dep.owner, 15);
    let bound = AuthorityKey::Ed25519(second.verifying_key().to_bytes());
    dep.bind_on(&bound, dep.member, &first);
    let history = dep.history();
    let presence = scripted_gate(&dep.vault, [Err(PresenceError::Declined)]);
    let refused = dep
        .vault
        .remove_shared_member(&dep.owner_proof(), SHARED, dep.member, None);
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined
            }))
        ),
        "a declined confirm refuses the removal: {refused:?}"
    );
    assert_eq!(presence.prompts(), 1, "the removal showed one prompt");
    assert_eq!(
        dep.history(),
        history,
        "the log holds the entries it held before"
    );
    assert_eq!(
        dep.role_of(dep.member),
        Some(Role::Member),
        "the member still holds their role"
    );
    assert_eq!(dep.bound_to(&bound), Some(dep.member), "the binding stays");
    let presence = scripted_gate(&dep.vault, [Ok(())]);
    dep.vault
        .remove_shared_member(&dep.owner_proof(), SHARED, dep.member, None)
        .expect("the confirmed removal lands");
    assert_eq!(
        presence.prompts(),
        1,
        "the confirmed removal showed one prompt"
    );
    assert_eq!(dep.role_of(dep.member), None, "the member holds no role");
    assert_eq!(
        dep.bound_to(&bound),
        None,
        "the member's owner authority is ended"
    );
}

/// A leave that ends a binding the member holds asks.
#[test]
fn a_leave_that_ends_owner_authority_asks() {
    let dep = Departure::new();
    let first = dep.enrol_device_key(dep.owner, 7);
    let second = dep.enrol_device_key(dep.owner, 15);
    let bound = AuthorityKey::Ed25519(second.verifying_key().to_bytes());
    dep.bind_on(&bound, dep.member, &first);
    let history = dep.history();
    let presence = scripted_gate(&dep.vault, [Err(PresenceError::Declined)]);
    let refused = dep
        .vault
        .leave_shared_vault(&dep.member_proof(), SHARED, None);
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined
            }))
        ),
        "a declined confirm refuses the leave: {refused:?}"
    );
    assert_eq!(presence.prompts(), 1, "the leave showed one prompt");
    assert_eq!(
        dep.history(),
        history,
        "the log holds the entries it held before"
    );
    assert_eq!(
        dep.role_of(dep.member),
        Some(Role::Member),
        "the member still holds their role"
    );
    let presence = scripted_gate(&dep.vault, [Ok(())]);
    dep.vault
        .leave_shared_vault(&dep.member_proof(), SHARED, None)
        .expect("the confirmed leave lands");
    assert_eq!(
        presence.prompts(),
        1,
        "the confirmed leave showed one prompt"
    );
    assert_eq!(dep.role_of(dep.member), None, "the member holds no role");
    assert_eq!(
        dep.bound_to(&bound),
        None,
        "the member's owner authority is ended"
    );
}

/// A member who gains a binding after the door asked is a conflict that writes nothing.
#[test]
fn a_member_who_gains_owner_authority_after_the_door_asked_is_a_conflict() {
    let dep = Departure::new();
    let first = dep.enrol_device_key(dep.owner, 7);
    let second = dep.enrol_device_key(dep.owner, 15);
    let bound = AuthorityKey::Ed25519(second.verifying_key().to_bytes());
    let presence = scripted_gate(&dep.vault, [Err(PresenceError::Declined)]);
    let before = dep.history();
    let conflict = remove_shared_member_between(
        &dep.vault,
        &dep.owner_proof(),
        SHARED,
        dep.member,
        None,
        || {
            dep.bind_on(&bound, dep.member, &first);
        },
    );
    assert!(
        matches!(conflict, Err(Error::ConcurrentWrite(_))),
        "the gained binding is a conflict: {conflict:?}"
    );
    assert_eq!(presence.prompts(), 0, "the conflict shows no prompt");
    assert_eq!(
        dep.role_of(dep.member),
        Some(Role::Member),
        "the member still holds their role"
    );
    assert_eq!(
        dep.bound_to(&bound),
        Some(dep.member),
        "between's binding stands"
    );
    assert_eq!(dep.history().len(), before.len() + 1, "only between wrote");
    let dep = Departure::new();
    let first = dep.enrol_device_key(dep.owner, 7);
    let second = dep.enrol_device_key(dep.owner, 15);
    let bound = AuthorityKey::Ed25519(second.verifying_key().to_bytes());
    let presence = scripted_gate(&dep.vault, [Err(PresenceError::Declined)]);
    let before = dep.history();
    let conflict =
        leave_shared_vault_between(&dep.vault, &dep.member_proof(), SHARED, None, || {
            dep.bind_on(&bound, dep.member, &first);
        });
    assert!(
        matches!(conflict, Err(Error::ConcurrentWrite(_))),
        "the leave's gained binding is a conflict: {conflict:?}"
    );
    assert_eq!(presence.prompts(), 0, "the leave conflict shows no prompt");
    assert_eq!(
        dep.role_of(dep.member),
        Some(Role::Member),
        "the member still holds their role"
    );
    assert_eq!(
        dep.bound_to(&bound),
        Some(dep.member),
        "between's binding stands"
    );
    assert_eq!(dep.history().len(), before.len() + 1, "only between wrote");
}

/// An ordinary removal lands unasked on a PIN device whose window ended, while an important one answers PIN required.
#[test]
fn a_removal_on_a_device_whose_pin_window_ended() {
    let dep = Departure::new();
    let holding = person(&dep.vault);
    dep.join(holding, Role::Member);
    // The enrolments ask as important acts, so they come before the PIN is set.
    let signer = dep.enrol_device_key(dep.owner, 7);
    dep.bound_key(holding, &signer, 15);
    let pin = DevicePin::with_clock_and_cost(
        dep.keystore.clone(),
        ManualPresenceClock::new(1_000_000, 1_000_000),
        PassphraseCost::FLOOR,
    )
    .expect("device PIN over the vault's keystore");
    dep.vault
        .install_device_pin(pin.clone())
        .expect("install device PIN");
    dep.vault
        .set_device_pin_as(
            &ActAuthority::Owner(dep.owner_proof(), ActSurface::ThisInstall),
            PIN,
            false,
        )
        .expect("set the device PIN as the owner");
    pin.end_window();
    dep.vault
        .remove_shared_member(&dep.owner_proof(), SHARED, dep.member, None)
        .expect("an ordinary removal lands unasked on a PIN device whose window ended");
    assert_eq!(dep.role_of(dep.member), None, "the member holds no role");
    let history = dep.history();
    let refused = dep
        .vault
        .remove_shared_member(&dep.owner_proof(), SHARED, holding, None);
    assert!(
        matches!(
            refused,
            Err(Error::Secret(SecretError::DevicePin(
                DevicePinRefusal::Required
            )))
        ),
        "an important removal answers PIN required: {refused:?}"
    );
    assert_eq!(
        dep.history(),
        history,
        "the log holds the entries it held before"
    );
    assert_eq!(
        dep.role_of(holding),
        Some(Role::Member),
        "the member still holds their role"
    );
}
