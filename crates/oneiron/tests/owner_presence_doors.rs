//! Every door that signs an owner proof asks for the person first (row
//! OWNER-CONFIRM-SHEET, PR 4b-1): a declined confirm refuses the door and
//! writes nothing, one confirm serves the acts of its window, an agent is
//! refused with no prompt, ordinary acts ask nothing, and a redeem on a
//! standing ground asks nothing.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, CheckpointPolicyView, HostSlipIssuer, LastDeviceKeyConfirmation,
    MachineAnswerLanding, MachineEnrolmentRequest, MachineOwnership, MachineRole, OwnerActKind,
    OwnerKeyEnrollment, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{
    ConsolidationHomePickReceipt, ConsolidationHomePickRequest, consolidation_home_pick_as,
};
use oneiron::error::{DevicePinRefusal, OwnerPresenceRefusal, RecordError, SecretError};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::MemoryResult;
use oneiron::origin::residence::OriginResidence;
use oneiron::recovery::PassphraseCost;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_support::{bind_host_owner, provision_engine_machines, test_host_issuer};
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::world_keys::DevicePin;
use oneiron::{EntityId, Error, HostingPrivacyPosture, Vault, VaultConfig};
use oneiron_keystore::{
    ManualPresenceClock, MemoryKeystore, PresenceError, PresenceGate, PresenceWindow,
    ScriptedPresence,
};

use oneiron_store::ports::manual_clock::ManualClock;

/// The reason lines the doors show, as the engine's constants hold them:
/// the test asserts them literally, since those constants are crate-private.
const CHECKPOINT_POLICY_REASON: &str = "change which devices vouch for this vault";
const SET_MACHINE_ROLE_REASON: &str = "change what a device may do in this vault";
const REMOVE_OWNER_KEY_REASON: &str = "remove a device that can approve changes";

/// A rooted vault with its serving install profiled and its owner authenticated.
/// The vault drops before its directory.
struct ServedVault {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl ServedVault {
    fn hosted() -> Self {
        Self::open(HostingPrivacyPosture::Hosted)
    }

    fn self_host() -> Self {
        Self::open(HostingPrivacyPosture::SelfHostLocal)
    }

    fn open(posture: HostingPrivacyPosture) -> Self {
        let (vault, dir) = open_vault(posture);
        vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
        let issuer = provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let owner = if posture == HostingPrivacyPosture::Hosted {
            embedded_owner(&vault)
                .expect("authenticated embedded owner")
                .1
        } else {
            let person = vault.ensure_embedded_owner_actor().expect("the owner");
            bind_host_owner(&vault, &issuer, person).expect("the owner's host binding");
            vault
                .authenticate_owner(
                    person,
                    &person.to_hex(),
                    true,
                    GateDecisionId::from_bytes([2; 16]),
                )
                .expect("the owner's proof")
        };
        Self {
            vault,
            issuer,
            owner,
            _dir: dir,
        }
    }

    fn owner_authority(&self) -> ActAuthority {
        ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall)
    }

    /// The owner enrols this install's owner signing key: the roster then
    /// holds a key that proves for him, and this handle holds it.
    fn enrol_owner_key(&self) {
        self.vault
            .enrol_device_owner_signing_key(&self.owner_authority(), &self.issuer)
            .expect("the owner enrols this install's owner signing key");
    }

    /// This install's MACHINE row.
    fn install(&self) -> EntityId {
        self.vault
            .local_machine()
            .expect("read this install")
            .expect("this install is profiled")
            .id
    }

    /// Whether the fold trusts this install as the owner's machine.
    fn install_is_mine(&self) -> bool {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .trusted_machine(self.install())
            .is_some()
    }

    /// How many authority log rows the fold holds valid.
    fn stored_rows(&self) -> usize {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .valid_entries
            .len()
    }

    /// The owner clears his checkpoint root choice through this install.
    fn clear_checkpoint_policy(&self) -> oneiron::Result<CheckpointPolicyView> {
        self.vault
            .set_checkpoint_policy_as(&self.owner_authority(), None, None)
    }

    /// The vault's checkpoint root policy as the owner's surface shows it.
    fn checkpoint_policy(&self) -> CheckpointPolicyView {
        self.vault
            .checkpoint_policy_view()
            .expect("checkpoint policy view")
    }

    /// The owner answers through this install that it is his.
    fn answer_this_install_is_mine(&self) -> oneiron::Result<MachineAnswerLanding> {
        self.vault.set_machine_role(
            &self.owner,
            ActSurface::ThisInstall,
            self.install(),
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
    }

    /// How many answers still ask the owner.
    fn asking(&self) -> usize {
        self.vault
            .held_machine_answers(&self.owner)
            .expect("the held answer list")
            .answers
            .len()
    }

    /// The owner's home pick through this install.
    fn pick_home(&self, node: u64) -> MemoryResult<ConsolidationHomePickReceipt> {
        consolidation_home_pick_as(
            &self.vault,
            &self.owner,
            ActSurface::ThisInstall,
            ConsolidationHomePickRequest {
                node_id: Some(node.to_string()),
                seen: None,
            },
        )
    }

    /// The owner sets the vault's training setting through this install.
    /// Answers whether the setting is on after it.
    fn set_learning(&self, on: bool, allow_opt_out: bool) -> oneiron::Result<bool> {
        self.vault
            .set_conversation_learning(
                &self.owner,
                ActSurface::ThisInstall,
                on,
                allow_opt_out,
                None,
            )
            .map(|view| view.on)
    }

    /// The authenticated person leaves their own messages out of training,
    /// or lets them back in, through this install. Answers whether they are
    /// left out after it.
    fn leave_my_messages_out(&self, leave_out: bool) -> oneiron::Result<bool> {
        self.vault
            .set_conversation_training(&self.owner, ActSurface::ThisInstall, leave_out, None)
            .map(|view| view.leave_out)
    }

    /// Another install's request to join this vault, made by a throwaway
    /// second install over its own keys.
    fn second_install_request(&self) -> MachineEnrolmentRequest {
        let vault_id = self
            .vault
            .authority_fold()
            .expect("authority fold")
            .vault_id
            .expect("the vault is rooted");
        let (install, _dir) = open_vault(HostingPrivacyPosture::SelfHostLocal);
        install.install_device_keystore(Arc::new(MemoryKeystore::default()));
        let key = install
            .machine_encryption_key(vault_id)
            .expect("the second install's encryption key");
        install
            .machine_enrolment_request(vault_id, key)
            .expect("the second install's enrolment request")
    }

    /// The owner enrols a second machine as his and a second owner key whose
    /// enrolment names it, from `second_signing_key`'s proof of possession.
    /// Answers the machine and the enrolled key.
    fn enrol_second_machine_and_key(
        &self,
        second_signing_key: &SigningKey,
    ) -> (EntityId, [u8; 32]) {
        let request = self.second_install_request();
        let landing = self
            .vault
            .enroll_machine(
                &self.owner,
                ActSurface::ThisInstall,
                &request,
                MachineRole::Owned(MachineOwnership::Yours),
                None,
            )
            .expect("the owner enrols the second machine");
        assert!(
            landing.held().is_none(),
            "the second machine stands with the owner's key"
        );
        let second_key = second_signing_key.verifying_key().to_bytes();
        let challenge = self
            .vault
            .owner_key_enrollment_challenge_as(
                &self.owner_authority(),
                request.machine,
                &second_key,
            )
            .expect("the second key's challenge");
        let receipt = self
            .vault
            .enrol_owner_signing_key_as_host(
                &self.owner_authority(),
                OwnerKeyEnrollment {
                    machine: request.machine,
                    public_key: second_key,
                    proof: second_signing_key.sign(&challenge).to_bytes().to_vec(),
                },
                &self.issuer,
            )
            .expect("the owner enrols the second key on the second machine");
        assert_eq!(
            receipt.public_key, second_key,
            "the receipt names the second key"
        );
        (request.machine, second_key)
    }
}

fn open_vault(posture: HostingPrivacyPosture) -> (Vault, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("vault directory");
    let mut config = VaultConfig::device();
    config.privacy.posture = posture;
    config.store_clock = ManualClock::new(1_790_000_000).bundle();
    let vault = Vault::open(dir.path(), config).expect("vault");
    (vault, dir)
}

/// A scripted device prompt on `vault`: `answers` in order, a prompt past
/// the script declined. Answers the device, which counts prompts and reasons.
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

/// An agent's act on `vault`: a named agent whose live Grant from `owner`
/// names the free-time policy act, one of the acts an agent's Grant may name.
fn agent_act(vault: &Vault, owner: &AuthenticatedOwner) -> ActAuthority {
    let agent = vault
        .ensure_agent_principal("owner-presence-doors-agent")
        .expect("a named agent");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        "free_time_policy_set".to_owned(),
    ]));
    let minted = mint_agent_grant_as(
        vault,
        owner,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("the owner grants the agent the act");
    assert!(minted.grant.confers, "guard: the agent's Grant is live");
    ActAuthority::Agent(
        vault
            .granted_act(agent, minted.grant.grant_ref, OwnerActKind::FreeTimePolicy)
            .expect("the agent's Grant names the act"),
    )
}

/// A declined confirm refuses the checkpoint policy choice and writes nothing.
#[test]
fn a_declined_confirm_refuses_the_checkpoint_policy_choice_and_writes_nothing() {
    let served = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let (rows, history, policy) = (
        served.stored_rows(),
        served
            .vault
            .export_signed_authority_history()
            .expect("the signed history"),
        served.checkpoint_policy(),
    );
    let refused = served.clear_checkpoint_policy();
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined
            }))
        ),
        "a declined confirm refuses the choice: {refused:?}"
    );
    assert_eq!(presence.prompts(), 1, "the door showed one prompt");
    assert_eq!(served.stored_rows(), rows, "the refusal stores no row");
    assert_eq!(
        served
            .vault
            .export_signed_authority_history()
            .expect("the signed history"),
        history,
        "the log holds the entries it held before"
    );
    assert_eq!(
        served.checkpoint_policy(),
        policy,
        "the policy stands as it did"
    );
}

/// A confirmed choice lands, and its window serves the next important act.
#[test]
fn a_confirmed_choice_lands_and_its_window_serves_the_next_important_act() {
    let served = ServedVault::hosted();
    served.enrol_owner_key();
    let presence = scripted_gate(&served.vault, [Ok(())]);
    let view = served
        .clear_checkpoint_policy()
        .expect("the confirmed clear lands");
    assert_eq!(view.heads.len(), 1, "the clear is the one live choice");
    assert_eq!(presence.prompts(), 1, "the first act itself prompted");
    let landing = served
        .answer_this_install_is_mine()
        .expect("the next important act stands in the confirm's window");
    assert!(landing.held().is_none(), "the proven answer stands");
    assert!(served.install_is_mine(), "the answer makes it his machine");
    assert_eq!(presence.prompts(), 1, "one prompt for two important acts");
}

/// An agent's checkpoint policy act is refused with no prompt.
#[test]
fn an_agent_is_refused_with_no_prompt() {
    let served = ServedVault::hosted();
    let agent = agent_act(&served.vault, &served.owner);
    let presence = scripted_gate(&served.vault, [Ok(())]);
    let refused = served.vault.set_checkpoint_policy_as(&agent, None, None);
    assert!(
        matches!(
            &refused,
            Err(Error::Record(RecordError::AuthorityRefused(reason)))
                if *reason == "the checkpoint root policy is the owner's; no Grant action names it"
        ),
        "an agent's act is refused as the owner's only: {refused:?}"
    );
    assert_eq!(presence.prompts(), 0, "the refusal shows no prompt");
}

/// A home pick asks nothing and lands.
#[test]
fn a_home_pick_asks_nothing() {
    let served = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, [Ok(())]);
    let receipt = served.pick_home(7).expect("the pick lands");
    assert_eq!(
        receipt.pick.as_deref(),
        Some("7"),
        "the pick names the node"
    );
    assert_eq!(presence.prompts(), 0, "an ordinary act shows no prompt");
}

/// Opting out of training asks nothing, and opting back in asks.
#[test]
fn opting_out_of_training_asks_nothing_and_opting_back_in_asks() {
    let served = ServedVault::hosted();
    served
        .set_learning(true, true)
        .expect("the setting that lets people opt out lands");
    let presence = scripted_gate(&served.vault, [Ok(())]);
    assert!(
        served
            .leave_my_messages_out(true)
            .expect("the opt-out lands"),
        "their messages are left out"
    );
    assert_eq!(presence.prompts(), 0, "opting out shows no prompt");
    assert!(
        !served
            .leave_my_messages_out(false)
            .expect("the opt back in lands"),
        "their messages are let back in"
    );
    assert_eq!(presence.prompts(), 1, "opting back in shows one prompt");
}

/// Turning learning off asks nothing, and turning it on asks.
#[test]
fn turning_learning_off_asks_nothing_and_turning_it_on_asks() {
    let served = ServedVault::hosted();
    served
        .set_learning(true, false)
        .expect("guard: the setting starts on");
    let presence = scripted_gate(&served.vault, [Ok(())]);
    assert!(
        !served
            .set_learning(false, false)
            .expect("turning it off lands"),
        "the setting is off"
    );
    assert_eq!(presence.prompts(), 0, "turning it off shows no prompt");
    assert!(
        served
            .set_learning(true, false)
            .expect("turning it on lands"),
        "the setting is on"
    );
    assert_eq!(presence.prompts(), 1, "turning it on shows one prompt");
}

/// A declined confirm refuses a machine answer and writes nothing.
#[test]
fn a_declined_confirm_refuses_a_machine_answer_and_writes_nothing() {
    let served = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let rows = served.stored_rows();
    let history = served
        .vault
        .export_signed_authority_history()
        .expect("the signed history");
    let refused = served.answer_this_install_is_mine();
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined
            }))
        ),
        "a declined confirm refuses the answer: {refused:?}"
    );
    assert_eq!(presence.prompts(), 1, "the door showed one prompt");
    assert_eq!(served.stored_rows(), rows, "the refusal stores no row");
    assert_eq!(
        served
            .vault
            .export_signed_authority_history()
            .expect("the signed history"),
        history,
        "the log holds the entries it held before"
    );
    assert_eq!(served.asking(), 0, "nothing asks: the door stored nothing");
    assert!(!served.install_is_mine(), "the machine stands as it did");
}

/// A declined confirm refuses an owner key removal and writes nothing.
#[test]
fn a_declined_confirm_refuses_an_owner_key_removal() {
    let served = ServedVault::hosted();
    served.enrol_owner_key();
    let second_signing_key = SigningKey::from_bytes(&[72; 32]);
    let (_, second_key) = served.enrol_second_machine_and_key(&second_signing_key);
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let rows = served.stored_rows();
    let history = served
        .vault
        .export_signed_authority_history()
        .expect("the signed history");
    let refused = served.vault.remove_owner_key(
        &served.owner,
        second_key,
        LastDeviceKeyConfirmation::NotGiven,
    );
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined
            }))
        ),
        "a declined confirm refuses the removal: {refused:?}"
    );
    assert_eq!(presence.prompts(), 1, "the door showed one prompt");
    assert_eq!(served.stored_rows(), rows, "the refusal stores no row");
    assert_eq!(
        served
            .vault
            .export_signed_authority_history()
            .expect("the signed history"),
        history,
        "the log holds the entries it held before"
    );
    assert!(
        served
            .vault
            .enrolled_owner_keys()
            .expect("enrolled owner keys")
            .iter()
            .any(|enrolled| enrolled.public_key == second_key && enrolled.live),
        "the second key stays live"
    );
}

/// Each prompt shows its door's reason line: three declines, so each door
/// prompts again and nothing lands.
#[test]
fn each_prompt_shows_its_doors_reason_line() {
    let served = ServedVault::hosted();
    served.enrol_owner_key();
    let second_signing_key = SigningKey::from_bytes(&[73; 32]);
    let (_, second_key) = served.enrol_second_machine_and_key(&second_signing_key);
    let presence = scripted_gate(
        &served.vault,
        [
            Err(PresenceError::Declined),
            Err(PresenceError::Declined),
            Err(PresenceError::Declined),
        ],
    );
    let rows = served.stored_rows();
    for refused in [
        served.clear_checkpoint_policy().map(drop),
        served.answer_this_install_is_mine().map(drop),
        served
            .vault
            .remove_owner_key(
                &served.owner,
                second_key,
                LastDeviceKeyConfirmation::NotGiven,
            )
            .map(drop),
    ] {
        assert!(
            matches!(
                refused,
                Err(Error::Record(RecordError::OwnerPresenceRequired {
                    here: OwnerPresenceRefusal::Declined
                }))
            ),
            "a declined confirm refuses the door: {refused:?}"
        );
    }
    assert_eq!(
        presence.reasons(),
        [
            CHECKPOINT_POLICY_REASON,
            SET_MACHINE_ROLE_REASON,
            REMOVE_OWNER_KEY_REASON,
        ],
        "each prompt shows its door's line"
    );
    assert_eq!(served.stored_rows(), rows, "the refusals store no row");
}

/// The owner door that accepts a pack's held defaults makes its own checks
/// on a read before its confirm: a yes to a proposal that is not the pack's
/// waiting one is refused with that reason, and the person is never asked.
/// The door's prompt and its line are held by
/// `tests/owner_presence_pack_defaults_accept.rs`.
#[test]
fn the_pack_defaults_accept_refuses_a_proposal_that_is_not_waiting_and_never_prompts() {
    let served = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, []);
    let rows = served.stored_rows();
    let refused = served
        .vault
        .accept_pack_defaults(&served.owner, "engine", &"0".repeat(64));
    assert!(
        matches!(refused, Err(Error::InvalidConfig(_))),
        "the door refuses the proposal, not the confirm: {refused:?}"
    );
    assert_eq!(presence.prompts(), 0, "the door showed no prompt");
    assert_eq!(served.stored_rows(), rows, "the refusal stores no row");
}

/// A door's own checks come before its confirm: an origin cut of a
/// repository this vault does not serve is refused with that reason, and
/// the person is never asked.
#[test]
fn an_origin_cut_of_a_repository_the_vault_does_not_serve_never_prompts() {
    let served = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, []);
    let rows = served.stored_rows();
    let refused = served.vault.set_served_origin_authority_as_owner(
        &served.owner,
        ActSurface::ThisInstall,
        "a-repository-this-vault-does-not-serve",
        None,
        OriginResidence::LocalVault,
        EntityId::now(),
        false,
        None,
    );
    assert!(
        refused.is_err()
            && !matches!(
                refused,
                Err(Error::Record(RecordError::OwnerPresenceRequired { .. }))
            ),
        "the door refuses the repository, not the confirm: {refused:?}"
    );
    assert_eq!(presence.prompts(), 0, "the door showed no prompt");
    assert_eq!(served.stored_rows(), rows, "the refusal stores no row");
}

/// One vault with a device PIN set, over a process-memory keystore, on a
/// clock the test moves. The vault drops first.
struct PinDevice {
    vault: Vault,
    proof: AuthenticatedOwner,
    pin: Arc<DevicePin>,
    _dir: tempfile::TempDir,
}

/// The device PIN: a passphrase, since nothing counts wrong tries but this
/// process.
const PIN: &[u8] = b"quiet harbour lantern";

impl PinDevice {
    fn with_pin_set() -> Self {
        let (vault, dir) = open_vault(HostingPrivacyPosture::Hosted);
        let keystore = Arc::new(MemoryKeystore::new());
        vault.install_device_keystore(keystore.clone());
        let issuer = provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("install's machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let proof = vault
            .authenticate_owner(
                owner,
                &owner.to_hex(),
                true,
                GateDecisionId::from_bytes([1; 16]),
            )
            .expect("authenticated owner");
        let pin = DevicePin::with_clock_and_cost(
            keystore,
            ManualPresenceClock::new(1_000_000, 1_000_000),
            PassphraseCost::FLOOR,
        )
        .expect("device PIN over the vault's keystore");
        vault
            .install_device_pin(pin.clone())
            .expect("install device PIN");
        let authority = ActAuthority::Owner(proof.clone(), ActSurface::ThisInstall);
        vault
            .set_device_pin_as(&authority, PIN, false)
            .expect("set the device PIN as the owner");
        Self {
            vault,
            proof,
            pin,
            _dir: dir,
        }
    }

    /// This install's MACHINE row.
    fn install(&self) -> EntityId {
        self.vault
            .local_machine()
            .expect("read this install")
            .expect("this install is profiled")
            .id
    }

    /// How many authority log rows the fold holds valid.
    fn stored_rows(&self) -> usize {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .valid_entries
            .len()
    }
}

/// A device with a PIN set answers PIN required at the door, and writes nothing.
#[test]
fn a_device_with_a_pin_set_answers_pin_required_at_the_door() {
    let device = PinDevice::with_pin_set();
    device.pin.end_window();
    let presence = scripted_gate(&device.vault, [Ok(())]);
    let rows = device.stored_rows();
    let history = device
        .vault
        .export_signed_authority_history()
        .expect("the signed history");
    let refused = device.vault.set_machine_role(
        &device.proof,
        ActSurface::ThisInstall,
        device.install(),
        MachineRole::Owned(MachineOwnership::Yours),
        None,
    );
    assert!(
        matches!(
            refused,
            Err(Error::Secret(SecretError::DevicePin(
                DevicePinRefusal::Required
            )))
        ),
        "outside the PIN's window the door asks for the PIN: {refused:?}"
    );
    assert_eq!(presence.prompts(), 0, "the PIN answers before any prompt");
    assert_eq!(device.stored_rows(), rows, "the refusal stores no row");
    assert_eq!(
        device
            .vault
            .export_signed_authority_history()
            .expect("the signed history"),
        history,
        "the log holds the entries it held before"
    );
}

/// A pairing redeem asks nothing and enrols the machine.
#[test]
fn a_pairing_redeem_asks_nothing() {
    let host = ServedVault::self_host();
    host.vault
        .hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
    let answer = host
        .answer_this_install_is_mine()
        .expect("the host's answer lands");
    assert!(
        answer.held().is_none(),
        "the host can carry the pairing act"
    );

    let request = host.second_install_request();
    let link = host
        .vault
        .issue_hosted_node_pairing_link(
            &host.issuer,
            &host.owner,
            ActSurface::ThisInstall,
            Scope::top(),
            3600,
            PairingPrincipal::default(),
        )
        .expect("the owner issues a hosted-node link");
    let pairing_key = SigningKey::from_bytes(&[11; 32]);
    let device_key = pairing_key.verifying_key().to_bytes();
    let holder = request.machine.to_hex();
    let transcript = pairing_binding_transcript(&link.code, &device_key, &holder)
        .expect("the binding transcript");
    let proof = pairing_key.sign(&transcript).to_bytes();
    let presence = scripted_gate(&host.vault, [Ok(())]);
    let (_slip, landing) = host
        .vault
        .redeem_machine_pairing_link(
            &host.issuer,
            &link.code,
            &holder,
            device_key,
            &proof,
            &request,
        )
        .expect("the machine redeems");
    let MachineAnswerLanding::Stands(machine) = landing else {
        panic!("the enrolled machine must stand");
    };
    let roster = machine.roster.as_ref().expect("a roster revision");
    assert_eq!(roster.profile.machine, request.machine);
    assert_eq!(roster.profile.role, MachineRole::HostedNode);
    assert!(roster.is_live(), "the hosted node stands");
    assert!(!machine.is_mine(None), "a hosted node is never mine");
    assert_eq!(
        presence.prompts(),
        0,
        "a redeem on a standing ground shows no prompt"
    );
}
