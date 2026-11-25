//! Six owner doors read the value in force before they ask (row OWNER-CONFIRM-SHEET, PR 4b-3a).
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, ConversationLearningView, HostSlipIssuer, MachineEnrolmentRequest,
    MachineOwnership, MachineRole, OwnerKeyEnrollment,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::{GateError, OwnerPresenceRefusal, RecordError};
use oneiron::federation::{SharedTrainingSetup, SharedTrainingSetupAnswer};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::owner_presence_between::{
    set_conversation_learning_between, set_conversation_training_between, set_machine_role_between,
};
use oneiron::test_doors::restored_enrolment::forged_rows::publish_pinned_root_and_mark;
use oneiron::test_support::provision_engine_machines;
use oneiron::world_keys::PolicyRevision;
use oneiron::{EntityId, Error, HostingPrivacyPosture, Vault, VaultConfig};
use oneiron_keystore::{
    ManualPresenceClock, MemoryKeystore, PRESENCE_WINDOW_SECS, PresenceClock, PresenceError,
    PresenceGate, PresenceInstant, PresenceWindow, ScriptedPresence,
};
use oneiron_store::ports::manual_clock::ManualClock;

struct ServedVault {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl ServedVault {
    fn hosted() -> Self {
        let (vault, dir) = open_vault(HostingPrivacyPosture::Hosted);
        vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
        let issuer = provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let owner = embedded_owner(&vault)
            .expect("authenticated embedded owner")
            .1;
        Self {
            vault,
            issuer,
            owner,
            _dir: dir,
        }
    }

    fn enrol_owner_key(&self) {
        self.vault
            .enrol_device_owner_signing_key(
                &ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall),
                &self.issuer,
            )
            .expect("the owner enrols this install's owner signing key");
    }

    fn install(&self) -> EntityId {
        self.vault
            .local_machine()
            .expect("read this install")
            .expect("this install is profiled")
            .id
    }

    fn history(&self) -> Vec<Vec<u8>> {
        self.vault
            .export_signed_authority_history()
            .expect("the signed history")
    }

    fn set_learning(
        &self,
        on: bool,
        allow_opt_out: bool,
    ) -> oneiron::Result<ConversationLearningView> {
        self.vault.set_conversation_learning(
            &self.owner,
            ActSurface::ThisInstall,
            on,
            allow_opt_out,
            None,
        )
    }

    fn leave_my_messages_out(&self, leave_out: bool) -> oneiron::Result<bool> {
        self.vault
            .set_conversation_training(&self.owner, ActSurface::ThisInstall, leave_out, None)
            .map(|view| view.leave_out)
    }

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

    fn enrol_second_as_yours(&self) -> EntityId {
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
        assert!(landing.held().is_none(), "the second machine stands");
        request.machine
    }

    fn remark(&self, machine: EntityId, role: MachineRole) {
        self.vault
            .set_machine_role(&self.owner, ActSurface::ThisInstall, machine, role, None)
            .expect("the answer lands");
    }

    fn enrol_second_machine_and_key(
        &self,
        second_signing_key: &SigningKey,
    ) -> (EntityId, [u8; 32]) {
        let machine = self.enrol_second_as_yours();
        let second_key = second_signing_key.verifying_key().to_bytes();
        let challenge = self
            .vault
            .owner_key_enrollment_challenge_as(
                &ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall),
                machine,
                &second_key,
            )
            .expect("the second key's challenge");
        self.vault
            .enrol_owner_signing_key_as_host(
                &ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall),
                OwnerKeyEnrollment {
                    machine,
                    public_key: second_key,
                    proof: second_signing_key.sign(&challenge).to_bytes().to_vec(),
                },
                &self.issuer,
            )
            .expect("the owner enrols the second key");
        (machine, second_key)
    }

    fn machine_role(&self, machine: EntityId) -> MachineRole {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .machine(machine)
            .and_then(|folded| folded.roster.as_ref())
            .expect("a roster revision names the machine")
            .profile
            .role
    }

    fn share_and_pending(&self) -> ([u8; 32], PolicyRevision) {
        self.vault
            .initialize_shared_vault(&self.owner, 44, None, &[], 1)
            .expect("a shared vault");
        let status = self
            .vault
            .shared_training_setup_status(&self.owner)
            .expect("the pending question");
        let SharedTrainingSetup::Pending { question_ref, .. } =
            status.setup.expect("a pending setup")
        else {
            panic!("the setup is pending");
        };
        (question_ref, status.seen)
    }

    fn answer_setup(
        &self,
        question_ref: [u8; 32],
        on: bool,
        seen: PolicyRevision,
    ) -> oneiron::federation::SharedTrainingSetupQuestion {
        self.vault
            .answer_shared_training_setup(
                &self.owner,
                ActSurface::ThisInstall,
                &SharedTrainingSetupAnswer {
                    question_ref,
                    on,
                    seen,
                },
            )
            .expect("the setup answer lands")
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

struct ExpiresAtOnce {
    next_ms: AtomicU64,
}

impl ExpiresAtOnce {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            next_ms: AtomicU64::new(1_000_000),
        })
    }
}

impl PresenceClock for ExpiresAtOnce {
    fn now(&self) -> PresenceInstant {
        let ms = self
            .next_ms
            .fetch_add(PRESENCE_WINDOW_SECS * 1_000 + 1, Ordering::SeqCst);
        PresenceInstant {
            wall_ms: ms,
            monotonic_ms: ms,
        }
    }
}

fn expiring_gate(
    vault: &Vault,
    answers: impl IntoIterator<Item = Result<(), PresenceError>>,
) -> Arc<ScriptedPresence> {
    let presence = Arc::new(ScriptedPresence::new(answers));
    let window = PresenceWindow::new(ExpiresAtOnce::new());
    let gate = PresenceGate::new(presence.clone(), window);
    vault.install_presence_gate(Arc::new(gate));
    presence
}

fn assert_declined<T: std::fmt::Debug>(refused: &oneiron::Result<T>, what: &str) {
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined
            }))
        ),
        "a declined confirm refuses {what}: {refused:?}"
    );
}

/// A machine answer that stops a machine being the owner's asks nothing.
#[test]
fn a_machine_answer_that_stops_a_machine_being_the_owners_asks_nothing() {
    let work = MachineRole::Owned(MachineOwnership::WorkSchool);
    let served = ServedVault::hosted();
    served.enrol_owner_key();
    let machine = served.enrol_second_as_yours();
    let presence = scripted_gate(&served.vault, []);
    served.remark(machine, work);
    assert_eq!(
        presence.prompts(),
        0,
        "the narrowing answer shows no prompt"
    );
    assert_eq!(served.machine_role(machine), work);
}

/// A machine answer that makes a machine the owner's asks.
#[test]
fn a_machine_answer_that_makes_a_machine_the_owners_asks() {
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let work = MachineRole::Owned(MachineOwnership::WorkSchool);
    let served = ServedVault::hosted();
    served.enrol_owner_key();
    let machine = served.enrol_second_as_yours();
    served.remark(machine, work);
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let history = served.history();
    let refused =
        served
            .vault
            .set_machine_role(&served.owner, ActSurface::ThisInstall, machine, yours, None);
    assert_declined(&refused, "the widening answer");
    assert_eq!(presence.prompts(), 1, "the door showed one prompt");
    assert_eq!(served.history(), history, "the log holds its entries");
    assert_eq!(served.machine_role(machine), work);
    let presence = scripted_gate(&served.vault, [Ok(())]);
    served.remark(machine, yours);
    assert_eq!(
        presence.prompts(),
        1,
        "the widening answer shows one prompt"
    );
    assert_eq!(served.machine_role(machine), yours);
}

/// A machine answer between roles that are never the owner's asks.
#[test]
fn a_machine_answer_between_roles_that_are_never_the_owners_asks() {
    let work = MachineRole::Owned(MachineOwnership::WorkSchool);
    let rented = MachineRole::Owned(MachineOwnership::Rented);
    let served = ServedVault::hosted();
    served.enrol_owner_key();
    let machine = served.enrol_second_as_yours();
    served.remark(machine, work);
    let presence = scripted_gate(&served.vault, [Ok(())]);
    served.remark(machine, rented);
    assert_eq!(
        presence.prompts(),
        1,
        "the widening answer shows one prompt"
    );
    assert_eq!(served.machine_role(machine), rented);
}

/// A removal that ends no owner key asks nothing.
#[test]
fn a_removal_that_ends_no_owner_key_asks_nothing() {
    let served = ServedVault::hosted();
    served.enrol_owner_key();
    let machine = served.enrol_second_as_yours();
    let presence = scripted_gate(&served.vault, []);
    served.remark(machine, MachineRole::Removed);
    assert_eq!(presence.prompts(), 0, "the removal shows no prompt");
    assert_eq!(served.machine_role(machine), MachineRole::Removed);
}

/// A removal through the answer door that ends an owner key asks.
#[test]
fn a_removal_through_the_answer_door_that_ends_an_owner_key_asks() {
    let served = ServedVault::hosted();
    served.enrol_owner_key();
    let second_signing_key = SigningKey::from_bytes(&[72; 32]);
    let (machine, second_key) = served.enrol_second_machine_and_key(&second_signing_key);
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let history = served.history();
    let refused = served.vault.set_machine_role(
        &served.owner,
        ActSurface::ThisInstall,
        machine,
        MachineRole::Removed,
        None,
    );
    assert_declined(&refused, "the removal");
    assert_eq!(presence.prompts(), 1, "the door showed one prompt");
    assert_eq!(served.history(), history, "the log holds its entries");
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

/// A machine answer refused on its read never raises the prompt.
#[test]
fn a_machine_answer_refused_on_its_read_never_raises_the_prompt() {
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let work = MachineRole::Owned(MachineOwnership::WorkSchool);
    let served = ServedVault::hosted();
    served.enrol_owner_key();
    let machine = served.enrol_second_as_yours();
    let other = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, []);
    let history = served.history();
    let stale = served.vault.set_machine_role(
        &served.owner,
        ActSurface::ThisInstall,
        machine,
        work,
        Some([9; 32]),
    );
    assert!(matches!(stale, Err(Error::ConcurrentWrite(_))));
    let unknown = served.vault.set_machine_role(
        &served.owner,
        ActSurface::ThisInstall,
        EntityId::from_bytes([9; 16]).expect("a valid unknown machine id"),
        yours,
        None,
    );
    assert!(matches!(
        unknown,
        Err(Error::Record(RecordError::InvalidAuthorityLogBody(_)))
    ));
    let foreign = served.vault.set_machine_role(
        &other.owner,
        ActSurface::ThisInstall,
        served.install(),
        yours,
        None,
    );
    assert!(matches!(
        foreign,
        Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
    ));
    assert_eq!(presence.prompts(), 0, "no refusal showed a prompt");
    assert_eq!(served.history(), history, "the log holds its entries");
}

/// A machine answer that became a widening since it asked is a conflict.
#[test]
fn a_machine_answer_that_became_a_widening_since_it_asked_is_a_conflict() {
    let work = MachineRole::Owned(MachineOwnership::WorkSchool);
    let rented = MachineRole::Owned(MachineOwnership::Rented);
    let served = ServedVault::hosted();
    served.enrol_owner_key();
    let machine = served.enrol_second_as_yours();
    let presence = scripted_gate(&served.vault, []);
    let conflict = set_machine_role_between(
        &served.vault,
        &served.owner,
        ActSurface::ThisInstall,
        machine,
        work,
        None,
        || served.remark(machine, rented),
    );
    assert!(matches!(conflict, Err(Error::ConcurrentWrite(_))));
    assert_eq!(presence.prompts(), 0, "neither act showed a prompt");
    assert_eq!(served.machine_role(machine), rented);
}

/// An enrolment asks.
#[test]
fn an_enrolment_asks() {
    let work = MachineRole::Owned(MachineOwnership::WorkSchool);
    let served = ServedVault::hosted();
    served.enrol_owner_key();
    let request = served.second_install_request();
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let history = served.history();
    let refused =
        served
            .vault
            .enroll_machine(&served.owner, ActSurface::ThisInstall, &request, work, None);
    assert_declined(&refused, "the enrolment");
    assert_eq!(presence.prompts(), 1, "the door showed one prompt");
    assert_eq!(served.history(), history, "the log holds its entries");

    let anchored = ServedVault::hosted();
    anchored.enrol_owner_key();
    let request = anchored.second_install_request();
    let owner = anchored
        .owner
        .actor_for_read(&anchored.vault)
        .expect("the owner");
    let mark = publish_pinned_root_and_mark(&anchored.vault, owner, &request)
        .expect("the pinned anchor marks the second install");
    let fold = anchored.vault.authority_fold().expect("authority fold");
    let machine = fold
        .machine(request.machine)
        .expect("the mark names the machine");
    assert!(machine.roster.is_none());
    let heads = machine.standing_heads(fold.pinned_root.as_ref());
    assert!(matches!(heads.as_slice(), [head] if head.entry == mark && head.is_live()));
    let presence = scripted_gate(&anchored.vault, []);
    let answer = anchored
        .vault
        .enroll_machine(
            &anchored.owner,
            ActSurface::ThisInstall,
            &request,
            work,
            None,
        )
        .expect("the enrolment beside the standing head lands");
    assert!(answer.held().is_none());
    assert_eq!(presence.prompts(), 0, "the answer narrows the pinned mark");
    assert_eq!(anchored.machine_role(request.machine), work);
}

/// A held answer that makes a machine the owner's asks at its confirm.
#[test]
fn a_held_answer_that_makes_a_machine_the_owners_asks_at_its_confirm() {
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let served = ServedVault::hosted();
    served
        .vault
        .set_machine_role(
            &served.owner,
            ActSurface::ThisInstall,
            served.install(),
            yours,
            None,
        )
        .expect("the unproven answer is stored");
    let held = served
        .vault
        .held_machine_answers(&served.owner)
        .expect("the held answer list");
    assert_eq!(held.answers.len(), 1, "one held answer: {held:?}");
    served.enrol_owner_key();
    let presence = expiring_gate(&served.vault, [Err(PresenceError::Declined)]);
    let history = served.history();
    served
        .vault
        .confirm_held_machine_answers(
            &served.owner,
            ActSurface::ThisInstall,
            &[],
            &BTreeMap::new(),
        )
        .expect("an empty confirmation needs no prompt");
    assert_eq!(
        presence.prompts(),
        0,
        "an empty confirmation shows no prompt"
    );
    assert_eq!(
        served.history(),
        history,
        "an empty confirmation adds no row"
    );
    let entries = [held.answers[0].entry];
    let refused = served.vault.confirm_held_machine_answers(
        &served.owner,
        ActSurface::ThisInstall,
        &entries,
        &BTreeMap::new(),
    );
    assert_declined(&refused, "the confirm");
    assert_eq!(presence.prompts(), 1, "the door showed one prompt");
    assert_eq!(served.history(), history, "the log holds its entries");
    assert_eq!(
        served
            .vault
            .held_machine_answers(&served.owner)
            .expect("the held answer list")
            .answers
            .len(),
        1
    );
}

/// Opting back in asks only when the person is out.
#[test]
fn opting_back_in_asks_only_when_the_person_is_out() {
    let served = ServedVault::hosted();
    served
        .set_learning(true, true)
        .expect("the setting that lets people opt out lands");
    let presence = expiring_gate(&served.vault, [Ok(()), Ok(()), Ok(())]);
    assert!(
        !served
            .leave_my_messages_out(false)
            .expect("the no-op lands")
    );
    assert_eq!(presence.prompts(), 0, "staying in shows no prompt");
    assert!(
        served
            .leave_my_messages_out(true)
            .expect("the opt-out lands")
    );
    assert_eq!(presence.prompts(), 0, "opting out shows no prompt");
    assert!(
        !served
            .leave_my_messages_out(false)
            .expect("the opt back in lands")
    );
    assert_eq!(presence.prompts(), 1, "opting back in shows one prompt");
}

/// A learning choice asks only when it widens.
#[test]
fn a_learning_choice_asks_only_when_it_widens() {
    let served = ServedVault::hosted();
    let presence = expiring_gate(&served.vault, [Ok(()), Ok(()), Ok(()), Ok(()), Ok(())]);
    let view = served
        .set_learning(true, true)
        .expect("turning it on lands");
    assert_eq!((view.on, view.allow_opt_out), (true, true));
    assert_eq!(presence.prompts(), 1, "turning it on shows one prompt");
    let view = served
        .set_learning(true, true)
        .expect("the same choice lands");
    assert_eq!((view.on, view.allow_opt_out), (true, true));
    assert_eq!(presence.prompts(), 1, "the same choice shows no prompt");
    let view = served
        .set_learning(true, false)
        .expect("withdrawing the opt-out lands");
    assert_eq!((view.on, view.allow_opt_out), (true, false));
    assert_eq!(
        presence.prompts(),
        2,
        "withdrawing the opt-out shows one prompt"
    );
    let view = served
        .set_learning(true, true)
        .expect("giving the opt-out back lands");
    assert_eq!((view.on, view.allow_opt_out), (true, true));
    assert_eq!(
        presence.prompts(),
        2,
        "giving the opt-out back shows no prompt"
    );
    let view = served
        .set_learning(false, false)
        .expect("turning it off lands");
    assert!(!view.on);
    assert_eq!(presence.prompts(), 2, "turning it off shows no prompt");
}

/// A training choice refused on its read never raises the prompt.
#[test]
fn a_training_choice_refused_on_its_read_never_raises_the_prompt() {
    let closed = ServedVault::hosted();
    let presence = scripted_gate(&closed.vault, []);
    let history = closed.history();
    let refused =
        closed
            .vault
            .set_conversation_training(&closed.owner, ActSurface::ThisInstall, false, None);
    assert!(
        matches!(
            &refused,
            Err(Error::Record(RecordError::AuthorityRefused(reason)))
                if *reason == "this vault does not allow opt-outs"
        ),
        "opting back in where none is allowed is refused: {refused:?}"
    );
    assert_eq!(presence.prompts(), 0, "the refusal showed no prompt");
    assert_eq!(closed.history(), history, "the log holds its entries");
    let served = ServedVault::hosted();
    served
        .set_learning(true, true)
        .expect("the setting that lets people opt out lands");
    let presence = scripted_gate(&served.vault, []);
    let history = served.history();
    let stale = served.vault.set_conversation_training(
        &served.owner,
        ActSurface::ThisInstall,
        false,
        Some(PolicyRevision([9; 32])),
    );
    assert!(matches!(stale, Err(Error::ConcurrentWrite(_))));
    assert_eq!(presence.prompts(), 0, "the conflict showed no prompt");
    assert_eq!(served.history(), history, "the log holds its entries");
}

/// A learning choice refused on its read never raises the prompt.
#[test]
fn a_learning_choice_refused_on_its_read_never_raises_the_prompt() {
    let served = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, []);
    let history = served.history();
    let stale = served.vault.set_conversation_learning(
        &served.owner,
        ActSurface::ThisInstall,
        true,
        false,
        Some(PolicyRevision([9; 32])),
    );
    assert!(matches!(stale, Err(Error::ConcurrentWrite(_))));
    assert_eq!(presence.prompts(), 0, "the conflict showed no prompt");
    assert_eq!(served.history(), history, "the log holds its entries");
}

/// An opt back in that became a widening since it asked is a conflict.
#[test]
fn an_opt_back_in_that_became_a_widening_since_it_asked_is_a_conflict() {
    let served = ServedVault::hosted();
    served
        .set_learning(true, true)
        .expect("the setting that lets people opt out lands");
    let presence = scripted_gate(&served.vault, []);
    let conflict = set_conversation_training_between(
        &served.vault,
        &served.owner,
        ActSurface::ThisInstall,
        false,
        None,
        || {
            served
                .leave_my_messages_out(true)
                .expect("between opts the person out");
        },
    );
    assert!(matches!(conflict, Err(Error::ConcurrentWrite(_))));
    assert_eq!(presence.prompts(), 0, "neither act showed a prompt");
    assert!(
        served
            .vault
            .conversation_training_view(&served.owner)
            .expect("the person's own training view")
            .leave_out
    );
}

/// A learning choice that became a widening since it asked is a conflict.
#[test]
fn a_learning_choice_that_became_a_widening_since_it_asked_is_a_conflict() {
    let served = ServedVault::hosted();
    served
        .set_learning(true, true)
        .expect("the setting starts on with opt-outs");
    let presence = scripted_gate(&served.vault, []);
    let conflict = set_conversation_learning_between(
        &served.vault,
        &served.owner,
        ActSurface::ThisInstall,
        true,
        true,
        None,
        || {
            served
                .set_learning(false, false)
                .expect("between turns learning off");
        },
    );
    assert!(matches!(conflict, Err(Error::ConcurrentWrite(_))));
    assert_eq!(presence.prompts(), 0, "neither act showed a prompt");
    assert!(
        !served
            .vault
            .conversation_learning_status()
            .expect("conversation learning status")
            .on
    );
}

/// A replayed setup answer asks nothing.
#[test]
fn a_replayed_setup_answer_asks_nothing() {
    let off = ServedVault::hosted();
    let (question_ref, seen) = off.share_and_pending();
    let presence = scripted_gate(&off.vault, []);
    let answered = off.answer_setup(question_ref, false, seen);
    assert_eq!(presence.prompts(), 0, "a fresh off answer shows no prompt");
    assert!(matches!(
        answered.setup,
        Some(SharedTrainingSetup::Answered { on: false, .. })
    ));
    let served = ServedVault::hosted();
    let (question_ref, seen) = served.share_and_pending();
    let presence = expiring_gate(&served.vault, [Ok(()), Ok(())]);
    let first = served.answer_setup(question_ref, true, seen);
    assert_eq!(
        presence.prompts(),
        1,
        "the fresh on answer shows one prompt"
    );
    let replay = served.answer_setup(question_ref, true, seen);
    assert_eq!(presence.prompts(), 1, "the replay shows no prompt");
    assert_eq!(replay, first, "the replay answers the same question back");
}
