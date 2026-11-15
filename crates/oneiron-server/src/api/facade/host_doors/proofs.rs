//! The proof rules of the host doors (UC-01 PR 0a; fable/19 DESIGN section 2): who a door admits, and
//! the proof it hands the door. Each host-door row names its rule (`proof` in its verb row). The
//! generated [`HostDoorRow::admits`](super::super::host_door_rows::HostDoorRow::admits) runs the rule
//! before the row's pre hooks, so a hook never fires on a call the door refuses (FIX 1763), and the
//! door runs it again for the proof it acts under. A row whose rule is `in_door` names no rule here:
//! its door proves its caller itself, after the hooks.
//!
//! The 49 proof kinds the rows named are 29 rules. Two kinds share a rule only where their admit
//! fns admitted the same callers; a shared rule keeps one refusal text, with the verb in it. Each
//! rule runs the fn its kinds ran, or the same calls in the same order. The old hand list of verb
//! names went into the rows: `share_doors::principal` and `weave_doors::own_caller` are
//! [`Caller`], `graph_ask_doors::asker` is [`VerdictAsker`], and `weave_doors::person_lens` is
//! [`LensPerson`] (FIX-LIST HOST-DOOR-HAND-LIST-PRECHECK-MISMATCH).

use oneiron::authority::VerifiedSlip;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::usage_repair::UsageRepairVerb;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::{EdgeActorClass, EntityId, WriteActor};

use super::super::host_door_rows::HostDoorRow;
use super::super::owner_binding::{facade_caller_or, facade_owner, host_preflight};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// One proof rule: who a door admits, and the proof it hands the door.
pub(in crate::api::facade) trait ProofRule {
    /// What the door acts under once the rule admits its caller.
    type Proof;
    /// Admits this request for `verb`, or refuses it with the rule's refusal.
    fn prove(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<Self::Proof>;
}

/// The check host-door row `verb`'s door runs before the row's pre chain: the rule its row names.
/// A row whose rule is `in_door`, and a verb that is no host-door row, pass: such a door checks its
/// caller itself.
pub(in crate::api::facade) fn door_admits(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<()> {
    HostDoorRow::from_verb(verb).map_or(Ok(()), |row| row.admits(server, auth, verb))
}

/// The refusal of a rule that binds the credential's own actor: `verb` `acts`.
fn forbidden(verb: &str, acts: &str, suggestion: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{verb} {acts}"),
        &[suggestion],
    )
}

/// The vault's owner, as `/v1/owner` takes it: the owner's own slip, a managed vault's attested
/// owner, or a self-hosted root acting as the owner.
pub(in crate::api::facade) struct Owner;
impl ProofRule for Owner {
    type Proof = AuthenticatedOwner;
    fn prove(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<AuthenticatedOwner> {
        facade_owner(server, auth, verb)
    }
}

/// The owner, or any live person on their own verified human slip (was `shared_person` and
/// `trusted_contact_person`, which tried the owner's proof first and then this).
pub(in crate::api::facade) struct Person;
impl ProofRule for Person {
    type Proof = AuthenticatedOwner;
    fn prove(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<AuthenticatedOwner> {
        super::super::shared_act_doors::person(server, auth, verb)
    }
}

/// As [`Person`], but bound as a person: never on a managed vault or a host action, never an
/// invitee (was `workflow_member` and `check_in_holder`).
pub(in crate::api::facade) struct Member;
impl ProofRule for Member {
    type Proof = AuthenticatedOwner;
    fn prove(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<AuthenticatedOwner> {
        super::super::agent_definition_doors::member_proof(server, auth, verb)
    }
}

/// The owner under its proof (`Some`); else a person or agent on its own verified slip (`None`),
/// whose Grant the engine checks at the read or write (was `engine_controller`,
/// `substrate_reader`, `run_reader`, `skill_reader`, `import_canceller` and `skill_forker`).
pub(in crate::api::facade) struct OwnerOrHolder;
impl ProofRule for OwnerOrHolder {
    type Proof = Option<AuthenticatedOwner>;
    fn prove(
        server: &SyncServer,
        auth: &CoreAuth,
        verb: &str,
    ) -> MemoryResult<Option<AuthenticatedOwner>> {
        super::super::substrate_read_doors::substrate_reader(server, auth, verb)
    }
}

/// The owner under its proof (`Some`); else the credential's own actor, of any class (`None`),
/// whose live Grant the engine checks. A caller bound to no actor keeps the owner refusal (was
/// `claim_settler`, `consent_revoker` and `model_binding_proposer`).
pub(in crate::api::facade) struct OwnerOrCaller;
impl ProofRule for OwnerOrCaller {
    type Proof = Option<AuthenticatedOwner>;
    fn prove(
        server: &SyncServer,
        auth: &CoreAuth,
        verb: &str,
    ) -> MemoryResult<Option<AuthenticatedOwner>> {
        match facade_owner(server, auth, verb) {
            Ok(owner) => Ok(Some(owner)),
            Err(refusal) => facade_caller_or(server, auth, || refusal).map(|_| None),
        }
    }
}

/// The credential's own actor: a person, an agent or a system actor (was `origin_publish`,
/// `diary_reader`, `facade_actor`, `artifact_asker`, `code_import`, `slide_reviewer` and
/// `image_editor`).
pub(in crate::api::facade) struct Caller;
impl ProofRule for Caller {
    type Proof = (EntityId, EdgeActorClass);
    fn prove(
        server: &SyncServer,
        auth: &CoreAuth,
        verb: &str,
    ) -> MemoryResult<(EntityId, EdgeActorClass)> {
        facade_caller_or(server, auth, || {
            forbidden(
                verb,
                "acts as the credential's own principal",
                "Present a slip paired from a link created with --principal-ref and --actor-class.",
            )
        })
    }
}

/// [`Caller`], on a credential that is not channel-bound (was `code_export_preview`,
/// `review_policy`, `view_editor` and `checkout_holder`).
pub(in crate::api::facade) struct LaneCaller;
impl ProofRule for LaneCaller {
    type Proof = (EntityId, EdgeActorClass);
    fn prove(
        server: &SyncServer,
        auth: &CoreAuth,
        verb: &str,
    ) -> MemoryResult<(EntityId, EdgeActorClass)> {
        auth.require_lane_record_scope().map_err(|_| {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!("a channel-bound credential reaches no {verb} door"),
                &[],
            )
        })?;
        Caller::prove(server, auth, verb)
    }
}

/// An owner-grade credential (was `media_owner_grade` and `video_job_owner_grade`).
pub(in crate::api::facade) struct OwnerGrade;
impl ProofRule for OwnerGrade {
    type Proof = ();
    fn prove(_: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<()> {
        super::support::owner_grade(auth, &format!("{verb} is the owner's"))
    }
}

/// [`Caller`], then the usage-repair writer's own admission for the verb: the owner's own proof or
/// an agent's own Grant naming it (was `usage_repair_list`, `usage_repair_remove` and
/// `usage_repair_receipts`).
pub(in crate::api::facade) struct UsageRepair;
impl ProofRule for UsageRepair {
    type Proof = ();
    fn prove(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<()> {
        let repair = [
            UsageRepairVerb::List,
            UsageRepairVerb::Remove,
            UsageRepairVerb::Receipts,
        ]
        .into_iter()
        .find(|repair| repair.name() == verb)
        .ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!("{verb} is no usage repair verb"),
                &[],
            )
        })?;
        super::super::usage_repair_doors::repair_admits(server, auth, repair)
    }
}

/// The owner; else a person or agent on its own slip, never a host holder or a managed owner: the
/// off-record session rows' manager.
pub(in crate::api::facade) struct OffRecord;
impl ProofRule for OffRecord {
    type Proof = ();
    fn prove(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<()> {
        super::super::off_record_doors::off_record_admits(server, auth, verb)
    }
}

/// Decided per verb: an off-record room's starter, participant, exporter, suggesting agent or
/// holder.
pub(in crate::api::facade) struct OffRecordRoom;
impl ProofRule for OffRecordRoom {
    type Proof = ();
    fn prove(_: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<()> {
        super::super::off_record_room_doors::off_record_room_admits(auth, verb)
    }
}

/// A live person on their own proof; else a designed voice's creator on its own credential (FIX
/// 4393).
pub(in crate::api::facade) struct VoiceBank;
impl ProofRule for VoiceBank {
    type Proof = ();
    fn prove(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<()> {
        super::super::voice_bank_doors::voice_bank_admits(server, auth, verb)
    }
}

/// The booking plane's host owner act.
pub(in crate::api::facade) struct BookingOwnerAct;
impl ProofRule for BookingOwnerAct {
    type Proof = ();
    fn prove(server: &SyncServer, auth: &CoreAuth, _: &str) -> MemoryResult<()> {
        host_preflight(server, auth)?;
        crate::api::host_action::require_host_owner_act(server, auth)
            .map(drop)
            .map_err(|error| super::super::FacadeApiError::from(error).into_memory_error())
    }
}

/// The owner's proof, or an agent acting for the owner (OF-378).
pub(in crate::api::facade) struct PacksSetup;
impl ProofRule for PacksSetup {
    type Proof = ();
    fn prove(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<()> {
        super::packs::setup_admits(server, auth, verb)
    }
}

/// A slip that names a person or a bound agent, read off the credential alone.
pub(in crate::api::facade) struct DecisionHolder;
impl ProofRule for DecisionHolder {
    type Proof = WriteActor;
    fn prove(_: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<WriteActor> {
        super::super::decision_ask_doors::holder(auth, verb)
    }
}

/// [`Caller`] on a verified, on-record slip.
pub(in crate::api::facade) struct HydeCaller;
impl ProofRule for HydeCaller {
    type Proof = (EntityId, EdgeActorClass);
    fn prove(
        server: &SyncServer,
        auth: &CoreAuth,
        _: &str,
    ) -> MemoryResult<(EntityId, EdgeActorClass)> {
        super::super::hyde_doors::hyde_caller(server, auth)
    }
}

/// A live guest Grant slip.
pub(in crate::api::facade) struct GuestDocumentReader;
impl ProofRule for GuestDocumentReader {
    type Proof = VerifiedSlip;
    fn prove(server: &SyncServer, auth: &CoreAuth, _: &str) -> MemoryResult<VerifiedSlip> {
        super::super::guest_document_doors::guest_document_reader(server, auth)
    }
}

/// The owner; else a person or agent, slip not required (FIX 8178).
pub(in crate::api::facade) struct TradeoffPicker;
impl ProofRule for TradeoffPicker {
    type Proof = super::super::goal_optimize_doors::Picker;
    fn prove(
        server: &SyncServer,
        auth: &CoreAuth,
        verb: &str,
    ) -> MemoryResult<super::super::goal_optimize_doors::Picker> {
        super::super::goal_optimize_doors::picker(server, auth, verb)
    }
}

/// The owner; else any actor on a verified slip, whose publish the outbound Gate judges (FIX 8161).
pub(in crate::api::facade) struct ArtifactPublisher;
impl ProofRule for ArtifactPublisher {
    type Proof = Option<AuthenticatedOwner>;
    fn prove(
        server: &SyncServer,
        auth: &CoreAuth,
        verb: &str,
    ) -> MemoryResult<Option<AuthenticatedOwner>> {
        super::super::artifact_hosting_doors::publisher(server, auth, verb)
    }
}

/// The owner; else an agent whose credential still reads (slice 6.5c).
pub(in crate::api::facade) struct ModelStepCaller;
impl ProofRule for ModelStepCaller {
    type Proof = ();
    fn prove(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<()> {
        super::super::model_step_doors::step_caller_admits(server, auth, verb)
    }
}

/// The owner; else a person who holds the policy power, which the manifest writer checks (FIX
/// 8177; was `policy_putter`). The flag says whether the person acts under that power.
pub(in crate::api::facade) struct PolicyPower;
impl ProofRule for PolicyPower {
    type Proof = (AuthenticatedOwner, bool);
    fn prove(
        server: &SyncServer,
        auth: &CoreAuth,
        verb: &str,
    ) -> MemoryResult<(AuthenticatedOwner, bool)> {
        super::super::gate_policy_doors::policy_putter(server, auth, verb)
    }
}

/// The owner; else a person who holds the ramp demotion power, which the demotion writer checks
/// again (census L7-33; was `ramp_demoter`).
pub(in crate::api::facade) struct RampPower;
impl ProofRule for RampPower {
    type Proof = AuthenticatedOwner;
    fn prove(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<AuthenticatedOwner> {
        super::super::graduation_doors::ramp_demoter(server, auth, verb)
    }
}

/// The owner, or the person or agent an access request asks, on their own proof (FIX 1379).
pub(in crate::api::facade) struct GrantsAnswer;
impl ProofRule for GrantsAnswer {
    type Proof = ();
    fn prove(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<()> {
        super::super::grants_doors::answer_admits(server, auth, verb)
    }
}

/// A caller with its own holder-bound slip.
pub(in crate::api::facade) struct CredentialHolder;
impl ProofRule for CredentialHolder {
    type Proof = ();
    fn prove(_: &SyncServer, auth: &CoreAuth, _: &str) -> MemoryResult<()> {
        super::super::credential_doors::holder(auth).map(drop)
    }
}

/// A live slip with read and propose scope and a read key.
pub(in crate::api::facade) struct ForeignCode;
impl ProofRule for ForeignCode {
    type Proof = ();
    fn prove(server: &SyncServer, auth: &CoreAuth, _: &str) -> MemoryResult<()> {
        super::super::foreign_code_doors::foreign_code_admits(server, auth)
    }
}

/// The slip's principal, or the owner a host acts as (was `verdict_asker` and the hand list's
/// `graph_ask_doors::asker`, the same lines).
pub(in crate::api::facade) struct VerdictAsker;
impl ProofRule for VerdictAsker {
    type Proof = (EntityId, EdgeActorClass);
    fn prove(
        server: &SyncServer,
        auth: &CoreAuth,
        _: &str,
    ) -> MemoryResult<(EntityId, EdgeActorClass)> {
        super::support::asking(auth, server)
    }
}

/// [`Caller`], then the engine's admission for the eval-authoring pass: the owner's own proof or
/// an agent's own Grant naming the verb (LEARNING-06).
pub(in crate::api::facade) struct EvalAuthoring;
impl ProofRule for EvalAuthoring {
    type Proof = ();
    fn prove(server: &SyncServer, auth: &CoreAuth, _: &str) -> MemoryResult<()> {
        super::super::eval_doors::execute_admits(server, auth)
    }
}

/// [`Caller`] with a read key.
pub(in crate::api::facade) struct SavedQuery;
impl ProofRule for SavedQuery {
    type Proof = ();
    fn prove(server: &SyncServer, auth: &CoreAuth, _: &str) -> MemoryResult<()> {
        super::super::saved_query_doors::admits(server, auth)
    }
}

/// A person's proof, as [`Person`], and the credential's own actor beside it: a lens label (was
/// the hand list's `weave_doors::person_lens`).
pub(in crate::api::facade) struct LensPerson;
impl ProofRule for LensPerson {
    type Proof = (AuthenticatedOwner, (EntityId, EdgeActorClass));
    fn prove(
        server: &SyncServer,
        auth: &CoreAuth,
        verb: &str,
    ) -> MemoryResult<(AuthenticatedOwner, (EntityId, EdgeActorClass))> {
        let proof = Person::prove(server, auth, verb)?;
        let caller = facade_caller_or(server, auth, || {
            forbidden(
                verb,
                "labels in the credential's own lens",
                "Present your own verified human credential.",
            )
        })?;
        Ok((proof, caller))
    }
}
