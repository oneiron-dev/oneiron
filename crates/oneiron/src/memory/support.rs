//! Shared facade plumbing: [`Memory`] itself, actor/scope verification,
//! JSON<->MessagePack wire encoding, and ref/short-id utilities used across
//! the concern files. Split from the flat `facade.rs`.

use super::structural::*;
use super::*;

use rmpv::Value;

use crate::Vault;

use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Error;

mod actors;
mod builders;
mod constructors;
mod refs;
mod transactions;
mod wire;

pub(crate) use self::actors::*;
pub use self::refs::*;
pub(crate) use self::wire::*;

const SCOPE_SENSITIVITY_KEY: &str = "sensitivity";

const GATE_RECEIPT_SCAN_LIMIT: usize = 512;

/// The actor-bound memory SURFACE: every verb takes the actor context bound
/// at construction (W3 — construction is not authority; the gate decides).
///
/// A facade by pattern, and the module still describes it that way — but the
/// pattern is an implementation note and the surface is what a caller reaches
/// for, so the type is named for the thing rather than for the shape.
#[derive(Clone)]
pub struct Memory<'v> {
    pub(super) vault: &'v Vault,
    pub(super) actor: EntityId,
    pub(super) actor_class: EdgeActorClass,
    /// Sitting selected by the authenticated host, including its peer machine.
    pub(super) session_key: Option<crate::session_lifecycle::SessionKey>,
    /// Private signer stays with the machine host; only the transcript crosses
    /// this callback, and each commit re-signs after its final approval choice.
    pub(super) machine_signer: Option<([u8; 32], &'v MachineSignFn<'v>)>,
    /// The verified credential this actor presented, when a host bound one:
    /// every read verb then reads under the key that proof builds.
    pub(super) read_proof: Option<crate::authority::VerifiedSlip>,
    /// The host action this handle's actor is, when a host bound one
    /// (`with_host_action_authority`, FIX 2222): every read verb then reads
    /// under its guarded owner key.
    pub(super) host_action: Option<crate::authority::HostActionAuthority>,
    /// The room turn this handle runs inside, when a host bound one.
    pub(super) room_turn: Option<crate::claim::RoomTurnCeiling>,
    /// The write origin a host bound, when one did: claim doors stamp it in
    /// place of the caller's declared source.
    pub(super) host_origin: Option<HostWriteOrigin>,
    /// Where the caller sits; see [`Memory::at`].
    pub(super) locality: crate::claim::CallerLocality,
    /// Where the caller's rows go, each machine its connection proved beside
    /// the locality (mesh PR2b); see [`Memory::for_destination`].
    pub(super) destination: crate::settings::ReadDestination,
    /// Where a host collects the rows its reads pick (`listing_producers`).
    pub(super) producers: Option<&'v super::ProducerRows>,
    /// Where a host bound its writer's TASKs to be born (`with_birth_position`).
    pub(super) birth_position: crate::federation::record_scope::BirthPosition,
    /// The vault owner's authentication, when a host bound the owner's own
    /// direct request (`with_owner_authorship`).
    pub(super) owner_authorship: Option<crate::consent::AuthenticatedOwner>,
    /// Where the owner's request reached this install, as its host verified
    /// it (`with_owner_surface`): the audit record of an owner act this
    /// surface makes, never authority (FIX 4650).
    pub(super) owner_surface: crate::authority::ActSurface,
    /// The host's own slip issuer, when a host bound it
    /// (`with_host_slip_issuer`, FIX 3875).
    pub(super) host_slip_issuer: Option<&'v crate::authority::HostSlipIssuer>,
    /// The logical verb's id a host carried in (`with_invocation`): verb
    /// hooks run once per id, across wrappers (ARCH-0080 §3).
    pub(super) invocation: Option<crate::runtime_hooks::InvocationId>,
    /// The hook pause a transport's call names as the one it resumes, by
    /// its ask handle (`with_hook_ask`, L13 PR-D): a session-only call's
    /// pause the keep no longer holds then refuses, never running as a new
    /// call. Context, not authority.
    pub(super) hook_ask: Option<EntityId>,
    /// The signed instrument the caller's request was admitted on, when a
    /// host bound one (`with_invocation_slip`): work this surface queues
    /// carries it, and it is verified again when that work runs.
    pub(super) invocation_slip: Option<crate::authority::InvocationSlipBinding>,
    /// A transport's caller reaches this surface, slip or none
    /// (`with_transport_invocation`). Only the host sets it, and nothing
    /// clears it: a surface without it is the in-process host's own.
    pub(super) transport_invocation: bool,
    /// The ask guest's grant a host admitted for this surface's actor
    /// (`with_task_grant`, OF-220): its task verbs prove the actor by it.
    pub(super) task_grant: Option<crate::authority::AdmittedTaskGrant>,
    /// The conversation whose request this surface's work answers, when a
    /// host bound one (`with_origin_conversation`, OF-221): context, not
    /// authority.
    pub(super) origin_conversation: Option<EntityId>,
    /// The running agent attempt a host bound as this surface's TASK creator
    /// (`with_task_host`, OF-532).
    pub(super) task_host: Option<crate::task_verb::HostBinding>,
    /// The host's decision path for the task surface's questions, when a
    /// host bound one (`with_task_decisions`, OF-533): advice, not authority.
    pub(super) task_decisions: Option<std::sync::Arc<crate::task_verb::TaskDecisions<'v>>>,
    /// The off-record session the host's request named
    /// (`in_off_record_session`): context, not authority.
    pub(super) off_record_session: Option<String>,
    /// A host bound this surface for a caller its credential admitted
    /// (`for_credential`); only that host verifies the credential again.
    pub(super) credential: bool,
    /// The exact instrument that credential is, when the host can verify it
    /// again (`with_credential_instrument`).
    pub(super) credential_instrument: Option<crate::runtime_hooks::verb::VerbAskInstrument>,
    /// The managed vault's attested owner the host bound this caller to
    /// (FIX 11129), carried apart from the vault's authority id, so a
    /// rootless managed vault's owner is still known; `None` for any other
    /// caller.
    pub(super) attested_owner: Option<EntityId>,
    /// The door the caller came in by, when its host can run the call again
    /// through it (`with_credential_door`).
    pub(super) credential_door: Option<crate::runtime_hooks::verb::VerbAskDoor>,
    /// The door's own admission of a hook's rewritten args
    /// (`with_rewrite_admit`).
    pub(super) rewrite_admit: Option<RewriteAdmit>,
    /// The vault task-work turn this surface's operation holds
    /// (`with_task_work_turn`, Rule 5): its nested task work runs on it and
    /// never waits for another. A turn that waited out the line still counts.
    pub(super) task_work_turn: Option<std::sync::Arc<crate::work_line::TaskWorkTurn>>,
    /// The authenticated Git transport ONE outside-import call lends this
    /// handle (`with_external_git_source_host`, FIX 6871); none otherwise.
    pub(super) external_git_source_host:
        Option<std::sync::Arc<dyn crate::repo_mutation::external_import::ExternalGitSourceHost>>,
    /// The host bound this handle to an MCP tool call (FIX 8961,
    /// `for_repo_tool_recipient`): repo bytes read masked whatever
    /// credential rides it, with the actual recipient when the host proved
    /// one (FIX 7608 2b-ii). Off on every other handle.
    pub(super) repo_tool_recipient: crate::origin::secret_projection::RepoToolRecipient,
}

/// A door's admission of a verb hook's rewritten args, run on the verb's name
/// and the new args after the row's own input check, as if the caller sent
/// them (ARCH-0080 §3). The reason refuses the rewrite.
pub type RewriteAdmit = std::sync::Arc<
    dyn Fn(&str, &serde_json::Value) -> std::result::Result<(), String> + Send + Sync,
>;

/// A host-owned write origin: the source, lineage and provenance a [`Memory`]
/// surface's claim doors stamp in place of the caller's declared source.
///
/// Only the engine builds one, from a write envelope it owns: the code-run
/// dispatcher, for a guest's verb call. A host passes it through to
/// [`Memory::with_host_origin`]; nothing the guest sends reaches its fields.
#[derive(Debug, Clone, PartialEq)]
pub struct HostWriteOrigin {
    envelope: crate::WriteEnvelope,
    /// The running agent attempt the dispatcher bound as the call's TASK
    /// creator (OF-532), read from its live lease, never from the guest.
    task_host: Option<crate::task_verb::HostBinding>,
    /// The model provider the host's ladder served the calling program's
    /// turn from (OF-560), read from the served receipt, never from the
    /// guest. `None` when no ladder stamped the turn.
    model_provider: Option<String>,
    /// Where a code-mode `connector.call` sits in its durable run (DOOR-079
    /// 1a), built by the dispatcher from the executor's own bridge position,
    /// never from the guest: a hold for consent alone binds a code consent
    /// wait to it.
    code_consent: Option<crate::code_run::CodeConsentCallSite>,
    /// The hook pause a call the run makes again resumes (FIX 5526): the ask
    /// an earlier try of the same call in its durable run parked on, read
    /// from the run's own history, never from the guest. It names the pause
    /// only, beside the call's invocation.
    hook_ask: Option<EntityId>,
    /// The live, verified slip whose turn woke the calling program (FIX
    /// 8717), from the program's own binding, never from the guest: the
    /// surface the origin reaches reads and writes under it.
    read_proof: Option<crate::authority::VerifiedSlip>,
    /// The durable code run the dispatcher is bound to (its replay record's
    /// id), from the dispatcher's own binding, never from the guest: the
    /// one run a creation this origin's writer asserts can be proved in
    /// (FIX 1211).
    bound_run: Option<EntityId>,
}

impl HostWriteOrigin {
    pub(crate) const fn new(envelope: crate::WriteEnvelope) -> Self {
        Self {
            envelope,
            task_host: None,
            model_provider: None,
            code_consent: None,
            hook_ask: None,
            read_proof: None,
            bound_run: None,
        }
    }

    /// This origin with the waking slip a turn program's call runs under,
    /// if its program has one (FIX 8717).
    pub(crate) fn with_read_proof(mut self, proof: Option<crate::authority::VerifiedSlip>) -> Self {
        self.read_proof = proof;
        self
    }

    /// This origin naming the hook pause its call resumes, if it resumes one.
    pub(crate) const fn with_hook_ask(mut self, ask: Option<EntityId>) -> Self {
        self.hook_ask = ask;
        self
    }

    /// This origin with the call's place in its durable run, for a call a
    /// code consent wait may bind.
    pub(crate) fn with_code_consent(mut self, site: crate::code_run::CodeConsentCallSite) -> Self {
        self.code_consent = Some(site);
        self
    }

    /// This origin with the provider the run's last turn was served from.
    pub(crate) fn with_model_provider(mut self, provider: Option<String>) -> Self {
        self.model_provider = provider;
        self
    }

    /// The model provider the host bound, if any.
    #[must_use]
    pub fn model_provider(&self) -> Option<&str> {
        self.model_provider.as_deref()
    }

    /// This origin with the run's TASK creator binding, if it has one.
    pub(crate) fn with_task_host(mut self, binding: Option<crate::task_verb::HostBinding>) -> Self {
        self.task_host = binding;
        self
    }

    /// The TASK creator the dispatcher bound, if any.
    #[must_use]
    pub const fn task_host(&self) -> Option<&crate::task_verb::HostBinding> {
        self.task_host.as_ref()
    }

    /// The source every claim written under this origin carries.
    #[must_use]
    pub const fn source(&self) -> ClaimSource {
        self.envelope.source()
    }

    /// This origin bound to the durable run its dispatcher is bound to.
    pub(crate) const fn with_bound_run(mut self, run: Option<EntityId>) -> Self {
        self.bound_run = run;
        self
    }

    /// The durable code run the dispatcher bound this origin to, if any.
    pub(crate) const fn bound_run(&self) -> Option<EntityId> {
        self.bound_run
    }
}

type MachineSignFn<'a> = dyn Fn(&[u8]) -> crate::Result<[u8; 64]> + Send + Sync + 'a;
