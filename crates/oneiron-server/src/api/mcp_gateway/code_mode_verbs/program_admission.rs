//! A queued browser program admission's run (CUA E8b; DESIGN-2 "The
//! Coach", row E8). The host's admission worker hands a claimed job here
//! with the caller its sources were captured under. That caller is
//! established again now: a native agent by its grant, a credential caller
//! by the binding its request was admitted on, verified again against
//! current authority (`kept_instrument_auth`), and for a connector its
//! registration as it stands now, at the ceiling it was admitted at, and a
//! person with no credential only as this vault's live recorded owner,
//! proved afresh at each call (`managed_owner_proof`). No other caller is
//! acted as: never the host, a stand-in owner or the Coach.
//!
//! The job's run is a new run, the job's own: each call takes the write
//! origin its leased try binds (`HostSelfDispatcher::program_admission_origin`)
//! and goes through the run's guest door as that caller, the row's hooks,
//! gates and grants included. Its first call re-opens the pre-press page:
//! the proposal's steps, filled from its own arguments, in one batch no
//! model answers. Only a batch that ended Done goes on to the library's
//! propose door, which checks the page itself, replays the program on a
//! fresh guest with no model and files it, placed by rule alone, the filing
//! kept against the job in its own write. The run captures no evidence: a
//! replay is no source run. Its seat ends with it, whatever it came to.

use super::*;
use oneiron::WriteActor;
use oneiron::attempt_queue::AttemptRecord;
use oneiron::authority::InvocationSlipBinding;
use oneiron::browser_library::{
    AdmissionCaller, CallerUnavailable, ProgramAdmissionJob, ProgramAdmissionOutcome,
    SolvedRunEvidence, admission_readiness,
};
use oneiron::claim::CallerLocality;
use oneiron::code_run::HostSelfDispatcher;
use oneiron::runtime_hooks::verb::{
    VerbAskCredentialRef, VerbAskCredentialSource, VerbAskDoor, VerbAskRefusal,
};
use oneiron_browser::{BatchInput, ProposeOutput, SubgoalStatus};

/// The caller one admission job acts as, established at its start.
enum JobCaller {
    /// A native agent: its own surface on this device, as its run's door.
    Agent(WriteActor),
    /// A connector's credential, through its registration as it stands now.
    Mcp(McpCallContext),
    /// This vault's live recorded owner, with no credential: proved afresh
    /// at each call (`managed_owner_proof`), on the owner's surface on this
    /// device under the job's run origin.
    Owner(WriteActor),
    /// A facade credential: established again at each call, at the verb's
    /// own door.
    Facade {
        reference: VerbAskCredentialRef,
        witness: InvocationSlipBinding,
        writer: WriteActor,
    },
}

impl JobCaller {
    fn actor(&self) -> WriteActor {
        match self {
            Self::Agent(actor) | Self::Owner(actor) => *actor,
            Self::Mcp(context) => WriteActor::new(context.actor_ref, context.actor_class),
            Self::Facade { writer, .. } => *writer,
        }
    }
}

impl RunGuests {
    /// Runs the admission job `job` (id `job_id`, leased as `leased`) as
    /// `caller`, its sources' caller as they stand now (CUA E8b): what it
    /// came to. A caller that does not stand now acts on nothing, and only
    /// once it stands is the proposal's readiness against `evidence` judged
    /// (FIX 10720): a revocation surfaces first.
    pub(crate) fn admit_program(
        server: &Arc<SyncServer>,
        runtime: &tokio::runtime::Handle,
        leased: &AttemptRecord,
        job_id: oneiron::EntityId,
        job: &ProgramAdmissionJob,
        caller: &AdmissionCaller,
        evidence: &[SolvedRunEvidence],
    ) -> ProgramAdmissionOutcome {
        let caller = match established(server, job_id, caller) {
            Ok(caller) => caller,
            Err(cause) => return ProgramAdmissionOutcome::CredentialUnavailable { cause },
        };
        if let Some(lacking) = admission_readiness(job, evidence) {
            return lacking;
        }
        let guests = Self {
            browser: RunBrowser::new(server, job_id),
            desktop: None,
            refused: browser_guest::KeptRefusal::default(),
            planner: None,
            payer: None,
            admission: Some(job.filing(job_id)),
            admission_lease: Some(leased.clone()),
        };
        let outcome = guests.reconstruct_and_propose(server, runtime, leased, &caller, job);
        drop(guests);
        // The job's run ends here: its seat goes, and its run-bound secrets
        // with it.
        server.browser_seats.end_run(job_id);
        outcome
    }

    /// Re-opens the proposal's pre-press page with no model, then proposes
    /// it through the library's door, on this run as `caller`.
    fn reconstruct_and_propose(
        &self,
        server: &Arc<SyncServer>,
        runtime: &tokio::runtime::Handle,
        leased: &AttemptRecord,
        caller: &JobCaller,
        job: &ProgramAdmissionJob,
    ) -> ProgramAdmissionOutcome {
        let refused = |code: &str| ProgramAdmissionOutcome::BrowserRefused {
            code: code.to_owned(),
        };
        let proposal = &job.proposal;
        let program = WorkflowProgram {
            subgoal: proposal.subgoal.clone(),
            params: proposal.params.clone(),
            secret_params: Vec::new(),
            steps: proposal.steps.clone(),
            postcondition: proposal.postcondition.clone(),
        };
        let (steps, checks) = match program.fill(&proposal.args) {
            Ok(filled) => filled,
            Err(error) => return refused(error.code()),
        };
        let batch = BatchInput {
            subgoal: Some(proposal.subgoal.clone()),
            steps,
            base: None,
            until_ms: None,
            no_model: true,
        };
        let Ok(input) = serde_json::to_value(batch) else {
            return refused("admission_batch_encode");
        };
        let verb = AgentVerb::SelfBrowserBatch;
        let output = match self.job_call(server, runtime, leased, caller, verb, input) {
            Ok(output) => output,
            Err(outcome) => return outcome,
        };
        let status = output
            .get("status")
            .and_then(|status| serde_json::from_value::<SubgoalStatus>(status.clone()).ok());
        match status {
            Some(SubgoalStatus::Done) => {}
            Some(status) => return ProgramAdmissionOutcome::ReconstructionStopped { status },
            None => return refused("admission_batch_unread"),
        }
        // The filled postcondition on the reconstructed page (FIX 10721),
        // read as propose's own Solved check reads its expects: a Done batch
        // whose page misses checks ends here, proposing nothing. Only the
        // fills this side reproduces are read here: propose slots secret
        // operands against the proposing session's driver, which this job
        // has none of, so a proposal carrying typed secret arguments, or
        // naming a seed candidate whose own program stands in for the
        // proposal's, is read by propose itself as before, and nothing it
        // would have admitted ends here.
        let own_read = proposal.secret_args.is_empty() && proposal.candidate.is_none();
        let mut unmet = Vec::new();
        if own_read {
            for (index, check) in checks.iter().enumerate() {
                let Ok(input) = serde_json::to_value(check) else {
                    return refused("admission_expect_encode");
                };
                let verb = AgentVerb::SelfBrowserExpect;
                let output = match self.job_call(server, runtime, leased, caller, verb, input) {
                    Ok(output) => output,
                    Err(outcome) => return outcome,
                };
                match output.get("met").and_then(|met| met.as_bool()) {
                    Some(true) => {}
                    Some(false) => unmet.push(index),
                    None => return refused("admission_expect_unread"),
                }
            }
        }
        if !unmet.is_empty() {
            return ProgramAdmissionOutcome::PostconditionUnmet { unmet };
        }
        let Ok(input) = serde_json::to_value(proposal) else {
            return refused("admission_proposal_encode");
        };
        let verb = AgentVerb::SelfBrowserLibraryPropose;
        let output = match self.job_call(server, runtime, leased, caller, verb, input) {
            Ok(output) => output,
            Err(outcome) => return outcome,
        };
        let Ok(answer) = serde_json::from_value::<ProposeOutput>(output) else {
            return refused("admission_propose_unread");
        };
        if !answer.admitted {
            return ProgramAdmissionOutcome::Refused {
                check: answer.refused_by,
                unmet: answer.unmet,
            };
        }
        match answer.workflow.as_deref().map(oneiron::EntityId::from_hex) {
            Some(Ok(workflow)) => ProgramAdmissionOutcome::Admitted {
                workflow,
                superseded: answer.superseded,
            },
            _ => refused("admission_propose_unread"),
        }
    }

    /// One call of the job's run as `caller`, under the write origin its
    /// leased try binds now and a fresh invocation, through the run's guest
    /// door and its hooks: its output, or what the job came to.
    fn job_call(
        &self,
        server: &Arc<SyncServer>,
        runtime: &tokio::runtime::Handle,
        leased: &AttemptRecord,
        caller: &JobCaller,
        verb: AgentVerb,
        input: Value,
    ) -> Result<Value, ProgramAdmissionOutcome> {
        let refused = |code: String| ProgramAdmissionOutcome::BrowserRefused { code };
        let actor = caller.actor();
        let origin =
            HostSelfDispatcher::program_admission_origin(&server.vault, actor, leased, verb)
                .map_err(|error| refused(error.code))?;
        let invocation = InvocationId::mint();
        let call = SelfAgentVerbCall { verb, input };
        let answered = match caller {
            JobCaller::Agent(agent) => {
                let memory = server
                    .vault
                    .memory(agent.entity_ref(), agent.actor_class())
                    .at(CallerLocality::OnDevice)
                    .with_host_origin(origin.clone())
                    .with_invocation(invocation);
                let asker = VerdictAsker::Agent(*agent, None);
                self.call(
                    server,
                    runtime,
                    &call,
                    &origin,
                    &memory,
                    asker,
                    agent.entity_ref(),
                )
            }
            JobCaller::Owner(owner) => {
                // The owner is proved again at each call; once they are not
                // the live recorded owner, the job acts no more.
                if owner_proof(server, *owner).is_none() {
                    return Err(ProgramAdmissionOutcome::CredentialUnavailable {
                        cause: CallerUnavailable::ContextUnavailable,
                    });
                }
                let memory = server
                    .vault
                    .memory(owner.entity_ref(), owner.actor_class())
                    .at(CallerLocality::OnDevice)
                    .with_host_origin(origin.clone())
                    .with_invocation(invocation);
                let asker = VerdictAsker::Agent(*owner, None);
                self.call(
                    server,
                    runtime,
                    &call,
                    &origin,
                    &memory,
                    asker,
                    owner.entity_ref(),
                )
            }
            JobCaller::Mcp(context) => {
                // The connector's binding and live credential at each call,
                // as code mode's browser door checks them.
                mcp_admit_host_verb(context, verb)
                    .and_then(|()| mcp_execute_code_gate(server, context))
                    .map_err(|error| refused(error.kind.to_string()))?;
                let memory = crate::api::mcp_credential_memory(
                    &server.vault,
                    context.actor.auth.as_ref(),
                    context.actor_ref,
                    context.actor_class,
                )
                .at(context.locality())
                .with_invocation(invocation);
                let asker = VerdictAsker::Connector(McpCallContext {
                    invocation: None,
                    hook_ask: None,
                    ..context.clone()
                });
                self.call(
                    server,
                    runtime,
                    &call,
                    &origin,
                    &memory,
                    asker,
                    context.actor_ref,
                )
            }
            JobCaller::Facade {
                reference,
                witness,
                writer,
            } => {
                let auth = kept_auth(server, reference, witness, Some(verb.as_str()))
                    .map_err(|cause| ProgramAdmissionOutcome::CredentialUnavailable { cause })?;
                // The facade's own row admission, run again at each call
                // (FIX 10715), as the MCP arm's gates run again: the
                // credential still binds the writer its door established,
                // and it holds the verb's dispatch scope (both job verbs
                // are Write rows, whose require also holds the record
                // scope unrestricted). Its hooks run in the call below.
                if auth.principal_ref() != Some(writer.entity_ref().to_hex().as_str())
                    || auth.actor_class() != Some(writer.actor_class().gate_actor_class())
                {
                    return Err(ProgramAdmissionOutcome::CredentialUnavailable {
                        cause: CallerUnavailable::CredentialChanged,
                    });
                }
                auth.require(crate::auth::CoreScope::Write)
                    .map_err(|error| refused(error.code().as_str().to_owned()))?;
                let memory = crate::api::credential_memory(
                    &server.vault,
                    Some(&auth),
                    writer.entity_ref(),
                    writer.actor_class(),
                )
                .at(auth.locality())
                .with_host_origin(origin.clone())
                .with_invocation(invocation);
                let asker = VerdictAsker::Credential(auth.clone(), *writer);
                self.call(
                    server,
                    runtime,
                    &call,
                    &origin,
                    &memory,
                    asker,
                    writer.entity_ref(),
                )
            }
        };
        match answered {
            Ok(Ok(answer)) => Ok(answer.output),
            Ok(Err(refusal)) => Err(refused(refusal.code)),
            // By kind only: an engine error can quote the vault.
            Err(error) => Err(refused(format!("engine_error:{:?}", error.kind()))),
        }
    }
}

/// `caller` as it stands now (CUA E8b, CALLS row "source kinds"), or why
/// it does not.
fn established(
    server: &Arc<SyncServer>,
    job_id: oneiron::EntityId,
    caller: &AdmissionCaller,
) -> Result<JobCaller, CallerUnavailable> {
    match caller {
        AdmissionCaller::Agent(agent) => {
            // The agent's grant, read again now.
            let stands = server
                .vault
                .gate_actor_ceiling_exists(
                    agent.actor_class().gate_actor_class(),
                    &agent.entity_ref().to_hex(),
                )
                .map_err(|_| CallerUnavailable::CredentialUnavailable)?;
            if !stands {
                return Err(CallerUnavailable::ScopeRefused);
            }
            Ok(JobCaller::Agent(*agent))
        }
        AdmissionCaller::Credential {
            actor,
            reference,
            witness,
        } => {
            // A managed vault's attested owner kept no binding (FIX 11063):
            // he is acted for as the person he is, as a person with no
            // credential is, only while this vault records him as its live
            // owner.
            if let VerbAskCredentialSource::AttestedOwner { holder } = reference.instrument.source {
                attested_owner_source(server, reference, holder, actor, witness.as_ref())?;
                return match owner_proof(server, *actor) {
                    Some(_) => Ok(JobCaller::Owner(*actor)),
                    None => Err(CallerUnavailable::ContextUnavailable),
                };
            }
            let witness = witness
                .as_ref()
                .ok_or(CallerUnavailable::InstrumentNotHeld)?;
            match &reference.door {
                VerbAskDoor::Mcp {
                    connection,
                    ceiling,
                } => {
                    let auth = kept_auth(server, reference, witness, None)?;
                    let context = connector(server, job_id, auth, connection, ceiling)?;
                    if context.actor_ref != actor.entity_ref()
                        || context.actor_class != actor.actor_class()
                    {
                        return Err(CallerUnavailable::CredentialChanged);
                    }
                    Ok(JobCaller::Mcp(context))
                }
                // Only the attested owner comes by his own stream.
                VerbAskDoor::McpOwner { .. } => Err(CallerUnavailable::CredentialChanged),
                // A room turn's door is not rebuilt for a job.
                VerbAskDoor::Facade { room: Some(_) } => Err(CallerUnavailable::ContextUnavailable),
                VerbAskDoor::Facade { room: None } => {
                    let auth = kept_auth(server, reference, witness, None)?;
                    // The facade binds its writes to the credential's own
                    // holder.
                    if auth.principal_ref() != Some(actor.entity_ref().to_hex().as_str())
                        || auth.actor_class() != Some(actor.actor_class().gate_actor_class())
                    {
                        return Err(CallerUnavailable::CredentialChanged);
                    }
                    Ok(JobCaller::Facade {
                        reference: reference.clone(),
                        witness: witness.clone(),
                        writer: *actor,
                    })
                }
            }
        }
        // A person is acted for only as this vault's live recorded owner.
        AdmissionCaller::Person(person) => match owner_proof(server, *person) {
            Some(_) => Ok(JobCaller::Owner(*person)),
            None => Err(CallerUnavailable::ContextUnavailable),
        },
        AdmissionCaller::Unsupported => Err(CallerUnavailable::ContextUnavailable),
    }
}

/// Whether an attested owner's kept `reference` is his own source's: it
/// names `actor`, a human, in this vault, and no slip binding stands beside
/// it. His standing is judged at use, as a person's is.
fn attested_owner_source(
    server: &SyncServer,
    reference: &VerbAskCredentialRef,
    holder: oneiron::EntityId,
    actor: &WriteActor,
    witness: Option<&InvocationSlipBinding>,
) -> Result<(), CallerUnavailable> {
    if holder != actor.entity_ref()
        || actor.actor_class() != oneiron::EdgeActorClass::Human
        || witness.is_some()
    {
        return Err(CallerUnavailable::CredentialChanged);
    }
    match server.vault.authority_vault_id() {
        Ok(Some(vault)) if vault == reference.instrument.vault => Ok(()),
        Ok(_) => Err(CallerUnavailable::CredentialChanged),
        Err(_) => Err(CallerUnavailable::CredentialUnavailable),
    }
}

/// The owner's proof for `person`, made afresh: a person this vault records
/// as its owner, while that owner is live, as a managed owner's request is
/// proved. `None` for anyone else.
fn owner_proof(
    server: &SyncServer,
    person: WriteActor,
) -> Option<oneiron::consent::AuthenticatedOwner> {
    if person.actor_class() != oneiron::EdgeActorClass::Human {
        return None;
    }
    crate::api::managed_owner_proof(server, person.entity_ref())
        .ok()
        .flatten()
}

/// The credential `reference` names, from the binding `witness` its
/// request was admitted on, verified again now, where its caller sat.
fn kept_auth(
    server: &SyncServer,
    reference: &VerbAskCredentialRef,
    witness: &InvocationSlipBinding,
    door: Option<&str>,
) -> Result<crate::auth::CoreAuth, CallerUnavailable> {
    let locality = if reference.on_device {
        CallerLocality::OnDevice
    } else {
        CallerLocality::OffDevice
    };
    crate::code_consent_host::kept_instrument_auth(
        server,
        &reference.instrument,
        Some(witness),
        door,
    )
    .map(|auth| auth.at(locality))
    .map_err(unavailable)
}

/// A connector's registration whose STREAM connection is `connection`, as
/// it stands now, never a saved copy: at the `ceiling` its call was
/// admitted at, holding `auth`, its credential verified again.
fn connector(
    server: &Arc<SyncServer>,
    job_id: oneiron::EntityId,
    auth: crate::auth::CoreAuth,
    connection: &str,
    ceiling: &[u8; 32],
) -> Result<McpCallContext, CallerUnavailable> {
    let now = server
        .vault
        .capability_slip_now()
        .map_err(|_| CallerUnavailable::CredentialUnavailable)?;
    let registry = server.mcp_registry.blocking_lock();
    let resolved = registry.resolve_connection(connection, now, |class, actor| {
        server
            .vault
            .gate_actor_ceiling_exists(class, actor)
            .unwrap_or(false)
    });
    drop(registry);
    let mut actor = resolved.map_err(registration_unavailable)?;
    if !crate::code_consent_host::ceiling_holds(
        ceiling,
        &crate::api::mcp_gateway::verb_hooks::mcp_adapter_ceiling(&actor),
    ) {
        return Err(CallerUnavailable::ScopeRefused);
    }
    crate::api::mcp_gateway::actor_dispatch::mcp_proof_admits(server, &actor, &auth)
        .map_err(|_| CallerUnavailable::CredentialChanged)?;
    actor.auth = Some(auth);
    let landing = crate::api::write_facet::landing_facet(
        &server.vault,
        None,
        &actor.scope.facets,
        actor.scope.facet_ref,
    );
    Ok(McpCallContext {
        actor,
        mode: McpSurfaceMode::ToolFirst,
        request_id: format!("browser-admission-{}", job_id.to_hex()),
        landing,
        invocation: None,
        hook_ask: None,
        off_record_session: None,
        room_turn: None,
        drain: None,
        forwarded: None,
        client_surface: None,
    })
}

/// Why a kept credential did not verify again, as a job's receipt says it.
const fn unavailable(refusal: VerbAskRefusal) -> CallerUnavailable {
    match refusal {
        VerbAskRefusal::CredentialMissing => CallerUnavailable::CredentialMissing,
        VerbAskRefusal::CredentialRevoked => CallerUnavailable::CredentialRevoked,
        VerbAskRefusal::CredentialExpired => CallerUnavailable::CredentialExpired,
        VerbAskRefusal::CredentialChanged => CallerUnavailable::CredentialChanged,
        VerbAskRefusal::CredentialUnavailable => CallerUnavailable::CredentialUnavailable,
        VerbAskRefusal::ScopeRefused => CallerUnavailable::ScopeRefused,
        VerbAskRefusal::ContextUnavailable => CallerUnavailable::ContextUnavailable,
        // A person no longer this vault's live owner is acted for not at
        // all, as a person with no credential is.
        VerbAskRefusal::OwnerNotLive => CallerUnavailable::ContextUnavailable,
    }
}

/// Why a connector's registration no longer stands, as a job's receipt
/// says it. One this process does not hold, as after a restart, is
/// unavailable: it is never rebuilt from a saved copy.
const fn registration_unavailable(
    error: crate::mcp::McpConnectorActorResolutionError,
) -> CallerUnavailable {
    use crate::mcp::McpConnectorActorResolutionError as Unresolved;
    match error {
        Unresolved::UnknownCredential => CallerUnavailable::CredentialUnavailable,
        Unresolved::RevokedCredential => CallerUnavailable::CredentialRevoked,
        Unresolved::ExpiredCredential => CallerUnavailable::CredentialExpired,
        Unresolved::MissingActorCeiling => CallerUnavailable::ScopeRefused,
    }
}
