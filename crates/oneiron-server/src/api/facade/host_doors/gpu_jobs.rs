//! The customer GPU job doors (row L10-31; CROSS-ARCH-0023 lifecycle, C2):
//! `vault.gpu.jobs.quote`, `.start`, `.status`, `.list`, `.cancel` and
//! `.allow` over this host's `[gpu_jobs]` offers and registered backends.
//! The engine decides (`oneiron::gpu_job`); a door reads the offer and
//! backend, builds the job's run, and calls it. Quotes, status and the list
//! are reads: the owner under their own proof, or an agent whose own Grant
//! names the verb. Start (and resume) and cancel are the owner's acts, or an
//! agent's under its own Grant within the per-job maximum the owner set
//! beside it with `allow` (RULING L10-31-STARTER = B); the engine judges the
//! agent again in the act's own write. Pressing start on the quote is the
//! owner's showing of its maximum (C2 01). Job records live in side tables,
//! which hold no entity row: the doors list none.

use std::sync::Arc;

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::gpu_job::{
    GpuJobActor, GpuJobAgent, GpuJobAllowRequest, GpuJobAllowanceView, GpuJobError, GpuJobList,
    GpuJobListRequest, GpuJobQuote, GpuJobQuoteRequest, GpuJobQuoteTerms, GpuJobRef,
    GpuJobStartRequest, GpuJobStatus, GpuJobVerb,
};
use oneiron::llm::run_admission::ResumeRefused;
use oneiron::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND, MemoryError,
    MemoryResult,
};

use super::super::FacadeApiError;
use super::support::{Listed, credential_listing, owner_proof};
use crate::auth::CoreAuth;
use crate::gpu_host::{GpuHostError, job_admission, now_ms, offer_with_backend};
use crate::server::SyncServer;

impl From<GpuHostError> for MemoryError {
    fn from(error: GpuHostError) -> Self {
        match error {
            GpuHostError::NoOffer(_) => Self::new(MEMORY_CODE_NOT_FOUND, error.to_string(), &[]),
            GpuHostError::NoBackend(_) => Self::new(
                MEMORY_CODE_INVALID_STATE,
                error.to_string(),
                &["The host operator registers a backend for this offer's provider."],
            ),
            GpuHostError::Job(error) => error.into(),
        }
    }
}

/// A GPU job door's caller, as the engine admitted it: the owner under
/// their own proof, or an agent under its own handle.
enum DoorCaller {
    Owner(AuthenticatedOwner),
    Agent(GpuJobAgent),
}

impl DoorCaller {
    fn actor(&self) -> GpuJobActor<'_> {
        match self {
            Self::Owner(owner) => GpuJobActor::Owner(owner),
            Self::Agent(agent) => GpuJobActor::Agent(agent),
        }
    }
}

/// `act` off the runtime on the caller's own handle, after the engine admits
/// the caller to `verb`: the caller's own owner proof when its credential is
/// owner-grade, its agent handle otherwise.
async fn gpu_door<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: GpuJobVerb,
    act: impl FnOnce(&SyncServer, &DoorCaller) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let caller = match crate::api::facade::facade_actor(server, auth)
        .map_err(FacadeApiError::into_memory_error)
    {
        Ok(caller) => caller,
        Err(error) => return (Err(error), Vec::new()),
    };
    let owner = if auth.is_owner_grade() {
        match owner_proof(auth, server, verb.name()) {
            Ok(owner) => Some(owner),
            Err(error) => return (Err(error), Vec::new()),
        }
    } else {
        None
    };
    credential_listing(
        server,
        auth,
        caller,
        verb.name(),
        move |server, _, memory| {
            memory.gpu_job_admits(owner.as_ref(), verb)?;
            let caller = match owner {
                Some(owner) => DoorCaller::Owner(owner),
                None => DoorCaller::Agent(memory.gpu_job_agent()),
            };
            act(server, &caller)
        },
    )
    .await
}

/// The GPU job rows' early authority check: the engine's admission of the
/// caller for `verb` (the owner's own proof on an owner-grade credential,
/// else an agent's own Grant naming any verb but `allow`), judged before the
/// row's verb hooks fire. The door admits the caller again when it acts.
pub(super) fn gpu_job_caller_admits(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<()> {
    let verb = GpuJobVerb::from_name(verb).ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is not a GPU job verb"),
            &[],
        )
    })?;
    let (actor, class) = crate::api::facade::facade_actor(server, auth)
        .map_err(FacadeApiError::into_memory_error)?;
    let owner = if auth.is_owner_grade() {
        Some(owner_proof(auth, server, verb.name())?)
    } else {
        None
    };
    crate::api::credential_memory(&server.vault, Some(auth), actor, class)
        .at(auth.locality())
        .gpu_job_admits(owner.as_ref(), verb)
}

/// The owner's proof an owner act runs under; the admission already refused
/// any other caller.
fn owner_act(caller: &DoorCaller, verb: GpuJobVerb) -> MemoryResult<&AuthenticatedOwner> {
    match caller {
        DoorCaller::Owner(owner) => Ok(owner),
        DoorCaller::Agent(_) => Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{} takes the vault owner's own proof", verb.name()),
            &["Call it as the vault owner."],
        )),
    }
}

/// `vault.gpu.jobs.quote`: the price of one chunk on one of this host's
/// offers, for a new job or one more chunk of a stopped one. It writes
/// nothing.
pub(crate) async fn vault_gpu_jobs_quote(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GpuJobQuoteRequest,
) -> Listed<GpuJobQuoteTerms> {
    gpu_door(server, auth, GpuJobVerb::Quote, move |server, _| {
        let settings = &server.config.gpu_jobs;
        let offer = settings
            .offer(&input.offer)
            .ok_or_else(|| GpuHostError::NoOffer(input.offer.clone()))?;
        let resume = input
            .resume_job
            .as_deref()
            .map(|job| EntityId::from_hex(job).map_err(|_| GpuJobError::NotFound))
            .transpose()?;
        let quote = offer.offer.quote(
            &input.request(),
            resume,
            settings.default_maximum_secs,
            now_ms(),
        )?;
        Ok(GpuJobQuoteTerms::from(&quote))
    })
    .await
}

/// `vault.gpu.jobs.start`: the owner starts a job on the quote they saw, or
/// an agent within the per-job maximum its Grant carries; with `resume`, the
/// next chunk of the stopped job it names from the checkpoint its stop kept
/// (an agent's own job only). The whole quote is reserved before anything is
/// written or created; an offer whose backend this host has not registered
/// refuses before that.
pub(crate) async fn vault_gpu_jobs_start(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GpuJobStartRequest,
) -> Listed<GpuJobStatus> {
    gpu_door(server, auth, GpuJobVerb::Start, move |server, caller| {
        let quote = GpuJobQuote::try_from(input.quote)?;
        let (offer, connector) = offer_with_backend(server, &quote.offer)?;
        let resume = if input.resume {
            let job = server
                .vault
                .gpu_job(&quote.job)?
                .ok_or(GpuJobError::NotFound)?;
            let stop = job
                .stop
                .ok_or(GpuJobError::Resume(ResumeRefused::NotStopped))?;
            Some(stop.resume)
        } else {
            None
        };
        let admission = job_admission(server, &offer.offer, &quote);
        let job = server.vault.start_gpu_job(
            caller.actor(),
            &offer.offer,
            &quote,
            resume.as_ref(),
            &admission,
            server.gpu_jobs.permits(),
            connector.as_ref(),
            now_ms(),
        )?;
        Ok(GpuJobStatus::from(&job))
    })
    .await
}

/// `vault.gpu.jobs.status`: where one job stands, with its spend against its
/// maximum.
pub(crate) async fn vault_gpu_jobs_status(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GpuJobRef,
) -> Listed<GpuJobStatus> {
    gpu_door(server, auth, GpuJobVerb::Status, move |server, _| {
        let id = input.id()?;
        let job = server.vault.gpu_job(&id)?.ok_or(GpuJobError::NotFound)?;
        Ok(GpuJobStatus::from(&job))
    })
    .await
}

/// `vault.gpu.jobs.list`: every GPU job of the vault, newest first.
pub(crate) async fn vault_gpu_jobs_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: GpuJobListRequest,
) -> Listed<GpuJobList> {
    gpu_door(server, auth, GpuJobVerb::List, move |server, _| {
        let mut jobs = server.vault.gpu_jobs()?;
        jobs.sort_by_key(|job| std::cmp::Reverse(job.created_at_ms));
        Ok(GpuJobList {
            jobs: jobs.iter().map(GpuJobStatus::from).collect(),
        })
    })
    .await
}

/// `vault.gpu.jobs.cancel`: the owner ends their job, or an agent one it
/// started. A live chunk is terminated and settles its billed time; a
/// stopped job gives up its resume. When the provider does not answer, the
/// cancel stands and the worker terminates the chunk on its next steps.
pub(crate) async fn vault_gpu_jobs_cancel(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GpuJobRef,
) -> Listed<GpuJobStatus> {
    gpu_door(server, auth, GpuJobVerb::Cancel, move |server, caller| {
        let id = input.id()?;
        let job = server.vault.gpu_job(&id)?.ok_or(GpuJobError::NotFound)?;
        let (_, connector) = offer_with_backend(server, &job.offer.name)?;
        let job = match server.vault.cancel_gpu_job(
            caller.actor(),
            &id,
            server.gpu_jobs.permits(),
            connector.as_ref(),
            now_ms(),
        ) {
            Ok(job) => job,
            Err(GpuJobError::Connector(_)) => {
                server.vault.gpu_job(&id)?.ok_or(GpuJobError::NotFound)?
            }
            Err(error) => return Err(error.into()),
        };
        Ok(GpuJobStatus::from(&job))
    })
    .await
}

/// `vault.gpu.jobs.allow`: the owner sets the longest run time one GPU job an
/// agent starts under the Grant `grant` may declare (RULING L10-31-STARTER =
/// B); 0 removes it. The Grant must be the one that admits its agent to
/// `vault.gpu.jobs.start` now.
pub(crate) async fn vault_gpu_jobs_allow(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GpuJobAllowRequest,
) -> Listed<GpuJobAllowanceView> {
    gpu_door(server, auth, GpuJobVerb::Allow, move |server, caller| {
        let owner = owner_act(caller, GpuJobVerb::Allow)?;
        let grant = input.grant_id()?;
        let allowance = server
            .vault
            .allow_gpu_jobs(owner, &grant, input.maximum_secs, now_ms())?;
        Ok(GpuJobAllowanceView::of(&grant, allowance.as_ref()))
    })
    .await
}
