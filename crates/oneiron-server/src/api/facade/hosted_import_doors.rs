//! The host doors of the hosted import's verbs (ARCH-0027 #hosted-import;
//! substrate behind grants): `vault.imports.get` and `vault.imports.cancel`.
//! Each admits the vault owner under its proof, or a person or agent on a
//! verified slip of its own, whose Steward grant the engine checks: `read`
//! at the read, `delete` in the cancel's own write. Anyone else keeps the
//! owner refusal.
//!
//! Each lists no row (`host_door_lists`): the job lives in a side table,
//! which holds none.
//!
//! Beside them, `vault.imports.hook_transcript` (census L10-17, Engine
//! ruling 17 Nov 06:50): the owner on its proof, or the actor its credential
//! binds, whose live Grant naming the verb the engine checks at the door's
//! admission, before the import and in each of its writers, lands one Claude
//! Code session. It lists no row: its answer names the session's
//! CONVERSATION by id. `vault.imports.hook_transcript_part` (FIX
//! HOOK-TRANSCRIPT-IMPORT-PAST-CARRIER) carries the owner's request too long
//! for one call over the socket in parts, staged in the server's memory
//! (`server::hook_transcript_uploads`). It is a transport-only row
//! (`host_door_transport_only`): no verb hook sees a part. Its last part
//! runs the whole request as one call of `vault.imports.hook_transcript`,
//! whose admission, hooks and record scope judge it as they judge any call
//! of that verb. The owner alone stages: any other caller's calls ride
//! HTTP, which takes the whole request in one call.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::ingest::history::{
    HistoryImportCaller, HookTranscriptImportRequest, HookTranscriptImportView,
    HookTranscriptPartRequest, HookTranscriptPartView, HostedImportCancel, HostedImportCanceller,
    HostedImportLookup, HostedImportView, hosted_import_cancel_as, hosted_import_get_as_owner,
    hosted_import_get_as_reader,
};
use oneiron::memory::{MemoryError, MemoryResult};

use super::{FacadeApiError, FacadeCall, FacadeCallOutput};

use super::host_doors::support::{Listed, internal, owner_proof};
use super::legal_hold_doors::as_owner_naming;
use super::substrate_read_doors::{as_reader, substrate_reader};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use crate::server::hook_transcript_uploads::{LandingRun, Staged};

/// Who may cancel a hosted import: the owner under its proof (`Some`), or a
/// person or agent on its own verified slip (`None`), whose Steward `delete`
/// grant the cancel's writer checks. The same admission as a substrate read.
pub(super) fn import_canceller(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> oneiron::memory::MemoryResult<Option<AuthenticatedOwner>> {
    substrate_reader(server, auth, verb)
}

/// The caller of a cancel, resolved before the write.
enum Canceller {
    Owner(AuthenticatedOwner),
    Holder(EntityId),
}

/// `vault.imports.get`.
pub(crate) async fn vault_imports_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HostedImportLookup,
) -> Listed<Option<HostedImportView>> {
    const VERB: &str = "vault.imports.get";
    match substrate_reader(server, auth, VERB) {
        Ok(Some(_)) => {
            as_owner_naming(
                server,
                auth,
                VERB,
                move |server, owner| hosted_import_get_as_owner(server.vault(), owner, &input),
                |_| Vec::new(),
            )
            .await
        }
        Ok(None) => {
            let answer = as_reader(server, auth, VERB, move |server, reader| {
                hosted_import_get_as_reader(server.vault(), reader, &input)
            })
            .await;
            (answer, Vec::new())
        }
        Err(refusal) => (Err(refusal), Vec::new()),
    }
}

/// `vault.imports.cancel`.
pub(crate) async fn vault_imports_cancel(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HostedImportLookup,
) -> Listed<Option<HostedImportCancel>> {
    const VERB: &str = "vault.imports.cancel";
    let canceller = match import_canceller(server, auth, VERB) {
        Ok(Some(owner)) => Canceller::Owner(owner),
        Ok(None) => match super::facade_actor(server, auth) {
            Ok((holder, _)) => Canceller::Holder(holder),
            Err(error) => return (Err(error.into_memory_error()), Vec::new()),
        },
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    let server = Arc::clone(server);
    let answer = super::clock_ingress::run_blocking(move || {
        let canceller = match &canceller {
            Canceller::Owner(owner) => HostedImportCanceller::Owner(owner),
            Canceller::Holder(holder) => HostedImportCanceller::Holder(*holder),
        };
        hosted_import_cancel_as(server.vault(), canceller, &input)
    })
    .await
    .map_err(|_| internal(VERB))
    .and_then(|answer| answer);
    (answer, Vec::new())
}

/// Who lands a hook transcript: the owner on its proof, or the actor its
/// credential binds, whose live Grant naming `vault.imports.hook_transcript`
/// the engine checks. The agent's credential travels with it so the engine can
/// judge a hand-over whose folder is bound against that credential.
pub(in crate::api::facade) enum TranscriptImporter {
    Owner(AuthenticatedOwner),
    Agent(EntityId, Option<oneiron::authority::VerifiedSlip>),
}

/// `vault.imports.hook_transcript`'s caller, as `door_admits` checks it first
/// and the door acts under it: the owner's proof, else the credential's own
/// actor, whose live Grant naming the verb the engine judges here, before any
/// verb hook sees the call; a credential bound to none keeps the owner
/// refusal.
pub(in crate::api::facade) fn transcript_importer(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<TranscriptImporter> {
    match owner_proof(auth, server, verb) {
        Ok(owner) => Ok(TranscriptImporter::Owner(owner)),
        Err(refusal) => {
            let (actor, _class) = super::owner_binding::facade_caller_or(server, auth, || refusal)?;
            server
                .vault()
                .admit_hook_transcript_caller(HistoryImportCaller::GrantedAgent(actor))?;
            Ok(TranscriptImporter::Agent(
                actor,
                auth.verified_slip().cloned(),
            ))
        }
    }
}

/// `vault.imports.hook_transcript`.
pub(crate) async fn vault_imports_hook_transcript(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HookTranscriptImportRequest,
) -> Listed<HookTranscriptImportView> {
    const VERB: &str = "vault.imports.hook_transcript";
    let importer = match transcript_importer(server, auth, VERB) {
        Ok(importer) => importer,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    let server = Arc::clone(server);
    let answer = super::clock_ingress::run_blocking(move || {
        let (caller, presented) = match &importer {
            TranscriptImporter::Owner(owner) => (HistoryImportCaller::Owner(owner), None),
            TranscriptImporter::Agent(agent, presented) => (
                HistoryImportCaller::GrantedAgent(*agent),
                presented.as_ref(),
            ),
        };
        server
            .vault()
            .import_hook_transcript(caller, presented, &input)
    })
    .await
    .map_err(|_| internal(VERB))
    .and_then(|answer| answer);
    (answer, Vec::new())
}

/// The verb a staged upload's whole request is a call of.
pub(crate) const HOOK_TRANSCRIPT_VERB: &str = "vault.imports.hook_transcript";

/// The row that stages one.
const HOOK_TRANSCRIPT_PART_VERB: &str = "vault.imports.hook_transcript_part";

/// Staged text that is not `vault.imports.hook_transcript`'s input.
const ERR_STAGED_REQUEST: &str =
    "the staged hook transcript request is not vault.imports.hook_transcript's input";

/// What one part of an upload leaves for its transport: the answer of a
/// part that keeps the upload open, or the run of its landing.
pub(crate) enum HookTranscriptStaged<'a> {
    Open(HookTranscriptPartView),
    Landing(LandingRun<'a>, serde_json::Value),
}

/// Stages `input` for the owner on its proof under `auth`: the upload's
/// holder is the proof's own person, once the proof is this vault's. A last
/// part hands back its landing's run and the whole request as JSON, which
/// the transport runs as one call of [`HOOK_TRANSCRIPT_VERB`] and answers
/// through [`hook_transcript_landing_view`]. Staged text that is not that
/// verb's input ends the upload, refused by name before any call runs.
///
/// # Errors
///
/// The owner refusal of any other caller; the uploads' refusal of the part;
/// staged text that is not [`HOOK_TRANSCRIPT_VERB`]'s input.
pub(crate) fn stage_hook_transcript_part<'a>(
    server: &'a SyncServer,
    auth: &CoreAuth,
    input: &HookTranscriptPartRequest,
) -> MemoryResult<HookTranscriptStaged<'a>> {
    let owner = owner_proof(auth, server, HOOK_TRANSCRIPT_PART_VERB)?;
    let holder = owner.actor_for_read(server.vault())?;
    let run = match server.hook_transcript_uploads.stage(holder, input)? {
        Staged::Open(staged) => {
            return Ok(HookTranscriptStaged::Open(HookTranscriptPartView {
                upload: input.upload.clone(),
                staged,
                imported: None,
            }));
        }
        Staged::Whole(run) => run,
    };
    let request = serde_json::from_str::<serde_json::Value>(&run.text)
        .map_err(|error| error.to_string())
        .and_then(|request| {
            oneiron::task_verb::sdk::validate_input(HOOK_TRANSCRIPT_VERB, &request)
                .map(|()| request)
                .map_err(|refusal| refusal.message)
        });
    match request {
        Ok(request) => Ok(HookTranscriptStaged::Landing(run, request)),
        Err(error) => {
            run.answered(false);
            Err(MemoryError::bad_request(format!(
                "{ERR_STAGED_REQUEST}: {error}"
            )))
        }
    }
}

/// The part's answer once its landing's call answered `imported`, the view
/// that call's post hooks left, as it came; the run ends the upload.
pub(crate) fn hook_transcript_landing_view(
    run: LandingRun<'_>,
    upload: &str,
    imported: serde_json::Value,
) -> HookTranscriptPartView {
    let staged = run.staged();
    run.answered(false);
    HookTranscriptPartView {
        upload: upload.to_owned(),
        staged,
        imported: Some(imported),
    }
}

/// `vault.imports.hook_transcript_part`, a transport-only row: the owner,
/// on its proof, stages one part of a `vault.imports.hook_transcript`
/// request, and no verb hook sees it. The last part runs the whole request
/// as one call of that verb under this call's credential and the invocation
/// its upload minted (`FacadeCall::staged_landing`), through the one verb
/// table, so that verb's admission, input check, hooks and record scope
/// judge it; the view its post hooks leave comes back as `imported`, the
/// rows it was derived from with it. A call its hooks hold on an ask keeps
/// the upload: the last part sent again runs the same call again, which
/// finds its ask and lands at most once.
pub(crate) async fn vault_imports_hook_transcript_part(
    server: &Arc<SyncServer>,
    call: &FacadeCall<'_>,
    input: HookTranscriptPartRequest,
) -> Result<FacadeCallOutput, FacadeApiError> {
    let (run, request) = match stage_hook_transcript_part(server, call.auth(), &input)? {
        // Derived from no row.
        HookTranscriptStaged::Open(view) => {
            return Ok(FacadeCallOutput {
                value: super::facade_output(view)?,
                rows: Some(Vec::new()),
                hook_notice: false,
            });
        }
        HookTranscriptStaged::Landing(run, request) => (run, request),
    };
    let landing = call.staged_landing(run.invocation);
    let answer = super::call_verb(server, &landing, HOOK_TRANSCRIPT_VERB, Ok(request)).await;
    match answer {
        Ok(output) => {
            let view = hook_transcript_landing_view(run, &input.upload, output.value);
            Ok(FacadeCallOutput {
                value: super::facade_output(view)?,
                rows: output.rows,
                hook_notice: output.hook_notice,
            })
        }
        Err(refusal) => {
            run.answered(refusal.held_on_ask());
            Err(refusal)
        }
    }
}
