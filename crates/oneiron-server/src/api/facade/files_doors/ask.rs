//! `vault.files.sources.ask` (census L2-16 PR 2; ARCH-0027 #files-world:
//! "The owner can ask about a file and get an answer with citations"): the
//! owner's question of one file, or of the files `vault.files.sources.search`
//! finds for it, answered by one call of this host's house chat role and
//! checked in fixed code (`oneiron::task_verb::sdk::files_ask_outcome`).
//!
//! The files' text goes only where the Files world lets it be read: the call
//! carries its notes as sources each rung's destination is admitted to
//! ([`SourceAdmission`], FIX 8714), judged by the release verdict every read
//! that leaves this install takes (`Vault::release_hold_for`). The Files
//! world is read on this install only (`ReadLocation::OneMachine`), so a rung
//! off this install is passed over, and a seat with no rung on this install
//! answers nothing. The call is the owner's, metered on his budget line as
//! any owner call is.
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult};
use oneiron::settings::{ReadDestination, ReleaseHold};
use oneiron::task_verb::sdk::{
    self, FilesAskOutcome, FilesAskText, FilesNoCitedAnswer, FilesSourceAskAnswer,
    FilesSourceAskRequest,
};
use oneiron::write_envelope::WriteActor;
use oneiron::{BudgetExhaustionPolicy, ContentPart, EntityId, LlmMessageRole, LlmRequest, Vault};

use super::super::clock_ingress::run_blocking;
use super::super::host_doors::support::{Listed, internal, owner_proof, refused};
use crate::ai_host::CHAT_ROLE;
use crate::api::ai::chat::{chat_request, text_message};
use crate::auth::CoreAuth;
use crate::models::{SourceAdmission, SourceOffer};
use crate::server::{SyncServer, blocking};

const VERB: &str = "vault.files.sources.ask";

/// `vault.files.sources.ask`: the owner's question, answered with citations
/// that hold, or with none. With no named file it runs
/// `vault.files.sources.search` first and reads the first files with text
/// that it found. It lists the search's rows and the notes it read.
pub(crate) async fn vault_files_sources_ask(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FilesSourceAskRequest,
) -> Listed<FilesSourceAskAnswer> {
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    let (searched, mut rows) = match sdk::files_ask_search(&input) {
        Some(search) => match super::vault_files_sources_search(server, auth, search).await {
            (Ok(answer), rows) => (Some(answer), rows),
            (Err(refusal), _) => return refused(refusal),
        },
        None => (None, Vec::new()),
    };
    let query = input.query.clone();
    let hits = searched
        .as_ref()
        .map(|answer| answer.hits.clone())
        .unwrap_or_default();
    let reader = Arc::clone(server);
    let read_owner = owner.clone();
    let texts = match run_blocking(move || {
        sdk::files_ask_read(reader.vault(), &read_owner, &input, searched.as_ref())
    })
    .await
    {
        Ok(Ok(texts)) => texts,
        Ok(Err(refusal)) => return refused(refusal),
        Err(_) => return refused(internal(VERB)),
    };
    rows.extend(texts.iter().map(|read| read.file.note));
    let read = texts.iter().map(|read| read.file.clone()).collect();
    if texts.is_empty() {
        let answer = FilesSourceAskAnswer {
            outcome: FilesAskOutcome::NoCitedAnswer {
                why: FilesNoCitedAnswer::NoTextFile,
            },
            read,
            hits,
        };
        return (Ok(answer), rows);
    }
    let reply = match asked(server, &owner, &query, &texts).await {
        Ok(reply) => reply,
        Err(refusal) => return refused(refusal),
    };
    let checker = Arc::clone(server);
    let outcome = run_blocking(move || -> MemoryResult<FilesAskOutcome> {
        let vault = checker.vault();
        owner.revalidate(vault)?;
        let unchanged = sdk::files_ask_unchanged(vault, &texts)?;
        Ok(sdk::files_ask_outcome(&reply, &texts, &unchanged))
    })
    .await;
    match outcome {
        Ok(Ok(outcome)) => (
            Ok(FilesSourceAskAnswer {
                outcome,
                read,
                hits,
            }),
            rows,
        ),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => refused(internal(VERB)),
    }
}

/// The model's reply to the owner's question over `texts`: one call of the
/// house chat role, on the owner's budget line, each rung sent the files'
/// text only where the Files world may be read.
async fn asked(
    server: &Arc<SyncServer>,
    owner: &AuthenticatedOwner,
    query: &str,
    texts: &[FilesAskText],
) -> MemoryResult<String> {
    let ai = &server.ai;
    let vault: &Vault = server.vault();
    let seat = ai
        .chat_seat()
        .ok_or_else(|| no_model("this server has no chat model to answer it".to_owned()))?;
    let request = chat_request(
        seat,
        vec![
            text_message(
                LlmMessageRole::System,
                sdk::FILES_ASK_INSTRUCTION.to_owned(),
            ),
            text_message(LlmMessageRole::User, sdk::files_ask_prompt(query, texts)),
        ],
    );
    let call = ai
        .admit_role(vault, CHAT_ROLE, request)
        .map_err(|refusal| no_model(format!("the chat role refused the question: {refusal}")))?;
    let _turn = ai.enter_turn();
    let run_id = format!("files-ask:{}", EntityId::now().to_hex());
    let units = ai.chat_settings().turn_budget_units;
    let meter = blocking(|| -> MemoryResult<_> {
        let payer = WriteActor::new(owner.revalidate(vault)?, EdgeActorClass::Human);
        Ok(vault.policy_budget_guard(
            run_id.clone(),
            units,
            oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(units),
            BudgetExhaustionPolicy::Suspend,
            payer,
        )?)
    })?;
    let notes: Vec<EntityId> = texts.iter().map(|read| read.file.note).collect();
    let run = ai
        .undeclared_run(run_id, meter)
        .sourced(Some(notes.clone()));
    let sources = AskSources {
        vault,
        texts,
        notes,
        sent: Mutex::new(None),
    };
    let response = call
        .ladder
        .generate_admitted(&run, call.request, None, &sources)
        .await
        .map_err(|error| {
            no_model(format!(
                "no model the Files world's text may go to answered: {error}"
            ))
        })?;
    Ok(response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect())
}

/// A refusal of the model call: the question was not answered.
fn no_model(message: String) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        message,
        &[
            "The Files world is read on this install only: route the chat role to a model on \
             this install, then ask again.",
        ],
    )
}

/// The files an ask reads, as sources each rung's destination is admitted
/// to: the request goes whole to a destination every note may be read at,
/// and to no other.
struct AskSources<'a> {
    vault: &'a Vault,
    texts: &'a [FilesAskText],
    notes: Vec<EntityId>,
    sent: Mutex<Option<ReadDestination>>,
}

impl AskSources<'_> {
    /// Why `destination` may not read every file now, or `None` when it
    /// may: the release verdict over the files' notes, and each file still
    /// reads as the request carries it.
    fn held(&self, destination: &ReadDestination) -> Option<&'static str> {
        let judged = blocking(|| -> MemoryResult<Option<&'static str>> {
            if let Some(hold) = self.vault.release_hold_for(&self.notes, destination)? {
                return Ok(Some(hold.reason()));
            }
            let unchanged = sdk::files_ask_unchanged(self.vault, self.texts)?;
            Ok((!unchanged.iter().all(|same| *same)).then(|| ReleaseHold::Placement.reason()))
        });
        judged.unwrap_or_else(|_| Some(ReleaseHold::Placement.reason()))
    }
}

impl SourceAdmission for AskSources<'_> {
    fn offer(&self, request: &LlmRequest, destination: &ReadDestination) -> SourceOffer {
        if let Some(reason) = self.held(destination) {
            return SourceOffer::Held(reason);
        }
        *self.sent.lock().unwrap_or_else(PoisonError::into_inner) = Some(destination.clone());
        SourceOffer::Send(request.clone())
    }

    fn recheck(&self, destination: &ReadDestination) -> Option<&'static str> {
        let sent = self
            .sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if sent.as_ref() != Some(destination) {
            return Some(ReleaseHold::Placement.reason());
        }
        self.held(destination)
    }
}
