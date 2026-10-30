//! An owner's own program's owner rows (FIX 5911, after FIX 5717). A Dreamer
//! turn program a person woke binds the run host door under that person
//! (DOOR-141 PR2). The rows that door refuses an agent as the owner's, the
//! `ai.*` media calls past speech and `vault.hooks.replay`, are served here
//! through the owner's own doors (`api::facade::host_doors`), and only while
//! the waking person is proven, again at each such row, the vault's live
//! recorded owner. Anyone else, a person who is not the owner or an agent,
//! keeps the agent's door and its refusals. The program stays generated
//! code: its surface keeps the run's host origin, so nothing it writes reads
//! as the owner's own in-person act.
//!
//! Its media calls spend on its run's line, as its speech and its other
//! model calls do (FIX 6083): a video job's whole life too, from its submit
//! to its end. Its `ai.options` lists every media row it can call, with what
//! that line has left. A run its door bound no line to spends its media on
//! the owner's media meter, as the owner's own call does.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::media::AiOperation;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::memory::{
    HostWriteOrigin, MEMORY_CODE_INTERNAL, MemoryError, MemoryResult, ProducerRows,
};
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{self, AgentVerb};
use oneiron::task_verb::verb_hook_boundary;
use oneiron::{EdgeActorClass, EntityId, WriteActor};
use serde_json::Value;

use super::SyncServer;
use super::run_host_door::{agent_memory, answer_as_agent};

/// Whether `verb` is a row the run host door refuses an agent as the
/// owner's: a hook replay, or an `ai.*` media call other than speech; or
/// `ai.options`, which lists an owner's program those calls too (FIX 6083).
pub(super) fn is_owner_row(verb: AgentVerb) -> bool {
    matches!(
        verb,
        AgentVerb::VaultHooksReplay
            | AgentVerb::AiOptions
            | AgentVerb::AiImage
            | AgentVerb::AiTranscribe
            | AgentVerb::AiEmbed
            | AgentVerb::AiVideo
            | AgentVerb::AiVideoPoll
            | AgentVerb::AiVideoCancel
    )
}

/// The owner's proof for a program `actor` woke, made afresh for each row: a
/// person this vault records as its owner, while that owner is live, as a
/// managed owner's request is proved. `None` for anyone else.
fn program_owner(server: &SyncServer, actor: WriteActor) -> Option<AuthenticatedOwner> {
    if actor.actor_class() != EdgeActorClass::Human {
        return None;
    }
    crate::api::managed_owner_proof(server, actor.entity_ref())
        .ok()
        .flatten()
}

/// One owner row ([`is_owner_row`]) of the program `actor` woke, with its
/// verb hooks once around it on the program's own surface: served through
/// the owner's door when `actor` is proven the live recorded owner, its
/// media on `line`, the run's own, else answered exactly as the agent's door
/// answers it. Beside it, the rows its surface and its door listed, `None`
/// when those are not known. Blocking: call it on a blocking thread of the
/// server's runtime.
pub(super) fn answer(
    server: &Arc<SyncServer>,
    actor: WriteActor,
    origin: &HostWriteOrigin,
    invocation: InvocationId,
    verb: AgentVerb,
    input: Value,
    line: Option<&RunAdmission>,
    attempt: Option<&str>,
) -> MemoryResult<(Value, Option<Vec<EntityId>>)> {
    let Some(owner) = program_owner(server, actor) else {
        return answer_as_agent(
            server, actor, origin, invocation, verb, input, None, line, attempt,
        );
    };
    let producers = ProducerRows::default();
    let memory = agent_memory(server, actor, origin, invocation).listing_producers(&producers);
    let name = verb.as_str();
    let mut listed = Some(Vec::new());
    let output = verb_hook_boundary::row(&memory, name, input, |input| {
        sdk::validate_input(name, &input)?;
        owner_row(
            server,
            owner,
            actor.entity_ref(),
            line,
            attempt,
            verb,
            input,
            &mut listed,
        )
    })?;
    let rows = listed.map(|mut listed| {
        let mut rows = producers.take();
        rows.append(&mut listed);
        rows
    });
    Ok((output, rows))
}

/// The owner's door for one owner row, past its credential check: `owner`
/// is the proof [`program_owner`] made for this row, beside the program's
/// actor, who asks, and `line`, the run's own line its media spends on,
/// when its door bound one.
fn owner_row(
    server: &Arc<SyncServer>,
    owner: AuthenticatedOwner,
    actor: EntityId,
    line: Option<&RunAdmission>,
    attempt: Option<&str>,
    verb: AgentVerb,
    input: Value,
    listed: &mut Option<Vec<EntityId>>,
) -> MemoryResult<Value> {
    let runtime = tokio::runtime::Handle::current();
    // The program's media spends on its run's line, as its other model
    // calls do (FIX 6083); with none, on the owner's media meter.
    let media = |operation: AiOperation, input: Value| -> MemoryResult<Value> {
        let input = decode(input)?;
        let answered = match line {
            Some(line) => runtime.block_on(crate::api::ai_media_for_run(
                server, line, operation, attempt, input,
            )),
            None => runtime.block_on(crate::api::ai_media_as_owner(server, operation, input)),
        };
        encode(answered?)
    };
    match verb {
        AgentVerb::AiOptions => {
            let options = crate::api::ai_options_for_program(server, line, &decode(input)?)?;
            // Its rows are priced from the installed model catalog pack when
            // the registry holds none: that pack's source is listed, as the
            // facade's `ai.options` lists it.
            if !options.options.is_empty() {
                match (listed.as_mut(), server.vault.model_catalog_source()) {
                    (Some(listed), Ok(source)) => listed.extend(source),
                    _ => *listed = None,
                }
            }
            encode(options)
        }
        AgentVerb::VaultHooksReplay => {
            let (replayed, rows) = runtime.block_on(crate::api::vault_hooks_replay_as_owner(
                server,
                owner,
                decode(input)?,
            ))?;
            if let Some(listed) = listed.as_mut() {
                listed.extend(rows);
            }
            encode(replayed)
        }
        AgentVerb::AiImage => media(AiOperation::Image, input),
        AgentVerb::AiTranscribe => media(AiOperation::Transcribe, input),
        AgentVerb::AiEmbed => media(AiOperation::Embed, input),
        // The program that asked is the job's actor (KS-2B2); its job lives
        // on the run's line from its submit to its end.
        AgentVerb::AiVideo => {
            let input = decode(input)?;
            let ticket = match line {
                Some(line) => runtime.block_on(crate::api::ai_video_for_run(
                    server,
                    line,
                    attempt,
                    input,
                    Some(actor),
                )),
                None => runtime.block_on(crate::api::ai_video_as_owner(server, input, Some(actor))),
            };
            encode(ticket?)
        }
        AgentVerb::AiVideoPoll => {
            encode(runtime.block_on(crate::api::ai_video_poll_as_owner(server, decode(input)?))?)
        }
        AgentVerb::AiVideoCancel => {
            encode(runtime.block_on(crate::api::ai_video_cancel_as_owner(server, decode(input)?))?)
        }
        _ => Err(MemoryError::new(
            MEMORY_CODE_INTERNAL,
            format!(
                "{} is not an owner row of the run's host door",
                verb.as_str()
            ),
            &["Report this host-door failure."],
        )),
    }
}

fn decode<T: serde::de::DeserializeOwned>(input: Value) -> MemoryResult<T> {
    serde_json::from_value(input).map_err(|error| MemoryError::bad_request(error.to_string()))
}

fn encode<T: serde::Serialize>(output: T) -> MemoryResult<Value> {
    serde_json::to_value(output).map_err(|error| {
        MemoryError::new(
            MEMORY_CODE_INTERNAL,
            error.to_string(),
            &["Report this host-door failure."],
        )
    })
}
