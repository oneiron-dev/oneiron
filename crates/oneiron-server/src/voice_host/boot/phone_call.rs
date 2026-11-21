//! Call dependencies for a stranger answered by the authenticated line agent.

use std::io;
use std::sync::Arc;

use oneiron::interlocutor::{InterlocutorPartyInput, InterlocutorResolutionInput};
use oneiron::llm::{DEFAULT_BUDGET_RESERVE_UNITS, VoiceChunkPolicy};
use oneiron::task_verb::sdk::LiveVoiceStartRequest;
use oneiron::voice_cascade::VoiceSessionConfig;
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, EdgeActorClass, EntityId, WriteActor};
use tokio::sync::mpsc;

use super::{BRAIN_QUEUE, PreparedCall, failed};
use crate::auth::CoreAuth;
use crate::config::models::VoiceSettings;
use crate::managed::ManagedShutdown;
use crate::server::SyncServer;
use crate::voice_host::backend::CallBackend;
use crate::voice_host::phone::PhoneCallRead;
use crate::voice_host::{
    ChatBrain, ChatBrainBindings, VoiceHost, VoiceHostBindings, VoiceWireBindings,
    phone_call_opening, phone_call_record,
};

/// The voice session of the phone call `call_ref` the line agent `agent`
/// answers: its one other party an unknown speaker, its policy caller the
/// agent.
pub(crate) fn phone_call_session(call_ref: &str, agent: EntityId) -> VoiceSessionConfig {
    let mut session = VoiceSessionConfig::new(
        call_ref.to_owned(),
        InterlocutorResolutionInput {
            owner_session: false,
            parties: vec![InterlocutorPartyInput::UnknownLabel {
                label: call_ref.to_owned(),
                claimed_owner: false,
            }],
            voice_session_ref: None,
        },
    );
    session.policy_caller_ref = Some(agent.to_hex());
    session
}

pub(in crate::voice_host) fn prepare_phone_call(
    server: &Arc<SyncServer>,
    settings: &VoiceSettings,
    auth: &CoreAuth,
    input: LiveVoiceStartRequest,
    shutdown: &ManagedShutdown,
    phone: Arc<PhoneCallRead>,
) -> io::Result<PreparedCall> {
    let vault = server.vault();
    let agent = phone.admitted_for(vault, auth).map_err(failed)?;
    if input.room_ref.is_some() || input.roster_ref.is_some() {
        return Err(failed(crate::voice_host::HostError::InvalidRequest));
    }
    let payer = WriteActor::new(agent, EdgeActorClass::Agent);
    let instructions = phone
        .definition()
        .instructions
        .clone()
        .filter(|text| !text.trim().is_empty());
    let call_ref = format!("voice-call:{}", EntityId::now().to_hex());
    let session = phone_call_session(&call_ref, agent);
    let units = settings.call_budget_units;
    let line = vault
        .policy_budget_guard(
            call_ref.clone(),
            units,
            DEFAULT_BUDGET_RESERVE_UNITS.min(units),
            BudgetExhaustionPolicy::Suspend,
            payer.clone(),
        )
        .map_err(failed)?;
    let router = server
        .ai
        .models()
        .router()
        .ok_or_else(|| failed("no [models] router"))?;
    let run = server
        .ai
        .model_runtime()
        .funded_run(call_ref.clone(), line, None);
    let backend = CallBackend::for_phone(Arc::clone(server), router, run, Arc::clone(&phone))
        .map_err(failed)?;
    let host = VoiceHost::new(
        Arc::clone(vault),
        &server.config.runtime,
        VoiceHostBindings {
            backend: Arc::new(backend),
            budget: BudgetGuard::new(
                format!("{call_ref}:host"),
                units,
                BudgetExhaustionPolicy::Suspend,
            ),
            extraction_prompt: settings.extraction_prompt.clone().unwrap_or_default(),
            session,
            shutdown: shutdown.clone(),
            speculative_auth: Some(auth.clone()),
            phone: Some(Arc::clone(&phone)),
            // The policy plane's config is not an owner credential.
            owner_policy: server
                .decision_host()
                .policy_model_config(&server.policy_doors.owner),
        },
    )
    .map_err(failed)?;
    let (out, brain_out) = mpsc::channel(BRAIN_QUEUE);
    let brain = ChatBrain::new(ChatBrainBindings {
        ai: server.ai.clone(),
        vault: Arc::clone(vault),
        auth: auth.clone(),
        phone: Some(Arc::clone(&phone)),
        room: None,
        instructions,
        agent,
        payer,
        funding: None,
        out,
        // The caller's words and the answers, kept as the agent's thread
        // with that number under the owner's call-transcript setting
        // (UNBUILT-02 PR 3).
        record: phone_call_record(vault, agent, phone.caller(), &call_ref),
    })
    .map_err(failed)?;
    let render = settings
        .render
        .clone()
        .ok_or_else(|| failed("no voice to speak in"))?;
    // The owner's announcement, said before the caller's first words when
    // `voice.call_transcripts.announce` is on (UNBUILT-02 PR 3B).
    let opening = phone_call_opening(vault, phone.definition());
    Ok(PreparedCall {
        session_ref: call_ref,
        host,
        brain,
        media: VoiceWireBindings {
            door: server.phone_media_door(phone, None),
            vault: Arc::clone(vault),
            render,
            sample_rate: input.sample_rate,
            channels: input.channels,
            brain_out,
            chunking: VoiceChunkPolicy::default(),
            queue_capacity: settings.queue_capacity,
        },
        live: None,
        opening,
    })
}
