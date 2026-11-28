//! A project's lead turns (FIX NEON-LEAD-TURN-TRIGGER): `vault.projects.lead_turns.set`,
//! `.hold`, `.release`, `.owed`, `.claim`, `.finish`, `.list` and `.file`. The engine decides
//! (`oneiron::project_lead_turn`): the door admits the caller through the lane economy's door kit
//! (`verb_grant_caller`, the owner or an agent whose own live Grant lists the verb) and calls the
//! engine act, which judges the project's reach and the lead again in its own read or write, at
//! this host's clock. The lead is an attached seat: these doors never start, resume or message
//! it. The rows live in side tables, which hold no entity row: the doors list none.

use std::sync::Arc;

use oneiron::project_lead_turn::{
    LEAD_TURNS_CLAIM_VERB, LEAD_TURNS_FILE_VERB, LEAD_TURNS_FINISH_VERB, LEAD_TURNS_HOLD_VERB,
    LEAD_TURNS_LIST_VERB, LEAD_TURNS_OWED_VERB, LEAD_TURNS_RELEASE_VERB, LEAD_TURNS_SET_VERB,
    LeadTurn, LeadTurnFileView, LeadTurnRegistration, LeadTurnTicket, LeadTurnsClaimRequest,
    LeadTurnsFileRequest, LeadTurnsFinishRequest, LeadTurnsHoldRequest, LeadTurnsListRequest,
    LeadTurnsListView, LeadTurnsOwedView, LeadTurnsProjectRequest, LeadTurnsSetRequest,
};

use super::support::Listed;
use super::verb_grant::verb_grant_door;
use crate::auth::CoreAuth;
use crate::gpu_host::now_ms;
use crate::server::SyncServer;

/// `vault.projects.lead_turns.set`: the owner names a project's lead and its settings.
pub(crate) async fn vault_projects_lead_turns_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LeadTurnsSetRequest,
) -> Listed<LeadTurnRegistration> {
    verb_grant_door(
        server,
        auth,
        LEAD_TURNS_SET_VERB,
        move |_, memory, owner| memory.set_project_lead_turns(owner, &input, now_ms()),
    )
    .await
}

/// `vault.projects.lead_turns.hold`: holds a project's lead turns.
pub(crate) async fn vault_projects_lead_turns_hold(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LeadTurnsHoldRequest,
) -> Listed<LeadTurnRegistration> {
    verb_grant_door(
        server,
        auth,
        LEAD_TURNS_HOLD_VERB,
        move |_, memory, owner| memory.hold_project_lead_turns(owner, &input, now_ms()),
    )
    .await
}

/// `vault.projects.lead_turns.release`: lifts the hold.
pub(crate) async fn vault_projects_lead_turns_release(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LeadTurnsProjectRequest,
) -> Listed<LeadTurnRegistration> {
    verb_grant_door(
        server,
        auth,
        LEAD_TURNS_RELEASE_VERB,
        move |_, memory, owner| memory.release_project_lead_turns(owner, &input, now_ms()),
    )
    .await
}

/// `vault.projects.lead_turns.owed`: the turn a project owes its lead.
pub(crate) async fn vault_projects_lead_turns_owed(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LeadTurnsProjectRequest,
) -> Listed<LeadTurnsOwedView> {
    verb_grant_door(
        server,
        auth,
        LEAD_TURNS_OWED_VERB,
        move |_, memory, owner| memory.owed_project_lead_turn(owner, &input, now_ms()),
    )
    .await
}

/// `vault.projects.lead_turns.claim`: the lead claims its owed turn.
pub(crate) async fn vault_projects_lead_turns_claim(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LeadTurnsClaimRequest,
) -> Listed<LeadTurnTicket> {
    verb_grant_door(
        server,
        auth,
        LEAD_TURNS_CLAIM_VERB,
        move |_, memory, owner| memory.claim_project_lead_turn(owner, &input, now_ms()),
    )
    .await
}

/// `vault.projects.lead_turns.finish`: the lead closes its claimed turn.
pub(crate) async fn vault_projects_lead_turns_finish(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LeadTurnsFinishRequest,
) -> Listed<LeadTurn> {
    verb_grant_door(
        server,
        auth,
        LEAD_TURNS_FINISH_VERB,
        move |_, memory, owner| memory.finish_project_lead_turn(owner, &input, now_ms()),
    )
    .await
}

/// `vault.projects.lead_turns.list`: one line per turn.
pub(crate) async fn vault_projects_lead_turns_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LeadTurnsListRequest,
) -> Listed<LeadTurnsListView> {
    verb_grant_door(
        server,
        auth,
        LEAD_TURNS_LIST_VERB,
        move |_, memory, owner| memory.project_lead_turns(owner, &input),
    )
    .await
}

/// `vault.projects.lead_turns.file`: one file a turn kept.
pub(crate) async fn vault_projects_lead_turns_file(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LeadTurnsFileRequest,
) -> Listed<LeadTurnFileView> {
    verb_grant_door(
        server,
        auth,
        LEAD_TURNS_FILE_VERB,
        move |_, memory, owner| memory.project_lead_turn_file(owner, &input),
    )
    .await
}
