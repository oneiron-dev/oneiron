//! The host doors of the plugin Context Board sections (DOOR-112):
//! `vault.packs.sections.propose/list/grant/revoke/suggest` and the owner's
//! suggestion knob. `host_doors` re-exports them, so the generated HTTP
//! facade handler and the MCP dispatcher call them by the name every host
//! door has. Proposal, list and suggestion act on the caller's own
//! credential handle; grant, revoke and the knob additionally take the
//! vault owner's proof, as `/v1/owner` takes it, and the engine revalidates
//! that proof where each write commits. Each lists the rows its reads
//! derived the answer from (`host_door_lists`).
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{
    MemoryResult, PluginSectionGrant, PluginSectionGrantRequest, PluginSectionListRequest,
    PluginSectionProposal, PluginSectionProposeRequest, PluginSectionRevokeRequest,
    PluginSectionRevoked, PluginSectionSuggestRequest, PluginSectionSuggestion, PluginSectionsView,
    PluginSuggestionsSetRequest, PluginSuggestionsView,
};
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::EmptyRequest;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The vault owner's proof from the request, as `/v1/owner` takes it.
fn owner(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<AuthenticatedOwner> {
    super::owner_binding::facade_owner(server, auth, verb)
}

/// `vault.packs.sections.propose`: the caller offers one typed section
/// manifest; it waits as a proposed install claim and registers nothing.
pub(crate) async fn vault_packs_sections_propose(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: PluginSectionProposeRequest,
) -> Listed<PluginSectionProposal> {
    const VERB: &str = "vault.packs.sections.propose";
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.plugin_section_propose(&input)
    })
    .await
}

/// `vault.packs.sections.list`: pending offers, admitted sections and
/// pack-origin sections from the registry the board renders.
pub(crate) async fn vault_packs_sections_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: PluginSectionListRequest,
) -> Listed<PluginSectionsView> {
    const VERB: &str = "vault.packs.sections.list";
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.plugin_sections_list(&input)
    })
    .await
}

/// `vault.packs.sections.grant`: the owner approves exactly the reviewed
/// install claim and its section is admitted under that same consent.
pub(crate) async fn vault_packs_sections_grant(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: PluginSectionGrantRequest,
) -> Listed<PluginSectionGrant> {
    const VERB: &str = "vault.packs.sections.grant";
    let proof = match owner(server, auth, VERB) {
        Ok(proof) => proof,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.plugin_section_grant_as_owner(&proof, &input)
    })
    .await
}

/// `vault.packs.sections.revoke`: the owner retracts a live install grant;
/// its section and verbs leave the next board rebuild.
pub(crate) async fn vault_packs_sections_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: PluginSectionRevokeRequest,
) -> Listed<PluginSectionRevoked> {
    const VERB: &str = "vault.packs.sections.revoke";
    let proof = match owner(server, auth, VERB) {
        Ok(proof) => proof,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.plugin_section_revoke_as_owner(&proof, &input)
    })
    .await
}

/// `vault.packs.sections.suggest`: one workflow suggestion pass on the
/// caller's credential; at most one attributed proposal, never an install.
pub(crate) async fn vault_packs_sections_suggest(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: PluginSectionSuggestRequest,
) -> Listed<PluginSectionSuggestion> {
    const VERB: &str = "vault.packs.sections.suggest";
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.plugin_section_suggest(&input)
    })
    .await
}

/// `vault.packs.sections.suggestions.get`: the owner's suggestion knob.
pub(crate) async fn vault_packs_sections_suggestions_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    _input: EmptyRequest,
) -> Listed<PluginSuggestionsView> {
    const VERB: &str = "vault.packs.sections.suggestions.get";
    let proof = match owner(server, auth, VERB) {
        Ok(proof) => proof,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.plugin_suggestions_as_owner(&proof)
    })
    .await
}

/// `vault.packs.sections.suggestions.set`: the owner turns the suggestion
/// pass on or off; off silences it before any catalog access.
pub(crate) async fn vault_packs_sections_suggestions_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: PluginSuggestionsSetRequest,
) -> Listed<PluginSuggestionsView> {
    const VERB: &str = "vault.packs.sections.suggestions.set";
    let proof = match owner(server, auth, VERB) {
        Ok(proof) => proof,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.plugin_suggestions_set_as_owner(&proof, &input)
    })
    .await
}
