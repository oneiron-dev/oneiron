//! The routes managed ingress verifies a supervisor's owner attestation on,
//! past the facade, owner and console sets `state_serve` names (FIX 5255,
//! Engine ruling 10-19).
//!
//! The supervisor signs every request its vault's owner sends from his own
//! sign-in (`ManagedOwnerAction`). On each route here a verified one names
//! him as the request's caller, the person himself with every owner power,
//! where before the attestation was dropped and the request served as the
//! host's root. Each route is one registered method and path pattern, never
//! a prefix: `{..}` is one non-empty path segment, `{*..}` the non-empty rest
//! of the path. A route that is not registered still answers 404 or 405.
//!
//! Every route here takes a body the buffered verification already holds
//! (`MAX_REMOTE_REQUEST_BYTES`, 64 MiB). Not here, until a staged
//! verification keeps their streaming and their ceilings: git smart HTTP and
//! LFS, `/ws`, the blob artifact uploads (`POST /v1/core/artifacts` and an
//! artifact's `versions` and `outputs`) and the `/v1/ai` media uploads, which
//! take up to 96 MiB. Nor are the public doors, whose capability, signature
//! or provider proof stands alone; only the signing ceremony's action is
//! here, to class its caller as the owner.

use axum::http::Method;

/// One route: its method and its registered path pattern.
type Route = (&'static str, &'static str);

/// The API listener's attested routes, by the surface each belongs to.
const OWNER_ROUTES: &[Route] = &[
    // The root-admin and legacy doors: the schema, the skill pack, lease
    // repair, usage, operator recovery and semantic search.
    ("GET", "/api/openapi.json"),
    ("GET", "/api/skills/oneiron.skills.md"),
    ("POST", "/api/lease/revoke"),
    ("POST", "/v1/usage/events"),
    ("GET", "/v1/usage/owners/{owner}/vaults/{vault_id}/rollup"),
    ("POST", "/v1/operator/shared/recover-owner"),
    ("POST", "/api/search/semantic"),
    // The core writes.
    ("POST", "/v1/core/batch"),
    ("POST", "/v1/core/propose"),
    ("POST", "/v1/core/memory/verbs/{verb}"),
    ("POST", "/v1/core/conversations"),
    ("POST", "/v1/core/conversations/{conversation_id}/members"),
    ("POST", "/v1/core/conversations/{conversation_id}/records"),
    (
        "POST",
        "/v1/core/conversations/{conversation_id}/records/{record}/thread",
    ),
    ("POST", "/v1/core/messages/{message}/reactions"),
    (
        "POST",
        "/v1/core/conversations/{conversation_id}/records/{record}/thread/summary",
    ),
    ("PATCH", "/v1/core/sessions/{id}"),
    ("POST", "/v1/core/sessions/{id}/presence"),
    ("POST", "/v1/core/conversations/{conversation_id}/turns"),
    ("POST", "/v1/core/conversations/{conversation_id}/head"),
    (
        "POST",
        "/v1/core/conversations/{conversation_id}/migrate-dag",
    ),
    ("POST", "/v1/core/turns/{turn_id}/sub-sessions"),
    ("POST", "/v1/core/conversations/{conversation_id}/summaries"),
    ("POST", "/v1/core/summaries/{summary_id}/rederive"),
    ("POST", "/v1/core/turns/annotate"),
    ("POST", "/v1/core/surface-events"),
    // The core reads, boards and runs.
    ("GET", "/v1/core/org-admin/{org}/powers"),
    ("POST", "/v1/core/query"),
    ("POST", "/v1/core/context-pack"),
    ("POST", "/v1/core/context-board"),
    ("GET", "/v1/core/context-board/turns/{turn}"),
    ("GET", "/v1/core/explain/memory/{entity}"),
    ("GET", "/v1/core/explain/gate/{receipt}"),
    ("POST", "/v1/core/context-board/scratchpad"),
    ("POST", "/v1/core/context-board/scratchpad/recall"),
    ("POST", "/v1/core/hydrate"),
    ("POST", "/v1/core/batch/shortId/hydrate"),
    ("GET", "/v1/core/run-tree"),
    ("GET", "/v1/core/run-tree/observe"),
    ("POST", "/v1/core/run-tree/intervene"),
    ("GET", "/v1/core/memory/{id}/timeline"),
    ("GET", "/v1/core/memory/{id}/watch"),
    ("PUT", "/v1/core/memory/{id}/watch"),
    ("DELETE", "/v1/core/memory/{id}/watch"),
    ("GET", "/v1/core/outbound/capabilities"),
    ("GET", "/v1/core/outbound/capabilities/{connector}"),
    (
        "GET",
        "/v1/core/outbound/capabilities/{connector}/verbs/{verb}",
    ),
    ("GET", "/v1/core/conversations"),
    ("GET", "/v1/core/conversations/{conversation_id}/members"),
    ("GET", "/v1/core/conversations/{conversation_id}/records"),
    (
        "GET",
        "/v1/core/conversations/{conversation_id}/records/{record}/thread",
    ),
    ("GET", "/v1/core/conversations/{conversation_id}/canonical"),
    ("GET", "/v1/core/conversations/{conversation_id}/turns"),
    ("GET", "/v1/core/conversations/{conversation_id}/transcript"),
    ("POST", "/v1/core/messages/{message}/result"),
    ("POST", "/v1/core/conversations/{conversation_id}/scope"),
    ("GET", "/v1/core/turns/{turn_id}/sub-sessions"),
    ("GET", "/v1/core/summaries/{summary_id}/covers"),
    ("GET", "/v1/core/summary-attempts/{attempt}"),
    ("GET", "/v1/core/summaries/{summary_id}/derivation"),
    ("GET", "/v1/core/summary-purposes"),
    ("GET", "/v1/core/claims/{claim_id}/drill"),
    ("GET", "/v1/core/turns/{turn_id}"),
    ("GET", "/v1/core/turns/annotate"),
    ("GET", "/v1/core/surface-events/{correlation_id}"),
    // The other core doors: checkpoints, a device's renewal, widen answers,
    // the action list, a live run's attach and a role holder's asks.
    ("GET", "/v1/core/authority/checkpoints/{id}"),
    ("POST", "/v1/core/slips/renew"),
    ("POST", "/v1/core/consent/widen/accept"),
    ("POST", "/v1/core/consent/widen/reject"),
    ("GET", "/v1/core/actions"),
    ("POST", "/v1/core/live-runs/{run}/attach"),
    ("GET", "/v1/core/skills/tradeoff-asks"),
    ("POST", "/v1/core/skills/tradeoff-asks/pick"),
    ("GET", "/v1/core/decisions/asks"),
    ("POST", "/v1/core/decisions/asks/answer"),
    // The companion, campaign and saved-query resources.
    ("POST", "/v1/companion/access-grants"),
    ("POST", "/v1/companion/access-grants/{grant_id}/revoke"),
    ("GET", "/v1/companion/profiles"),
    ("GET", "/v1/companion/profiles/access-requests"),
    ("GET", "/v1/companion/profiles/{person_ref}"),
    ("POST", "/v1/companion/profiles/{person_ref}"),
    ("POST", "/v1/companion/memory/reason"),
    ("POST", "/campaigns"),
    ("GET", "/campaigns/{campaign_ref}"),
    ("PATCH", "/campaigns/{campaign_ref}"),
    ("POST", "/campaigns/{campaign_ref}/archive"),
    ("GET", "/campaigns/{campaign_ref}/members"),
    ("POST", "/campaigns/{campaign_ref}/programs"),
    ("GET", "/campaigns/{campaign_ref}/programs/{program_ref}"),
    ("PATCH", "/campaigns/{campaign_ref}/programs/{program_ref}"),
    (
        "POST",
        "/campaigns/{campaign_ref}/programs/{program_ref}/archive",
    ),
    ("POST", "/saved-queries"),
    ("GET", "/saved-queries/{query_ref}"),
    ("PATCH", "/saved-queries/{query_ref}"),
    ("POST", "/saved-queries/{query_ref}/archive"),
    ("GET", "/saved-queries/{query_ref}/members"),
    // The model routes, and of the media routes those that carry no upload.
    ("PUT", "/v1/llm/defaults"),
    ("POST", "/v1/llm/generate"),
    ("POST", "/v1/llm/stream"),
    ("POST", "/v1/llm/decision_read"),
    ("GET", "/v1/ai/status"),
    ("POST", "/v1/ai/session"),
    ("POST", "/v1/ai/chat"),
    ("POST", "/v1/ai/waves"),
    ("GET", "/v1/ai/options"),
    ("POST", "/v1/ai/quota/{question}"),
    ("DELETE", "/v1/ai/video/{job}"),
    ("DELETE", "/v1/ai/voices/{voice_id}/targets/{target}"),
    ("POST", "/v1/ai/anonymous-chat"),
    ("POST", "/v1/chat/completions"),
    // The blob artifact doors past the uploads, and `/a/` serving.
    ("GET", "/v1/core/artifacts/born-from"),
    ("GET", "/v1/core/artifacts/{artifact}"),
    ("GET", "/v1/core/artifacts/{artifact}/export"),
    (
        "GET",
        "/v1/core/artifacts/{artifact}/versions/{version}/export",
    ),
    ("GET", "/v1/core/artifacts/{artifact}/proposals"),
    ("POST", "/v1/core/artifacts/{artifact}/deck/proposals"),
    (
        "POST",
        "/v1/core/artifacts/{artifact}/proposals/{proposal}/keep",
    ),
    (
        "POST",
        "/v1/core/artifacts/{artifact}/proposals/{proposal}/discard",
    ),
    (
        "POST",
        "/v1/core/artifacts/{artifact}/proposals/{proposal}/undo",
    ),
    (
        "POST",
        "/v1/core/artifacts/{artifact}/versions/{version}/restore",
    ),
    ("GET", "/v1/core/artifacts/{artifact}/unattached"),
    ("GET", "/v1/core/artifacts/{artifact}/reattach-offers"),
    (
        "POST",
        "/v1/core/artifacts/{artifact}/threads/{thread}/reattach",
    ),
    ("GET", "/a/{artifact}"),
    ("GET", "/a/{artifact}/"),
    ("GET", "/a/{artifact}/{*path}"),
    // The off-record room, the signing editor and the signing action.
    ("GET", "/v1/core/off-record"),
    ("GET", "/v1/core/off-record/"),
    ("POST", "/v1/core/off-record/start"),
    ("POST", "/v1/core/off-record/witness"),
    ("POST", "/v1/core/off-record/save"),
    ("POST", "/v1/core/off-record/export"),
    ("POST", "/v1/core/off-record/save-from-here"),
    ("POST", "/v1/core/off-record/suggest-save"),
    ("POST", "/v1/core/off-record/confirm-save"),
    ("POST", "/v1/core/off-record/decline-save"),
    ("GET", "/sign/editor"),
    ("POST", "/sign/action"),
    // The tool-first MCP endpoint, beside `/mcp`.
    ("POST", "/mcp/tool-first"),
];

/// The artifact listener's routes: this vault's `/a/`, its names under an
/// artifact domain (`<vault>.<domain>/<artifact>/…`) and an app's own origin
/// (`<app>--<vault>.<domain>/…`). The listener serves nothing else.
const ARTIFACT_ROUTES: &[Route] = &[
    ("GET", "/a/{artifact}"),
    ("GET", "/a/{artifact}/"),
    ("GET", "/a/{artifact}/{*path}"),
    ("GET", "/{artifact}"),
    ("GET", "/{artifact}/"),
    ("GET", "/{artifact}/{*path}"),
    ("GET", "/"),
    ("GET", "/{*path}"),
];

/// Whether `method` and `path` are one of the API listener's attested
/// routes here.
pub(super) fn owner_route(method: &Method, path: &str) -> bool {
    listed(OWNER_ROUTES, method, path)
}

/// Whether `method` and `path` are one of the artifact listener's routes.
pub(super) fn artifact_route(method: &Method, path: &str) -> bool {
    listed(ARTIFACT_ROUTES, method, path)
}

fn listed(routes: &[Route], method: &Method, path: &str) -> bool {
    routes
        .iter()
        .any(|(wanted, pattern)| method.as_str() == *wanted && registers(pattern, path))
}

/// Whether `path` is one that `pattern` registers.
fn registers(pattern: &str, path: &str) -> bool {
    let mut wanted = pattern.split('/');
    let mut segments = path.split('/');
    loop {
        match (wanted.next(), segments.next()) {
            (None, None) => return true,
            (Some(want), Some(segment)) if want.starts_with("{*") => {
                return !segment.is_empty() || segments.next().is_some();
            }
            (Some(want), Some(segment)) if want.starts_with('{') => {
                if segment.is_empty() {
                    return false;
                }
            }
            (Some(want), Some(segment)) => {
                if want != segment {
                    return false;
                }
            }
            _ => return false,
        }
    }
}
