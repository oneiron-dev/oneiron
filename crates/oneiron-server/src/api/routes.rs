//! The HTTP API router: every `/api`, `/v1` and facade route, with its layers in their order.
//! `api_routes` is its call surface.
//! The api root and its modules define the handlers and middleware this router wires.

use super::*;

/// Builds the HTTP API routes.
pub(crate) fn api_routes(server: Arc<SyncServer>) -> Router {
    crate::wire_telemetry::start_window_receipts(&server);
    let idempotency = IdempotencyLayerState::new(server.clone());
    let legacy_mutation_routes = Router::new()
        // owner recovery surface (ONE-1140, OD-8): revoke a lost/stolen
        // device's lease binding (terminal)
        .route("/api/lease/revoke", post(lease_revoke))
        .route_layer(middleware::from_fn_with_state(
            idempotency.clone(),
            idempotency_middleware,
        ));
    let core_mutation_routes = Router::new()
        .route("/org-admin/{org}/policy", post(org_admin::configure))
        .route("/batch", post(core_batch))
        .route("/propose", post(core_propose))
        .route("/memory/verbs/{verb}", post(core_memory_verb))
        .route("/conversations", post(create_core_conversation))
        .route(
            "/conversations/{conversation_id}/members",
            post(conversation_members::write_member),
        )
        .route(
            "/conversations/{conversation_id}/records",
            post(append_core_record),
        )
        .route(
            "/conversations/{conversation_id}/records/{record}/thread",
            post(reply_in_thread),
        )
        .route("/messages/{message}/reactions", post(react_core_message))
        .route(
            "/conversations/{conversation_id}/records/{record}/thread/summary",
            post(summarize_thread),
        )
        .route("/sessions/{id}", axum::routing::patch(sessions::mode))
        .route("/sessions/{id}/presence", post(sessions::presence))
        .route(
            "/conversations/{conversation_id}/turns",
            post(create_core_conversation_turn),
        )
        .route(
            "/conversations/{conversation_id}/head",
            post(move_core_head),
        )
        .route(
            "/conversations/{conversation_id}/migrate-dag",
            post(migrate_core_dag),
        )
        .route(
            "/turns/{turn_id}/sub-sessions",
            post(spawn_core_sub_session),
        )
        .route(
            "/conversations/{conversation_id}/summaries",
            post(mint_core_scope_summary),
        )
        .route(
            "/summaries/{summary_id}/rederive",
            post(rederive_core_scope_summary),
        )
        .route("/turns/annotate", post(annotate_turn_vad))
        .route("/surface-events", post(submit_core_surface_event))
        .route("/linear/push", post(linear_push::core_linear_push))
        .route_layer(middleware::from_fn_with_state(
            idempotency.clone(),
            idempotency_middleware,
        ));
    let core_routes = Router::new()
        // A consumed approval must never replay a cached 200, even with an idempotency key.
        .route("/consent/widen/accept", post(core_accept_widen))
        .route("/consent/widen/reject", post(core_reject_widen))
        .route("/org-admin/{org}/powers", get(org_admin::powers))
        .route("/query", post(core_query))
        .route("/context-pack", post(core_context_pack))
        // Only a hydration that records its TURN's board is a keyed mutation.
        .route(
            "/context-board",
            post(context_board_hydrate).route_layer(middleware::from_fn_with_state(
                idempotency.clone(),
                board_turn_idempotency,
            )),
        )
        .route(
            "/context-board/turns/{turn}",
            get(context_board_turn_history),
        )
        .route("/explain/memory/{entity}", get(core_explain_memory))
        .route("/explain/gate/{receipt}", get(core_explain_gate))
        .route("/context-board/scratchpad", post(context_board_scratchpad))
        .route(
            "/context-board/scratchpad/recall",
            post(context_board_scratchpad_recall),
        )
        .route("/hydrate", post(core_hydrate))
        .route("/batch/shortId/hydrate", post(core_batch_short_id_hydrate))
        .route("/run-tree", get(core_run_tree))
        .route("/run-tree/observe", get(core_run_tree_observe))
        // FIX 6056: a keyed intervention runs once and replays its effect.
        .route(
            "/run-tree/intervene",
            post(core_run_tree_intervene).route_layer(middleware::from_fn_with_state(
                idempotency.clone(),
                intervene_idempotency,
            )),
        )
        .route("/memory/{id}/timeline", get(core_memory_timeline))
        .route(
            "/memory/{id}/watch",
            get(memory::core_memory_watch_read)
                .put(memory::core_memory_watch_enable)
                .delete(memory::core_memory_watch_disable),
        )
        .route(
            "/outbound/capabilities",
            get(list_core_outbound_capabilities),
        )
        .route(
            "/outbound/capabilities/{connector}",
            get(get_core_outbound_capability),
        )
        .route(
            "/outbound/capabilities/{connector}/verbs/{verb}",
            get(get_core_outbound_verb_contract),
        )
        .route("/conversations", get(list_core_conversations))
        .route(
            "/conversations/{conversation_id}/members",
            get(conversation_members::read_members),
        )
        .route(
            "/conversations/{conversation_id}/records",
            get(get_core_dag),
        )
        .route(
            "/conversations/{conversation_id}/records/{record}/thread",
            get(get_thread),
        )
        .route(
            "/conversations/{conversation_id}/canonical",
            get(get_canonical),
        )
        .route(
            "/conversations/{conversation_id}/turns",
            get(list_core_conversation_turns),
        )
        .route(
            "/conversations/{conversation_id}/transcript",
            get(conversation_transcript::get_core_conversation_transcript),
        )
        // A read with a POST body, so it stays out of the idempotency layer.
        .route(
            "/messages/{message}/result",
            post(message_result::read_core_message_result),
        )
        .route(
            "/conversations/{conversation_id}/scope",
            post(resolve_core_scope),
        )
        .route("/turns/{turn_id}/sub-sessions", get(list_core_sub_sessions))
        .route(
            "/summaries/{summary_id}/covers",
            get(get_core_summary_covers),
        )
        .route("/summary-attempts/{attempt}", get(get_core_summary_status))
        .route(
            "/summaries/{summary_id}/derivation",
            get(get_core_summary_metadata),
        )
        .route("/summary-purposes", get(list_core_summary_purposes))
        .route("/claims/{claim_id}/drill", get(drill_core_header))
        .route("/turns/{turn_id}", get(get_core_turn))
        .route("/turns/annotate", get(read_turn_vad_annotation))
        .route(
            "/surface-events/{correlation_id}",
            get(get_core_surface_event),
        )
        .merge(core_mutation_routes);
    // First-party code-run `self.*` dispatch is host-side only. External
    // clients keep the plain REST verb/batch surface and bring their own runner.
    let companion_mutation_routes = Router::new()
        .route("/access-grants", post(create_companion_access_grant))
        .route(
            "/access-grants/{grant_id}/revoke",
            post(revoke_companion_access_grant),
        )
        .route_layer(middleware::from_fn_with_state(
            idempotency,
            idempotency_middleware,
        ));
    let companion_routes = Router::new()
        .route("/profiles", get(list_profiles))
        .route("/profiles/access-requests", get(list_access_requests))
        .route(
            "/profiles/{person_ref}",
            get(get_companion_profile).post(refresh_companion_profile),
        )
        // ONE-207: the depth-dialed reasoning read. A POST that WRITES
        // NOTHING, so it stays off `companion_mutation_routes` and out of the
        // idempotency layer above: an idempotency key on a pure read would
        // cache an answer against a vault that moves under it, and there is no
        // replayed mutation for the layer to protect.
        .route("/memory/reason", post(companion_memory_reason))
        .merge(companion_mutation_routes);

    Router::new()
        .route("/api/openapi.json", get(openapi_json))
        .route("/api/skills/oneiron.skills.md", get(skills_pack))
        .route("/api/health", get(health))
        .route("/.well-known/oneiron", get(pairing::descriptor))
        .route("/v1/core/pairing/links", post(pairing::create_link))
        .route("/v1/core/pairing/redeem", post(pairing::redeem))
        .route("/v1/core/pairing/oauth", post(pairing::oauth_exchange))
        .route("/v1/core/slips/revoke", post(pairing::revoke))
        .route("/v1/core/slips/renew", post(slip_renewal::renew))
        .route(
            "/v1/core/authority/checkpoints/{id}",
            get(authority_checkpoint::bundle),
        )
        .merge(artifact_routes())
        // ONE-1704: two SEPARATELY REGISTERED MCP endpoints, each pinned to one
        // immutable surface mode by its route entry. Nothing on the wire moves a
        // connection between them.
        //
        // Each endpoint's registered surface is its WHOLE callable surface: no
        // retired `oneiron.*` plain-verb name resolves on either route.
        //
        // Registration reflects this server's verified host binding. A bound
        // QuickJS provider enables durable execute_code on both endpoints;
        // without one, admission returns code_host_unbound before any run.
        .route("/mcp", post(mcp_gateway))
        .route("/mcp/tool-first", post(mcp_tool_first_gateway))
        .route("/api/core/discover", get(discover))
        .route("/api/search/vector", get(search_vector))
        .route("/api/search/semantic", post(search_semantic))
        .route("/api/search/text", get(search_text))
        .route("/api/entity/{id}", get(get_entity))
        .route("/api/edges/{id}", get(get_edges))
        // CA-07's `self.*` surface, at the resource paths ARCH-0059 ratified.
        // Both routers dispatch into `oneiron::campaign::surface`; neither owns
        // campaign semantics.
        .merge(self::campaign::campaign_routes())
        .merge(self::saved_query::saved_query_routes())
        // BK-08's machine-readable booking surface. Every route addresses the
        // page by opaque token and dispatches into the one shared executor.
        .merge(self::booking::booking_routes())
        .merge(self::esign::editor_routes())
        .merge(self::blob_artifacts::routes())
        // ONE-1908: git smart-HTTP. Stock clients clone, fetch, and push here;
        // every route streams through one `git http-backend` child.
        .merge(self::git_http::git_http_routes())
        .nest("/v1/llm", self::llm::routes())
        .merge(self::openai_proxy::routes())
        .nest("/v1/ai", self::ai::routes())
        .nest("/v1/core", core_routes)
        // ONE-1441: the facade projection is its own nest, not an arm inside
        // `core_routes`. Nesting expands each row into a concrete
        // `/v1/core/facade/<verb>` path, so it neither shadows nor is shadowed
        // by the storage-shaped `/v1/core` routes above, and its 64 MiB body
        // limit stays a property of this nest alone.
        .nest(
            "/v1/core/facade",
            self::facade::recorded_facade_routes(server.clone()),
        )
        // OF-181: the app's one action layer, for its buttons and its agents.
        .merge(self::facade::action_routes::routes())
        // OF-181: a host-rendered lens card's events and close, on its held frame.
        .merge(self::facade::ui_action_routes::routes())
        .nest("/v1/companion", companion_routes)
        .nest("/v1/owner", self::owner_routes::routes())
        .merge(self::operator_routes::routes())
        // OF-158: a removed member's own leave notices, on its revoked slip.
        .merge(crate::auth::left_notice_routes())
        .merge(self::report::routes())
        // OF-495: an agent role holder's skill tradeoff asks and picks.
        .merge(self::facade::role_picks::routes())
        // OF-516: a role holder's door to the ladder's person asks.
        .merge(self::facade::decision_role_asks::routes())
        .route("/v1/usage/events", post(record_usage_event))
        .route(
            "/v1/usage/owners/{owner}/vaults/{vault_id}/rollup",
            get(get_usage_rollup),
        )
        .merge(legacy_mutation_routes)
        // Config-only CIMD documents remain public before OAuth bootstrap.
        .route("/oauth/client/native.json", get(client_metadata::native))
        .route("/oauth/client/web.json", get(client_metadata::web))
        // The public ceremony bypasses the hosted device lease but retains
        // matched-route wire receipts and threshold questions.
        .merge(self::esign::public_routes())
        // OF-519: the served built-in channels' provider webhooks. Keyless;
        // the provider's HMAC over the raw body authenticates each one.
        .merge(crate::builtin_host::routes())
        .merge(crate::linear_host::webhook_routes())
        .layer(middleware::from_fn_with_state(
            server.clone(),
            crate::wire_telemetry::observe_http,
        ))
        // Published anonymous booking capabilities validate a live owner publication
        // and scoped tokens; they do not authorize access to private vault routes.
        .merge(self::booking::public_booking_router())
        // The open feedback inbox: keyless, and mounted only when its
        // config section turns it on (ARCH-0056 #open-inbox).
        .merge(self::feedback_inbox::routes(&server))
        // OF-273: a former peer's signed courtesy deletion ask and answer.
        // Keyless; the signed body authenticates against the pinned pact key.
        .merge(self::courtesy_delete::routes())
        // FIX 922: a kit-only restore's read of the sealed cloud bundle.
        // Keyless; each request is signed with the kit's owner anchor.
        .merge(self::recovery_bundle::routes())
        // ARCH-0052 D5: everyone in a room keeps their own copy of an
        // off-record talk. Its own nest, outside the idempotency layer and
        // the wire receipts: nothing of the stretch may outlive it. The
        // owner's own off-record routes sit out here for the same reason.
        // Anonymous turns also keep no wire or idempotency receipt, and say so.
        .merge(
            self::anonymous_chat::routes()
                .layer(middleware::map_response(call_receipt::no_record_reply)),
        )
        // OF-538's one exception: these replies carry no call receipt, and
        // say so (`x-oneiron-receipt-ref: none; no-record`).
        .nest(
            "/v1/core/off-record",
            self::off_record_rooms::routes()
                .layer(middleware::map_response(call_receipt::no_record_reply)),
        )
        .nest(
            "/v1/owner",
            self::owner_routes::off_record_routes()
                .layer(middleware::map_response(call_receipt::no_record_reply)),
        )
        .with_state(server.clone())
        // OF-604: inside admission, outside every route and pre-reader, so
        // digests and body limits see the decoded bytes.
        .layer(middleware::from_fn(self::body_codec::body_codec))
        .layer(middleware::from_fn_with_state(
            server.clone(),
            crate::auth::admit_http_binding,
        ))
        // FIX 811: outside the binding door, so a reply that reached no
        // door's receipt is still its connection's.
        .layer(middleware::from_fn_with_state(
            server,
            call_receipt::connection_receipt,
        ))
}
