//! The facade's error envelope: an engine `MemoryError` or an `ApiError` as one HTTP reply.
//! `FacadeApiError` (defined in the facade root) is its entry type.
//! The facade root defines `FacadeApiError` and its envelope; `oneiron::memory` owns the codes.

use super::*;

impl FacadeApiError {
    pub(super) fn new(
        status: StatusCode,
        code: &str,
        message: impl Into<String>,
        suggestions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            status,
            body: FacadeErrorEnvelope {
                error: FacadeErrorBody {
                    code: code.to_owned(),
                    message: message.into(),
                    request_id: facade_request_id(),
                    suggestions: suggestions.into_iter().map(Into::into).collect(),
                    receipt_ref: None,
                    wrong_root: None,
                    hook: None,
                    retry_after: None,
                    resets_at: Vec::new(),
                    reason_codes: Vec::new(),
                    legal_hold: None,
                    program_steps: Vec::new(),
                },
                narrowing: None,
            },
        }
    }

    pub(super) fn forbidden(
        message: impl Into<String>,
        suggestions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            MEMORY_CODE_FORBIDDEN,
            message,
            suggestions,
        )
    }
}

/// The engine's refusal, forwarded whole.
///
/// The status is derived from the code; the code, message, and suggestions are
/// the engine's own bytes. An unrecognized code keeps its string and takes a
/// `500`: unknown means this server cannot claim to know the failure is the
/// caller's fault.
impl From<MemoryError> for FacadeApiError {
    fn from(error: MemoryError) -> Self {
        let status = match error.code.as_str() {
            // A wrong root is the caller's spelling, refused before any
            // effect with the name to call instead.
            MEMORY_CODE_BAD_REQUEST | oneiron::memory::MEMORY_CODE_WRONG_ROOT => {
                StatusCode::BAD_REQUEST
            }
            MEMORY_CODE_NOT_FOUND => StatusCode::NOT_FOUND,
            // `LEASE_REQUIRED` is a refusal to serve without a credential the
            // caller does not hold, which is what 403 means. The engine code
            // carries the specific meaning; the status only has to be an
            // honest 4xx so no client reads the body as success.
            // `OWNER_BINDING_REQUIRED` is a 403 for the same reason
            // `FORBIDDEN` is: the authority log refuses this actor the verb.
            // It carries its own code so a client can tell the authority door
            // from the gate door, but the status is the same honest 403.
            // FIX 2222: a host credential where no host acts as a person.
            // WILL-PLAN L13 row 03: a room's whole off-record stretch, which
            // no consent record admits a session row to manage.
            MEMORY_CODE_FORBIDDEN
            | MEMORY_CODE_LEASE_REQUIRED
            | MEMORY_CODE_OWNER_BINDING_REQUIRED
            | oneiron::memory::MEMORY_CODE_HOST_ACTION_REFUSED
            | oneiron::memory::MEMORY_CODE_ROOM_MANAGEMENT => StatusCode::FORBIDDEN,
            // Both are "the store is not in a state that admits this", which
            // is the conflict family the rest of this plane already maps to
            // 409. `VAULT_LOCKED_SINGLE_WRITER` cannot arise server-side — it
            // is the EMBEDDED constructor's refusal — and is mapped anyway so
            // the vocabulary has no hole.
            MEMORY_CODE_INVALID_STATE
            | MEMORY_CODE_OFF_RECORD_SESSION_DOOR
            | MEMORY_CODE_VAULT_LOCKED_SINGLE_WRITER
            | oneiron::workspace_roster::MEMORY_CODE_AGENT_THREAD_WALK_IN_FORBIDDEN => {
                StatusCode::CONFLICT
            }
            // OF-123: the person the effect names is not settled yet; the
            // same request succeeds once `self.identity.settle` settles it.
            oneiron::memory::MEMORY_CODE_IDENTITY_UNSETTLED => StatusCode::CONFLICT,
            // FIX 7463a: the owner's world read setting keeps a row the call
            // reads from where its answer goes, or its placement cannot be
            // verified. The row's state refuses, named, never a row not found.
            oneiron_contracts::memory::MEMORY_CODE_WORLD_RECIPIENT_LIMIT
            | oneiron_contracts::memory::MEMORY_CODE_WORLD_PLACEMENT_UNVERIFIABLE => {
                StatusCode::CONFLICT
            }
            // FIX 7650: a foreign guest's proposal spool met the host's disk
            // floor. The server's storage, named, never the caller's request.
            oneiron_contracts::memory::MEMORY_CODE_SANDBOX_PROPOSAL_DISK_FLOOR => {
                StatusCode::INSUFFICIENT_STORAGE
            }
            // A paid call its line cannot cover, as a chat turn's is.
            MEMORY_CODE_BUDGET_SPENT => StatusCode::PAYMENT_REQUIRED,
            // A verb hook asked first: accepted, not run, and the body names
            // the ask a retry with the same invocation waits on.
            MEMORY_CODE_PENDING_ASK => StatusCode::ACCEPTED,
            // The model the request needs did not answer: not the caller's
            // fault, and not this server's to stand in for.
            MEMORY_CODE_MODEL_UNAVAILABLE => StatusCode::SERVICE_UNAVAILABLE,
            // FIX 10011: the owner's model pin stands and no offered seat
            // serves it. The owner's setting refuses it, as `error_map` does.
            oneiron_contracts::memory::MEMORY_CODE_MODEL_PIN_UNAVAILABLE => StatusCode::CONFLICT,
            // FIX 8189: an OpenAI proxy call the caller's own deadline cut,
            // as its raw door answers it.
            crate::api::openai_proxy::TIMEOUT_CODE => StatusCode::GATEWAY_TIMEOUT,
            // FIX 11198: the OpenAI proxy's own refusal codes, each with the
            // status its raw door already answers (wire.rs upstream_error, mod.rs
            // invalid/forbidden/error, choices.rs, release.rs, and llm.rs admission
            // for the proxied call). A typed caller reads a rate limit as 429,
            // not a server fault.
            "rate_limited" | "quota_spent" => StatusCode::TOO_MANY_REQUESTS,
            "upstream_error" | "upstream_auth" | "label_read" => StatusCode::BAD_GATEWAY,
            "kept_on_device" | "world_route_not_admitted" | "recall_failed" | "llm_unavailable" => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            "budget_denied" => StatusCode::PAYMENT_REQUIRED,
            "model_not_found" => StatusCode::NOT_FOUND,
            "connector_auth_required" => StatusCode::UNAUTHORIZED,
            "memory_withheld"
            | "session_refused"
            | "scope_refused"
            | "verb_unbound"
            | "connector_unregistered"
            | "connector_grant_revoked"
            | "extraction_egress_denied" => StatusCode::FORBIDDEN,
            "n_unsupported"
            | "stream_unsupported"
            | "user_message_required"
            | "invalid_request"
            | "route_selector_forbidden" => StatusCode::BAD_REQUEST,
            // OF-063: the write named a record its writer cannot resolve. The
            // request was well formed and refused, so it is the caller's
            // to correct, and a missing record and an unreadable one are this
            // same status.
            oneiron::memory::MEMORY_CODE_INVENTED_REFERENCE => StatusCode::UNPROCESSABLE_ENTITY,
            // A credential call settlement refused before it ran (ARCH-0080
            // §3 Ask): the caller's credential no longer admits it, or this
            // host could not run it again. Either way a new invocation.
            code if VerbAskRefusal::from_code(code)
                .is_some_and(VerbAskRefusal::names_credential) =>
            {
                StatusCode::FORBIDDEN
            }
            code if VerbAskRefusal::from_code(code).is_some() => StatusCode::CONFLICT,
            // OF-580: the call ran once its ask settled, and only its result
            // was not kept. A conflict with the call's own record, not this
            // server's failure, and no retry runs it again.
            HOOK_RESULT_NOT_RETAINED => StatusCode::CONFLICT,
            // FIX 7664: a typed browser refusal (a press the owner owes, a page
            // that timed out, a refused destination) is not this server's fault.
            code if browser_doors::browser_refusal_status(code).is_some() => {
                browser_doors::browser_refusal_status(code)
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
            }
            // FIX 7653: a render that ran past its deadline or met a machine
            // floor is not the caller's fault, and can be asked again.
            crate::slide_render::RENDER_DEADLINE
            | crate::slide_render::RENDER_MEMORY_FLOOR
            | crate::slide_render::RENDER_DISK_FLOOR => StatusCode::SERVICE_UNAVAILABLE,
            // FIX 5325: a hosted vault paused for its reap answers what its
            // served writes answer (K18): temporary, and lifted by the reap's
            // abort or the vault's wake, never this server's failure.
            crate::managed::WRITES_FROZEN_TAG => StatusCode::SERVICE_UNAVAILABLE,
            // FIX 679: `ai.ask_image`'s door refuses under its route's own
            // code, and answers with the route's status.
            code if host_doors::ask_image_refusal_status(code).is_some() => {
                host_doors::ask_image_refusal_status(code)
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
            }
            MEMORY_CODE_INTERNAL => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(code = %error.code, error = %error.message, "facade verb failed");
        } else if error.code == HOOK_RESULT_NOT_RETAINED {
            tracing::info!(code = %error.code, "facade verb ran; its result was not retained");
        } else if browser_doors::browser_refusal_status(&error.code).is_some() {
            tracing::info!(code = %error.code, error = %error.message, "browser verb refused");
        }
        Self {
            status,
            body: FacadeErrorEnvelope {
                error: FacadeErrorBody {
                    code: error.code,
                    message: error.message,
                    request_id: facade_request_id(),
                    suggestions: error.suggestions,
                    receipt_ref: None,
                    wrong_root: error.wrong_root,
                    hook: error.hook,
                    retry_after: error.retry_after,
                    resets_at: error.resets_at,
                    reason_codes: error.reason_codes,
                    legal_hold: error.legal_hold,
                    program_steps: Vec::new(),
                },
                narrowing: error.read_receipt,
            },
        }
    }
}

/// Scope refusals keep coming from the shared `CoreAuth::require`, so the one
/// scope check in this crate stays one implementation. Only the SERIALIZATION
/// changes here: the closed enum's stable string becomes this envelope's raw
/// `code`, which is the same text a client would have read either way.
impl From<ApiError> for FacadeApiError {
    fn from(error: ApiError) -> Self {
        let legal_hold = error.legal_hold().cloned().map(Box::new);
        let mut refusal = Self::new(
            error.status(),
            error.code().as_str(),
            error.message().to_owned(),
            error.suggestions().to_vec(),
        );
        refusal.body.error.legal_hold = legal_hold;
        refusal
    }
}

impl FacadeApiError {
    /// The refusal with a failed run's program type feedback beside it (FIX
    /// 10389), each item as its destination is given it: never among its
    /// words, its status, code and retry as they were.
    pub(crate) fn with_program_steps(
        mut self,
        program_steps: Vec<oneiron::code_run::ProgramStepFeedbackRelease>,
    ) -> Self {
        self.body.error.program_steps = program_steps;
        self
    }

    /// The refusal's wire reply: its status and `{error, narrowing?}` body,
    /// and `Retry-After` when the refusal says when to call again.
    pub(super) fn reply(&self) -> Response {
        let mut response = (self.status, Json(&self.body)).into_response();
        if let Some(seconds) = self.body.error.retry_after {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, HeaderValue::from(seconds));
        }
        response
    }

    /// The refusal as the engine's typed error, for a door outside the
    /// facade (MCP's row door admission, the held socket's `rpc.err`): its
    /// open code, message and suggestions, its read receipt, wrong-root
    /// correction and hook stop. Only the HTTP status stays behind.
    pub(crate) fn into_memory_error(self) -> MemoryError {
        let FacadeErrorEnvelope { error, narrowing } = self.body;
        let mut refusal = MemoryError::new(&error.code, error.message, &[]);
        refusal.suggestions = error.suggestions;
        refusal.read_receipt = narrowing;
        refusal.wrong_root = error.wrong_root;
        refusal.hook = error.hook;
        refusal.retry_after = error.retry_after;
        refusal.resets_at = error.resets_at;
        refusal.reason_codes = error.reason_codes;
        refusal.legal_hold = error.legal_hold;
        refusal
    }
}

/// The reply, with the refusal itself riding along in the response's
/// extensions, so the facade's receipt layer reads its code and states the
/// call's receipt in its body (OF-538).
impl IntoResponse for FacadeApiError {
    fn into_response(self) -> Response {
        let mut response = self.reply();
        response.extensions_mut().insert(self);
        response
    }
}

/// Diagnostic correlation id for one facade error.
///
/// Its own counter with its own prefix rather than a reach into
/// `crate::error`'s private one: two sequences that cannot be confused for
/// each other are better than one sequence shared through a widened seam that
/// this ticket is not allowed to widen.
pub(super) fn facade_request_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("facade-req-{id:016x}")
}
