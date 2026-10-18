//! One facade call as every server transport hands it to the generated
//! dispatch (OF-489): the credential it is bound to, and what the transport
//! carried beside the verb's input. The HTTP route reads its headers into
//! one; the held socket binds its connection's credential. The actor, its
//! class, its read proof and its locality are the credential's own, never a
//! transport field's.

use axum::http::{HeaderMap, StatusCode};
use oneiron::EntityId;
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, ProducerRows};
use oneiron::runtime_hooks::InvocationId;
use oneiron::runtime_hooks::verb::VerbAskDrainPermit;

use super::{FacadeApiError, INVOCATION_HEADER, ROOM_TURN_HEADER};
use crate::api::call_receipt;
use crate::api::write_facet::request_session;
use crate::auth::CoreAuth;
use crate::lens_frames::CardOwner;

/// What a transport carried for one context field of a call.
#[derive(Clone, Copy)]
enum Carried<T> {
    Absent,
    Named(T),
    /// Spelled as no value of its kind: refused where the row reads it, so
    /// the refusal keeps its place among the row's own.
    Malformed,
}

impl<T: Copy> Carried<T> {
    fn spelled(text: Option<Option<&str>>, parse: impl FnOnce(&str) -> Option<T>) -> Self {
        match text {
            None => Self::Absent,
            Some(text) => text.and_then(parse).map_or(Self::Malformed, Self::Named),
        }
    }

    fn read(self, refusal: impl FnOnce() -> FacadeApiError) -> Result<Option<T>, FacadeApiError> {
        match self {
            Self::Absent => Ok(None),
            Self::Named(value) => Ok(Some(value)),
            Self::Malformed => Err(refusal()),
        }
    }
}

/// Header `name` of a request: absent, or its text, `None` when it is no text.
fn header<'h>(headers: &'h HeaderMap, name: &str) -> Option<Option<&'h str>> {
    headers.get(name).map(|value| value.to_str().ok())
}

/// The invocation a request's header names, if it names one (ARCH-0080
/// §3): its verb hooks fire once for it, and a retry of a pending call names
/// the same one to find its ask.
pub(super) fn facade_invocation_id(
    headers: &HeaderMap,
) -> Result<Option<InvocationId>, FacadeApiError> {
    invocation_header(headers).read(invalid_invocation)
}

fn invocation_header(headers: &HeaderMap) -> Carried<InvocationId> {
    Carried::spelled(header(headers, INVOCATION_HEADER), InvocationId::parse_hex)
}

fn invalid_invocation() -> FacadeApiError {
    FacadeApiError::new(
        StatusCode::BAD_REQUEST,
        MEMORY_CODE_BAD_REQUEST,
        "invalid invocation header",
        ["Name the invocation as 32 lowercase hex digits."],
    )
}

/// One call of a facade verb, as the dispatch admits it.
pub(crate) struct FacadeCall<'a> {
    auth: &'a CoreAuth,
    /// The room whose turn the call runs in (ARCH-0067 §8).
    room_turn: Carried<EntityId>,
    /// The logical verb the call runs (ARCH-0080 §3): its verb hooks fire
    /// once for it, and a retry of a pending call names the same one.
    invocation: Carried<InvocationId>,
    /// The session whose mode places a narrowed credential's writes.
    session: Carried<EntityId>,
    /// The same session as text, for the off-record surface (OF-063).
    session_ref: Option<&'a str>,
    /// The drain's permit, on a call settlement runs again (ARCH-0080 §3
    /// Ask): the row's pre chain enters as the drain's run of it.
    drain: Option<VerbAskDrainPermit>,
    /// The run that creates the live lens card this call renders, as the
    /// host names it (`EntityId::to_hex()`). Host-only, like `subscription`:
    /// no transport header or verb input sets either (OF-181, FIX 2612).
    creator_run: Option<String>,
    /// The live subscription the call's lens card renders for.
    subscription: Option<String>,
}

impl<'a> FacadeCall<'a> {
    /// A request on the HTTP facade: its credential, and the room turn,
    /// invocation and session its headers name.
    pub(super) fn http(auth: &'a CoreAuth, headers: &'a HeaderMap) -> Self {
        Self {
            auth,
            room_turn: Carried::spelled(header(headers, ROOM_TURN_HEADER), |room| {
                EntityId::from_hex(room).ok()
            }),
            invocation: invocation_header(headers),
            session: match request_session(headers) {
                Ok(None) => Carried::Absent,
                Ok(Some(session)) => Carried::Named(session),
                Err(()) => Carried::Malformed,
            },
            session_ref: call_receipt::request_session_ref(headers),
            drain: None,
            creator_run: None,
            subscription: None,
        }
    }

    /// A call on a held socket, under the credential its connection bound
    /// (`auth.bind`, at the socket's locality): no room turn and no session,
    /// and the logical invocation the call names, if it names one.
    pub(crate) const fn bound(auth: &'a CoreAuth, invocation: Option<InvocationId>) -> Self {
        Self {
            auth,
            room_turn: Carried::Absent,
            invocation: match invocation {
                Some(invocation) => Carried::Named(invocation),
                None => Carried::Absent,
            },
            session: Carried::Absent,
            session_ref: None,
            drain: None,
            creator_run: None,
            subscription: None,
        }
    }

    /// A credential caller's call the drain runs again once its hook's ask
    /// settled proceed (ARCH-0080 §3 Ask), under its credential as it
    /// verified again now: the room turn and invocation the call named, and
    /// no session, since a call that named one resumes only on its retry.
    #[cfg(feature = "code-sandbox-wasmtime")]
    pub(crate) const fn resumed(
        auth: &'a CoreAuth,
        room: Option<EntityId>,
        invocation: InvocationId,
        drain: VerbAskDrainPermit,
    ) -> Self {
        Self {
            auth,
            room_turn: match room {
                Some(room) => Carried::Named(room),
                None => Carried::Absent,
            },
            invocation: Carried::Named(invocation),
            session: Carried::Absent,
            session_ref: None,
            drain: Some(drain),
            creator_run: None,
            subscription: None,
        }
    }

    pub(super) const fn auth(&self) -> &'a CoreAuth {
        self.auth
    }

    pub(super) fn room_turn(&self) -> Result<Option<EntityId>, FacadeApiError> {
        self.room_turn.read(|| {
            FacadeApiError::new(
                StatusCode::BAD_REQUEST,
                MEMORY_CODE_BAD_REQUEST,
                "invalid room turn header",
                ["Name the room as its 32-hex id."],
            )
        })
    }

    pub(super) fn invocation(&self) -> Result<Option<InvocationId>, FacadeApiError> {
        self.invocation.read(invalid_invocation)
    }

    pub(super) fn session(&self) -> Result<Option<EntityId>, FacadeApiError> {
        self.session.read(|| {
            FacadeApiError::new(
                StatusCode::BAD_REQUEST,
                MEMORY_CODE_BAD_REQUEST,
                "invalid session header",
                ["Name the session as its 32-hex id."],
            )
        })
    }

    pub(super) const fn session_ref(&self) -> Option<&'a str> {
        self.session_ref
    }

    /// The drain's permit, when settlement runs this call again.
    pub(super) const fn drain(&self) -> Option<&VerbAskDrainPermit> {
        self.drain.as_ref()
    }

    /// This call, its live lens card held for `creator_run` and
    /// `subscription`, as the host that admitted the call names them. Only
    /// a host binds them; a call missing either holds its card unowned.
    #[allow(
        dead_code,
        reason = "FIX 2059: the socket's rpc.req call context names the subscription, an attached run the creator"
    )]
    pub(crate) fn lens_held(
        self,
        creator_run: Option<String>,
        subscription: Option<String>,
    ) -> Self {
        Self {
            creator_run,
            subscription,
            ..self
        }
    }

    /// Who owns the live lens card this call renders: its creating run and
    /// its subscription, when the host bound both. A call missing either,
    /// as every HTTP call does, holds its card through
    /// `LensFrameStore::record` (FIX 2612 (c)).
    pub(super) fn lens_owner(&self) -> Option<CardOwner> {
        match (&self.creator_run, &self.subscription) {
            (Some(creator_run), Some(subscription)) => Some(CardOwner {
                creator_run: creator_run.clone(),
                subscription: Some(subscription.clone()),
            }),
            _ => None,
        }
    }

    /// This call owned whole, for a row that runs on a blocking thread
    /// (OF-533).
    pub(super) fn owned(&self) -> OwnedFacadeCall {
        OwnedFacadeCall {
            auth: self.auth.clone(),
            room_turn: self.room_turn,
            invocation: self.invocation,
            session: self.session,
            session_ref: self.session_ref.map(str::to_owned),
            drain: self.drain.clone(),
            creator_run: self.creator_run.clone(),
            subscription: self.subscription.clone(),
        }
    }
}

/// A [`FacadeCall`] that owns its credential and session text, so it can
/// cross to a blocking thread. Every carried field stays as the transport
/// carried it: a malformed one is still refused where the row reads it.
pub(super) struct OwnedFacadeCall {
    auth: CoreAuth,
    room_turn: Carried<EntityId>,
    invocation: Carried<InvocationId>,
    session: Carried<EntityId>,
    session_ref: Option<String>,
    drain: Option<VerbAskDrainPermit>,
    creator_run: Option<String>,
    subscription: Option<String>,
}

impl OwnedFacadeCall {
    /// The call again, borrowed from this one.
    pub(super) fn call(&self) -> FacadeCall<'_> {
        FacadeCall {
            auth: &self.auth,
            room_turn: self.room_turn,
            invocation: self.invocation,
            session: self.session,
            session_ref: self.session_ref.as_deref(),
            drain: self.drain.clone(),
            creator_run: self.creator_run.clone(),
            subscription: self.subscription.clone(),
        }
    }
}

/// What one facade call answered: the verb's result, and the rows it was
/// derived from.
pub(crate) struct FacadeCallOutput {
    pub(crate) value: serde_json::Value,
    /// The rows the result was derived from, as its reads listed them
    /// (DEC-0005), the rows it names by ref aside: `None` when the row's door
    /// opens handles of its own and lists none, never an empty list standing
    /// in for an unknown one.
    pub(crate) rows: Option<Vec<EntityId>>,
}

impl FacadeCallOutput {
    /// A result whose reads listed their rows in `producers`.
    pub(super) fn listed(value: serde_json::Value, producers: &ProducerRows) -> Self {
        Self {
            value,
            rows: Some(producers.take()),
        }
    }

    /// A result whose door lists none of its rows.
    pub(super) fn unlisted(value: serde_json::Value) -> Self {
        Self { value, rows: None }
    }
}

/// The context a verb-table row runs in when no facade call can carry it.
#[derive(Clone, Copy)]
pub(super) enum VerbContext {
    /// An MCP session's board stream (`BoardVerbContext`).
    Board,
    /// A code run's own browser session.
    Browser,
    /// A code run, over its own dispatcher and storage route.
    Run,
}

/// The facade's code for a row a facade call cannot run: the context it
/// needs is named in the message and the suggestion.
pub(super) const FACADE_CODE_CONTEXT_REQUIRED: &str = "CONTEXT_REQUIRED";

/// Refuses `verb`, a row of the verb table that runs only in `context`.
pub(super) fn context_required(verb: &str, context: VerbContext) -> FacadeApiError {
    let (message, suggestion) = match context {
        VerbContext::Board => (
            format!(
                "`{verb}` is a board verb: it runs on an MCP session's board stream, which a facade call does not carry"
            ),
            "Call it over the MCP session whose board it serves.",
        ),
        VerbContext::Browser => (
            format!(
                "`{verb}` is a browser verb: a code run's own browser session answers it, and a facade call carries none"
            ),
            "Call it from code mode (`execute_code`), inside the run whose browser it drives.",
        ),
        VerbContext::Run => (
            format!(
                "`{verb}` is a run verb: a code run answers it over its own dispatcher, and a facade call carries no run"
            ),
            "Call it from code mode (`execute_code`), inside the run it belongs to.",
        ),
    };
    FacadeApiError::new(
        StatusCode::BAD_REQUEST,
        FACADE_CODE_CONTEXT_REQUIRED,
        message,
        [suggestion],
    )
}
