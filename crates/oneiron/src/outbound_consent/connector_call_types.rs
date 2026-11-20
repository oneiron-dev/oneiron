//! The connector-call shapes: the request, the host seam, its replies and
//! questions, and the caller's status view.
//! Entry: `ConnectorCallHost`. Defines its own items; the stored rows stay in `connector_call`.

use serde_json::Value;

use crate::attempt_queue::AttemptId;
use crate::connector_key::ConnectorCallRoute;
use crate::entity_id::EntityId;
use crate::secret_custody::{RunSecretHolder, SentPresentation};
use crate::secret_lease::SecretGrantRef;

use super::connector_call_input_resume::ConnectorResumeState;
use super::result_scrub::OutboundResultSender;

#[doc(hidden)]
pub use oneiron_verb_wire::outbound_consent::connector_call_types::{
    ConnectorCallRequest, ConnectorSource,
};

/// The host's own identity for one call (a code-mode step, a job attempt).
/// The ledger keys one logical send by it, so the same step run again
/// replays instead of sending twice. Never taken from the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectorCallInvocation {
    pub attempt_id: AttemptId,
    pub call_seq: u64,
}

#[doc(hidden)]
pub use oneiron_records::outbound_consent::connector_call_types::{
    ConnectorAwaitingInput, ConnectorCallOutcome, ConnectorQuestion, ConnectorResultAbsence,
    UntrustedToolResult,
};

/// Who the next send runs for and under which standing grant, as the engine
/// resolved them: a host binds a question the connector asks to exactly
/// these, never to anything the guest named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorCallCaller {
    /// The calling actor, hex.
    pub principal_ref: String,
    pub grant_id: EntityId,
    /// The catalog name the caller called.
    pub name: String,
}

/// The served side of the generic connector call: an
/// [`OutboundResultSender`] that also knows where each connector is
/// installed and keeps its own copy of the last reply.
pub trait ConnectorCallHost: OutboundResultSender {
    /// The endpoint this host installed for the routed connector, or `None`
    /// when it has none. The grant's endpoint allowlist still gates it.
    fn tool_endpoint(&self, route: &ConnectorCallRoute) -> Option<String>;

    /// Takes the reply the last `send` read, kept before the ledger's scrub
    /// destroyed the raw bytes. `None` when that send read no reply.
    fn take_result(&mut self) -> Option<UntrustedToolResult>;

    /// Presents the custody record `credential` as each send's credential
    /// from here on, in place of the route's own secret, through the
    /// credential door for the route's effector; `None` goes back to the
    /// route's. With a `grant`, each send redeems it at its door
    /// (`Vault::redeem_secret_grant_at_door`) instead. A record the use's
    /// own `run` found presents through that run's seat binding, under the
    /// route effector's door policy (`Vault::with_run_secret_for`, FIX
    /// 8334), in each send and each live exchange taken up again. False
    /// when this host cannot present a record or a grant: a call that names
    /// one is then refused unsent.
    fn present_credential(
        &mut self,
        credential: Option<EntityId>,
        grant: Option<SecretGrantRef>,
        _run: Option<RunSecretHolder>,
    ) -> bool {
        credential.is_none() && grant.is_none()
    }

    /// Binds the caller and grant the next send runs for, or none. A host
    /// that keeps a connector's questions binds them to these; one that
    /// serves no questions ignores it.
    fn bind_caller(&mut self, _caller: Option<ConnectorCallCaller>) {}

    /// Takes the questions the last `send`'s connector answered with in
    /// place of a result, kept before the ledger's scrub. `None` when it
    /// asked none.
    fn take_awaiting_input(&mut self) -> Option<ConnectorAwaitingInput> {
        None
    }

    /// Ends the live questions `handle` names, which no caller will hold:
    /// the send's ledger step did not reach Done, or the call's row could
    /// not keep the questions (FIX 3844). Their worker cancels them now. A
    /// host that keeps no questions ignores it.
    fn abandon_awaiting_input(&mut self, _handle: &str) {}

    /// Binds live questions to the row the engine is about to keep, before
    /// that writer can publish their reply. This is in-memory only: no vault
    /// writer or durable resume persistence. A failed commit abandons them.
    fn bind_awaiting_call(&mut self, _handle: &str, _call_ref: EntityId) {}

    /// Takes the bound round's opaque resume state before the row writer opens.
    /// The engine seals it in that writer; a host without resume state returns none.
    fn take_awaiting_resume(
        &mut self,
        _handle: &str,
        _call_ref: EntityId,
    ) -> Option<ConnectorResumeState> {
        None
    }

    /// The row and its reply committed. The host can mark an exchange that
    /// already ended uncertain. A host without live questions ignores it.
    fn awaiting_call_committed(&mut self, _handle: &str, _call_ref: EntityId) {}

    /// Takes the custody record the last `send` presented, as its door
    /// resolved it (FIX 5455): an empty list when it presented none, `None`
    /// when this host cannot say, which leaves the call's rows unknown.
    fn take_sent_custody(&mut self) -> Option<Vec<EntityId>> {
        None
    }

    /// Whether every send clears its reply, its questions and its raw copy
    /// of the custody value it presented, whatever selected it (a record, a
    /// grant or the route's own secret), INSIDE the door's callback with the
    /// bytes that door released (FIX 7646, FIX 7647), before any of it
    /// leaves. A host that does not has a named record's reply cleared by a
    /// reread instead, as before.
    fn clears_at_door(&self) -> bool {
        false
    }

    /// Takes the custody presentation the last `send` made, as its door
    /// released it: the record, the generation sent and its reply's release
    /// policy (FIX 7646). `None` when it presented none, or this host cannot
    /// say. Ids and generation only, never a value.
    fn take_sent_presentation(&mut self) -> Option<SentPresentation> {
        None
    }

    /// Takes the hold the last `send` met at its door (FIX 9303): the call's
    /// durable issuer binding, read again as its credential would leave,
    /// held its row, so nothing was presented or sent, and its outcome is a
    /// certain non-delivery. `None` when it met none, or this host does not
    /// read it there.
    fn take_send_hold(&mut self) -> Option<&'static str> {
        None
    }

    /// Takes the session manifest of the runner the last `send` went
    /// through (canon `#runner-fence`, row L8-27): a stdio connector's
    /// child. `None` when it went through none, or this host starts none.
    fn take_session_manifest(&mut self) -> Option<oneiron_container::SessionManifest> {
        None
    }
}

/// One held or pending-delivery call, as a settler lists it: its ref, the
/// catalog name and tool it calls, and whether a resume already settled it
/// (then its row waits only for
/// [`crate::Vault::ack_connector_call_delivery_keeping_caller`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingConnectorCallRef {
    pub call_ref: EntityId,
    pub name: String,
    pub tool: String,
    pub settled: bool,
    /// A full count-bound budget window paced the call (FIX 8686): `Some`
    /// with `true` while its window is still shut on the engine's clock, so
    /// no resume runs; `Some(false)` once it opened, so the next pass drives
    /// it at once.
    pub paced: Option<bool>,
}

/// One tool's approved input schema, on the governing key the caller's own
/// grant resolves, or why there is none. Read-only and secret-free.
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectorToolSchema {
    Approved {
        input_schema: Value,
        destructive_hint: bool,
    },
    /// The hold or refusal a call of the tool would meet first.
    Unavailable { reasons: Vec<String> },
}

/// Where one connector call stands, for its caller-bound status read (FIX
/// 2279): who called it, what it calls, and how far it got. Secret-free and
/// reply-free: a settled reply is its wait's.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorCallState {
    /// The calling actor, hex.
    pub principal_ref: String,
    /// The exact grant the last send ran under, hex; absent after acknowledgement.
    pub grant_id: Option<String>,
    pub name: String,
    pub tool: String,
    /// When it was first held; `None` once a settler acknowledged it.
    pub held_at_ms: Option<u64>,
    /// The hold reasons the owner's ask carried, once an ask was tried.
    pub reasons: Vec<String>,
    /// What a resume settled it to, receipt-only, while its wait reply is
    /// not yet acknowledged.
    pub settled: Option<ConnectorCallOutcome>,
    /// A settler answered its wait and acknowledged it: the reply is the
    /// wait's.
    pub acknowledged: bool,
    /// The rows the call's passes picked (FIX 5455) while its row stands;
    /// `None` when they are not known, and once acknowledged, when they ride
    /// the wait's reply instead.
    pub source_rows: Option<Vec<EntityId>>,
    /// FIX 6424 part 3: the approve-once digest the call's approvable hold
    /// named, kept on its row while it is held: the owner's press on it
    /// releases exactly the call as it was prepared. `None` once settled,
    /// and for a call no approvable hold asked about.
    pub approval_digest: Option<String>,
    /// The round of questions its connector asked once it was sent
    /// (FIX 3837), kept on its row: unanswered while `settled` is `None`.
    pub input: Option<super::connector_call_input::ConnectorCallInput>,
}
