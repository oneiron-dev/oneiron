//! The generic connector call (ONE-2510): one tool on one catalogued
//! connector, through the scoped-MCP prepare → execute path.
//!
//! The engine owns the authority: the route, the caller's standing grant,
//! the approved schema on the governing key, the gate and the ledger. A
//! [`ConnectorCallHost`] owns what lives beneath the catalog name: the
//! installed transport and endpoint, and the credential, which it presents
//! only inside the send. A call the gate holds for consent or governance
//! keeps its exact request in one durable row, and
//! [`crate::Vault::resume_connector_call`] re-enters it with the same logical
//! identity. The tool's own reply comes back to the caller as foreign data;
//! the ledger's scrub still keeps its raw bytes out of durable storage.
//!
//! A host's identity for a call fixes its row's ref, so the same call run
//! again finds the call it held. Once a resume settles a held call, the row
//! keeps that outcome, without the reply, until a settler lists it
//! ([`crate::Vault::pending_connector_calls`]), answers the wait the ref names and
//! acknowledges it ([`crate::Vault::ack_connector_call_delivery`]).
//! [`crate::Vault::connector_tool_schema`] reads a tool's approved schema through
//! the same resolution a call takes.
//!
//! A hold asks the owner once (`connector_call_asks`); the answer grants
//! nothing, the consent and key doors still do. A call nobody settles
//! expires a fixed time after it was first held (`connector_call_pending`).
//! A held call the ledger already admitted resumes from that frozen row by
//! its intent id (`connector_call_resume`), never from bytes prepared again.
//!
//! A `self.use` call (`Vault::call_connector_with_secret`, OF-560) names a
//! custody record as its credential in place of the route's own secret. Its
//! row keeps the record, so every pass presents the same one through the
//! host ([`ConnectorCallHost::present_credential`]), the credential door
//! rechecks the record's binding at each send, and a delivered reply is
//! cleared of the value before it goes anywhere. A call under a secret grant
//! (FIX 4313) keeps the grant beside the record, and the host redeems it again
//! at every send. Whatever selected it, a handle, a grant or the route's own
//! secret, each send's actual presentation is the host's to clear its reply
//! of, inside the door, with the bytes it sent
//! ([`ConnectorCallHost::clears_at_door`], FIX 7646, FIX 7647).
//!
//! A connector may answer a call with questions instead of a result (its
//! mid-call elicitation). The request reached it, so the send is delivered:
//! the ledger completes the intent and nothing replays. The host keeps the
//! questions, foreign data, for the caller in place of the tool's reply
//! ([`ConnectorCallHost::take_awaiting_input`]) and the call comes back as
//! [`ConnectorCallOutcome::AwaitingInput`]; the host binds them to the caller
//! and grant [`ConnectorCallHost::bind_caller`] named before the send. The
//! answer is the host's to carry, checked under the same grant
//! ([`crate::Vault::authorize_connector_elicitation_answer`]).

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::connector_key::ConnectorCallRoute;
use crate::entity_id::EntityId;
use crate::outbound_intent_ledger::IntentLedgerError;
use crate::secret_lease::SecretGrantRef;
use crate::side_table::{self, Named, SideTable};

use super::tool_call::MutationIntent;

mod rows;

pub(super) use super::connector_call_dispatch::{
    escalation_code, intent_escalation_code, step_from_host,
};
pub(super) use super::connector_call_driver::{Step, refused};
pub use super::connector_call_types::{
    ConnectorAwaitingInput, ConnectorCallCaller, ConnectorCallHost, ConnectorCallInvocation,
    ConnectorCallOutcome, ConnectorCallRequest, ConnectorCallState, ConnectorQuestion,
    ConnectorResultAbsence, ConnectorToolSchema, PendingConnectorCallRef, UntrustedToolResult,
};

/// The most bytes of one connector discovery or qualification reply a host
/// reads at admission. A `tools/call` reply is read whole (FIX 8227). One
/// constant, so a later ruling changes one line.
pub const CONNECTOR_REPLY_MAX_BYTES: usize = 1024 * 1024;

/// The held and pending-delivery calls, by call ref.
pub(super) const PENDING_CALLS: SideTable<EntityId, PendingConnectorCall, Named> =
    SideTable::new(&side_table::OUTBOUND_CONNECTOR_CALL_PENDING);

/// The derivation domain of the call ref a host's own identity fixes, so the
/// same logical call finds its held row again instead of holding a second.
const CONNECTOR_CALL_REF_DOMAIN: &[u8] = b"oneiron:connector-call-ref:v1";

/// The effector a call on `route` presents its credential for:
/// `connector:<connector>`. A `self.use` binding names it.
pub(crate) fn connector_call_effector(route: &ConnectorCallRoute) -> String {
    format!("connector:{}", route.connector)
}

/// The exact request a held call re-enters with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingConnectorCall {
    pub(super) name: String,
    pub(super) tool: String,
    /// The guest's arguments as JSON text, exactly as first given.
    pub(super) arguments: String,
    pub(super) mutation: MutationIntent,
    /// The standing grant the last attempt ran under (hex), if one matched.
    pub(super) grant_id: Option<String>,
    pub(super) attempt_id: AttemptId,
    pub(super) call_seq: u64,
    pub(super) principal_ref: String,
    /// When the call was first held. Its expiry deadline counts from here,
    /// and no retry moves it.
    pub(super) held_at_ms: u64,
    /// What the call came to once a resume settled it. The row outlives its
    /// terminal outcome until the settler acknowledges the wait reply that
    /// carries it, so a crash before that reply commits strands no waiter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) settled: Option<SettledConnectorCall>,
    /// The hold reasons the owner's ask carried, kept once an ask was tried.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) held_reasons: Vec<String>,
    /// The arrival number of the owner's ask about this hold, once queued:
    /// the call asks once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) owner_ask_seq: Option<u64>,
    /// The custody record a `self.use` call presents as its credential, in
    /// place of the route's own secret. Every pass presents it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) credential: Option<EntityId>,
    /// The secret grant a lease-aware `self.use` call redeems at every send,
    /// beside its record (FIX 4313).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) grant: Option<SecretGrantRef>,
    /// The code consent wait bound beside this hold (DOOR-079 1a), in the
    /// writer that first kept it: only its owner's answer and the effect's
    /// own gate settle the call then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) code_consent_wait: Option<EntityId>,
    /// The rows the call's passes picked themselves (FIX 5455), unioned over
    /// every pass: the catalog route key, each standing grant read, the
    /// governing key, each slate read, and the custody record or secret
    /// grant a send presented. Ids only, never a value; `None` once a pass's
    /// are not known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) source_rows: Option<Vec<EntityId>>,
    /// The approvable asks the call's holds named (FIX 6424 part 3,
    /// `approval`): digests only, read tolerantly (undecodable is absent).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::approval::tolerant_approval"
    )]
    pub(super) approval: Option<super::approval::ConnectorCallApproval>,
    /// The round of questions the call's connector asked once the call was
    /// sent (FIX 3837): its handle, generation and count, never the text;
    /// kept until the connector answers the call, and beside its delivery
    /// after. A row with it is never resumed or expired: the send was
    /// delivered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) input: Option<super::connector_call_input::PendingConnectorInput>,
    /// This pass's code consent context (`connector_call_code`); never
    /// stored.
    #[serde(skip)]
    pub(super) code: Option<Box<super::connector_call_code::CodePass>>,
    /// An off-record caller's arguments, sealed under the call's resume
    /// custody (FIX 9159): the stored row's `arguments` is then empty. They
    /// go, and their keys retire, with the row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) sealed_arguments: Option<Vec<u8>>,
    /// This pass's caller keeps no record (FIX 9159): its row keeps its
    /// arguments sealed, never in the clear. Never stored.
    #[serde(skip)]
    pub(super) off_record: bool,
    /// A full count-bound budget window paces this call until this engine
    /// instant, Unix seconds (FIX 8686): it asks no one, does not expire, and
    /// the settler drives it again from then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) paced_until: Option<u64>,
}

/// A held call's terminal outcome, without the tool's reply: the ledger
/// never keeps a reply's bytes, so a recovery from this row is receipt-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SettledConnectorCall {
    Delivered {
        intent: Option<[u8; 32]>,
    },
    Refused {
        decision_ref: Option<String>,
        reasons: Vec<String>,
    },
    Unsettled {
        intent: [u8; 32],
        reasons: Vec<String>,
    },
}

impl SettledConnectorCall {
    pub(super) fn outcome(&self) -> ConnectorCallOutcome {
        match self.clone() {
            Self::Delivered { intent } => ConnectorCallOutcome::Delivered {
                intent,
                result: None,
                result_absence: Some(ConnectorResultAbsence::NotRetained),
                budget_steering: Vec::new(),
            },
            Self::Refused {
                decision_ref,
                reasons,
            } => ConnectorCallOutcome::Refused {
                decision_ref,
                reasons,
            },
            Self::Unsettled { intent, reasons } => ConnectorCallOutcome::PendingDelivery {
                intent,
                call_ref: None,
                reasons,
            },
        }
    }
}

/// The call ref a host's identity fixes for one caller: the same caller's
/// same logical call always names the same held row.
pub(super) fn connector_call_ref(
    principal_ref: &str,
    invocation: ConnectorCallInvocation,
) -> Result<EntityId, IntentLedgerError> {
    Ok(EntityId::derive(
        CONNECTOR_CALL_REF_DOMAIN,
        &[
            principal_ref.as_bytes(),
            invocation.attempt_id.as_bytes(),
            &invocation.call_seq.to_le_bytes(),
        ],
    )?)
}

pub(super) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// One held call's principal, connector name and tool, so the owner's
/// connector consent binds exactly the actor that will resume it. A row a
/// resume or an expiry already settled holds nothing, so it answers `None`.
pub(crate) fn held_connector_call_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    call_ref: &EntityId,
) -> crate::Result<Option<(String, String, String)>> {
    Ok(PENDING_CALLS
        .get(store, txn, call_ref)?
        .filter(|row| row.settled.is_none() && row.input.is_none())
        .map(|row| (row.principal_ref, row.name, row.tool)))
}

/// Who called one connector call a settler answered and acknowledged, and
/// what it calls (FIX 2279): the status read's binding once the held row is
/// gone. The reply itself is the settled wait's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AcknowledgedConnectorCall {
    pub(super) principal_ref: String,
    pub(super) name: String,
    pub(super) tool: String,
    /// A call whose connector asked for input, kept here once its settled
    /// status was read (FIX 9158): its outcome, receipt-only, which its
    /// status reads from here, never its settled wait's first questions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) settled: Option<SettledConnectorCall>,
    /// The rows that call's passes picked (FIX 5455), ids only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) source_rows: Option<Vec<EntityId>>,
}

/// The acknowledged calls' callers, by call ref.
pub(super) const ACKNOWLEDGED_CALLS: SideTable<EntityId, AcknowledgedConnectorCall, Named> =
    SideTable::new(&side_table::OUTBOUND_CONNECTOR_CALL_CALLER);
