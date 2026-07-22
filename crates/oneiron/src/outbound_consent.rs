//! Payload-aware consent and transport boundary for scoped outbound tools.
//!
//! A real transport implementation is intentionally outside this module. Any
//! implementation plugged into [`OutboundResultSender`] must enforce
//! [`OutboundTransportPolicy`]: stdio children run with explicit environment,
//! inherited-FD, and filesystem allowlists; network transports verify TLS; and
//! the resolved endpoint checked here is the endpoint shown at grant time.

use std::fmt;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::outbound_grant::{StandingOutboundGrant, StandingOutboundGrantScope};
use crate::outbound_intent_ledger::{
    FrozenOutboundCall, IntentDispatchResult, IntentLedgerError, IntentRecoveryReport, IntentState,
    OutboundAuthorizationBinding, OutboundCallClass, OutboundSendOutcome, OutboundToolDescriptor,
    classify_outbound_tool, derive_intent_id,
};
use crate::registry::ENTITY_TYPE_OUTBOUND_GRANT;

const AUTHORIZED_RECOVERY_LEASE_KEY: &[u8] = b"outbound:authorized_recovery_lease:v1";
const AUTHORIZED_RECOVERY_LEASE_VALUE_LEN: usize = 24;

#[cfg(test)]
std::thread_local! {
    static FROZEN_MCP_PAYLOAD_FREEZE_EVENTS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// Payload sensitivity ordered from least to most restrictive.
///
/// [`Self::Unclassified`] is the fail-closed parse result. It sorts above the
/// highest grantable ceiling, so it can never accidentally become public.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DataClass {
    Public,
    Personal,
    Secret,
    Unclassified,
}

impl DataClass {
    /// Parses a payload class. Unknown spellings stay above every grantable
    /// ceiling and therefore force escalation.
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value {
            "public" => Self::Public,
            "personal" => Self::Personal,
            "secret" => Self::Secret,
            _ => Self::Unclassified,
        }
    }

    /// Stable spelling used by the standing-grant codec.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Personal => "personal",
            Self::Secret => "secret",
            Self::Unclassified => "unclassified",
        }
    }

    /// Only known classes may be persisted as grant ceilings.
    #[must_use]
    pub const fn is_grantable(self) -> bool {
        !matches!(self, Self::Unclassified)
    }
}

impl std::str::FromStr for DataClass {
    type Err = ();

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let parsed = Self::parse(value);
        parsed.is_grantable().then_some(parsed).ok_or(())
    }
}

/// Borrowed payload-aware axes of one scoped standing grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopedMcpGrantRef<'a> {
    pub server: &'a str,
    pub tool: &'a str,
    pub data_class_ceiling: DataClass,
    pub endpoint_allowlist: &'a [String],
}

/// One outbound tool call as the automated consent check sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopedMcpCall<'a> {
    pub server: &'a str,
    pub tool: &'a str,
    pub payload_data_class: DataClass,
    pub resolved_endpoint: &'a str,
}

/// Owned call axes threaded through the Gate before any transport is chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedMcpCallContext {
    pub server: String,
    pub tool: String,
    pub payload_data_class: DataClass,
    pub resolved_endpoint: String,
}

impl ScopedMcpCallContext {
    #[must_use]
    pub fn as_call(&self) -> ScopedMcpCall<'_> {
        ScopedMcpCall {
            server: &self.server,
            tool: &self.tool,
            payload_data_class: self.payload_data_class,
            resolved_endpoint: &self.resolved_endpoint,
        }
    }
}

/// Why one call cannot auto-fire under its standing authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScopedMcpEscalationReason {
    InvalidGrant,
    WrongPrincipal,
    WrongServer,
    WrongTool,
    EndpointNotAllowed,
    UnknownDataClass,
    DataClassCeilingExceeded,
    ConnectorKeyUnregistered,
    ConnectorKeyPending,
    ConnectorKeySuspended,
    ConnectorKeyRevoked,
    ConnectorKeyCharterDrift,
    ConnectorKeyCharterNeverList,
    ConnectorKeyBudgetExhausted,
}

/// Automated per-call consent decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScopedMcpConsentDecision {
    AutoFire,
    Escalate(ScopedMcpEscalationReason),
}

/// Counted result of evaluating a batch without escalation coalescing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScopedMcpBatchVerdict {
    pub auto_fired: usize,
    pub human_escalations: usize,
    pub decisions: Vec<ScopedMcpConsentDecision>,
}

/// Evaluates one call against all payload-aware grant axes.
#[must_use]
pub fn evaluate_scoped_mcp_call(
    grant: ScopedMcpGrantRef<'_>,
    call: ScopedMcpCall<'_>,
) -> ScopedMcpConsentDecision {
    if !is_canonical_non_empty(grant.server)
        || !is_canonical_non_empty(grant.tool)
        || grant.endpoint_allowlist.is_empty()
        || grant
            .endpoint_allowlist
            .iter()
            .any(|endpoint| !is_canonical_non_empty(endpoint))
        || !grant.data_class_ceiling.is_grantable()
    {
        return ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::InvalidGrant);
    }
    if !is_canonical_non_empty(call.server) {
        return ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::WrongServer);
    }
    if !is_canonical_non_empty(call.tool) {
        return ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::WrongTool);
    }
    if !is_canonical_non_empty(call.resolved_endpoint) {
        return ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::EndpointNotAllowed);
    }
    if call.server != grant.server {
        return ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::WrongServer);
    }
    if call.tool != grant.tool {
        return ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::WrongTool);
    }
    if !grant
        .endpoint_allowlist
        .iter()
        .any(|endpoint| endpoint == call.resolved_endpoint)
    {
        return ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::EndpointNotAllowed);
    }
    if !call.payload_data_class.is_grantable() {
        return ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::UnknownDataClass);
    }
    if call.payload_data_class > grant.data_class_ceiling {
        return ScopedMcpConsentDecision::Escalate(
            ScopedMcpEscalationReason::DataClassCeilingExceeded,
        );
    }
    ScopedMcpConsentDecision::AutoFire
}

/// Evaluates calls independently; every exceed produces its own escalation.
#[must_use]
pub fn evaluate_scoped_mcp_calls(
    grant: ScopedMcpGrantRef<'_>,
    calls: &[ScopedMcpCall<'_>],
) -> ScopedMcpBatchVerdict {
    let mut verdict = ScopedMcpBatchVerdict::default();
    verdict.decisions.reserve(calls.len());
    for call in calls {
        let decision = evaluate_scoped_mcp_call(grant, *call);
        match decision {
            ScopedMcpConsentDecision::AutoFire => {
                verdict.auto_fired = verdict.auto_fired.saturating_add(1);
            }
            ScopedMcpConsentDecision::Escalate(_) => {
                verdict.human_escalations = verdict.human_escalations.saturating_add(1);
            }
        }
        verdict.decisions.push(decision);
    }
    verdict
}

/// Raw provider result. Diagnostics redact every provider-controlled field.
pub struct RawOutboundResult {
    body: Option<Vec<u8>>,
    error: Option<String>,
    stderr: Option<Vec<u8>>,
    url: Option<String>,
}

impl RawOutboundResult {
    #[must_use]
    pub fn new(
        body: Option<Vec<u8>>,
        error: Option<String>,
        stderr: Option<Vec<u8>>,
        url: Option<String>,
    ) -> Self {
        Self {
            body,
            error,
            stderr,
            url,
        }
    }

    #[must_use]
    pub fn scrubbable_field_count(&self) -> usize {
        usize::from(self.body.is_some())
            + usize::from(self.error.is_some())
            + usize::from(self.stderr.is_some())
            + usize::from(self.url.is_some())
    }
}

impl fmt::Debug for RawOutboundResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawOutboundResult")
            .field("body", &self.body.as_ref().map(std::vec::Vec::len))
            .field("error", &self.error.as_ref().map(|_| "[redacted]"))
            .field("stderr", &self.stderr.as_ref().map(std::vec::Vec::len))
            .field("url", &self.url.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// Provider result after all raw fields have been destroyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScrubbedOutboundResult {
    body: bool,
    error: bool,
    stderr: bool,
    url: bool,
}

impl ScrubbedOutboundResult {
    #[must_use]
    pub const fn scrubbed_field_count(self) -> usize {
        self.body as usize + self.error as usize + self.stderr as usize + self.url as usize
    }
}

/// In-memory quarantine carrier. It deliberately implements neither
/// serialization nor accessors for provider-controlled content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuarantinedOutboundResult {
    scrubbed: ScrubbedOutboundResult,
}

impl QuarantinedOutboundResult {
    #[must_use]
    pub const fn scrubbed_field_count(self) -> usize {
        self.scrubbed.scrubbed_field_count()
    }
}

/// Destructive result-scrub fence at the transport boundary.
#[must_use]
pub fn scrub_outbound_result(raw: RawOutboundResult) -> QuarantinedOutboundResult {
    QuarantinedOutboundResult {
        scrubbed: ScrubbedOutboundResult {
            body: raw.body.is_some(),
            error: raw.error.is_some(),
            stderr: raw.stderr.is_some(),
            url: raw.url.is_some(),
        },
    }
}

/// Result-carrying transport response before adaptation to the intent ledger.
pub struct OutboundTransportResult {
    pub outcome: OutboundSendOutcome,
    pub raw_result: RawOutboundResult,
}

/// Result-carrying transport seam. Implementations receive only the immutable
/// frozen call whose bytes were authorized.
pub trait OutboundResultSender {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundTransportResult;
}

/// Once-serialized payload consumed by the durable outbound pipeline.
pub struct FrozenMcpPayload {
    bytes: Vec<u8>,
    #[cfg(test)]
    freeze_event_baseline: usize,
}

impl FrozenMcpPayload {
    /// Freezes caller-serialized bytes. No later stage has a serialization
    /// API; the buffer is moved into the ledger request unchanged.
    #[must_use]
    pub fn new(serialized: Vec<u8>) -> Self {
        #[cfg(test)]
        let freeze_event_baseline = FROZEN_MCP_PAYLOAD_FREEZE_EVENTS.with(|counter| {
            let baseline = counter.get();
            counter.set(baseline.wrapping_add(1));
            baseline
        });
        Self {
            bytes: serialized,
            #[cfg(test)]
            freeze_event_baseline,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[cfg(test)]
    pub(crate) const fn freeze_event_baseline(&self) -> usize {
        self.freeze_event_baseline
    }

    #[cfg(test)]
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl fmt::Debug for FrozenMcpPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrozenMcpPayload")
            .field(
                "bytes",
                &format_args!("[{} bytes redacted]", self.bytes.len()),
            )
            .finish()
    }
}

/// Keyed authority that mints and verifies opaque ledger bindings.
pub struct OutboundBindingAuthority {
    key: [u8; 32],
}

impl OutboundBindingAuthority {
    /// Derives a device-local binding key from the vault's durable signing
    /// secret. The intent ledger is device-local, so recovery sees the same
    /// authority after restart without syncing secret material.
    pub fn for_vault(vault: &Vault) -> Result<Self> {
        let mut seed = None;
        vault.with_write_txn(|wtxn| {
            let identity = crate::identity::ensure_device_identity_in_txn(vault, wtxn)?;
            seed = Some(identity.signing_key.to_bytes());
            Ok(())
        })?;
        Ok(Self::from_secret(seed.expect("identity closure ran on Ok")))
    }

    /// Builds a session-scoped authority from 32 bytes of caller-managed
    /// cryptographic secret material.
    #[must_use]
    pub fn from_secret(secret: [u8; 32]) -> Self {
        Self {
            key: blake3::derive_key("oneiron.outbound.authorization_binding.v2", &secret),
        }
    }

    /// Mints only after the persisted live grant passes every scoped-consent
    /// axis. The caller's grant copy is never an authorization authority.
    #[expect(clippy::too_many_arguments)]
    pub fn authorize_request(
        &self,
        vault: &Vault,
        grant_id: EntityId,
        _caller_grant: &StandingOutboundGrant,
        principal_ref: &str,
        attempt_id: AttemptId,
        call_seq: u64,
        call: &ScopedMcpCallContext,
        payload: &[u8],
    ) -> std::result::Result<ScopedMcpAuthorization, IntentLedgerError> {
        let Some(grant) = vault.get_standing_outbound_grant(&grant_id)? else {
            return Ok(ScopedMcpAuthorization {
                decision: ScopedMcpConsentDecision::Escalate(
                    ScopedMcpEscalationReason::InvalidGrant,
                ),
                binding: None,
            });
        };
        if grant.principal_ref != principal_ref {
            return Ok(ScopedMcpAuthorization {
                decision: ScopedMcpConsentDecision::Escalate(
                    ScopedMcpEscalationReason::WrongPrincipal,
                ),
                binding: None,
            });
        }
        let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
        let current_policy_floor =
            crate::gate::resolve_policy_manifest(&vault.store, &rtxn)?.read_frontier_hash()?;
        let decision = if grant.is_active_under_policy(&current_policy_floor) {
            grant.scope.scoped_mcp_grant().map_or(
                ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::InvalidGrant),
                |scope| evaluate_scoped_mcp_call(scope, call.as_call()),
            )
        } else {
            ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::InvalidGrant)
        };
        if decision != ScopedMcpConsentDecision::AutoFire {
            return Ok(ScopedMcpAuthorization {
                decision,
                binding: None,
            });
        }

        let payload_hash = *blake3::hash(payload).as_bytes();
        let intent_id = derive_intent_id(
            attempt_id,
            call_seq,
            &call.server,
            &call.tool,
            &payload_hash,
        )?;
        let binding = self.binding_for_identity(
            grant_id,
            &grant,
            &intent_id,
            &call.server,
            &call.tool,
            &payload_hash,
            Some(&call.resolved_endpoint),
        );
        Ok(ScopedMcpAuthorization {
            decision,
            binding: Some(binding),
        })
    }

    /// Mints the v2 binding from the same serialized write snapshot that
    /// admitted and accounted the new effect.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn mint_scoped_binding_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        grant_id: EntityId,
        principal_ref: &str,
        intent_id: &[u8; 32],
        call: &ScopedMcpCallContext,
        payload_hash: &[u8; 32],
    ) -> std::result::Result<Option<OutboundAuthorizationBinding>, IntentLedgerError> {
        let Some(grant) =
            crate::outbound_grant::standing_outbound_grant_in_txn(&vault.store, txn, &grant_id)?
        else {
            return Ok(None);
        };
        if grant.principal_ref != principal_ref {
            return Ok(None);
        }
        let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
        if !grant.is_active_under_policy(&policy.read_frontier_hash()?) {
            return Ok(None);
        }
        let Some(scope) = grant.scope.scoped_mcp_grant() else {
            return Ok(None);
        };
        if evaluate_scoped_mcp_call(scope, call.as_call()) != ScopedMcpConsentDecision::AutoFire {
            return Ok(None);
        }
        Ok(Some(self.binding_for_identity(
            grant_id,
            &grant,
            intent_id,
            &call.server,
            &call.tool,
            payload_hash,
            Some(&call.resolved_endpoint),
        )))
    }

    /// Re-validates authenticity and current grant liveness immediately
    /// before a send, including recovery sends from persisted frozen bytes.
    pub fn validate_frozen_call(
        &self,
        vault: &Vault,
        call: &FrozenOutboundCall,
    ) -> Result<OutboundBindingValidation> {
        Ok(match self.validate_frozen_call_grant(vault, call)? {
            FrozenCallValidation::Valid => OutboundBindingValidation::Valid,
            FrozenCallValidation::Rejected(validation) => validation,
        })
    }

    fn validate_frozen_call_grant(
        &self,
        vault: &Vault,
        call: &FrozenOutboundCall,
    ) -> Result<FrozenCallValidation> {
        self.validate_frozen_call_grant_with_liveness(vault, call, true)
    }

    pub(crate) fn validate_frozen_call_grant_for_recovery(
        &self,
        vault: &Vault,
        call: &FrozenOutboundCall,
    ) -> Result<FrozenCallValidation> {
        self.validate_frozen_call_grant_with_liveness(vault, call, false)
    }

    fn validate_frozen_call_grant_with_liveness(
        &self,
        vault: &Vault,
        call: &FrozenOutboundCall,
        require_live_grant: bool,
    ) -> Result<FrozenCallValidation> {
        if call.binding_version() != crate::outbound_intent_ledger::OUTBOUND_BINDING_VERSION {
            return Ok(FrozenCallValidation::Rejected(
                OutboundBindingValidation::Invalid,
            ));
        }
        let Some(binding) = call.authorization_binding() else {
            return Ok(FrozenCallValidation::Rejected(
                OutboundBindingValidation::Missing,
            ));
        };
        let Some(intent_id) = call.intent_id() else {
            return Ok(FrozenCallValidation::Rejected(
                OutboundBindingValidation::Invalid,
            ));
        };
        let current_policy_floor = if require_live_grant {
            let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
            Some(crate::gate::resolve_policy_manifest(&vault.store, &rtxn)?.read_frontier_hash()?)
        } else {
            None
        };
        for grant_id in vault.entities_by_type(ENTITY_TYPE_OUTBOUND_GRANT)? {
            let Some(grant) = vault.get_standing_outbound_grant(&grant_id)? else {
                return Err(Error::CorruptedIndex("outbound grant type index row"));
            };
            let expected = self.binding_for_identity(
                grant_id,
                &grant,
                intent_id,
                call.server(),
                call.tool(),
                call.payload_hash(),
                call.resolved_endpoint(),
            );
            if !constant_time_eq(binding.as_bytes(), expected.as_bytes()) {
                continue;
            }
            if current_policy_floor
                .as_ref()
                .is_some_and(|floor| !grant.is_active_under_policy(floor))
            {
                return Ok(FrozenCallValidation::Rejected(
                    OutboundBindingValidation::GrantNotLive,
                ));
            }
            let Some(scope) = grant.scope.scoped_mcp_grant() else {
                return Ok(FrozenCallValidation::Rejected(
                    OutboundBindingValidation::Invalid,
                ));
            };
            if scope.server != call.server() || scope.tool != call.tool() {
                return Ok(FrozenCallValidation::Rejected(
                    OutboundBindingValidation::Invalid,
                ));
            }
            if call.resolved_endpoint().is_none_or(|endpoint| {
                !scope
                    .endpoint_allowlist
                    .iter()
                    .any(|allowed| allowed == endpoint)
            }) {
                return Ok(FrozenCallValidation::Rejected(
                    OutboundBindingValidation::Invalid,
                ));
            }
            return Ok(FrozenCallValidation::Valid);
        }
        Ok(FrozenCallValidation::Rejected(
            OutboundBindingValidation::Invalid,
        ))
    }

    /// Commits the granting scope digest and the selected per-call endpoint.
    #[expect(clippy::too_many_arguments)]
    fn binding_for_identity(
        &self,
        grant_id: EntityId,
        grant: &StandingOutboundGrant,
        intent_id: &[u8; 32],
        server: &str,
        tool: &str,
        payload_hash: &[u8; 32],
        resolved_endpoint: Option<&str>,
    ) -> OutboundAuthorizationBinding {
        let mut hasher = blake3::Hasher::new_keyed(&self.key);
        binding_hash_bytes(&mut hasher, b"oneiron.outbound.authorization_binding.v2");
        binding_hash_bytes(&mut hasher, grant_id.as_bytes());
        binding_hash_bytes(&mut hasher, intent_id);
        binding_hash_str(&mut hasher, server);
        binding_hash_str(&mut hasher, tool);
        binding_hash_bytes(&mut hasher, payload_hash);
        match resolved_endpoint {
            Some(endpoint) => {
                hasher.update(&[1]);
                binding_hash_str(&mut hasher, endpoint);
            }
            None => {
                hasher.update(&[0]);
            }
        }
        binding_hash_bytes(&mut hasher, &grant_scope_binding_digest(grant));
        OutboundAuthorizationBinding::new(*hasher.finalize().as_bytes())
    }
}

impl fmt::Debug for OutboundBindingAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundBindingAuthority")
            .field("key", &"[redacted]")
            .finish()
    }
}

/// Result of the authenticated per-call consent step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopedMcpAuthorization {
    pub decision: ScopedMcpConsentDecision,
    pub binding: Option<OutboundAuthorizationBinding>,
}

/// Binding status checked at the final transport boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutboundBindingValidation {
    Valid,
    Missing,
    Invalid,
    GrantNotLive,
}

pub(crate) enum FrozenCallValidation {
    Valid,
    Rejected(OutboundBindingValidation),
}

/// Counted output of one consent-bound durable dispatch.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopedMcpDispatchResult {
    pub decision: ScopedMcpConsentDecision,
    pub dispatch: Option<IntentDispatchResult>,
    pub freeze_events: usize,
    pub effectful_sends: usize,
    pub authorization_rejections: usize,
    pub scrubbable_result_fields: usize,
    pub scrubbed_result_fields: usize,
    checked_bytes: Vec<u8>,
}

impl fmt::Debug for ScopedMcpDispatchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedMcpDispatchResult")
            .field("decision", &self.decision)
            .field("dispatch", &self.dispatch)
            .field("freeze_events", &self.freeze_events)
            .field("effectful_sends", &self.effectful_sends)
            .field("authorization_rejections", &self.authorization_rejections)
            .field("scrubbable_result_fields", &self.scrubbable_result_fields)
            .field("scrubbed_result_fields", &self.scrubbed_result_fields)
            .field(
                "checked_bytes",
                &format_args!("[{} bytes redacted]", self.checked_bytes.len()),
            )
            .finish()
    }
}

/// Runs one scoped call through the intent ledger and authenticated result
/// sender. Scope-exceeds return without constructing a ledger request.
#[expect(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn execute_scoped_mcp_outbound_call<S: OutboundResultSender>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    grant_id: EntityId,
    grant: &StandingOutboundGrant,
    principal_ref: &str,
    descriptor: OutboundToolDescriptor,
    attempt_id: AttemptId,
    call_seq: u64,
    call: ScopedMcpCallContext,
    payload: FrozenMcpPayload,
    now_ms: u64,
    sender: &mut S,
) -> std::result::Result<ScopedMcpDispatchResult, IntentLedgerError> {
    #[cfg(test)]
    let freeze_event_baseline = payload.freeze_event_baseline;
    #[cfg(not(test))]
    let freeze_event_baseline = ();
    let _ = grant;
    let actor_entity_ref = Some(EntityId::from_hex(principal_ref).unwrap_or(grant_id));
    let gate = crate::gate::ExternalEffectGateInput {
        actor: crate::gate::GateActor {
            actor_class: "first_party".to_owned(),
            actor_ref: Some(principal_ref.to_owned()),
        },
        provenance: crate::gate::GateProvenanceHandles {
            actor_entity_ref,
            ..crate::gate::GateProvenanceHandles::default()
        },
        verb: "send".to_owned(),
        channel: format!("mcp:{}", call.server),
        channel_identity_ref: None,
        counterparty: None,
        brief_ref: None,
        send_ref: None,
        standing_grant_ref: None,
        scoped_mcp_call: Some(call.clone()),
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: false,
        has_permission: false,
        policy_risk: crate::gate::ExternalEffectPolicyRisk::Normal,
    };
    let idempotency_supported = descriptor.idempotency_supported()
        || classify_outbound_tool(descriptor) == OutboundCallClass::ReadOnly;
    let prepared = crate::outbound_chokepoint::PreparedEffect {
        attempt_id,
        call_seq,
        server: call.server.clone(),
        tool: call.tool.clone(),
        payload: payload.bytes,
        idempotency_supported,
        resolved_endpoint: Some(call.resolved_endpoint.clone()),
        gate,
        budget_class: crate::outbound_intent_ledger::BudgetClass::Send,
        authorization: crate::outbound_chokepoint::PreparedAuthorization::ScopedMcp {
            grant_id,
            principal_ref: principal_ref.to_owned(),
            call: call.clone(),
        },
        verified_actor: None,
    };
    let mut transport = ScopedResultTransport::new(sender);
    let effect = crate::outbound_chokepoint::execute_outbound_effect(
        vault,
        authority,
        crate::outbound_chokepoint::OutboundEffectCommand::New(prepared),
        now_ms,
        &mut transport,
    )?;
    let decision = scoped_decision_after_effect(vault, grant_id, principal_ref, &call, &effect)?;
    let authorization_rejections = usize::from(
        effect.dispatch.state == Some(IntentState::Abandoned)
            || (effect.dispatch.state == Some(IntentState::Pending)
                && effect.dispatch.send_outcome.is_none()
                && effect.dispatch.replayed),
    );
    let dispatch = (effect.dispatch.state.is_some()
        || effect.dispatch.send_outcome.is_some()
        || effect.dispatch.replayed)
        .then_some(effect.dispatch);
    Ok(ScopedMcpDispatchResult {
        decision,
        dispatch,
        freeze_events: observed_freeze_events_since(freeze_event_baseline),
        effectful_sends: transport.effectful_sends,
        authorization_rejections,
        scrubbable_result_fields: transport.scrubbable_result_fields,
        scrubbed_result_fields: transport.scrubbed_result_fields,
        checked_bytes: transport.checked_bytes,
    })
}

fn scoped_decision_after_effect(
    vault: &Vault,
    grant_id: EntityId,
    principal_ref: &str,
    call: &ScopedMcpCallContext,
    effect: &crate::outbound_chokepoint::OutboundEffectResult,
) -> std::result::Result<ScopedMcpConsentDecision, IntentLedgerError> {
    let connector_reason =
        effect
            .gate_receipt_reasons
            .iter()
            .find_map(|reason| match reason.as_str() {
                "connector_key_unregistered" => {
                    Some(ScopedMcpEscalationReason::ConnectorKeyUnregistered)
                }
                "connector_key_pending" => Some(ScopedMcpEscalationReason::ConnectorKeyPending),
                "connector_key_suspended" => Some(ScopedMcpEscalationReason::ConnectorKeySuspended),
                "connector_key_revoked" => Some(ScopedMcpEscalationReason::ConnectorKeyRevoked),
                "charter_drift" => Some(ScopedMcpEscalationReason::ConnectorKeyCharterDrift),
                "charter_never_list" => {
                    Some(ScopedMcpEscalationReason::ConnectorKeyCharterNeverList)
                }
                "effector_budget_exhausted" => {
                    Some(ScopedMcpEscalationReason::ConnectorKeyBudgetExhausted)
                }
                _ => None,
            });
    if let Some(reason) = connector_reason {
        return Ok(ScopedMcpConsentDecision::Escalate(reason));
    }
    if effect
        .dispatch
        .escalation
        .as_ref()
        .is_some_and(|escalation| {
            escalation.reason
                == crate::outbound_intent_ledger::IntentEscalationReason::ConnectorRevoked
        })
    {
        return Ok(ScopedMcpConsentDecision::Escalate(
            ScopedMcpEscalationReason::ConnectorKeyRevoked,
        ));
    }
    if effect
        .dispatch
        .escalation
        .as_ref()
        .is_some_and(|escalation| {
            escalation.reason
                == crate::outbound_intent_ledger::IntentEscalationReason::BindingInvalid
        })
    {
        return Ok(ScopedMcpConsentDecision::Escalate(
            ScopedMcpEscalationReason::InvalidGrant,
        ));
    }
    if effect
        .gate_outcome
        .as_deref()
        .is_none_or(|outcome| outcome == "allow")
    {
        return Ok(ScopedMcpConsentDecision::AutoFire);
    }
    let Some(grant) = vault.get_standing_outbound_grant(&grant_id)? else {
        return Ok(ScopedMcpConsentDecision::Escalate(
            ScopedMcpEscalationReason::InvalidGrant,
        ));
    };
    if grant.principal_ref != principal_ref {
        return Ok(ScopedMcpConsentDecision::Escalate(
            ScopedMcpEscalationReason::WrongPrincipal,
        ));
    }
    let current_policy_floor = {
        let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
        crate::gate::resolve_policy_manifest(&vault.store, &rtxn)?.read_frontier_hash()?
    };
    if !grant.is_active_under_policy(&current_policy_floor) {
        return Ok(ScopedMcpConsentDecision::Escalate(
            ScopedMcpEscalationReason::InvalidGrant,
        ));
    }
    Ok(grant.scope.scoped_mcp_grant().map_or(
        ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::InvalidGrant),
        |scope| evaluate_scoped_mcp_call(scope, call.as_call()),
    ))
}

#[cfg(test)]
pub(crate) fn observed_freeze_events_since(baseline: usize) -> usize {
    FROZEN_MCP_PAYLOAD_FREEZE_EVENTS.with(|counter| counter.get().wrapping_sub(baseline))
}

#[cfg(not(test))]
#[allow(dead_code)]
const fn observed_freeze_events_since(_baseline: ()) -> usize {
    0
}

struct ScopedResultTransport<'a, S> {
    inner: &'a mut S,
    effectful_sends: usize,
    scrubbable_result_fields: usize,
    scrubbed_result_fields: usize,
    checked_bytes: Vec<u8>,
}

impl<'a, S> ScopedResultTransport<'a, S> {
    fn new(inner: &'a mut S) -> Self {
        Self {
            inner,
            effectful_sends: 0,
            scrubbable_result_fields: 0,
            scrubbed_result_fields: 0,
            checked_bytes: Vec::new(),
        }
    }
}

impl<S: OutboundResultSender> crate::outbound_chokepoint::OutboundTransport
    for ScopedResultTransport<'_, S>
{
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.checked_bytes = call.payload().to_vec();
        let transport = self.inner.send(call);
        self.effectful_sends = self.effectful_sends.saturating_add(1);
        let scrubbable = transport.raw_result.scrubbable_field_count();
        let scrubbed = scrub_outbound_result(transport.raw_result).scrubbed_field_count();
        self.scrubbable_result_fields = self.scrubbable_result_fields.saturating_add(scrubbable);
        self.scrubbed_result_fields = self.scrubbed_result_fields.saturating_add(scrubbed);
        transport.outcome
    }
}

/// Recovery result plus final-boundary authorization/scrub counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedRecoveryReport {
    pub ledger: IntentRecoveryReport,
    pub effectful_sends: usize,
    pub authorization_rejections: usize,
    pub scrubbable_result_fields: usize,
    pub scrubbed_result_fields: usize,
}

/// Failure surface for lease-protected authorized recovery.
#[derive(Debug, thiserror::Error)]
pub enum AuthorizedRecoveryError {
    #[error(transparent)]
    Engine(#[from] Error),
    #[error(transparent)]
    Ledger(#[from] IntentLedgerError),
    #[error("outbound recovery lease is already held")]
    LeaseHeld,
    #[error("outbound recovery lease duration must be nonzero")]
    InvalidLeaseDuration,
}

/// Recovers pending intents under a device-local best-effort sweep lease and
/// re-validates every persisted binding before transport. Exactly-once resend
/// authority comes from the ledger's durable row state and replay fence, not
/// this lease; `now_ms` is the engine's trusted clock.
pub fn recover_authorized_outbound_intents<S: OutboundResultSender>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    sender: &mut S,
    now_ms: u64,
    lease_duration_ms: u64,
) -> std::result::Result<AuthorizedRecoveryReport, AuthorizedRecoveryError> {
    if lease_duration_ms == 0 {
        return Err(AuthorizedRecoveryError::InvalidLeaseDuration);
    }
    let token = AttemptId::now();
    let lease_until_ms = now_ms
        .checked_add(lease_duration_ms)
        .ok_or(AuthorizedRecoveryError::InvalidLeaseDuration)?;
    if !acquire_authorized_recovery_lease(vault, token, now_ms, lease_until_ms)? {
        return Err(AuthorizedRecoveryError::LeaseHeld);
    }

    let mut transport = ScopedResultTransport::new(sender);
    let recovered = (|| -> std::result::Result<_, AuthorizedRecoveryError> {
        let entries = crate::outbound_intent_ledger::intent_recovery_entries(vault)?;
        let mut report = IntentRecoveryReport {
            scanned: entries.len(),
            ..IntentRecoveryReport::default()
        };
        let mut authorization_rejections = 0_usize;
        for entry in entries {
            let record = match entry {
                crate::outbound_intent_ledger::IntentRecoveryEntry::Valid(record) => record,
                crate::outbound_intent_ledger::IntentRecoveryEntry::Corrupt(intent_id) => {
                    report
                        .escalations
                        .push(crate::outbound_intent_ledger::IntentEscalation {
                        intent_id,
                        reason:
                            crate::outbound_intent_ledger::IntentEscalationReason::CorruptLedgerRow,
                    });
                    continue;
                }
            };
            // This authorized sweep resumes every row it touches through the
            // scoped-MCP result transport. Connector-send rows carry no scoped
            // authorization binding and are driven forward (and replayed) by the
            // connector-task attempt queue instead; resuming one here would push
            // a connector payload through the MCP result sender. Skip them so the
            // scoped transport only ever sees scoped-authorized intents.
            if record.authorization_binding.is_none() {
                continue;
            }
            let original_state = record.state;
            let sends_before = transport.effectful_sends;
            let result = crate::outbound_chokepoint::execute_outbound_effect(
                vault,
                authority,
                crate::outbound_chokepoint::OutboundEffectCommand::Resume(record.id),
                now_ms,
                &mut transport,
            )?;
            let sent = transport.effectful_sends > sends_before;
            match original_state {
                IntentState::Done => report.skipped_done = report.skipped_done.saturating_add(1),
                IntentState::Abandoned => {
                    report.skipped_abandoned = report.skipped_abandoned.saturating_add(1);
                    if let Some(escalation) = result.dispatch.escalation {
                        report.escalations.push(escalation);
                    }
                }
                IntentState::Pending => {
                    if sent {
                        report.resent = report.resent.saturating_add(1);
                    }
                    match result.dispatch.state {
                        Some(IntentState::Done) => {
                            report.completed = report.completed.saturating_add(1);
                        }
                        Some(IntentState::Pending) => {
                            report.pending = report.pending.saturating_add(1);
                            if !sent && result.dispatch.send_outcome.is_none() {
                                authorization_rejections =
                                    authorization_rejections.saturating_add(1);
                            }
                            if let Some(OutboundSendOutcome::Failed(failure)) =
                                result.dispatch.send_outcome
                            {
                                report.failures.push(
                                    crate::outbound_intent_ledger::IntentRecoveryFailure {
                                        intent_id: record.id,
                                        failure,
                                    },
                                );
                            }
                        }
                        Some(IntentState::Abandoned) => {
                            authorization_rejections = authorization_rejections.saturating_add(1);
                            if let Some(escalation) = result.dispatch.escalation {
                                report.escalations.push(escalation);
                            }
                        }
                        None => {
                            return Err(IntentLedgerError::InvalidRecord(
                                "resume returned no durable state",
                            )
                            .into());
                        }
                    }
                }
            }
        }
        Ok((report, authorization_rejections))
    })();
    let release = release_authorized_recovery_lease(vault, token);
    let (ledger, authorization_rejections) = recovered?;
    release?;
    Ok(AuthorizedRecoveryReport {
        ledger,
        effectful_sends: transport.effectful_sends,
        authorization_rejections,
        scrubbable_result_fields: transport.scrubbable_result_fields,
        scrubbed_result_fields: transport.scrubbed_result_fields,
    })
}

/// Best-effort de-duplication for concurrent recovery sweeps. Exactly-once
/// resend authority remains the ledger state and replay fence; `now_ms` is the
/// engine's trusted clock.
fn acquire_authorized_recovery_lease(
    vault: &Vault,
    token: AttemptId,
    now_ms: u64,
    lease_until_ms: u64,
) -> Result<bool> {
    vault.with_write_txn(|wtxn| {
        if let Some(raw) = vault
            .store
            .vault_meta
            .get(&*wtxn, AUTHORIZED_RECOVERY_LEASE_KEY)?
        {
            let raw: &[u8] = &raw;
            if raw.len() != AUTHORIZED_RECOVERY_LEASE_VALUE_LEN {
                return Err(Error::CorruptedIndex("outbound recovery lease row"));
            }
            let expires_at = u64::from_le_bytes(
                raw[16..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("outbound recovery lease row"))?,
            );
            if expires_at > now_ms {
                return Ok(false);
            }
        }
        let mut encoded = Vec::with_capacity(AUTHORIZED_RECOVERY_LEASE_VALUE_LEN);
        encoded.extend_from_slice(token.as_bytes());
        encoded.extend_from_slice(&lease_until_ms.to_le_bytes());
        vault
            .store
            .vault_meta
            .put(wtxn, AUTHORIZED_RECOVERY_LEASE_KEY, &encoded)?;
        Ok(true)
    })
}

/// Releases only this sweep's best-effort lease token. The lease is not an
/// exactly-once authority; durable ledger state and its replay fence are.
fn release_authorized_recovery_lease(vault: &Vault, token: AttemptId) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        let Some(raw) = vault
            .store
            .vault_meta
            .get(&*wtxn, AUTHORIZED_RECOVERY_LEASE_KEY)?
        else {
            return Ok(());
        };
        let raw: &[u8] = &raw;
        if raw.len() != AUTHORIZED_RECOVERY_LEASE_VALUE_LEN {
            return Err(Error::CorruptedIndex("outbound recovery lease row"));
        }
        if &raw[..16] == token.as_bytes() {
            vault
                .store
                .vault_meta
                .delete(wtxn, AUTHORIZED_RECOVERY_LEASE_KEY)?;
        }
        Ok(())
    })
}

/// Stdio child restrictions a real transport must apply before spawn.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StdioSandboxPolicy {
    pub environment_allowlist: Vec<String>,
    pub inherited_fd_allowlist: Vec<u32>,
    pub filesystem_allowlist: Vec<String>,
}

/// Mandatory hardening contract for any real outbound sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundTransportPolicy {
    pub stdio_sandbox: StdioSandboxPolicy,
    tls_peer_verification_required: bool,
    resolved_endpoint_disclosure_required: bool,
}

impl OutboundTransportPolicy {
    #[must_use]
    pub const fn new(stdio_sandbox: StdioSandboxPolicy) -> Self {
        Self {
            stdio_sandbox,
            tls_peer_verification_required: true,
            resolved_endpoint_disclosure_required: true,
        }
    }

    #[must_use]
    pub const fn tls_peer_verification_required(&self) -> bool {
        self.tls_peer_verification_required
    }

    #[must_use]
    pub const fn resolved_endpoint_disclosure_required(&self) -> bool {
        self.resolved_endpoint_disclosure_required
    }
}

fn grant_scope_binding_digest(grant: &StandingOutboundGrant) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    binding_hash_bytes(
        &mut hasher,
        b"oneiron.outbound.authorization_grant_scope.v1",
    );
    binding_hash_bytes(&mut hasher, &grant.binding_diff_handle);
    binding_hash_bytes(&mut hasher, &grant.read_frontier_hash);
    match &grant.scope {
        StandingOutboundGrantScope::ScopedMcp {
            server,
            tool,
            data_class_ceiling,
            endpoint_allowlist,
        } => {
            binding_hash_str(&mut hasher, "scoped_mcp");
            binding_hash_str(&mut hasher, server);
            binding_hash_str(&mut hasher, tool);
            binding_hash_str(&mut hasher, data_class_ceiling.as_str());
            for endpoint in endpoint_allowlist {
                binding_hash_str(&mut hasher, endpoint);
            }
        }
        _ => binding_hash_str(&mut hasher, "not_scoped_mcp"),
    }
    *hasher.finalize().as_bytes()
}

fn binding_hash_str(hasher: &mut blake3::Hasher, value: &str) {
    binding_hash_bytes(hasher, value.as_bytes());
}

fn binding_hash_bytes(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn is_canonical_non_empty(value: &str) -> bool {
    !value.trim().is_empty() && value == value.trim()
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests;
