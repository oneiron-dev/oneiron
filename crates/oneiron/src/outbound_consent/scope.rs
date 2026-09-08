//! Payload-aware scope axes, consent decisions, and batch evaluation.

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
    // Both sides of the server axis must already satisfy the ONE shared
    // safe-segment rule and are then compared byte-for-byte. Admission never
    // trims, case-folds, or aliases `'-'` with `'_'`, so a different spelling
    // cannot become the granted authority (ONE-1885). Persisted grant scopes
    // carry this exact spelling through `validate_scope`/`decode_scope`.
    let Some(grant_server) = canonical_scoped_server(grant.server) else {
        return ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::InvalidGrant);
    };
    if !is_canonical_non_empty(grant.tool)
        || grant.endpoint_allowlist.is_empty()
        || grant
            .endpoint_allowlist
            .iter()
            .any(|endpoint| !is_canonical_non_empty(endpoint))
        || !grant.data_class_ceiling.is_grantable()
    {
        return ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::InvalidGrant);
    }
    let Some(call_server) = canonical_scoped_server(call.server) else {
        return ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::WrongServer);
    };
    if !is_canonical_non_empty(call.tool) {
        return ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::WrongTool);
    }
    if !is_canonical_non_empty(call.resolved_endpoint) {
        return ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::EndpointNotAllowed);
    }
    if call_server != grant_server {
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

/// Validates and preserves the ONE exact canonical scoped-server segment
/// (ONE-1885).
fn canonical_scoped_server(server: &str) -> Option<String> {
    crate::connector_key::canonical_scoped_server_segment(server)
}

fn is_canonical_non_empty(value: &str) -> bool {
    !value.trim().is_empty() && value == value.trim()
}
