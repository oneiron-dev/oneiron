//! ONE-1690 RT-09: payload-aware scoped-grant and frozen-buffer/scrub oracles plus result transports.

use super::shared::{install_oracle_scoped_fixture, open_vault, oracle_prepared_effect};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::outbound_chokepoint::{
    OutboundEffectCommand, OutboundTransport, execute_outbound_effect,
};
use crate::outbound_consent::{
    DataClass, FrozenMcpPayload, OutboundResultSender, OutboundTransportResult, RawOutboundResult,
    ScopedMcpCall as EngineScopedMcpCall,
    evaluate_scoped_mcp_calls as evaluate_engine_scoped_mcp_calls, observed_freeze_events_since,
    scrub_outbound_result,
};
use crate::outbound_grant::StandingOutboundGrantScope;
use crate::outbound_intent_ledger::{FrozenOutboundCall, IntentState, OutboundSendOutcome};

// ═══════════════════════════════════════════════════════════════════════
// ONE-1690 — [RT-09] external MCP via rmcp (SECURITY)
// ═══════════════════════════════════════════════════════════════════════

/// RT-09: the standing grant covering `self.mcp` calls is payload-aware —
/// it carries the (server, tool, data-class) axis. A scope WITHOUT that
/// axis must not cover an effectful MCP call. Red today: the shipped
/// channel scope matches on channel string + send-verb alone
/// (argument-blind `matches_effect`), which is exactly the verified hole.
#[test]
fn one_1690_argument_blind_scopes_must_not_cover_mcp_calls() {
    let scope = StandingOutboundGrantScope::Channel {
        channel: "mcp:calendar".to_owned(),
    };
    let covers = scope.matches_effect("send", "mcp:calendar", None, None);
    assert!(
        !covers,
        "an argument-blind grant scope must not cover an effectful MCP call — \
         the (server, tool, data-class) axis is required for auto-fire"
    );
}

/// The ticket's grant axes (ONE-1690): (server, tool, data-class) scope
/// plus the endpoint allowlist the human saw at grant time.
struct ScopedMcpGrant {
    server: &'static str,
    tool: &'static str,
    /// Highest data class the grant covers ("public" < "personal" < "secret").
    data_class_ceiling: &'static str,
    endpoint_allowlist: &'static [&'static str],
}

/// One `self.mcp` call as the automated per-call check sees it.
struct ScopedMcpCall {
    server: &'static str,
    tool: &'static str,
    payload_data_class: &'static str,
    resolved_endpoint: &'static str,
}

/// Per-batch verdict of the payload-aware scoped-grant check.
struct ScopedMcpVerdict {
    auto_fired: usize,
    human_escalations: usize,
}

/// ARMING SEAM (ONE-1690): evaluate `calls` against the standing SCOPED
/// grant — the payload-aware AUTOMATED per-call check (endpoint allowlist
/// + tool + data-class ceiling).
fn evaluate_scoped_mcp_calls(
    _vault: &Vault,
    grant: &ScopedMcpGrant,
    calls: &[ScopedMcpCall],
) -> ScopedMcpVerdict {
    let endpoint_allowlist = grant
        .endpoint_allowlist
        .iter()
        .map(|endpoint| (*endpoint).to_owned())
        .collect::<Vec<_>>();
    let scope = StandingOutboundGrantScope::ScopedMcp {
        server: grant.server.to_owned(),
        tool: grant.tool.to_owned(),
        data_class_ceiling: DataClass::parse(grant.data_class_ceiling),
        endpoint_allowlist,
    };
    let grant = scope.scoped_mcp_grant().expect("scoped fixture grant");
    let calls = calls
        .iter()
        .map(|call| EngineScopedMcpCall {
            server: call.server,
            tool: call.tool,
            payload_data_class: DataClass::parse(call.payload_data_class),
            resolved_endpoint: call.resolved_endpoint,
        })
        .collect::<Vec<_>>();
    let verdict = evaluate_engine_scoped_mcp_calls(grant, &calls);
    ScopedMcpVerdict {
        auto_fired: verdict.auto_fired,
        human_escalations: verdict.human_escalations,
    }
}

/// RT-09: a call INSIDE scope auto-fires with no human in the loop (auto
/// mode intact); a SCOPE-EXCEED — an off-allowlist endpoint or a payload
/// above the data-class ceiling — NEVER fires and escalates to a human.
/// The ticket states no escalation coalescing, so the escalation count is
/// pinned only as ≥ 1 (armer policy); the fire count is exactly 0.
#[test]
fn one_1690_in_scope_auto_fires_and_scope_exceeds_escalate_without_firing() {
    let (_dir, vault) = open_vault();
    let grant = ScopedMcpGrant {
        server: "files",
        tool: "read_file",
        data_class_ceiling: "personal",
        endpoint_allowlist: &["https://files.internal.example"],
    };
    let in_scope_call = || ScopedMcpCall {
        server: "files",
        tool: "read_file",
        payload_data_class: "personal",
        resolved_endpoint: "https://files.internal.example",
    };

    let in_scope = evaluate_scoped_mcp_calls(
        &vault,
        &grant,
        &[in_scope_call(), in_scope_call(), in_scope_call()],
    );
    assert_eq!(in_scope.auto_fired, 3, "inside scope every call auto-fires");
    assert_eq!(
        in_scope.human_escalations, 0,
        "inside scope there is NO human in the loop"
    );

    let off_allowlist = evaluate_scoped_mcp_calls(
        &vault,
        &grant,
        &[ScopedMcpCall {
            resolved_endpoint: "https://exfil.example",
            ..in_scope_call()
        }],
    );
    assert_eq!(
        off_allowlist.auto_fired, 0,
        "an off-allowlist endpoint never auto-fires"
    );
    assert!(
        off_allowlist.human_escalations >= 1,
        "an off-allowlist endpoint escalates to a human"
    );

    let secret_over_ceiling = evaluate_scoped_mcp_calls(
        &vault,
        &grant,
        &[ScopedMcpCall {
            payload_data_class: "secret",
            ..in_scope_call()
        }],
    );
    assert_eq!(
        secret_over_ceiling.auto_fired, 0,
        "a secret-tier payload under a personal ceiling never auto-fires"
    );
    assert!(
        secret_over_ceiling.human_escalations >= 1,
        "the data-class exceed escalates to a human"
    );

    let wrong_server = evaluate_scoped_mcp_calls(
        &vault,
        &grant,
        &[ScopedMcpCall {
            server: "calendar",
            ..in_scope_call()
        }],
    );
    assert_eq!(
        wrong_server.auto_fired, 0,
        "a grant for another server never auto-fires"
    );
    assert!(
        wrong_server.human_escalations >= 1,
        "a wrong-server call escalates to a human"
    );

    let wrong_tool = evaluate_scoped_mcp_calls(
        &vault,
        &grant,
        &[ScopedMcpCall {
            tool: "write_file",
            ..in_scope_call()
        }],
    );
    assert_eq!(
        wrong_tool.auto_fired, 0,
        "a grant for another tool never auto-fires"
    );
    assert!(
        wrong_tool.human_escalations >= 1,
        "a wrong-tool call escalates to a human"
    );
}

/// Byte-level trace of one consented effectful send.
struct EffectfulSendTrace {
    /// Effectful wire sends the drive performed — must be 1, or every
    /// other assert here is vacuous.
    effectful_sends: usize,
    /// Buffer FREEZE (serialization) events: exactly one, shared by check
    /// and send. A second event is the re-serialize TOCTOU sneaking back.
    freeze_events: usize,
    checked_bytes: Vec<u8>,
    sent_bytes: Vec<u8>,
    /// Scrubbable result fields the fixture seeded (body/error/stderr/URL).
    scrubbable_result_fields: usize,
    /// How many of those the fence actually scrubbed.
    scrubbed_result_fields: usize,
}

/// ARMING SEAM (ONE-1690): drive one effectful `self.mcp` call whose
/// result carries EXACTLY four scrubbable fields (body, error, stderr,
/// URL) and report the frozen-buffer + scrub trace.
#[derive(Default)]
struct OracleMcpResultSender {
    sent_bytes: Vec<Vec<u8>>,
}

impl OutboundResultSender for OracleMcpResultSender {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundTransportResult {
        self.sent_bytes.push(call.payload().to_vec());
        OutboundTransportResult {
            outcome: OutboundSendOutcome::Acked,
            raw_result: RawOutboundResult::new(
                Some(b"provider body".to_vec()),
                Some("provider error".to_owned()),
                Some(b"provider stderr".to_vec()),
                Some("https://provider.example/result".to_owned()),
            ),
        }
    }
}

struct OracleResultChokepointTransport<'a> {
    inner: &'a mut OracleMcpResultSender,
    effectful_sends: usize,
    checked_bytes: Vec<u8>,
    scrubbable_result_fields: usize,
    scrubbed_result_fields: usize,
}

impl OutboundTransport for OracleResultChokepointTransport<'_> {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.checked_bytes = call.payload().to_vec();
        let result = self.inner.send(call);
        self.effectful_sends = self.effectful_sends.saturating_add(1);
        self.scrubbable_result_fields = self
            .scrubbable_result_fields
            .saturating_add(result.raw_result.scrubbable_field_count());
        self.scrubbed_result_fields = self
            .scrubbed_result_fields
            .saturating_add(scrub_outbound_result(result.raw_result).scrubbed_field_count());
        result.outcome
    }
}

fn trace_effectful_mcp_send(vault: &Vault) -> EffectfulSendTrace {
    let fixture = install_oracle_scoped_fixture(vault);
    let payload = FrozenMcpPayload::new(b"{\"path\":\"calendar.txt\"}".to_vec());
    let freeze_event_baseline = payload.freeze_event_baseline();
    let prepared = oracle_prepared_effect(
        &fixture,
        AttemptId::from_bytes(&[0x91; 16]).expect("attempt id"),
        1,
        payload.into_bytes(),
        true,
    );
    let mut sender = OracleMcpResultSender::default();
    let (effectful_sends, checked_bytes, scrubbable_result_fields, scrubbed_result_fields) = {
        let mut transport = OracleResultChokepointTransport {
            inner: &mut sender,
            effectful_sends: 0,
            checked_bytes: Vec::new(),
            scrubbable_result_fields: 0,
            scrubbed_result_fields: 0,
        };
        let result = execute_outbound_effect(
            vault,
            &fixture.authority,
            OutboundEffectCommand::New(prepared),
            11,
            &mut transport,
        )
        .expect("effectful scoped send");
        assert_eq!(result.dispatch.state, Some(IntentState::Done));
        (
            transport.effectful_sends,
            transport.checked_bytes,
            transport.scrubbable_result_fields,
            transport.scrubbed_result_fields,
        )
    };
    EffectfulSendTrace {
        effectful_sends,
        freeze_events: observed_freeze_events_since(freeze_event_baseline),
        checked_bytes,
        sent_bytes: sender.sent_bytes.into_iter().next().unwrap_or_default(),
        scrubbable_result_fields,
        scrubbed_result_fields,
    }
}

/// RT-09 R2: for EFFECTFUL calls the checked bytes ARE the sent bytes —
/// one frozen immutable buffer, ONE freeze event, no re-serialize between
/// check and send (no TOCTOU) — and every seeded result field is scrubbed,
/// not just headers. Non-vacuous by construction: the trace must show the
/// send happened and the buffer carries real bytes.
#[test]
fn one_1690_checked_bytes_equal_sent_bytes_and_results_are_fully_scrubbed() {
    let (_dir, vault) = open_vault();
    let trace = trace_effectful_mcp_send(&vault);
    assert_eq!(
        trace.effectful_sends, 1,
        "exactly one effectful send occurred — the trace is not vacuous"
    );
    assert_eq!(
        trace.freeze_events, 1,
        "ONE freeze: check and send share one serialization, never two"
    );
    assert!(
        !trace.sent_bytes.is_empty(),
        "the frozen buffer carries real bytes"
    );
    assert_eq!(
        trace.checked_bytes, trace.sent_bytes,
        "consent must bind the exact frozen bytes the wire carries"
    );
    assert_eq!(
        trace.scrubbable_result_fields, 4,
        "the fixture seeds exactly body, error, stderr, URL"
    );
    assert_eq!(
        trace.scrubbed_result_fields, 4,
        "ALL four result fields are scrubbed — zero escape"
    );
}
