//! ONE-1720 (ES-07) unit tests: the closed verdict vocabulary, the fixed
//! evaluation order (blank-context floor, ED's typed standing read, the budget
//! ceiling, then the classifier), the adapter that has no kill arm, and the
//! human-ruling round trip through ED-06's own receipt and proposal machinery.
//!
//! Everything a classifier does here is in-process: a recording fixture with a
//! pinned answer and an invocation counter. No model, no network, no
//! credentials. Every storage write goes through ONE-1762's public API,
//! because ONE-1720 owns no storage.
//!
//! Three of these tests are RE-HOMED from `tests/it/effect_spine_oracle.rs`
//! under their original names. `outbound_chokepoint` is `pub(crate)`, so
//! ONE-1719's plan, estimate, and decider are neither nameable nor
//! constructible from an integration-test crate and those arms could only ever
//! live in-crate. Their doc comments carry the old-assert to new-assert map.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use super::*;

use crate::edit_distance::delta::{AmendmentDelta, DeltaSource, OpsSummary};
use crate::edit_distance::escalation::{
    ESCALATION_LAST_RULINGS_BOUND, accept_standing_policy, accept_standing_policy_at,
    is_escalation_receipt, maybe_propose_standing_policy_at, record_escalation_at,
};
use crate::receipt::{
    FIELD_ESCALATION_BUDGET_BAND, FIELD_ESCALATION_QUESTION, FIELD_ESCALATION_RATIONALE,
    FIELD_ESCALATION_RULING, FIELD_ESCALATION_SCOPE, FIELD_ESCALATION_TRIGGER, FIELD_TASK_REF,
    ReceiptKind, ReceiptQuery, ReceiptRecord,
};

/// This module's own source, read at compile time for the surface assertions.
const MODULE_SOURCE: &str = include_str!("../fanout_auto.rs");

const SCOPE: &str = "fan_out/consult";
const OTHER_SCOPE: &str = "fan_out/outreach";
const QUESTION: &str = "may this fan-out of 240 consults start?";
const RATIONALE: &str = "the peer list is the one we agreed";

/// The frozen digest byte the fixtures use, so the lower-hex projection has a
/// value a test can name.
const DIGEST_BYTE: u8 = 0x5a;

/// One byte past ED's scope bound, so its typed standing read fails the way an
/// unreadable row does: with `Err`, not `Ok(None)`.
const OVERLONG_SCOPE_LEN: usize = crate::consent::MAX_CONSENT_REF_LEN + 1;

/// The oracle's fan-out shape: 180 consults to one peer, 60 to another.
const FAN_OUT: [(&str, u32); 2] = [("codex", 180), ("cc-2", 60)];

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config())
}

// ---------------------------------------------------------------------------
// Plan / estimate fixtures
// ---------------------------------------------------------------------------

/// One frozen plan.
///
/// ONE-1719 pins exactly four names as its cross-lane surface and its edge type
/// is not one of them. ONE-1720 must not widen that surface to build a fixture,
/// so the plan is decoded through the serde shape ONE-1719 already derives.
fn plan_over(edges: &[(&str, u32)]) -> FanoutPlan {
    let edges: Vec<serde_json::Value> = edges
        .iter()
        .map(|(peer, count)| {
            serde_json::json!({
                "from_peer_ref": "peer_hub",
                "to_peer_ref": peer,
                "count": count,
            })
        })
        .collect();
    serde_json::from_value(serde_json::json!({
        "plan_ref": "plan-1",
        "brief_ref": "brief-1",
        "actor_ref": "actor-1",
        "mode": "auto",
        "edges": edges,
    }))
    .expect("the plan fixture decodes through ONE-1719's own serde shape")
}

/// The metering ONE-1719 hands the decider, built from the same edge list. The
/// digest is a pinned constant: this module reads those bytes and never
/// recomputes them.
fn estimate_over(edges: &[(&str, u32)]) -> FanoutEstimate {
    let mut per_peer: BTreeMap<String, u32> = BTreeMap::new();
    let mut total_count = 0_u32;
    for (peer, count) in edges {
        *per_peer.entry((*peer).to_owned()).or_insert(0) += *count;
        total_count += *count;
    }
    FanoutEstimate {
        total_count,
        per_peer,
        plan_digest: [DIGEST_BYTE; 32],
    }
}

fn context(scope: &str, trigger: FanoutAskTrigger) -> FanoutAskContext {
    FanoutAskContext {
        task_ref: crate::test_util::entity(0x72),
        scope: scope.to_owned(),
        trigger,
        question: QUESTION.to_owned(),
    }
}

/// A Δ fixture parameterized on one measured field, so "the same amendment
/// twice" and "two different amendments" are the same shape at two arguments.
fn delta(d_norm: f32) -> AmendmentDelta {
    AmendmentDelta {
        proposed_ref: "aa".repeat(16),
        final_ref: "bb".repeat(16),
        source: DeltaSource::FieldDiff,
        d_norm,
        ops_summary: OpsSummary {
            ins: 3,
            del: 1,
            kept: 9,
            moved: 0,
            approx: false,
        },
        engine_ver: "test".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// The classifier fixture
// ---------------------------------------------------------------------------

/// What one classifier invocation saw. Recorded rather than asserted inline so
/// a test can prove the seam is provider-neutral: every field here is std or
/// ONE-1720-owned, and none of it is ONE-1719's plan representation.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SeenAsk {
    scope: String,
    trigger: FanoutAskTrigger,
    question: String,
    peer_count: u64,
    total_count: u64,
    per_peer_counts: Vec<(String, u64)>,
    plan_digest: String,
    history: FanoutDecisionHistory,
}

/// What the fixture answers with.
#[derive(Clone, Copy)]
enum Answer {
    /// A pinned closed verdict.
    Verdict(FanoutAskVerdict),
    /// A classifier that cannot rule at all.
    Error,
    /// A host adapter decoding one wire token; anything outside the closed
    /// vocabulary fails to decode and reaches the engine as an error.
    HostToken(&'static str),
}

/// An in-process classifier: a pinned answer, an invocation counter, and a
/// recording of every ask it saw.
struct RecordingClassifier {
    answer: Answer,
    calls: Cell<usize>,
    seen: RefCell<Vec<SeenAsk>>,
}

impl RecordingClassifier {
    fn with(answer: Answer) -> Self {
        Self {
            answer,
            calls: Cell::new(0),
            seen: RefCell::new(Vec::new()),
        }
    }

    fn ruling(verdict: FanoutAskVerdict) -> Self {
        Self::with(Answer::Verdict(verdict))
    }

    fn failing() -> Self {
        Self::with(Answer::Error)
    }

    fn host_token(token: &'static str) -> Self {
        Self::with(Answer::HostToken(token))
    }

    fn calls(&self) -> usize {
        self.calls.get()
    }

    fn only_ask(&self) -> SeenAsk {
        let seen = self.seen.borrow();
        assert_eq!(seen.len(), 1, "the classifier rules at most once per ask");
        seen[0].clone()
    }
}

impl FanoutAskClassifier for RecordingClassifier {
    fn classify(
        &self,
        context: &FanoutAskContext,
        view: &FanoutClassifierView<'_>,
        history: &FanoutDecisionHistory,
    ) -> Result<FanoutAskVerdict> {
        self.calls.set(self.calls.get() + 1);
        self.seen.borrow_mut().push(SeenAsk {
            scope: context.scope.clone(),
            trigger: context.trigger,
            question: context.question.clone(),
            peer_count: view.peer_count(),
            total_count: view.total_count(),
            per_peer_counts: view.per_peer_counts(),
            plan_digest: view.plan_digest(),
            history: history.clone(),
        });
        match self.answer {
            Answer::Verdict(verdict) => Ok(verdict),
            Answer::Error => Err(Error::InvalidConfig(
                "the classifier fixture cannot rule".to_owned(),
            )),
            Answer::HostToken(token) => {
                serde_json::from_str::<FanoutAskVerdict>(token).map_err(|_| {
                    Error::InvalidConfig(
                        "the host answered outside the closed verdict vocabulary".to_owned(),
                    )
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Storage fixtures — every write goes through ONE-1762's public API
// ---------------------------------------------------------------------------

fn record(
    vault: &Vault,
    scope: &str,
    trigger: EscalationTrigger,
    ruling: &EscalationRuling,
    band: Option<u64>,
    at: u64,
) -> EntityId {
    record_escalation_at(
        vault,
        EscalationReceipt {
            task_ref: crate::test_util::entity(0x71),
            scope: scope.to_owned(),
            trigger,
            question: QUESTION.to_owned(),
            ruling: ruling.clone(),
            rationale: RATIONALE.to_owned(),
            budget_band: band,
        },
        at,
    )
    .expect("ED records the ruling")
}

/// Seeds the three agreeing rulings ED's default N asks for, takes the
/// proposal they earn, and optionally taps ED's acceptance door.
fn seed_standing(
    vault: &Vault,
    scope: &str,
    trigger: EscalationTrigger,
    ruling: &EscalationRuling,
    band: Option<u64>,
    accept: bool,
) -> EntityId {
    for index in 0..3 {
        record(vault, scope, trigger, ruling, band, 1_000 + index);
    }
    let row_ref = maybe_propose_standing_policy_at(vault, scope, trigger, 2_000)
        .expect("ED reads the pattern")
        .expect("three agreeing rulings earn a proposed row");
    if accept {
        accept_standing_policy_at(vault, &row_ref, 3_000).expect("the owner accepts the row");
    }
    row_ref
}

fn standing_row(vault: &Vault, scope: &str, trigger: EscalationTrigger) -> Option<StandingPolicy> {
    standing_policy_for(vault, scope, trigger).expect("ED's typed standing read")
}

/// Overwrites every stored row whose bytes carry `marker`, so ED's typed read
/// of that range fails. The rows are found by the content ONE-1762 wrote, not
/// by a key prefix duplicated out of ED's private keyspace.
fn corrupt_rows_carrying(vault: &Vault, marker: &str) {
    let mut keys: Vec<Vec<u8>> = Vec::new();
    {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        for entry in vault.store.vault_meta.iter(&rtxn).expect("scan vault meta") {
            let (key, raw) = entry.expect("vault meta row");
            if raw
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
            {
                keys.push(key.to_vec());
            }
        }
    }
    assert!(!keys.is_empty(), "the fixture wrote a row to corrupt");
    vault
        .with_write_txn(|wtxn| {
            for key in &keys {
                vault
                    .store
                    .vault_meta
                    .put(wtxn, key, b"not a stored escalation row")?;
            }
            Ok(())
        })
        .expect("corrupt the stored rows");
}

fn gate_receipts(vault: &Vault) -> Vec<ReceiptRecord> {
    vault
        .receipts(ReceiptQuery::new(1_000).with_kind(ReceiptKind::Gate))
        .expect("gate receipts")
}

fn escalation_receipt_count(vault: &Vault) -> usize {
    gate_receipts(vault)
        .into_iter()
        .filter(is_escalation_receipt)
        .count()
}

/// ONE-1719's own pause and choice receipts. This module writes none: it
/// decides before the primitive permits anything downstream, and records only
/// ED's learning row.
fn fanout_surface_receipts(vault: &Vault) -> usize {
    gate_receipts(vault)
        .into_iter()
        .filter(|record| record.receipt_id.starts_with("fanout:"))
        .count()
}

fn field<'a>(record: &'a ReceiptRecord, key: &str) -> Option<&'a str> {
    record.fields.get(key).map(String::as_str)
}

// ---------------------------------------------------------------------------
// Source-surface helpers
// ---------------------------------------------------------------------------

/// The module's source with every comment line removed, so prose about what
/// ES-07 does NOT do can neither satisfy nor break a source assertion.
fn module_code() -> String {
    MODULE_SOURCE
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Every declaration the module makes `pub`, reduced to its head: an item
/// signature up to its body or terminator, or a field's `name: type` pair.
///
/// `pub(crate)` and `pub(super)` are excluded by construction, because the
/// token scanned for is `pub` with a trailing space. That is the stated
/// carve-out: the crate-private classification wrapper and the crate-visible
/// decider impl are exactly the places allowed to name ONE-1719's types.
fn public_declaration_heads(code: &str) -> Vec<String> {
    const ITEM_KEYWORDS: [&str; 9] = [
        "fn ", "const ", "struct ", "enum ", "trait ", "type ", "mod ", "static ", "use ",
    ];

    let mut heads = Vec::new();
    let mut rest = code;
    while let Some(at) = rest.find("pub ") {
        let tail = &rest[at + "pub ".len()..];
        let end = if ITEM_KEYWORDS
            .iter()
            .any(|keyword| tail.starts_with(keyword))
        {
            tail.find(['{', ';']).unwrap_or(tail.len())
        } else {
            tail.find(',').unwrap_or(tail.len())
        };
        heads.push(tail[..end].trim().to_owned());
        rest = tail;
    }
    heads
}

// ---------------------------------------------------------------------------
// The closed vocabulary
// ---------------------------------------------------------------------------

#[test]
fn es07_verdict_vocabulary_is_closed() {
    for (verdict, token) in [
        (FanoutAskVerdict::Allow, "\"allow\""),
        (FanoutAskVerdict::Deny, "\"deny\""),
        (FanoutAskVerdict::EscalateToHuman, "\"escalate-to-human\""),
    ] {
        assert_eq!(serde_json::to_string(&verdict).expect("encode"), token);
        assert_eq!(
            serde_json::from_str::<FanoutAskVerdict>(token).expect("decode"),
            verdict
        );
    }

    for unknown in [
        "\"escalate_to_human\"",
        "\"EscalateToHuman\"",
        "\"escalate\"",
        "\"run\"",
        "\"surface-human\"",
        "\"allow \"",
        "\"\"",
    ] {
        assert!(
            serde_json::from_str::<FanoutAskVerdict>(unknown).is_err(),
            "{unknown} is outside the closed vocabulary"
        );
    }

    // The ask trigger is closed the same way, and a budget ask cannot omit the
    // magnitude its ceiling comparison is made of.
    for trigger in [
        FanoutAskTrigger::Unsure,
        FanoutAskTrigger::Policy,
        FanoutAskTrigger::Budget { magnitude: 300 },
    ] {
        let encoded = serde_json::to_string(&trigger).expect("encode");
        assert!(encoded.contains("\"kind\""), "{encoded} is tagged");
        assert_eq!(
            serde_json::from_str::<FanoutAskTrigger>(&encoded).expect("decode"),
            trigger
        );
    }
    assert!(
        serde_json::from_str::<FanoutAskTrigger>("{\"kind\":\"budget\"}").is_err(),
        "a budget ask carries its magnitude or it does not decode"
    );

    // Exhaustive and catch-all free: a fourth verdict would be a compile error
    // here and in the adapter rather than defaulting into one of these arms.
    for verdict in [
        FanoutAskVerdict::Allow,
        FanoutAskVerdict::Deny,
        FanoutAskVerdict::EscalateToHuman,
    ] {
        let expected = match verdict {
            FanoutAskVerdict::Allow => FanoutAutoDisposition::Allow,
            FanoutAskVerdict::Deny => FanoutAutoDisposition::SurfaceHuman,
            FanoutAskVerdict::EscalateToHuman => FanoutAutoDisposition::SurfaceHuman,
        };
        assert_eq!(disposition_of(verdict), expected);
    }
}

#[test]
fn auto_decider_adapter_never_silent_kills() {
    let (_dir, vault) = open_vault();
    let plan = plan_over(&FAN_OUT);
    let estimate = estimate_over(&FAN_OUT);

    for (verdict, expected) in [
        (FanoutAskVerdict::Allow, FanoutAutoDisposition::Allow),
        (FanoutAskVerdict::Deny, FanoutAutoDisposition::SurfaceHuman),
        (
            FanoutAskVerdict::EscalateToHuman,
            FanoutAutoDisposition::SurfaceHuman,
        ),
    ] {
        let classifier = RecordingClassifier::ruling(verdict);
        let decider = LearningFanoutAutoDecider::new(
            &vault,
            context(SCOPE, FanoutAskTrigger::Unsure),
            Some(&classifier),
        )
        .expect("a usable ask context");
        assert_eq!(
            decider
                .decide(&plan, &estimate)
                .expect("the adapter never errors"),
            expected
        );
        assert_eq!(classifier.calls(), 1);
    }

    // A classifier that is missing, and one that fails, land on the same human
    // surface. Neither is authority to start a fan-out or to cancel one.
    let absent =
        LearningFanoutAutoDecider::new(&vault, context(SCOPE, FanoutAskTrigger::Unsure), None)
            .expect("a usable ask context");
    assert_eq!(
        absent.decide(&plan, &estimate).expect("no error"),
        FanoutAutoDisposition::SurfaceHuman
    );

    let failing = RecordingClassifier::failing();
    let broken = LearningFanoutAutoDecider::new(
        &vault,
        context(SCOPE, FanoutAskTrigger::Unsure),
        Some(&failing),
    )
    .expect("a usable ask context");
    assert_eq!(
        broken.decide(&plan, &estimate).expect("no error"),
        FanoutAutoDisposition::SurfaceHuman
    );
    assert_eq!(failing.calls(), 1);

    // Only a proven Allow proceeds, and nothing above created an effect.
    assert_eq!(fanout_surface_receipts(&vault), 0);
    assert_eq!(escalation_receipt_count(&vault), 0);
}

#[test]
fn classifier_is_provider_neutral_and_injected() {
    let (_dir, vault) = open_vault();
    let plan = plan_over(&FAN_OUT);
    let estimate = estimate_over(&FAN_OUT);
    let ask = context(SCOPE, FanoutAskTrigger::Budget { magnitude: 240 });

    // The engine half of the seam depends on itself, std, and serde. There is
    // no provider client, prompt template, credential, or transport in it.
    for line in MODULE_SOURCE
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("use "))
    {
        assert!(
            line.starts_with("use crate::")
                || line.starts_with("use serde")
                || line.starts_with("use std::"),
            "ES-07 depends on the engine, std, and serde only: {line}"
        );
    }
    let code = module_code();
    for marker in [
        "http",
        "api_key",
        "bearer",
        "credential",
        "reqwest",
        "prompt",
        "retry",
    ] {
        assert!(
            !code.contains(marker),
            "ES-07 carries no provider machinery: {marker}"
        );
    }

    // The injected fixture receives the ask, the four view projections, and
    // the normalized history — and nothing else.
    let classifier = RecordingClassifier::ruling(FanoutAskVerdict::Allow);
    assert_eq!(
        classify_fan_out_ask(&vault, &ask, &plan, &estimate, Some(&classifier)),
        FanoutAskVerdict::Allow
    );
    let seen = classifier.only_ask();
    assert_eq!(seen.scope, SCOPE);
    assert_eq!(seen.trigger, FanoutAskTrigger::Budget { magnitude: 240 });
    assert_eq!(seen.question, QUESTION);
    assert_eq!(seen.peer_count, 2);
    assert_eq!(seen.total_count, 240);
    assert_eq!(
        seen.per_peer_counts,
        vec![("cc-2".to_owned(), 60), ("codex".to_owned(), 180)]
    );
    assert_eq!(seen.plan_digest, "5a".repeat(32));
    assert_eq!(seen.history, FanoutDecisionHistory::default());

    // Every closed verdict comes back verbatim through the same seam.
    for verdict in [
        FanoutAskVerdict::Allow,
        FanoutAskVerdict::Deny,
        FanoutAskVerdict::EscalateToHuman,
    ] {
        let injected = RecordingClassifier::ruling(verdict);
        assert_eq!(
            classify_fan_out_ask(&vault, &ask, &plan, &estimate, Some(&injected)),
            verdict
        );
        assert_eq!(injected.calls(), 1);
    }
}

#[test]
fn classifier_view_is_the_only_public_plan_carrier() {
    let code = module_code();
    let heads = public_declaration_heads(&code);
    assert!(
        heads
            .iter()
            .any(|head| head.starts_with("enum FanoutAskVerdict")),
        "the surface scan found this module's public declarations: {heads:?}"
    );
    for head in &heads {
        assert!(
            !head.contains("FanoutPlan"),
            "ONE-1719's plan type never crosses a public declaration: {head}"
        );
        assert!(
            !head.contains("FanoutEstimate"),
            "ONE-1719's estimate type never crosses a public declaration: {head}"
        );
    }
    // The stated carve-out: the classification wrapper stays crate-private and
    // the decider impl is the trait's own crate-visible surface.
    assert!(
        code.contains("pub(crate) fn classify_fan_out_ask"),
        "the classification wrapper stays crate-private"
    );
    assert!(
        code.contains("impl FanoutAutoDecider for LearningFanoutAutoDecider"),
        "the decider impl is the carve-out that names ONE-1719's types"
    );

    // The view projects four things and no plan representation.
    let plan = plan_over(&FAN_OUT);
    let estimate = estimate_over(&FAN_OUT);
    let view = FanoutClassifierView::new(&plan, &estimate);
    assert_eq!(view.peer_count(), view.per_peer_counts().len() as u64);
    assert_eq!(view.peer_count(), 2);
    assert!(
        !view
            .per_peer_counts()
            .iter()
            .any(|(peer, _)| peer == "peer_hub"),
        "the parent endpoint sending the consults is never counted as a peer"
    );
    assert_eq!(view.total_count(), 240);
    assert_eq!(
        view.plan_digest(),
        bytes_to_hex_lower(&estimate.plan_digest)
    );

    // A wider plan under the SAME frozen estimate keeps the same digest: the
    // projection reads the existing bytes and never rehashes.
    let wider = plan_over(&[("codex", 180), ("cc-2", 60), ("peer_c", 1)]);
    let wider_view = FanoutClassifierView::new(&wider, &estimate);
    assert_eq!(wider_view.plan_digest(), view.plan_digest());
    assert_eq!(wider_view.peer_count(), 3);
}

// ---------------------------------------------------------------------------
// Re-homed ES-07 oracle arms
// ---------------------------------------------------------------------------

/// Re-homed from `tests/it/effect_spine_oracle.rs` (doc 13 §5 amendment): the
/// AUTO classifier gains a THIRD output, so an uncertain / over-policy ask
/// ESCALATES TO A HUMAN instead of being forced into an allow or a deny.
///
/// Relocation map: the oracle's `AutoGateRuling::EscalateToHuman` is this
/// module's `FanoutAskVerdict::EscalateToHuman`, and ONE-1719's pause surface
/// is `FanoutAutoDisposition::SurfaceHuman`. No assert is weakened; the
/// `uncertain: true` fixture argument becomes `FanoutAskTrigger::Unsure`.
#[test]
fn es07_classifier_escalates_uncertain_asks_to_human() {
    let (_dir, vault) = open_vault();
    let plan = plan_over(&[("codex", 60)]);
    let estimate = estimate_over(&[("codex", 60)]);
    let ask = context(SCOPE, FanoutAskTrigger::Unsure);

    let uncertain = RecordingClassifier::ruling(FanoutAskVerdict::EscalateToHuman);
    assert_eq!(
        classify_fan_out_ask(&vault, &ask, &plan, &estimate, Some(&uncertain)),
        FanoutAskVerdict::EscalateToHuman
    );
    assert_eq!(uncertain.calls(), 1);

    // Absence is the same answer, for the same reason.
    assert_eq!(
        classify_fan_out_ask(&vault, &ask, &plan, &estimate, None),
        FanoutAskVerdict::EscalateToHuman
    );

    let decider = LearningFanoutAutoDecider::new(&vault, ask, Some(&uncertain))
        .expect("a usable ask context");
    assert_eq!(
        decider.decide(&plan, &estimate).expect("no error"),
        FanoutAutoDisposition::SurfaceHuman
    );
    assert_eq!(fanout_surface_receipts(&vault), 0);
}

/// Re-homed from `tests/it/effect_spine_oracle.rs` (doc 13 §5 amendment): "the
/// classifier conditions on decision history — it learns from escalations".
///
/// the landed stub's history-alone→Run contract is superseded — history is
/// conditioning data, license lives on accepted standing rows (blueprint
/// L24-25).
///
/// Relocation map: the oracle's in-cap `AutoGateRuling::Run` becomes an
/// `Allow` outcome carried by an ACCEPTED ED standing Budget row whose
/// `budget_band_ceiling` is 500 (ask 300); its two `EscalateToHuman` arms — a
/// different key, and an over-cap magnitude (ask 501) — stay
/// `EscalateToHuman`. The history half is asserted separately, against ED's
/// exact-key counts and its own bounded window.
#[test]
fn es07_classifier_conditions_on_decision_history() {
    let (_dir, vault) = open_vault();
    let plan = plan_over(&FAN_OUT);
    let estimate = estimate_over(&FAN_OUT);

    seed_standing(
        &vault,
        SCOPE,
        EscalationTrigger::Budget,
        &EscalationRuling::Approve,
        Some(500),
        true,
    );
    let before = standing_row(&vault, SCOPE, EscalationTrigger::Budget);

    let classifier = RecordingClassifier::ruling(FanoutAskVerdict::Allow);
    let in_cap = context(SCOPE, FanoutAskTrigger::Budget { magnitude: 300 });
    assert_eq!(
        classify_fan_out_ask(&vault, &in_cap, &plan, &estimate, Some(&classifier)),
        FanoutAskVerdict::Allow
    );
    assert_eq!(
        classifier.calls(),
        0,
        "an accepted row answers without a classifier"
    );

    let other_key = context(OTHER_SCOPE, FanoutAskTrigger::Budget { magnitude: 300 });
    assert_eq!(
        classify_fan_out_ask(&vault, &other_key, &plan, &estimate, None),
        FanoutAskVerdict::EscalateToHuman
    );

    let over_cap = context(SCOPE, FanoutAskTrigger::Budget { magnitude: 501 });
    assert_eq!(
        classify_fan_out_ask(&vault, &over_cap, &plan, &estimate, Some(&classifier)),
        FanoutAskVerdict::EscalateToHuman
    );
    assert_eq!(classifier.calls(), 0);
    assert_eq!(
        standing_row(&vault, SCOPE, EscalationTrigger::Budget),
        before,
        "neither ask widened or rewrote the standing row"
    );

    // History as conditioning data: more than eight mixed rulings on ONE key,
    // with unrelated rulings on two others that must not leak into the counts.
    let history_scope = "fan_out/history";
    let mixed = [
        EscalationRuling::Approve,
        EscalationRuling::Deny,
        EscalationRuling::Amend(delta(0.25)),
        EscalationRuling::Approve,
        EscalationRuling::Approve,
        EscalationRuling::Deny,
        EscalationRuling::Amend(delta(0.5)),
        EscalationRuling::Approve,
        EscalationRuling::Deny,
        EscalationRuling::Approve,
    ];
    for (index, ruling) in mixed.iter().enumerate() {
        record(
            &vault,
            history_scope,
            EscalationTrigger::Unsure,
            ruling,
            None,
            4_000 + index as u64,
        );
    }
    for index in 0_u64..4 {
        record(
            &vault,
            history_scope,
            EscalationTrigger::Policy,
            &EscalationRuling::Deny,
            None,
            5_000 + index,
        );
        record(
            &vault,
            OTHER_SCOPE,
            EscalationTrigger::Unsure,
            &EscalationRuling::Deny,
            None,
            6_000 + index,
        );
    }

    let conditioned = RecordingClassifier::ruling(FanoutAskVerdict::Deny);
    let ask = context(history_scope, FanoutAskTrigger::Unsure);
    assert_eq!(
        classify_fan_out_ask(&vault, &ask, &plan, &estimate, Some(&conditioned)),
        FanoutAskVerdict::Deny,
        "the classifier's verdict is returned verbatim"
    );
    assert!(conditioned.calls() >= 1);

    let seen = conditioned.only_ask();
    assert_eq!(seen.history.approve, 5);
    assert_eq!(seen.history.deny, 3);
    assert_eq!(seen.history.amend, 2);
    assert_eq!(
        seen.history.last_rulings.len(),
        ESCALATION_LAST_RULINGS_BOUND
    );
    assert_eq!(
        seen.history.last_rulings,
        vec![
            FanoutHistoryRuling::Amend,
            FanoutHistoryRuling::Approve,
            FanoutHistoryRuling::Approve,
            FanoutHistoryRuling::Deny,
            FanoutHistoryRuling::Amend,
            FanoutHistoryRuling::Approve,
            FanoutHistoryRuling::Deny,
            FanoutHistoryRuling::Approve,
        ],
        "the newest eight, oldest-to-newest"
    );

    // History alone never produces Allow without a classifier Allow.
    let refusing = RecordingClassifier::ruling(FanoutAskVerdict::EscalateToHuman);
    assert_eq!(
        classify_fan_out_ask(&vault, &ask, &plan, &estimate, Some(&refusing)),
        FanoutAskVerdict::EscalateToHuman
    );
    assert_eq!(
        classify_fan_out_ask(&vault, &ask, &plan, &estimate, None),
        FanoutAskVerdict::EscalateToHuman
    );
}

/// Re-homed from `tests/it/effect_spine_oracle.rs` (ticket ONE-1720: "human
/// rulings OPTIONALLY persist as policy rows"). Persistence is optional;
/// APPLICATION is not — but application is ONE-1719's approval surface, and
/// this module never resumes, dispatches, or deletes a plan.
///
/// Relocation map: the oracle's `count_pending_escalations == 1` becomes
/// ONE-1719's pause-surface read (a pre-ruling ask is a paused, visible plan,
/// so `decide` surfaces); `count_pending_escalations == 0` after a ruling
/// becomes the committed `receipt_ref` the caller then applies through
/// ONE-1719; and `count_fan_out_policy_rows` — ONE-1719-owned and untouched
/// here — becomes ED's own `standing_policy_for` status read, since ONE-1762
/// owns policy rows. The storage schema the oracle deferred is ONE-1762's.
#[test]
fn es07_human_ruling_persistence_is_optional() {
    let (_dir, vault) = open_vault();
    let plan = plan_over(&[("codex", 60)]);
    let estimate = estimate_over(&[("codex", 60)]);
    let ask = context(SCOPE, FanoutAskTrigger::Unsure);

    // Before any ruling the ask is a paused, visible plan.
    let escalating = RecordingClassifier::ruling(FanoutAskVerdict::EscalateToHuman);
    let decider = LearningFanoutAutoDecider::new(&vault, ask.clone(), Some(&escalating))
        .expect("a usable ask context");
    assert_eq!(
        decider.decide(&plan, &estimate).expect("no error"),
        FanoutAutoDisposition::SurfaceHuman
    );
    assert_eq!(standing_row(&vault, SCOPE, EscalationTrigger::Unsure), None);

    // Approved, unpersisted: the receipt commits and no standing row appears.
    let approved = apply_escalation_ruling(
        &vault,
        &ask,
        FanoutEscalationRuling::Approve,
        RATIONALE.to_owned(),
    )
    .expect("the ruling records");
    assert_eq!(approved.proposal, FanoutProposalOutcome::NotProposed);
    assert_eq!(standing_row(&vault, SCOPE, EscalationTrigger::Unsure), None);

    // Denied, unpersisted: same shape, opposite ruling, still no row.
    let denied_scope = "fan_out/denied";
    let denied_ask = context(denied_scope, FanoutAskTrigger::Unsure);
    let denied = apply_escalation_ruling(
        &vault,
        &denied_ask,
        FanoutEscalationRuling::Deny,
        RATIONALE.to_owned(),
    )
    .expect("the ruling records");
    assert_eq!(denied.proposal, FanoutProposalOutcome::NotProposed);
    assert_eq!(
        standing_row(&vault, denied_scope, EscalationTrigger::Unsure),
        None
    );
    assert_ne!(denied.receipt_ref, approved.receipt_ref);

    // Persisted: the third agreeing ruling earns EXACTLY ONE row for that key,
    // and it is proposed rather than accepted.
    let second = apply_escalation_ruling(
        &vault,
        &ask,
        FanoutEscalationRuling::Approve,
        RATIONALE.to_owned(),
    )
    .expect("the ruling records");
    assert_eq!(second.proposal, FanoutProposalOutcome::NotProposed);
    let third = apply_escalation_ruling(
        &vault,
        &ask,
        FanoutEscalationRuling::Approve,
        RATIONALE.to_owned(),
    )
    .expect("the ruling records");
    let row_ref = match &third.proposal {
        FanoutProposalOutcome::Proposed(row_ref) => *row_ref,
        other => panic!("three agreeing rulings earn a proposed row, not {other:?}"),
    };
    let row = standing_row(&vault, SCOPE, EscalationTrigger::Unsure).expect("the proposed row");
    assert_eq!(row.row_ref, row_ref);
    assert_eq!(row.status, StandingPolicyStatus::Proposed);
    assert_eq!(row.ruling, EscalationRuling::Approve);

    // A fourth ruling does not mint a second row for the same key.
    let fourth = apply_escalation_ruling(
        &vault,
        &ask,
        FanoutEscalationRuling::Approve,
        RATIONALE.to_owned(),
    )
    .expect("the ruling records");
    assert_eq!(fourth.proposal, FanoutProposalOutcome::NotProposed);
    assert_eq!(
        standing_row(&vault, SCOPE, EscalationTrigger::Unsure)
            .expect("still exactly one row")
            .row_ref,
        row_ref
    );

    // Five rulings, five receipts — and no ONE-1719 pause or choice receipt,
    // because nothing here resumed or killed a plan.
    assert_eq!(escalation_receipt_count(&vault), 5);
    assert_eq!(fanout_surface_receipts(&vault), 0);
}

// ---------------------------------------------------------------------------
// Standing policy
// ---------------------------------------------------------------------------

#[test]
fn standing_policy_suppresses_repeat_ask() {
    let (_dir, vault) = open_vault();
    let plan = plan_over(&FAN_OUT);
    let estimate = estimate_over(&FAN_OUT);

    seed_standing(
        &vault,
        SCOPE,
        EscalationTrigger::Policy,
        &EscalationRuling::Approve,
        None,
        true,
    );
    let approving = RecordingClassifier::ruling(FanoutAskVerdict::EscalateToHuman);
    let allow_ask = context(SCOPE, FanoutAskTrigger::Policy);
    assert_eq!(
        classify_fan_out_ask(&vault, &allow_ask, &plan, &estimate, Some(&approving)),
        FanoutAskVerdict::Allow
    );
    assert_eq!(approving.calls(), 0);

    seed_standing(
        &vault,
        OTHER_SCOPE,
        EscalationTrigger::Policy,
        &EscalationRuling::Deny,
        None,
        true,
    );
    let denying = RecordingClassifier::ruling(FanoutAskVerdict::Allow);
    let deny_ask = context(OTHER_SCOPE, FanoutAskTrigger::Policy);
    assert_eq!(
        classify_fan_out_ask(&vault, &deny_ask, &plan, &estimate, Some(&denying)),
        FanoutAskVerdict::Deny
    );
    assert_eq!(denying.calls(), 0);

    // A learned deny still SURFACES: the primitive has no kill arm.
    let decider = LearningFanoutAutoDecider::new(&vault, deny_ask, Some(&denying))
        .expect("a usable ask context");
    assert_eq!(
        decider.decide(&plan, &estimate).expect("no error"),
        FanoutAutoDisposition::SurfaceHuman
    );
    assert_eq!(denying.calls(), 0);
}

#[test]
fn standing_policy_survives_missing_classifier() {
    let (_dir, vault) = open_vault();
    let plan = plan_over(&FAN_OUT);
    let estimate = estimate_over(&FAN_OUT);

    seed_standing(
        &vault,
        SCOPE,
        EscalationTrigger::Unsure,
        &EscalationRuling::Approve,
        None,
        true,
    );
    let allowed =
        LearningFanoutAutoDecider::new(&vault, context(SCOPE, FanoutAskTrigger::Unsure), None)
            .expect("a usable ask context");
    assert_eq!(
        allowed.decide(&plan, &estimate).expect("no error"),
        FanoutAutoDisposition::Allow
    );

    seed_standing(
        &vault,
        OTHER_SCOPE,
        EscalationTrigger::Unsure,
        &EscalationRuling::Deny,
        None,
        true,
    );
    let before = standing_row(&vault, OTHER_SCOPE, EscalationTrigger::Unsure);
    let deny_ask = context(OTHER_SCOPE, FanoutAskTrigger::Unsure);
    let denied = LearningFanoutAutoDecider::new(&vault, deny_ask.clone(), None)
        .expect("a usable ask context");
    assert_eq!(
        denied.decide(&plan, &estimate).expect("no error"),
        FanoutAutoDisposition::SurfaceHuman
    );
    assert_eq!(
        classify_fan_out_ask(&vault, &deny_ask, &plan, &estimate, None),
        FanoutAskVerdict::Deny
    );
    assert_eq!(
        standing_row(&vault, OTHER_SCOPE, EscalationTrigger::Unsure),
        before
    );

    // No row and no classifier is a human ask, not a proceed.
    let unlicensed = LearningFanoutAutoDecider::new(
        &vault,
        context("fan_out/bare", FanoutAskTrigger::Unsure),
        None,
    )
    .expect("a usable ask context");
    assert_eq!(
        unlicensed.decide(&plan, &estimate).expect("no error"),
        FanoutAutoDisposition::SurfaceHuman
    );

    // The construction door rejects a blank scope and a blank question.
    let mut blank_scope = context(SCOPE, FanoutAskTrigger::Unsure);
    blank_scope.scope = "   ".to_owned();
    assert!(LearningFanoutAutoDecider::new(&vault, blank_scope.clone(), None).is_err());
    let mut blank_question = context(SCOPE, FanoutAskTrigger::Unsure);
    blank_question.question = String::new();
    assert!(LearningFanoutAutoDecider::new(&vault, blank_question.clone(), None).is_err());

    // The wrapper repeats the check as a floor BEFORE any storage read: the
    // blank-question ask names the scope that DOES carry an accepted standing
    // approval, and it still escalates instead of short-circuiting on it.
    let recording = RecordingClassifier::ruling(FanoutAskVerdict::Allow);
    assert_eq!(
        classify_fan_out_ask(&vault, &blank_question, &plan, &estimate, Some(&recording)),
        FanoutAskVerdict::EscalateToHuman
    );
    assert_eq!(
        classify_fan_out_ask(&vault, &blank_scope, &plan, &estimate, Some(&recording)),
        FanoutAskVerdict::EscalateToHuman
    );
    assert_eq!(recording.calls(), 0);
}

#[test]
fn budget_standing_policy_never_widens() {
    let (_dir, vault) = open_vault();
    let plan = plan_over(&FAN_OUT);
    let estimate = estimate_over(&FAN_OUT);
    let classifier = RecordingClassifier::ruling(FanoutAskVerdict::Allow);

    seed_standing(
        &vault,
        SCOPE,
        EscalationTrigger::Budget,
        &EscalationRuling::Approve,
        Some(500),
        true,
    );
    let before = standing_row(&vault, SCOPE, EscalationTrigger::Budget).expect("the accepted row");
    assert_eq!(before.budget_band_ceiling, Some(500));

    for magnitude in [1_u64, 499, 500] {
        assert_eq!(
            classify_fan_out_ask(
                &vault,
                &context(SCOPE, FanoutAskTrigger::Budget { magnitude }),
                &plan,
                &estimate,
                Some(&classifier),
            ),
            FanoutAskVerdict::Allow,
            "{magnitude} is at or under the ceiling"
        );
    }
    for magnitude in [501_u64, 5_000] {
        assert_eq!(
            classify_fan_out_ask(
                &vault,
                &context(SCOPE, FanoutAskTrigger::Budget { magnitude }),
                &plan,
                &estimate,
                Some(&classifier),
            ),
            FanoutAskVerdict::EscalateToHuman,
            "{magnitude} is over the ceiling"
        );
    }
    assert_eq!(classifier.calls(), 0);
    assert_eq!(
        standing_row(&vault, SCOPE, EscalationTrigger::Budget),
        Some(before),
        "the row is byte-identical after every ask"
    );

    // A band-less budget row licenses no magnitude at all.
    seed_standing(
        &vault,
        OTHER_SCOPE,
        EscalationTrigger::Budget,
        &EscalationRuling::Approve,
        None,
        true,
    );
    let bandless =
        standing_row(&vault, OTHER_SCOPE, EscalationTrigger::Budget).expect("the band-less row");
    assert_eq!(bandless.budget_band_ceiling, None);
    for magnitude in [1_u64, 500] {
        assert_eq!(
            classify_fan_out_ask(
                &vault,
                &context(OTHER_SCOPE, FanoutAskTrigger::Budget { magnitude }),
                &plan,
                &estimate,
                Some(&classifier),
            ),
            FanoutAskVerdict::EscalateToHuman,
            "a band-less row cannot license {magnitude}"
        );
    }
    assert_eq!(classifier.calls(), 0);
    assert_eq!(
        standing_row(&vault, OTHER_SCOPE, EscalationTrigger::Budget),
        Some(bandless)
    );
}

#[test]
fn proposed_row_escalates_until_accepted() {
    let (_dir, vault) = open_vault();
    let plan = plan_over(&FAN_OUT);
    let estimate = estimate_over(&FAN_OUT);
    let classifier = RecordingClassifier::ruling(FanoutAskVerdict::Allow);
    let ask = context(SCOPE, FanoutAskTrigger::Policy);

    let row_ref = seed_standing(
        &vault,
        SCOPE,
        EscalationTrigger::Policy,
        &EscalationRuling::Approve,
        None,
        false,
    );
    assert_eq!(
        standing_row(&vault, SCOPE, EscalationTrigger::Policy)
            .expect("the proposed row")
            .status,
        StandingPolicyStatus::Proposed
    );
    assert_eq!(
        classify_fan_out_ask(&vault, &ask, &plan, &estimate, Some(&classifier)),
        FanoutAskVerdict::EscalateToHuman
    );
    assert_eq!(
        classifier.calls(),
        0,
        "a proposed row suppresses nothing and licenses nothing"
    );

    accept_standing_policy(&vault, &row_ref).expect("the owner accepts through ED's door");
    assert_eq!(
        standing_row(&vault, SCOPE, EscalationTrigger::Policy)
            .expect("the accepted row")
            .status,
        StandingPolicyStatus::Accepted
    );
    assert_eq!(
        classify_fan_out_ask(&vault, &ask, &plan, &estimate, Some(&classifier)),
        FanoutAskVerdict::Allow
    );
    assert_eq!(classifier.calls(), 0);
}

#[test]
fn uncertain_policy_state_escalates() {
    let (_dir, vault) = open_vault();
    let plan = plan_over(&FAN_OUT);
    let estimate = estimate_over(&FAN_OUT);
    let classifier = RecordingClassifier::ruling(FanoutAskVerdict::Allow);

    // A proposed row on the asked key, beside an ACCEPTED row on a
    // neighbouring trigger: no fallback scan may pick the neighbour up.
    seed_standing(
        &vault,
        SCOPE,
        EscalationTrigger::Unsure,
        &EscalationRuling::Approve,
        None,
        false,
    );
    seed_standing(
        &vault,
        SCOPE,
        EscalationTrigger::Policy,
        &EscalationRuling::Approve,
        None,
        true,
    );
    assert_eq!(
        classify_fan_out_ask(
            &vault,
            &context(SCOPE, FanoutAskTrigger::Unsure),
            &plan,
            &estimate,
            Some(&classifier),
        ),
        FanoutAskVerdict::EscalateToHuman
    );

    // An amend standing posture never allows.
    seed_standing(
        &vault,
        OTHER_SCOPE,
        EscalationTrigger::Unsure,
        &EscalationRuling::Amend(delta(0.25)),
        None,
        true,
    );
    assert_eq!(
        classify_fan_out_ask(
            &vault,
            &context(OTHER_SCOPE, FanoutAskTrigger::Unsure),
            &plan,
            &estimate,
            Some(&classifier),
        ),
        FanoutAskVerdict::EscalateToHuman
    );

    // A typed read that returns `Err` is uncertainty, not absence.
    let unreadable = context(&"x".repeat(OVERLONG_SCOPE_LEN), FanoutAskTrigger::Unsure);
    assert!(
        standing_policy_for(&vault, &unreadable.scope, EscalationTrigger::Unsure).is_err(),
        "the fixture scope really does fail ED's typed read"
    );
    assert_eq!(
        classify_fan_out_ask(&vault, &unreadable, &plan, &estimate, Some(&classifier)),
        FanoutAskVerdict::EscalateToHuman
    );
    let decider = LearningFanoutAutoDecider::new(&vault, unreadable, Some(&classifier))
        .expect("a non-blank scope passes the construction door");
    assert_eq!(
        decider.decide(&plan, &estimate).expect("no error"),
        FanoutAutoDisposition::SurfaceHuman
    );

    assert_eq!(
        classifier.calls(),
        0,
        "no classifier overrides uncertainty about an authoritative row"
    );
}

#[test]
fn classifier_error_or_history_error_escalates() {
    let (_dir, vault) = open_vault();
    let plan = plan_over(&FAN_OUT);
    let estimate = estimate_over(&FAN_OUT);
    let ask = context(SCOPE, FanoutAskTrigger::Unsure);

    // An injected classifier that cannot rule.
    let failing = RecordingClassifier::failing();
    assert_eq!(
        classify_fan_out_ask(&vault, &ask, &plan, &estimate, Some(&failing)),
        FanoutAskVerdict::EscalateToHuman
    );
    assert_eq!(failing.calls(), 1);
    let decider = LearningFanoutAutoDecider::new(&vault, ask.clone(), Some(&failing))
        .expect("a usable ask context");
    assert_eq!(
        decider.decide(&plan, &estimate).expect("no error"),
        FanoutAutoDisposition::SurfaceHuman
    );

    // A host handed a token outside the closed vocabulary cannot decode it.
    let undecodable = RecordingClassifier::host_token("\"run\"");
    assert_eq!(
        classify_fan_out_ask(&vault, &ask, &plan, &estimate, Some(&undecodable)),
        FanoutAskVerdict::EscalateToHuman
    );
    assert_eq!(undecodable.calls(), 1);
    // The same adapter decodes a closed token fine, so the fixture is testing
    // the vocabulary rather than a broken host.
    let decodable = RecordingClassifier::host_token("\"allow\"");
    assert_eq!(
        classify_fan_out_ask(&vault, &ask, &plan, &estimate, Some(&decodable)),
        FanoutAskVerdict::Allow
    );

    // A history read that fails: no standing row exists, but ED cannot fold
    // the ledger, so the ask escalates without reaching the classifier.
    record(
        &vault,
        SCOPE,
        EscalationTrigger::Unsure,
        &EscalationRuling::Approve,
        None,
        1_000,
    );
    corrupt_rows_carrying(&vault, QUESTION);
    assert!(
        escalation_stats(&vault, SCOPE, EscalationTrigger::Unsure).is_err(),
        "the fixture really does break ED's fold"
    );
    assert_eq!(
        standing_policy_for(&vault, SCOPE, EscalationTrigger::Unsure)
            .expect("the standing read is unaffected"),
        None
    );
    let unread = RecordingClassifier::ruling(FanoutAskVerdict::Allow);
    assert_eq!(
        classify_fan_out_ask(&vault, &ask, &plan, &estimate, Some(&unread)),
        FanoutAskVerdict::EscalateToHuman
    );
    assert_eq!(unread.calls(), 0);
}

// ---------------------------------------------------------------------------
// Recording a human ruling
// ---------------------------------------------------------------------------

#[test]
fn proposal_outcome_preserves_partial_success() {
    let (_dir, vault) = open_vault();
    let ask = context(SCOPE, FanoutAskTrigger::Unsure);

    // `Ok(None)` -> NotProposed.
    let first = apply_escalation_ruling(
        &vault,
        &ask,
        FanoutEscalationRuling::Approve,
        RATIONALE.to_owned(),
    )
    .expect("the ruling records");
    assert_eq!(first.proposal, FanoutProposalOutcome::NotProposed);

    // `Ok(Some(id))` -> Proposed(id).
    apply_escalation_ruling(
        &vault,
        &ask,
        FanoutEscalationRuling::Approve,
        RATIONALE.to_owned(),
    )
    .expect("the ruling records");
    let third = apply_escalation_ruling(
        &vault,
        &ask,
        FanoutEscalationRuling::Approve,
        RATIONALE.to_owned(),
    )
    .expect("the ruling records");
    let row_ref = match &third.proposal {
        FanoutProposalOutcome::Proposed(row_ref) => *row_ref,
        other => panic!("the third agreeing ruling proposes a row, not {other:?}"),
    };
    assert_eq!(
        standing_row(&vault, SCOPE, EscalationTrigger::Unsure)
            .expect("the proposed row")
            .row_ref,
        row_ref
    );

    // Only a failure BEFORE the receipt commits is `Err`, and it persists
    // nothing.
    let receipts_before = escalation_receipt_count(&vault);
    let mut blank = context(SCOPE, FanoutAskTrigger::Unsure);
    blank.scope = "  ".to_owned();
    assert!(
        apply_escalation_ruling(
            &vault,
            &blank,
            FanoutEscalationRuling::Approve,
            RATIONALE.to_owned(),
        )
        .is_err()
    );
    assert!(
        apply_escalation_ruling(
            &vault,
            &ask,
            FanoutEscalationRuling::Approve,
            "   ".to_owned(),
        )
        .is_err()
    );
    let unwritable = context(&"x".repeat(OVERLONG_SCOPE_LEN), FanoutAskTrigger::Unsure);
    assert!(
        apply_escalation_ruling(
            &vault,
            &unwritable,
            FanoutEscalationRuling::Approve,
            RATIONALE.to_owned(),
        )
        .is_err(),
        "a scope ED's ledger refuses returns Err with nothing persisted"
    );
    assert_eq!(escalation_receipt_count(&vault), receipts_before);

    // `Err` from the projector AFTER the receipt commits -> Failed(rendered),
    // and the caller still holds the committed receipt.
    let (_broken_dir, broken) = open_vault();
    record(
        &broken,
        SCOPE,
        EscalationTrigger::Unsure,
        &EscalationRuling::Approve,
        None,
        1_000,
    );
    corrupt_rows_carrying(&broken, QUESTION);
    let partial = apply_escalation_ruling(
        &broken,
        &ask,
        FanoutEscalationRuling::Approve,
        RATIONALE.to_owned(),
    )
    .expect("the receipt still commits");
    match &partial.proposal {
        FanoutProposalOutcome::Failed(rendered) => assert!(
            !rendered.is_empty(),
            "the projector failure is rendered, not swallowed"
        ),
        other => panic!("an unreadable ledger fails the projector, not {other:?}"),
    }
}

#[test]
fn escalation_ruling_roundtrip() {
    let (_dir, vault) = open_vault();
    let plan = plan_over(&FAN_OUT);
    let estimate = estimate_over(&FAN_OUT);
    let ask = context(SCOPE, FanoutAskTrigger::Budget { magnitude: 300 });

    // One ruling short of ED's proposal threshold.
    for at in [1_000_u64, 1_001] {
        record(
            &vault,
            SCOPE,
            EscalationTrigger::Budget,
            &EscalationRuling::Approve,
            Some(500),
            at,
        );
    }
    assert_eq!(standing_row(&vault, SCOPE, EscalationTrigger::Budget), None);

    let applied = apply_escalation_ruling(
        &vault,
        &ask,
        FanoutEscalationRuling::Approve,
        RATIONALE.to_owned(),
    )
    .expect("the ruling records");

    // One receipt, of ED's existing kind, carrying every field the ask and the
    // ruling were made of.
    assert_eq!(escalation_receipt_count(&vault), 3);
    let records: Vec<ReceiptRecord> = gate_receipts(&vault)
        .into_iter()
        .filter(is_escalation_receipt)
        .collect();
    let record = records
        .iter()
        .find(|record| field(record, FIELD_ESCALATION_BUDGET_BAND) == Some("300"))
        .expect("the applied ruling projects a receipt");
    let task_hex = crate::test_util::entity(0x72).to_hex();
    assert_eq!(record.receipt_kind, ReceiptKind::Gate);
    assert_eq!(field(record, FIELD_TASK_REF), Some(task_hex.as_str()));
    assert_eq!(field(record, FIELD_ESCALATION_SCOPE), Some(SCOPE));
    assert_eq!(field(record, FIELD_ESCALATION_TRIGGER), Some("budget"));
    assert_eq!(field(record, FIELD_ESCALATION_RULING), Some("approve"));
    assert_eq!(field(record, FIELD_ESCALATION_QUESTION), Some(QUESTION));
    assert_eq!(field(record, FIELD_ESCALATION_RATIONALE), Some(RATIONALE));
    assert_eq!(record.outcome, "approve");

    // The proposal is offered, never accepted here, and `receipt_ref` rides on
    // every Ok.
    let row_ref = match &applied.proposal {
        FanoutProposalOutcome::Proposed(row_ref) => *row_ref,
        other => panic!("the third agreeing ruling proposes a row, not {other:?}"),
    };
    let proposed = standing_row(&vault, SCOPE, EscalationTrigger::Budget).expect("the row");
    assert_eq!(proposed.status, StandingPolicyStatus::Proposed);
    assert_eq!(
        proposed.budget_band_ceiling,
        Some(300),
        "the ceiling is the MINIMUM band every citing ruling covered"
    );
    assert_eq!(applied.receipt_ref.to_hex().len(), 32);

    // Recording a ruling takes no plan at all, so it cannot resume, dispatch,
    // or delete one — and ONE-1719's surface recorded nothing.
    let heads = public_declaration_heads(&module_code());
    let ruling_head = heads
        .iter()
        .find(|head| head.starts_with("fn apply_escalation_ruling"))
        .expect("the ruling door is public");
    assert!(
        !ruling_head.contains("Plan"),
        "the ruling door never takes a plan: {ruling_head}"
    );
    assert_eq!(fanout_surface_receipts(&vault), 0);
    assert_eq!(plan_over(&FAN_OUT), plan);
    assert_eq!(estimate_over(&FAN_OUT), estimate);

    // The caller's second step is ED's acceptance door. Until it is tapped the
    // identical ask still escalates; afterwards it short-circuits with no
    // classifier work at all.
    let classifier = RecordingClassifier::ruling(FanoutAskVerdict::EscalateToHuman);
    assert_eq!(
        classify_fan_out_ask(&vault, &ask, &plan, &estimate, Some(&classifier)),
        FanoutAskVerdict::EscalateToHuman,
        "a proposed row does not yet license the ask"
    );
    accept_standing_policy(&vault, &row_ref).expect("the owner accepts through ED's door");
    assert_eq!(
        classify_fan_out_ask(&vault, &ask, &plan, &estimate, Some(&classifier)),
        FanoutAskVerdict::Allow
    );
    assert_eq!(classifier.calls(), 0);
}

#[test]
fn denied_ruling_never_becomes_silent_kill() {
    let (_dir, vault) = open_vault();
    let plan = plan_over(&FAN_OUT);
    let estimate = estimate_over(&FAN_OUT);
    let ask = context(SCOPE, FanoutAskTrigger::Policy);

    seed_standing(
        &vault,
        SCOPE,
        EscalationTrigger::Policy,
        &EscalationRuling::Deny,
        None,
        true,
    );
    let before = standing_row(&vault, SCOPE, EscalationTrigger::Policy);
    let receipts_before = escalation_receipt_count(&vault);

    let classifier = RecordingClassifier::ruling(FanoutAskVerdict::Allow);
    assert_eq!(
        classify_fan_out_ask(&vault, &ask, &plan, &estimate, Some(&classifier)),
        FanoutAskVerdict::Deny
    );
    assert_eq!(
        classifier.calls(),
        0,
        "a learned deny short-circuits classifier work"
    );

    let decider = LearningFanoutAutoDecider::new(&vault, ask, Some(&classifier))
        .expect("a usable ask context");
    assert_eq!(
        decider.decide(&plan, &estimate).expect("no error"),
        FanoutAutoDisposition::SurfaceHuman,
        "a deny is surfaced, never a kill"
    );
    assert_eq!(
        disposition_of(FanoutAskVerdict::Deny),
        FanoutAutoDisposition::SurfaceHuman
    );

    // No plan deleted, no row suppressed, no transport or TASK side effect.
    assert_eq!(
        standing_row(&vault, SCOPE, EscalationTrigger::Policy),
        before
    );
    assert_eq!(escalation_receipt_count(&vault), receipts_before);
    assert_eq!(fanout_surface_receipts(&vault), 0);
    assert_eq!(plan_over(&FAN_OUT), plan);
    assert_eq!(estimate_over(&FAN_OUT), estimate);
}

#[test]
fn amend_requires_new_plan_digest() {
    let (_dir, vault) = open_vault();
    let plan = plan_over(&FAN_OUT);
    let estimate = estimate_over(&FAN_OUT);

    // An amend HISTORY entry is conditioning data the classifier does see.
    record(
        &vault,
        SCOPE,
        EscalationTrigger::Unsure,
        &EscalationRuling::Amend(delta(0.25)),
        None,
        1_000,
    );
    record(
        &vault,
        SCOPE,
        EscalationTrigger::Unsure,
        &EscalationRuling::Amend(delta(0.5)),
        None,
        1_001,
    );
    record(
        &vault,
        SCOPE,
        EscalationTrigger::Unsure,
        &EscalationRuling::Approve,
        None,
        1_002,
    );
    let classifier = RecordingClassifier::ruling(FanoutAskVerdict::EscalateToHuman);
    let ask = context(SCOPE, FanoutAskTrigger::Unsure);
    assert_eq!(
        classify_fan_out_ask(&vault, &ask, &plan, &estimate, Some(&classifier)),
        FanoutAskVerdict::EscalateToHuman
    );
    let seen = classifier.only_ask();
    assert_eq!(seen.history.amend, 2);
    assert_eq!(seen.history.approve, 1);
    assert!(
        seen.history
            .last_rulings
            .contains(&FanoutHistoryRuling::Amend)
    );
    assert_eq!(seen.plan_digest, bytes_to_hex_lower(&estimate.plan_digest));

    // An amend STANDING posture cannot release the frozen plan, even though ED
    // reads the row as covering the ask.
    seed_standing(
        &vault,
        OTHER_SCOPE,
        EscalationTrigger::Unsure,
        &EscalationRuling::Amend(delta(0.25)),
        None,
        true,
    );
    let amend_row =
        standing_row(&vault, OTHER_SCOPE, EscalationTrigger::Unsure).expect("the amend row");
    assert_eq!(amend_row.status, StandingPolicyStatus::Accepted);
    assert!(matches!(amend_row.ruling, EscalationRuling::Amend(_)));
    assert!(
        amend_row.covers_ask(None),
        "ED's own coverage read says the row applies to this key"
    );

    let allowing = RecordingClassifier::ruling(FanoutAskVerdict::Allow);
    let amend_ask = context(OTHER_SCOPE, FanoutAskTrigger::Unsure);
    assert_eq!(
        classify_fan_out_ask(&vault, &amend_ask, &plan, &estimate, Some(&allowing)),
        FanoutAskVerdict::EscalateToHuman,
        "an amendment would move the digest, so the change returns through \
         ONE-1719 as a new plan"
    );
    assert_eq!(allowing.calls(), 0);

    let decider = LearningFanoutAutoDecider::new(&vault, amend_ask, Some(&allowing))
        .expect("a usable ask context");
    assert_eq!(
        decider.decide(&plan, &estimate).expect("no error"),
        FanoutAutoDisposition::SurfaceHuman
    );
    assert_eq!(
        estimate_over(&FAN_OUT),
        estimate,
        "the frozen estimate and its digest are untouched"
    );
}
