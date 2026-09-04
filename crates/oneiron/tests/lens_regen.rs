//! ONE-1431 — lens regen-on-update with the behavior-diff auto-adopt gate.
//!
//! This suite owns the end-to-end pure state machine: golden-corpus fixtures, the
//! injected summary-prompt/regeneration double, last-good and candidate golden
//! rendering, the behavior-diff gate, the no-blank active-revision guarantee, and the
//! version-pair load decision.
//!
//! Nothing here persists, queues, mounts, stamps approval, or routes a model. The
//! regenerator is a caller-owned double, exactly as the design requires.

use std::cell::Cell;
use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::json;

use oneiron::lens::{
    AnswerSheetAtom, ClaimLineAtom, CollectionAtom, GeneratedLens, LENS_APPS_CONTRACT_VERSION,
    LENS_ATOM_KIT_VERSION, LensAtom, LensAtomId, LensBehaviorFingerprint, LensBehaviorHandle,
    LensEvaluatedRevision, LensHandleName, LensHandleRef, LensHandleRole, LensLoadAction, LensNode,
    LensRegenFailure, LensRegenFailurePhase, LensRegenOutcome, LensRegenRequest, LensRegenerator,
    LensStatus, LensText, LensTextSpan, LensVersionStamp, MetaLineAtom, StatusDotAtom,
    TextBlockAtom, lens_load_action, regenerate_lens,
};

// ── Golden corpus ────────────────────────────────────────────────────────────
//
// The three fixtures are compiled in explicitly; nothing is discovered from the
// filesystem at run time.

const EMPTY_FIXTURE: &str = include_str!("fixtures/lens_golden/empty.json");
const SINGLE_ENTITY_FIXTURE: &str = include_str!("fixtures/lens_golden/single_entity.json");
const TIMELINE_FIXTURE: &str = include_str!("fixtures/lens_golden/timeline.json");

/// The corpus is intentionally small: kilobytes of hand-written engine test data.
const MAX_FIXTURE_BYTES: usize = 4096;

/// The case `CandidateFlavor::DropCase` omits from the candidate corpus.
const DROPPED_CASE_ID: &str = "empty-state";

/// The regenerator's own input. It never crosses the `regenerate_lens` API.
const BASELINE_PROMPT: &str = "summarize the open claims";

/// The same prompt with leading/trailing whitespace only.
const WHITESPACE_PROMPT: &str = "\n   summarize the open claims \t \n";

/// The private integration-test fixture schema. It is not a production API and is
/// deliberately absent from the lens module.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureVault {
    schema_version: u16,
    case_id: String,
    entities: Vec<FixtureEntity>,
    claims: Vec<FixtureClaim>,
    timeline: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureEntity {
    id: String,
    label: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureClaim {
    id: String,
    subject: String,
    predicate: String,
    value: String,
}

fn raw_corpus() -> [&'static str; 3] {
    [EMPTY_FIXTURE, SINGLE_ENTITY_FIXTURE, TIMELINE_FIXTURE]
}

fn corpus() -> Vec<FixtureVault> {
    raw_corpus()
        .into_iter()
        .map(|raw| serde_json::from_str::<FixtureVault>(raw).expect("golden fixture parses"))
        .collect()
}

// ── Lens construction helpers ────────────────────────────────────────────────

fn atom_id(value: &str) -> LensAtomId {
    LensAtomId::new(value).expect("valid lens atom id")
}

fn text(value: &str) -> LensText {
    LensText::new(value).expect("valid lens text")
}

fn handle(name: &str, role: LensHandleRole) -> LensHandleRef {
    LensHandleRef {
        name: LensHandleName::new(name).expect("valid lens handle name"),
        role,
    }
}

fn meta_node(id: &str, label: &str, value: &str) -> LensNode {
    LensNode::with_fallback_text(
        atom_id(id),
        LensAtom::MetaLine(MetaLineAtom {
            label: text(label),
            value: text(value),
        }),
        text(label),
    )
}

/// A bound section header. The `(name, role)` pair on this node is the fixture's
/// declared data read.
fn section(id: &str, label: &str, rows: usize, binding: LensHandleRef) -> LensNode {
    let mut node = meta_node(id, label, &rows.to_string());
    node.bindings.push(binding);
    node
}

/// The stamp used for a candidate that was compiled against the wrong contract pair.
///
/// Over-declaring the atom kit is accepted by the tree validator, so the body still
/// decodes — which is exactly the "newer than the running constants also decodes"
/// symmetry the load decision relies on.
const fn off_pair_stamp() -> LensVersionStamp {
    LensVersionStamp::new(LENS_ATOM_KIT_VERSION + 1, LENS_APPS_CONTRACT_VERSION)
}

/// A target pair that is not the live one.
const fn stale_target_stamp() -> LensVersionStamp {
    LensVersionStamp::new(LENS_ATOM_KIT_VERSION, 0)
}

/// Wrap a tree in a version-stamped envelope and decode it back through the shipped
/// `GeneratedLens` deserializer, so every body in this suite is really validated.
///
/// This is also how the wrong-stamp candidate is produced: a stale-stamped envelope,
/// never a test-only constructor or a `cfg(test)` setter.
fn lens_at(root: &LensNode, stamp: LensVersionStamp) -> Result<GeneratedLens, serde_json::Error> {
    serde_json::from_value(json!({
        "kit_version": stamp.kit_version(),
        "apps_contract_version": stamp.apps_contract_version(),
        "root": serde_json::to_value(root).expect("lens node encodes"),
    }))
}

// ── The injected regeneration double ─────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateFlavor {
    SameBehavior,
    StructuralRestyle,
    AddHandle,
    ChangeHandleRole,
    FailSummaryPromptRerun,
    FailCompile,
    FailValidate,
    FailGoldenRender,
    DropCase,
    WrongVersionStamp,
}

impl CandidateFlavor {
    /// Failures that happen before any candidate body exists.
    fn declared_failure(self) -> Option<LensRegenFailure> {
        match self {
            Self::FailSummaryPromptRerun => Some(LensRegenFailure::new(
                LensRegenFailurePhase::SummaryPromptRerun,
                "summary prompt rerun returned no candidate",
            )),
            Self::FailCompile => Some(LensRegenFailure::new(
                LensRegenFailurePhase::Compile,
                "candidate lens did not compile",
            )),
            _ => None,
        }
    }

    const fn restyles_structure(self) -> bool {
        matches!(self, Self::StructuralRestyle)
    }

    const fn adds_handle(self) -> bool {
        matches!(self, Self::AddHandle)
    }

    const fn rebinds_entities_as_query_result(self) -> bool {
        matches!(self, Self::ChangeHandleRole)
    }

    const fn duplicates_a_node_id(self) -> bool {
        matches!(self, Self::FailValidate)
    }
}

/// The per-fixture golden render. Every section count and every row node comes from the
/// fixture's own content, so no two cases render the same shape and no fingerprint is
/// hard-coded anywhere in this file.
fn render_root(fixture: &FixtureVault, heading: &str, flavor: CandidateFlavor) -> LensNode {
    let mut root = LensNode::with_fallback_text(
        atom_id("root"),
        LensAtom::Sheet(CollectionAtom {
            title: text(heading),
            rows: Vec::new(),
        }),
        text(heading),
    );

    if flavor.restyles_structure() {
        // Pure chrome: a new atom and a new tree shape, with the bound-read set
        // untouched.
        root.children.push(LensNode::with_fallback_text(
            atom_id("caption"),
            LensAtom::TextBlock(TextBlockAtom {
                spans: vec![LensTextSpan::Literal(text(heading))],
            }),
            text(heading),
        ));
    }

    root.children.push(entities_section(fixture, flavor));
    root.children.push(claims_section(fixture));
    if !fixture.timeline.is_empty() {
        root.children.push(timeline_section(fixture));
    }
    root.children.push(answer_node(fixture, flavor));
    root
}

fn entities_section(fixture: &FixtureVault, flavor: CandidateFlavor) -> LensNode {
    let role = if flavor.rebinds_entities_as_query_result() {
        LensHandleRole::QueryResult
    } else {
        LensHandleRole::EntitySet
    };
    let mut node = section(
        "entities",
        "entities",
        fixture.entities.len(),
        handle("entities", role),
    );
    for entity in &fixture.entities {
        node.children
            .push(meta_node(&entity.id, &entity.label, &entity.id));
    }
    node
}

fn claims_section(fixture: &FixtureVault) -> LensNode {
    let mut node = section(
        "claims",
        "claims",
        fixture.claims.len(),
        handle("claims", LensHandleRole::ClaimSet),
    );
    for claim in &fixture.claims {
        node.children.push(LensNode::with_fallback_text(
            atom_id(&claim.id),
            LensAtom::ClaimLine(ClaimLineAtom {
                subject: text(&claim.subject),
                predicate: text(&claim.predicate),
                value: text(&claim.value),
                status: StatusDotAtom {
                    status: LensStatus::Proposed,
                    label: None,
                },
                seal: None,
            }),
            text(&claim.predicate),
        ));
    }
    node
}

fn timeline_section(fixture: &FixtureVault) -> LensNode {
    let mut node = section(
        "timeline",
        "timeline",
        fixture.timeline.len(),
        handle("timeline", LensHandleRole::Timeline),
    );
    for entry in &fixture.timeline {
        node.children
            .push(meta_node(&format!("timeline-{entry}"), "step", entry));
    }
    node
}

fn answer_node(fixture: &FixtureVault, flavor: CandidateFlavor) -> LensNode {
    let mut citations = vec![handle("citations", LensHandleRole::QueryResult)];
    if flavor.adds_handle() {
        citations.push(handle("details", LensHandleRole::QueryResult));
    }
    LensNode::with_fallback_text(
        atom_id("answer"),
        LensAtom::AnswerSheet(AnswerSheetAtom {
            question: text("what is open"),
            answer: text(&format!("{} claims", fixture.claims.len())),
            citations,
        }),
        text("answer"),
    )
}

/// The revision's own body. A lens artifact is one tree; the corpus fingerprint is what
/// that same artifact produced across every fixture, so the double keeps them distinct
/// and `active_revision().lens()` is always a separately validated, nonblank body.
fn lens_body(
    fixtures: &[FixtureVault],
    heading: &str,
    flavor: CandidateFlavor,
    stamp: LensVersionStamp,
) -> Result<GeneratedLens, serde_json::Error> {
    let mut root = LensNode::with_fallback_text(
        atom_id("root"),
        LensAtom::Sheet(CollectionAtom {
            title: text(heading),
            rows: Vec::new(),
        }),
        text(heading),
    );
    for fixture in fixtures {
        root.children.push(meta_node(
            &format!("case-{}", fixture.case_id),
            &fixture.case_id,
            &fixture.claims.len().to_string(),
        ));
    }
    if flavor.duplicates_a_node_id() {
        if let Some(duplicate) = root.children.first().cloned() {
            root.children.push(duplicate);
        }
    }
    lens_at(&root, stamp)
}

/// Build the baseline revision: the last-good body plus a fingerprint over every
/// fixture render.
fn render_last_good(fixtures: &[FixtureVault]) -> LensEvaluatedRevision {
    let heading = BASELINE_PROMPT.trim();
    let body = lens_body(
        fixtures,
        heading,
        CandidateFlavor::SameBehavior,
        LensVersionStamp::current(),
    )
    .expect("baseline lens body is valid");
    let renders = fixtures
        .iter()
        .map(|fixture| {
            lens_at(
                &render_root(fixture, heading, CandidateFlavor::SameBehavior),
                LensVersionStamp::current(),
            )
            .expect("baseline golden render is a valid lens")
        })
        .collect::<Vec<_>>();
    let behavior = LensBehaviorFingerprint::from_golden_renders(
        fixtures
            .iter()
            .zip(renders.iter())
            .map(|(fixture, rendered)| (fixture.case_id.as_str(), rendered)),
    )
    .expect("baseline corpus fingerprints");
    LensEvaluatedRevision::new(body, behavior)
}

struct FixtureLensRegenerator {
    fixtures: Vec<FixtureVault>,
    summary_prompt: String,
    flavor: CandidateFlavor,
    calls: Cell<usize>,
}

impl FixtureLensRegenerator {
    fn new(flavor: CandidateFlavor, summary_prompt: &str) -> Self {
        Self {
            fixtures: corpus(),
            summary_prompt: summary_prompt.to_owned(),
            flavor,
            calls: Cell::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.get()
    }

    fn last_good(&self) -> LensEvaluatedRevision {
        render_last_good(&self.fixtures)
    }
}

impl LensRegenerator for FixtureLensRegenerator {
    fn regenerate(
        &self,
        request: &LensRegenRequest,
    ) -> Result<LensEvaluatedRevision, LensRegenFailure> {
        self.calls.set(self.calls.get() + 1);
        if let Some(failure) = self.flavor.declared_failure() {
            return Err(failure);
        }

        // The summary prompt is the regenerator's own input. Only its trimmed form
        // reaches the candidate body, and it lands as chrome text — which the
        // fingerprint ignores — so a whitespace-only prompt edit cannot move behavior.
        let heading = self.summary_prompt.trim();
        let stamp = if self.flavor == CandidateFlavor::WrongVersionStamp {
            off_pair_stamp()
        } else {
            request.target_version()
        };

        // Candidate construction really goes through the shipped deserializer, so the
        // `FailValidate` flavor captures a genuine `GeneratedLens` validation error
        // instead of smuggling an invalid body into the outcome.
        let body = lens_body(&self.fixtures, heading, self.flavor, stamp).map_err(|error| {
            LensRegenFailure::new(LensRegenFailurePhase::Validate, error.to_string())
        })?;

        let mut renders = Vec::new();
        for fixture in &self.fixtures {
            if self.flavor == CandidateFlavor::DropCase && fixture.case_id == DROPPED_CASE_ID {
                continue;
            }
            let rendered =
                lens_at(&render_root(fixture, heading, self.flavor), stamp).map_err(|error| {
                    LensRegenFailure::new(LensRegenFailurePhase::Validate, error.to_string())
                })?;
            renders.push((fixture.case_id.clone(), rendered));
        }
        if self.flavor == CandidateFlavor::FailGoldenRender {
            // A candidate corpus that is not uniquely keyed. `from_golden_renders`
            // rejects it and the regenerator reports it at the golden-render phase.
            if let Some(first) = renders.first().cloned() {
                renders.push(first);
            }
        }

        let behavior = LensBehaviorFingerprint::from_golden_renders(
            renders
                .iter()
                .map(|(case_id, rendered)| (case_id.as_str(), rendered)),
        )
        .map_err(|error| {
            LensRegenFailure::new(LensRegenFailurePhase::GoldenRender, error.to_string())
        })?;

        Ok(LensEvaluatedRevision::new(body, behavior))
    }
}

// ── Shared drivers ───────────────────────────────────────────────────────────

fn run(flavor: CandidateFlavor) -> LensRegenOutcome {
    run_with_prompt(flavor, BASELINE_PROMPT)
}

fn run_with_prompt(flavor: CandidateFlavor, prompt: &str) -> LensRegenOutcome {
    let regenerator = FixtureLensRegenerator::new(flavor, prompt);
    let last_good = regenerator.last_good();
    regenerate_lens(
        &regenerator,
        &LensRegenRequest::new(LensVersionStamp::current()),
        last_good,
    )
}

fn baseline_revision() -> LensEvaluatedRevision {
    render_last_good(&corpus())
}

fn expect_rollback(outcome: &LensRegenOutcome, phase: LensRegenFailurePhase) -> String {
    let LensRegenOutcome::RolledBack { last_good, failure } = outcome else {
        panic!("expected a rollback, got {outcome:?}");
    };
    assert_eq!(failure.phase(), phase, "rollback phase");
    assert_eq!(
        last_good,
        &baseline_revision(),
        "a rollback keeps the last-good revision active"
    );
    assert_eq!(
        outcome.active_revision(),
        &baseline_revision(),
        "the active revision is the last-good one"
    );
    assert!(outcome.diff().is_none(), "a rollback carries no diff");
    assert!(
        outcome.pending_candidate().is_none(),
        "a rollback proposes nothing"
    );
    failure.message().to_owned()
}

fn handle_pairs(handles: &BTreeSet<LensBehaviorHandle>) -> BTreeSet<(String, String)> {
    handles
        .iter()
        .map(|entry| {
            (
                entry.name().as_str().to_owned(),
                format!("{:?}", entry.role()),
            )
        })
        .collect()
}

/// Every referential rule the private fixture schema promises.
fn assert_fixture_is_sound(fixture: &FixtureVault) {
    assert_eq!(fixture.schema_version, 1, "fixture schema version");

    let mut entity_ids = BTreeSet::new();
    for entity in &fixture.entities {
        assert!(
            entity_ids.insert(entity.id.as_str()),
            "entity ids are unique: {}",
            entity.id
        );
        assert!(!entity.label.is_empty(), "entity labels are non-empty");
    }

    let mut claim_ids = BTreeSet::new();
    for claim in &fixture.claims {
        assert!(
            claim_ids.insert(claim.id.as_str()),
            "claim ids are unique: {}",
            claim.id
        );
        assert!(
            !claim.predicate.is_empty(),
            "claim predicates are non-empty"
        );
        assert!(!claim.value.is_empty(), "claim values are non-empty");
        assert!(
            entity_ids.contains(claim.subject.as_str()),
            "claim {} subjects a declared entity",
            claim.id
        );
    }

    for entry in &fixture.timeline {
        assert!(
            claim_ids.contains(entry.as_str()),
            "timeline id {entry} references a declared claim"
        );
    }
}

// ── 1. Corpus ────────────────────────────────────────────────────────────────

#[test]
fn golden_corpus_is_small_valid_and_complete() {
    for raw in raw_corpus() {
        assert!(
            raw.len() <= MAX_FIXTURE_BYTES,
            "golden fixtures stay small: {} bytes",
            raw.len()
        );
    }

    let fixtures = corpus();
    assert_eq!(fixtures.len(), 3, "the corpus ships three cases");

    let mut case_ids = BTreeSet::new();
    for fixture in &fixtures {
        assert!(
            case_ids.insert(fixture.case_id.as_str()),
            "case ids are unique: {}",
            fixture.case_id
        );
        assert_fixture_is_sound(fixture);
    }

    // The three cases really are the three intended shapes.
    assert!(
        fixtures[0].entities.is_empty()
            && fixtures[0].claims.is_empty()
            && fixtures[0].timeline.is_empty(),
        "the empty case has no rows at all"
    );
    assert_eq!(fixtures[1].entities.len(), 1);
    assert_eq!(fixtures[1].claims.len(), 1);
    assert_eq!(fixtures[2].entities.len(), 1);
    assert!(
        fixtures[2].claims.len() >= 2,
        "the timeline case is ordered"
    );
    assert_eq!(fixtures[2].timeline.len(), 2);

    // Every fixture participates in both the baseline and the candidate render.
    let baseline = baseline_revision();
    let baseline_ids = baseline.behavior().fixture_ids().collect::<Vec<_>>();
    assert_eq!(
        baseline_ids,
        vec!["empty-state", "single-entity", "timeline-window"],
        "the baseline fingerprint covers every case"
    );
    assert_eq!(baseline.behavior().fixture_count(), 3);

    let outcome = run(CandidateFlavor::SameBehavior);
    assert_eq!(
        outcome
            .active_revision()
            .behavior()
            .fixture_ids()
            .collect::<Vec<_>>(),
        baseline_ids,
        "the candidate fingerprint covers the same cases"
    );
}

// ── 2-3. Auto-adopt lanes ────────────────────────────────────────────────────

#[test]
fn structural_diff_with_same_handles_auto_adopts() {
    let outcome = run(CandidateFlavor::StructuralRestyle);
    let LensRegenOutcome::AutoAdopt { candidate, diff } = &outcome else {
        panic!("a restyle with unchanged bound reads auto-adopts, got {outcome:?}");
    };

    assert_eq!(
        diff.structural_cases().len(),
        3,
        "every case changed atom-tree shape"
    );
    assert!(
        !diff.inventory_changes().is_empty(),
        "the restyle changed the atom inventory"
    );
    assert!(
        diff.inventory_changes()
            .iter()
            .all(|change| change.before() != change.after()),
        "only unequal counts are reported"
    );
    assert!(diff.added_handles().is_empty(), "no bound read was added");
    assert!(
        diff.removed_handles().is_empty(),
        "no bound read was removed"
    );
    assert!(diff.role_changes().is_empty(), "no role moved");
    assert!(!diff.is_identical(), "the diff is not empty");
    assert!(!diff.has_data_read_change(), "structure is not authority");
    assert_eq!(
        outcome.active_revision(),
        candidate,
        "the candidate becomes active"
    );
    assert!(outcome.pending_candidate().is_none(), "nothing is pending");
}

#[test]
fn whitespace_only_summary_prompt_change_with_identical_behavior_auto_adopts() {
    assert_ne!(
        BASELINE_PROMPT, WHITESPACE_PROMPT,
        "the two prompts really differ as text"
    );
    assert_eq!(
        BASELINE_PROMPT.trim(),
        WHITESPACE_PROMPT.trim(),
        "they differ only in whitespace"
    );

    let outcome = run_with_prompt(CandidateFlavor::SameBehavior, WHITESPACE_PROMPT);
    let LensRegenOutcome::AutoAdopt { candidate, diff } = &outcome else {
        panic!("identical behavior auto-adopts, got {outcome:?}");
    };

    assert!(
        diff.is_identical(),
        "a whitespace-only prompt edit produces no behavior delta"
    );
    assert!(
        diff.inventory_changes().is_empty(),
        "equal counts produce no inventory entries"
    );
    let baseline = baseline_revision();
    assert_eq!(
        candidate.behavior(),
        baseline.behavior(),
        "the fingerprints compare equal"
    );
    // The request that crossed the API carries only the target stamp: there is no
    // prompt, source, or hash field to inspect on it.
    let request = LensRegenRequest::new(LensVersionStamp::current());
    assert_eq!(request.target_version(), LensVersionStamp::current());
}

// ── 4-5. Human-stamp lanes ───────────────────────────────────────────────────

#[test]
fn added_bound_handle_needs_human_stamp() {
    let outcome = run(CandidateFlavor::AddHandle);
    let LensRegenOutcome::NeedsHumanStamp {
        last_good,
        candidate,
        diff,
    } = &outcome
    else {
        panic!("an added bound read needs a human stamp, got {outcome:?}");
    };

    assert!(diff.has_data_read_change(), "the bound-read set changed");
    assert!(
        handle_pairs(diff.added_handles())
            .contains(&("details".to_owned(), "QueryResult".to_owned())),
        "the added pair is reported: {:?}",
        diff.added_handles()
    );
    assert_eq!(
        diff.added_handles().len(),
        3,
        "the new citation shows up in every case"
    );
    assert!(diff.removed_handles().is_empty(), "nothing was removed");
    assert!(diff.role_changes().is_empty(), "no existing role moved");
    assert_eq!(
        outcome.active_revision(),
        last_good,
        "the last-good revision stays active"
    );
    assert_eq!(last_good, &baseline_revision());
    assert_eq!(
        outcome.pending_candidate(),
        Some(candidate),
        "the candidate is offered for approval"
    );
}

#[test]
fn changed_handle_role_needs_human_stamp() {
    let outcome = run(CandidateFlavor::ChangeHandleRole);
    let LensRegenOutcome::NeedsHumanStamp { diff, .. } = &outcome else {
        panic!("a role change needs a human stamp, got {outcome:?}");
    };

    assert!(
        handle_pairs(diff.removed_handles())
            .contains(&("entities".to_owned(), "EntitySet".to_owned())),
        "the old pair is removed: {:?}",
        diff.removed_handles()
    );
    assert!(
        handle_pairs(diff.added_handles())
            .contains(&("entities".to_owned(), "QueryResult".to_owned())),
        "the new pair is added: {:?}",
        diff.added_handles()
    );

    assert_eq!(diff.role_changes().len(), 3, "one report per case");
    let ordered = diff
        .role_changes()
        .iter()
        .map(|change| (change.fixture_id(), change.name().as_str()))
        .collect::<Vec<_>>();
    let mut sorted = ordered.clone();
    sorted.sort_unstable();
    assert_eq!(ordered, sorted, "role changes are in canonical order");

    for change in diff.role_changes() {
        assert_eq!(change.name().as_str(), "entities");
        assert_eq!(
            change.before(),
            &BTreeSet::from([LensHandleRole::EntitySet]),
            "before role set"
        );
        assert_eq!(
            change.after(),
            &BTreeSet::from([LensHandleRole::QueryResult]),
            "after role set"
        );
    }
    assert_eq!(outcome.active_revision(), &baseline_revision());
}

// ── 6-9. Fail-safe lanes ─────────────────────────────────────────────────────

#[test]
fn compile_failure_rolls_back_to_last_good() {
    let outcome = run(CandidateFlavor::FailCompile);
    let message = expect_rollback(&outcome, LensRegenFailurePhase::Compile);
    assert!(
        message.contains("did not compile"),
        "the compile failure is recorded: {message}"
    );
}

#[test]
fn validation_failure_rolls_back_to_last_good() {
    let outcome = run(CandidateFlavor::FailValidate);
    let message = expect_rollback(&outcome, LensRegenFailurePhase::Validate);
    assert!(
        message.contains("duplicate ids"),
        "a real GeneratedLens validation error is captured: {message}"
    );
}

#[test]
fn golden_render_failure_rolls_back_to_last_good() {
    let outcome = run(CandidateFlavor::FailGoldenRender);
    let message = expect_rollback(&outcome, LensRegenFailurePhase::GoldenRender);
    assert!(
        message.contains("duplicate fixture id"),
        "the corpus construction error is carried: {message}"
    );
}

#[test]
fn corpus_case_drift_rolls_back_instead_of_adopting() {
    let outcome = run(CandidateFlavor::DropCase);
    let message = expect_rollback(&outcome, LensRegenFailurePhase::BehaviorDiff);
    assert!(
        message.contains("cover different golden fixtures"),
        "unequal fixture-id sets are refused rather than intersected: {message}"
    );
}

// ── 10-11. Version pair ──────────────────────────────────────────────────────

#[test]
fn candidate_with_wrong_version_stamp_rolls_back() {
    let regenerator =
        FixtureLensRegenerator::new(CandidateFlavor::WrongVersionStamp, BASELINE_PROMPT);
    let last_good = regenerator.last_good();
    let outcome = regenerate_lens(
        &regenerator,
        &LensRegenRequest::new(LensVersionStamp::current()),
        last_good,
    );

    assert_eq!(
        regenerator.calls(),
        1,
        "a live-targeted request does reach the regenerator"
    );
    let message = expect_rollback(&outcome, LensRegenFailurePhase::Validate);
    assert_eq!(
        message,
        "regenerated lens version does not match requested target"
    );

    // The wrong-stamp body is a perfectly decodable lens; only its pair is wrong.
    let stale = lens_body(
        &corpus(),
        BASELINE_PROMPT,
        CandidateFlavor::WrongVersionStamp,
        off_pair_stamp(),
    )
    .expect("a stale-stamped envelope still decodes");
    assert_eq!(stale.version_stamp(), off_pair_stamp());
}

#[test]
fn version_pair_mismatch_returns_queue_action() {
    let live = LensVersionStamp::current();
    assert_eq!(
        lens_load_action(live, live),
        LensLoadAction::MountCurrent,
        "an exact match mounts as current"
    );

    for stored in [
        LensVersionStamp::new(LENS_ATOM_KIT_VERSION + 1, LENS_APPS_CONTRACT_VERSION),
        LensVersionStamp::new(LENS_ATOM_KIT_VERSION, LENS_APPS_CONTRACT_VERSION + 1),
        LensVersionStamp::new(LENS_ATOM_KIT_VERSION + 1, LENS_APPS_CONTRACT_VERSION + 1),
        stale_target_stamp(),
    ] {
        assert_eq!(
            lens_load_action(stored, live),
            LensLoadAction::MountLastGoodAndQueueRegeneration { stored, live },
            "either component differing queues regeneration"
        );
    }

    // A decoded body answers the same question from its own wire data.
    let stale = lens_body(
        &corpus(),
        BASELINE_PROMPT,
        CandidateFlavor::SameBehavior,
        off_pair_stamp(),
    )
    .expect("a stale-stamped body decodes");
    assert_eq!(
        lens_load_action(stale.version_stamp(), live),
        LensLoadAction::MountLastGoodAndQueueRegeneration {
            stored: off_pair_stamp(),
            live,
        }
    );
}

// ── 12-14. No-blank guarantee and remaining phases ───────────────────────────

#[test]
fn all_outcomes_have_a_nonblank_active_revision() {
    let baseline = baseline_revision();

    let adopted = run(CandidateFlavor::SameBehavior);
    let LensRegenOutcome::AutoAdopt { candidate, .. } = &adopted else {
        panic!("expected AutoAdopt, got {adopted:?}");
    };
    assert_eq!(adopted.active_revision(), candidate);

    let stamped = run(CandidateFlavor::AddHandle);
    assert!(matches!(stamped, LensRegenOutcome::NeedsHumanStamp { .. }));
    assert_eq!(stamped.active_revision(), &baseline);

    let rolled_back = run(CandidateFlavor::FailCompile);
    assert!(matches!(rolled_back, LensRegenOutcome::RolledBack { .. }));
    assert_eq!(rolled_back.active_revision(), &baseline);

    for outcome in [&adopted, &stamped, &rolled_back] {
        let active = outcome.active_revision();
        assert!(
            !active.lens().root().children.is_empty(),
            "the active body is never blank"
        );
        assert!(
            !active
                .lens()
                .root()
                .fallback_text
                .as_str()
                .trim()
                .is_empty(),
            "the active body still renders text"
        );
        assert_eq!(
            active.behavior().fixture_count(),
            3,
            "the active revision keeps its corpus behavior"
        );
    }
}

#[test]
fn stale_targeted_request_rolls_back() {
    let regenerator = FixtureLensRegenerator::new(CandidateFlavor::SameBehavior, BASELINE_PROMPT);
    let last_good = regenerator.last_good();
    let outcome = regenerate_lens(
        &regenerator,
        &LensRegenRequest::new(stale_target_stamp()),
        last_good,
    );

    let message = expect_rollback(&outcome, LensRegenFailurePhase::Validate);
    assert_eq!(message, "regen request must target the live version pair");
    assert_eq!(
        regenerator.calls(),
        0,
        "a non-live target never reaches the regenerator"
    );
}

#[test]
fn summary_prompt_rerun_failure_rolls_back() {
    let outcome = run(CandidateFlavor::FailSummaryPromptRerun);
    let message = expect_rollback(&outcome, LensRegenFailurePhase::SummaryPromptRerun);
    assert!(
        message.contains("summary prompt rerun"),
        "the rerun failure is recorded: {message}"
    );
}
