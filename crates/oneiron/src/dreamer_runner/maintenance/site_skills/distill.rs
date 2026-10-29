//! Deterministic rendering for the Coach's site skills (CUA E8b, FIX 7606):
//! one candidate folder per site from the solved-run evidence and the live
//! programs the pass read. Pure: no model, browser or store.
//!
//! Filed bytes are shared-safe: origins, routes, workflow ids, run counts
//! and trap kinds with counts. No subgoal prose, arguments, replay
//! arguments, locators, task text, option values, secret values, seeds,
//! steps or timestamps ever render.

use std::collections::{BTreeMap, BTreeSet};

use oneiron_browser::{BatchStep, BatchStopCause, DraftGapKind, OperandGap, SiteOrigin};
use serde::Serialize;

use crate::browser_library::{RetiredWorkflow, SolvedRunEvidence, WorkflowRecord};
use crate::entity_id::bytes_to_hex_lower;
use crate::skill::SkillContentHash;
use crate::skill_hub::HubFile;
use crate::{EntityId, Error, Result};

/// The domain a site-skill candidate's fingerprint is hashed in. It must
/// differ from E8's [`CANDIDATE_DOMAIN`](crate::browser_library::CANDIDATE_DOMAIN):
/// the two facets never share a seen marker.
const SITE_SKILL_DISTILL_DOMAIN: &[u8] = b"oneiron:coach-site-skill-distill:v1";

/// The version of this distill, in each candidate's fingerprint and finding.
const SITE_SKILL_DISTILL_VERSION: u32 = 1;

/// The version a distilled folder declares, in frontmatter and record alike.
pub(super) const SITE_SKILL_VERSION: &str = "0.1.0";

/// Prefix for a record's content-named revision version. Frontmatter keeps
/// `SITE_SKILL_VERSION`; Native metadata binds the package, not this string.
const SITE_SKILL_REVISION_PREFIX: &str = "distill-";

/// The kind a site-skill fingerprint and finding carry.
const KIND: &str = "site_skill";

/// One live program the folder names, by workflow id only.
#[derive(Debug, Clone)]
pub(super) struct NamedProgram {
    /// The live program's id; prose names it `workflow:<32 hex>`.
    pub workflow: EntityId,
    /// Its current record counters.
    pub runs: u64,
    /// Its current record counters.
    pub failures: u64,
    /// Whether its filed proof includes the held-out check.
    pub held_out: bool,
}

/// One trap kind and its occurrence count. Kinds are stable snake-case
/// tokens; they never carry a locator, a value or caller-authored text.
#[derive(Debug, Clone, Serialize)]
pub(super) struct TrapCount {
    /// The stable kind token.
    pub kind: String,
    /// Its occurrence count.
    pub count: u64,
}

/// One candidate site skill and the folder that files it.
#[derive(Debug, Clone)]
pub(super) struct SiteSkillCandidate {
    /// `site-<slug>`; the hub wins a collision on it.
    pub skill_id: String,
    /// The site as evidence keys it.
    pub site: String,
    /// The observed origins [`SiteOrigin::parse`] accepts, sorted.
    pub origins: Vec<String>,
    /// The conservative mined routes, or empty for the whole site.
    pub routes: Vec<String>,
    /// The live programs named, by workflow id.
    pub programs: Vec<NamedProgram>,
    /// The trap kinds with counts, by kind.
    pub traps: Vec<TrapCount>,
    /// How many of the unit's groups a live program covers.
    pub covered_groups: usize,
    /// The evidence rows distilled, in (run id, evidence id) order.
    pub source_evidence: Vec<EntityId>,
    /// The distinct runs those rows came from, in first-seen order.
    pub from_runs: Vec<EntityId>,
    /// The candidate's fingerprint: no time, attempt or generation.
    pub fingerprint: [u8; 32],
    /// Exactly `SKILL.md` and `site.json`.
    pub files: Vec<HubFile>,
}

/// What one distill renders from.
pub(super) struct DistillInputs<'a> {
    /// The site as evidence keys it.
    pub site: &'a str,
    /// The unit's evidence rows, in any order.
    pub evidence: &'a [SolvedRunEvidence],
    /// The site's live programs (the commit passes the resolved ones).
    pub live: &'a [WorkflowRecord],
    /// The site's retired programs, for failure history only.
    pub retired: &'a [RetiredWorkflow],
    /// How many of the unit's groups a live program covers.
    pub covered_groups: usize,
}

/// Renders the unit's candidate, with one diagnostic per distinct invalid
/// origin. `None` holds no valid origin: a diagnostic and no candidate.
pub(super) fn distill(
    inputs: &DistillInputs<'_>,
) -> Result<(Option<SiteSkillCandidate>, Vec<String>)> {
    let mut ordered: Vec<&SolvedRunEvidence> = inputs.evidence.iter().collect();
    ordered.sort_by_key(|source| (source.run_id, source.id));
    let source_evidence: Vec<EntityId> = ordered.iter().map(|source| source.id).collect();
    let mut from_runs = Vec::new();
    for source in &ordered {
        if !from_runs.contains(&source.run_id) {
            from_runs.push(source.run_id);
        }
    }
    let (origins, diagnostics) = origins_of(inputs.evidence);
    if origins.is_empty() {
        return Ok((None, diagnostics));
    }
    let routes = routes_of(inputs.evidence);
    let programs = programs_of(inputs.live);
    let traps = traps_of(inputs.evidence, inputs.live, inputs.retired);
    let fingerprint = fingerprint(
        inputs.site,
        &origins,
        &routes,
        inputs.live,
        &traps,
        &source_evidence,
        &from_runs,
    )?;
    let skill_id = skill_id_for_site(inputs.site);
    let files = vec![
        HubFile::new(
            "SKILL.md",
            render_skill_md(&skill_id, inputs.site, &origins, &routes, &programs, &traps)
                .into_bytes(),
        ),
        HubFile::new(
            "site.json",
            render_site_json(&origins, &routes, &programs, &traps)?.into_bytes(),
        ),
    ];
    Ok((
        Some(SiteSkillCandidate {
            skill_id,
            site: inputs.site.to_owned(),
            origins,
            routes,
            programs,
            traps,
            covered_groups: inputs.covered_groups,
            source_evidence,
            from_runs,
            fingerprint,
            files,
        }),
        diagnostics,
    ))
}

/// The finding's stable value for a landing that files or points at
/// `skill`: no time, attempt or generation. `commit_diagnostics` names the
/// workflows the commit dropped, by hex id.
pub(super) fn finding_value(
    candidate: &SiteSkillCandidate,
    skill: &str,
    commit_diagnostics: &[String],
) -> serde_json::Value {
    serde_json::json!({
        "version": SITE_SKILL_DISTILL_VERSION,
        "kind": KIND,
        "site": candidate.site,
        "skill_id": candidate.skill_id,
        "skill": skill,
        "fingerprint": bytes_to_hex_lower(&candidate.fingerprint),
        "origins": candidate.origins,
        "routes": candidate.routes,
        "programs": candidate.programs.iter().map(|program| serde_json::json!({
            "workflow": program.workflow.to_hex(),
            "runs": program.runs,
            "failures": program.failures,
            "held_out": program.held_out,
        })).collect::<Vec<_>>(),
        "traps": candidate.traps,
        "covered_groups": candidate.covered_groups,
        "source_evidence": candidate.source_evidence.iter().map(EntityId::to_hex).collect::<Vec<_>>(),
        "from_runs": candidate.from_runs.iter().map(EntityId::to_hex).collect::<Vec<_>>(),
        "diagnostics": commit_diagnostics,
    })
}

/// The content-named record version of a revision. Equal bytes take the
/// duplicate branch, so this differs from its predecessor by construction.
pub(super) fn revision_version(content_hash: SkillContentHash) -> String {
    let hex = content_hash.to_hex();
    format!("{SITE_SKILL_REVISION_PREFIX}{}", &hex[..16])
}

/// The finding's stable value for a same-site next revision, citing both
/// the new Candidate and its predecessor.
pub(super) fn revision_value(
    candidate: &SiteSkillCandidate,
    skill: &str,
    predecessor: &str,
    commit_diagnostics: &[String],
) -> serde_json::Value {
    let mut value = finding_value(candidate, skill, commit_diagnostics);
    value["kind"] = serde_json::Value::from("site_skill_revision");
    value["predecessor"] = serde_json::Value::from(predecessor);
    value
}

/// The finding's stable value when `skill_id` already has a holder: the
/// hub wins, nothing is filed or merged, and the holder is named.
pub(super) fn collision_value(candidate: &SiteSkillCandidate, holder: &str) -> serde_json::Value {
    serde_json::json!({
        "version": SITE_SKILL_DISTILL_VERSION,
        "kind": "id_collision",
        "site": candidate.site,
        "skill_id": candidate.skill_id,
        "holder": holder,
        "fingerprint": bytes_to_hex_lower(&candidate.fingerprint),
        "source_evidence": candidate.source_evidence.iter().map(EntityId::to_hex).collect::<Vec<_>>(),
        "from_runs": candidate.from_runs.iter().map(EntityId::to_hex).collect::<Vec<_>>(),
    })
}

/// The skill id for a site: `site-<slug>`.
pub(super) fn skill_id_for_site(site: &str) -> String {
    format!("site-{}", slug_for_site(site))
}

/// The record and frontmatter description for a site. The site is
/// capped so the record's 4096-byte desc cap holds whatever the site key
/// holds; the folder's `Site:` line and the finding still name it whole.
pub(super) fn description_for_site(site: &str) -> String {
    format!(
        "Site know-how for {}: library-first routes, traps and program refs.",
        capped_site(site)
    )
}

/// The site as the description names it: whole to 1024 bytes, cut at a
/// char boundary past that. Deterministic.
fn capped_site(site: &str) -> &str {
    const CAP: usize = 1024;
    if site.len() <= CAP {
        return site;
    }
    let mut end = CAP;
    while !site.is_char_boundary(end) {
        end -= 1;
    }
    &site[..end]
}

/// The slug of a site: lowercased, runs of other characters as one `-`,
/// capped. Total: never empty.
fn slug_for_site(site: &str) -> String {
    let mut slug = String::with_capacity(site.len());
    let mut dash = true;
    for c in site.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash {
            slug.push('-');
            dash = true;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.len() > 64 {
        slug.truncate(64);
        while slug.ends_with('-') {
            slug.pop();
        }
    }
    if slug.is_empty() {
        slug.push_str("unknown");
    }
    slug
}

/// The distinct observed origins [`SiteOrigin::parse`] accepts, sorted,
/// with one diagnostic per distinct rejected one. A diagnostic names the
/// parse error only, never the rejected string.
fn origins_of(evidence: &[SolvedRunEvidence]) -> (Vec<String>, Vec<String>) {
    let mut distinct = BTreeSet::new();
    for source in evidence {
        distinct.insert(source.origin.clone());
    }
    let mut origins = Vec::new();
    let mut diagnostics = Vec::new();
    for origin in distinct {
        match SiteOrigin::parse(&origin) {
            Ok(_) => origins.push(origin),
            Err(error) => {
                diagnostics.push(format!("an observed origin is not a site origin: {error}"))
            }
        }
    }
    origins.sort();
    diagnostics.sort();
    (origins, diagnostics)
}

/// The conservative routes over the observed `open` URLs: their longest
/// shared `/`-boundary prefix, or none (the whole site) when they share
/// only `/`. A route needs at least two distinct paths: one distinct path
/// never mines a route.
fn routes_of(evidence: &[SolvedRunEvidence]) -> Vec<String> {
    let mut paths = BTreeSet::new();
    for source in evidence {
        for step in &source.draft.proposal.steps {
            if let BatchStep::Open { url } = step
                && let Some(path) = open_path(url)
            {
                paths.insert(path);
            }
        }
    }
    if paths.len() < 2 {
        return Vec::new();
    }
    common_route(&paths.into_iter().collect::<Vec<_>>())
}

/// The path of an `open` URL: `/` for none, cut at `?` or `#`. Only
/// http(s) URLs mine a route, as [`SiteOrigin::parse`] only takes those.
fn open_path(url: &str) -> Option<String> {
    let url = url.trim();
    let (scheme, rest) = url.split_once("://")?;
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return None;
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let path = rest[authority_end..].split(['?', '#']).next()?;
    Some(if path.is_empty() {
        "/".to_owned()
    } else {
        path.to_owned()
    })
}

/// The longest shared `/`-boundary prefix of every observed path, or none.
/// Cutting to a trailing `/` keeps every observed path matched: `/spread`
/// must never match `/spreadsheets`. The prefix then cuts before its first
/// id-like segment, so caller literals never file as routes.
fn common_route(paths: &[String]) -> Vec<String> {
    if paths.is_empty() {
        return Vec::new();
    }
    let mut shared = paths[0].len();
    for path in &paths[1..] {
        shared = paths[0]
            .bytes()
            .zip(path.bytes())
            .take(shared)
            .take_while(|(a, b)| a == b)
            .count();
        if shared == 0 {
            break;
        }
    }
    while !paths[0].is_char_boundary(shared) {
        shared -= 1;
    }
    let mut prefix = &paths[0][..shared];
    if prefix.len() > 1 && !prefix.ends_with('/') {
        prefix = &prefix[..prefix.rfind('/').map_or(0, |at| at + 1)];
    }
    if prefix.len() <= 1 {
        return Vec::new();
    }
    sanitize_route_prefix(prefix)
}

/// Floor for a hex-only segment to count as id-like. Mirrors the engine's
/// own floor for secret-shaped material (`MIN_SECRET_LEN = 8`,
/// `batch/secret_scan/shapes.rs:629`; private, mirrored by value).
const ROUTE_LONG_HEX_MIN_LEN: usize = 8;

/// Floor for a mixed letter+digit segment to count as token-like. The mix
/// rule mirrors `secret_candidate`'s letters+digits
/// (`batch/secret_scan/shapes.rs:644-663`); the length is raised 8->16
/// because bare path segments lack the credential-key context that
/// assignments carry.
const ROUTE_TOKEN_MIN_LEN: usize = 16;

/// Length at which any segment counts as token-like, whatever its alphabet.
const ROUTE_TOKEN_ANY_LEN: usize = 32;

/// Cuts a `/`-boundary common prefix before its first id-like segment and
/// rejoins the kept segments as `/` + kept + `/`. Zero kept segments is
/// the whole site (`[]`), same as a `/`-only prefix.
fn sanitize_route_prefix(prefix: &str) -> Vec<String> {
    let mut kept = Vec::new();
    for segment in prefix.split('/') {
        if segment.is_empty() {
            continue;
        }
        if route_segment_hit(segment) {
            break;
        }
        kept.push(segment);
    }
    if kept.is_empty() {
        Vec::new()
    } else {
        vec![format!("/{}/", kept.join("/"))]
    }
}

/// Whether one route-prefix segment is id-like: the route cuts before it.
/// Pure byte predicates over ASCII shapes; total and panic-free on any
/// UTF-8. No entropy float, no percent-decoding.
fn route_segment_hit(segment: &str) -> bool {
    is_all_digits(segment)
        || is_long_hex(segment)
        || is_uuid(segment)
        || is_token_like(segment)
        || is_opaque(segment)
}

/// Non-empty, all ASCII digits, any length.
fn is_all_digits(segment: &str) -> bool {
    !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit())
}

/// Hex-only at or above [`ROUTE_LONG_HEX_MIN_LEN`].
fn is_long_hex(segment: &str) -> bool {
    segment.len() >= ROUTE_LONG_HEX_MIN_LEN && segment.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Canonical UUID shape (8-4-4-4-12, dashes at 8/13/18/23, rest hex).
fn is_uuid(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (at, byte) in bytes.iter().enumerate() {
        if matches!(at, 8 | 13 | 18 | 23) {
            if *byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Token-like: mixed ASCII letters+digits at or above
/// [`ROUTE_TOKEN_MIN_LEN`], or anything at or above
/// [`ROUTE_TOKEN_ANY_LEN`].
fn is_token_like(segment: &str) -> bool {
    if segment.len() >= ROUTE_TOKEN_ANY_LEN {
        return true;
    }
    if segment.len() < ROUTE_TOKEN_MIN_LEN {
        return false;
    }
    let mut letter = false;
    let mut digit = false;
    for byte in segment.bytes() {
        if byte.is_ascii_alphabetic() {
            letter = true;
        } else if byte.is_ascii_digit() {
            digit = true;
        }
        if letter && digit {
            return true;
        }
    }
    false
}

/// Opaque: percent-encoded bytes, unfilled run slots, or dot-segments.
fn is_opaque(segment: &str) -> bool {
    segment == "."
        || segment == ".."
        || segment.bytes().any(|byte| byte == b'%')
        || segment.contains("{{")
        || segment.contains("}}")
}

/// The live programs named, by workflow id.
fn programs_of(live: &[WorkflowRecord]) -> Vec<NamedProgram> {
    let mut programs: Vec<NamedProgram> = live
        .iter()
        .map(|record| NamedProgram {
            workflow: record.id,
            runs: u64::from(record.runs),
            failures: u64::from(record.failures),
            held_out: record.proof.held_out,
        })
        .collect();
    programs.sort_by_key(|program| program.workflow);
    programs
}

/// The trap kinds with counts, by kind: gap kinds, pressed-through effect
/// classes, and the site's failure events across live and retired rows.
fn traps_of(
    evidence: &[SolvedRunEvidence],
    live: &[WorkflowRecord],
    retired: &[RetiredWorkflow],
) -> Vec<TrapCount> {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for source in evidence {
        for gap in &source.draft.gaps {
            *counts.entry(gap_token(&gap.gap)).or_default() += 1;
        }
        for press in &source.draft.pressed_through {
            let kind = format!("pressed_through:{}", effect_token(&press.effect_class));
            *counts.entry(kind).or_default() += 1;
        }
    }
    let failures: u64 = live
        .iter()
        .map(|record| u64::from(record.failures))
        .sum::<u64>()
        .saturating_add(
            retired
                .iter()
                .map(|trace| u64::from(trace.record.failures))
                .sum::<u64>(),
        );
    if failures > 0 {
        counts.insert("program_failures".to_owned(), failures);
    }
    counts
        .into_iter()
        .map(|(kind, count)| TrapCount { kind, count })
        .collect()
}

/// A draft gap as a stable kind token. Payloads that name a check index,
/// a foreign origin string or a secret kind are dropped: kinds and counts
/// only.
fn gap_token(gap: &DraftGapKind) -> String {
    match gap {
        DraftGapKind::PrePress { effect_class } => {
            format!("gap:pre_press:{}", effect_token(effect_class))
        }
        DraftGapKind::UnknownPress => "gap:unknown_press".to_owned(),
        DraftGapKind::NoAction => "gap:no_action".to_owned(),
        DraftGapKind::SecretWithheld { cause, .. } => {
            format!("gap:secret_withheld:{}", operand_token(cause))
        }
        DraftGapKind::Failed { cause } => format!("gap:failed:{}", cause_token(cause)),
        DraftGapKind::NoEffect => "gap:no_effect".to_owned(),
        DraftGapKind::MissingOpening => "gap:missing_opening".to_owned(),
        DraftGapKind::EmptySpan => "gap:empty_span".to_owned(),
        DraftGapKind::NoLiveOrigin => "gap:no_live_origin".to_owned(),
        DraftGapKind::ForeignOrigin { .. } => "gap:foreign_origin".to_owned(),
        DraftGapKind::TabChange => "gap:tab_change".to_owned(),
        DraftGapKind::GeneratedFill => "gap:generated_fill".to_owned(),
        DraftGapKind::UnrecordedNavigation => "gap:unrecorded_navigation".to_owned(),
        DraftGapKind::MissingContext => "gap:missing_context".to_owned(),
        DraftGapKind::CheckUnknownRef { .. } => "gap:check_unknown_ref".to_owned(),
        DraftGapKind::CheckSecretWithheld { cause, .. } => {
            format!("gap:check_secret_withheld:{}", operand_token(cause))
        }
        DraftGapKind::NoPostcondition => "gap:no_postcondition".to_owned(),
        DraftGapKind::NoSubgoal => "gap:no_subgoal".to_owned(),
    }
}

/// A stop cause as a coarse stable token: the variant only, never its
/// reason, scope or browser code.
fn cause_token(cause: &BatchStopCause) -> &'static str {
    match cause {
        BatchStopCause::PostconditionUnmet => "postcondition_unmet",
        BatchStopCause::LocatorMissing => "locator_missing",
        BatchStopCause::IncompleteObservation => "incomplete_observation",
        BatchStopCause::DeciderAskedUp { .. } => "decider_asked_up",
        BatchStopCause::Clock { .. } => "clock",
        BatchStopCause::PressNeeded => "press_needed",
        BatchStopCause::TakenOver => "taken_over",
        BatchStopCause::FieldText { .. } => "field_text",
        BatchStopCause::NoProgress => "no_progress",
        BatchStopCause::Browser { .. } => "browser",
    }
}

/// An operand gap as a stable token.
fn operand_token(cause: &OperandGap) -> &'static str {
    match cause {
        OperandGap::NoCustody => "no_custody",
        OperandGap::Refused => "refused",
        OperandGap::UnknownKind => "unknown_kind",
        OperandGap::Unbound => "unbound",
    }
}

/// A press effect class as a trap token: lowercased ASCII alphanumerics
/// and `_` only, capped, never empty.
fn effect_token(class: &str) -> String {
    let token: String = class
        .chars()
        .filter_map(|c| {
            if c.is_ascii_alphanumeric() {
                Some(c.to_ascii_lowercase())
            } else if matches!(c, '.' | '_' | '-') {
                Some('_')
            } else {
                None
            }
        })
        .take(48)
        .collect();
    let token = token.trim_matches('_').to_owned();
    if token.is_empty() {
        "other".to_owned()
    } else {
        token
    }
}

/// The finding's body, which the fingerprint hashes.
#[derive(Serialize)]
struct Body<'a> {
    version: u32,
    kind: &'static str,
    site: &'a str,
    origins: &'a [String],
    routes: &'a [String],
    programs: Vec<ProgramBody>,
    traps: &'a [TrapCount],
    source_evidence: Vec<String>,
    from_runs: Vec<String>,
}

/// One named program as the fingerprint hashes it: its id and its proof.
#[derive(Serialize)]
struct ProgramBody {
    workflow: String,
    proof: serde_json::Value,
}

/// The candidate's fingerprint: the version, the kind, the site, the
/// origins, the routes, the program ids with proof digests, the trap
/// counts, the source evidence and the runs. No time, attempt, dirty
/// generation or record counter: runs-only changes re-render nothing.
fn fingerprint(
    site: &str,
    origins: &[String],
    routes: &[String],
    live: &[WorkflowRecord],
    traps: &[TrapCount],
    source_evidence: &[EntityId],
    from_runs: &[EntityId],
) -> Result<[u8; 32]> {
    let mut ordered: Vec<&WorkflowRecord> = live.iter().collect();
    ordered.sort_by_key(|record| record.id);
    let mut programs = Vec::with_capacity(ordered.len());
    for record in ordered {
        let proof = serde_json::to_value(&record.proof)
            .map_err(|_| Error::InvariantViolation("site skill fingerprint encode failed"))?;
        programs.push(ProgramBody {
            workflow: record.id.to_hex(),
            proof,
        });
    }
    let body = Body {
        version: SITE_SKILL_DISTILL_VERSION,
        kind: KIND,
        site,
        origins,
        routes,
        programs,
        traps,
        source_evidence: source_evidence.iter().map(EntityId::to_hex).collect(),
        from_runs: from_runs.iter().map(EntityId::to_hex).collect(),
    };
    let bytes = serde_json::to_vec(&body)
        .map_err(|_| Error::InvariantViolation("site skill fingerprint encode failed"))?;
    Ok(digest(&[
        &SITE_SKILL_DISTILL_VERSION.to_be_bytes(),
        site.as_bytes(),
        &bytes,
    ]))
}

/// BLAKE3 over `parts` in [`SITE_SKILL_DISTILL_DOMAIN`], each part
/// length-delimited.
fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SITE_SKILL_DISTILL_DOMAIN);
    for part in parts {
        let len = u64::try_from(part.len()).unwrap_or(u64::MAX);
        hasher.update(&len.to_be_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// The wire shape of `site.json`: exactly origins, routes, programs and
/// traps, in that order. Never executable steps.
#[derive(Serialize)]
struct SiteJson<'a> {
    origins: &'a [String],
    routes: &'a [String],
    programs: Vec<ProgramEntry>,
    traps: &'a [TrapCount],
}

/// One program as `site.json` names it: the workflow id, the current
/// record counters, and the held-out bit. No args, bodies or prose.
#[derive(Serialize)]
struct ProgramEntry {
    workflow: String,
    runs: u64,
    failures: u64,
    held_out: bool,
}

/// Renders `site.json`: the exact contract shape, deterministic.
fn render_site_json(
    origins: &[String],
    routes: &[String],
    programs: &[NamedProgram],
    traps: &[TrapCount],
) -> Result<String> {
    let programs = programs
        .iter()
        .map(|program| ProgramEntry {
            workflow: program.workflow.to_hex(),
            runs: program.runs,
            failures: program.failures,
            held_out: program.held_out,
        })
        .collect();
    let mut text = serde_json::to_string_pretty(&SiteJson {
        origins,
        routes,
        programs,
        traps,
    })
    .map_err(|_| Error::InvariantViolation("site skill site.json encode failed"))?;
    text.push('\n');
    Ok(text)
}

/// Renders `SKILL.md`: folder-valid frontmatter (`name`, `description`,
/// `version`, `role: knowledge`) and deterministic library-first guidance
/// with the programs and traps. No second copy of any program's steps.
fn render_skill_md(
    skill_id: &str,
    site: &str,
    origins: &[String],
    routes: &[String],
    programs: &[NamedProgram],
    traps: &[TrapCount],
) -> String {
    let mut md = String::new();
    md.push_str("---\n");
    md.push_str(&format!("name: {skill_id}\n"));
    md.push_str(&format!(
        "description: {}\n",
        quoted(&description_for_site(site))
    ));
    md.push_str(&format!("version: {SITE_SKILL_VERSION}\n"));
    md.push_str("role: knowledge\n");
    md.push_str("---\n");
    md.push_str(&format!("# {skill_id}\n\n"));
    md.push_str("Site know-how distilled from solved browser runs. This skill holds\n");
    md.push_str("knowledge only: it names library programs by workflow id and never\n");
    md.push_str("repeats their steps.\n\n");
    md.push_str("## Scope\n\n");
    md.push_str(&format!("Site: {}\n", display_site(site)));
    md.push_str("Origins:\n");
    for origin in origins {
        md.push_str(&format!("- {origin}\n"));
    }
    if routes.is_empty() {
        md.push_str("Routes: the whole site\n");
    } else {
        md.push_str("Routes:\n");
        for route in routes {
            md.push_str(&format!("- {route}\n"));
        }
    }
    md.push('\n');
    md.push_str("## Library first\n\n");
    md.push_str("Run the named programs through the library; do not re-derive their\n");
    md.push_str("steps here. When none fits, solve the page and file a new program\n");
    md.push_str("through the library's own doors.\n\n");
    md.push_str("## Programs\n\n");
    if programs.is_empty() {
        md.push_str("No live programs name this site yet.\n");
    } else {
        md.push_str("| workflow | runs | failures | held out |\n");
        md.push_str("| --- | ---: | ---: | --- |\n");
        for program in programs {
            let held = if program.held_out { "yes" } else { "no" };
            md.push_str(&format!(
                "| {} | {} | {} | {held} |\n",
                program.workflow.to_hex(),
                program.runs,
                program.failures
            ));
        }
    }
    md.push('\n');
    md.push_str("## Traps\n\n");
    if traps.is_empty() {
        md.push_str("No traps recorded yet.\n");
    } else {
        md.push_str("| kind | count |\n");
        md.push_str("| --- | ---: |\n");
        for trap in traps {
            md.push_str(&format!("| {} | {} |\n", trap.kind, trap.count));
        }
    }
    md
}

/// The site as the SKILL.md body shows it: control characters folded away
/// so one hostile capture cannot inject lines past the scan's shape.
fn display_site(site: &str) -> String {
    site.chars()
        .map(|c| if c.is_control() { '-' } else { c })
        .collect()
}

/// Frontmatter quoting for one scalar: JSON string syntax, which the
/// folder's scalar reader takes.
fn quoted(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"site skill\"".to_owned())
}
