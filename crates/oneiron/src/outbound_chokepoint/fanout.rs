//! Pre-execution fan-out admission.
//!
//! One reusable primitive answers a single question before any peer call or
//! per-peer TASK exists: may this fan-out start, and if it may not, what does a
//! human see? The approval mode decides it at any width; width alone never
//! does (OF-393). It runs entirely ahead of the parent module's decide →
//! durable-pending → transport order, so a paused plan has created no effect to
//! undo and no row to reconcile.
//!
//! The order inside is fixed:
//!
//! 1. Meter every plan. A deterministic total plus a per-peer breakdown is
//!    always on and free, including plans that stay silent.
//! 2. Detect pathology — a directed cycle in the planned graph, or a projected
//!    per-peer rate that crosses a supplied spike threshold. Pathology pauses
//!    for judgment BEFORE any threshold or ladder logic; it never kills a run
//!    and never drops one silently.
//! 3. The r5v2 approval mode gates every plan, whatever its width: `manual`
//!    pauses for the person; `auto` asks the injected classifier, and an
//!    absent, failing or uncertain classifier pauses for the escalated role
//!    (never a silent allow, never a silent kill); `full-access` just goes.
//! 4. The threshold only marks the exceptional-width check, a check never a
//!    limit. Above it the check rides the plan's pause row when the mode
//!    holds the plan, is cleared by the classifier's allow under `auto`, and
//!    under `full-access` is a non-blocking question row. There is no depth
//!    limit, no total ceiling, no per-peer default budget, and no silent
//!    cancellation path anywhere in this module.
//!
//! A human approval resumes the exact frozen plan digest and is always
//! receipted; an answer to a width question is receipted the same way and
//! releases nothing, because nothing was held. Rendering and persisting the
//! surfaced rows belong to the caller; this module requires a
//! [`FanoutSurfaceSink`] and counts a pause or a question as surfaced only
//! once the sink hands back a durable ref.
//!
//! All absolute times here are milliseconds (`now_ms`, `created_at_ms`); only
//! explicit durations such as [`PeerRateSnapshot::window_secs`] are seconds.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::genui::{GrantMintIntent, GrantMintIntentScope};
use crate::receipt::{ReceiptKind, ReceiptRecord};

/// Domain separator for the frozen plan digest. The preimage is built by hand
/// below rather than taken from serde output, so a serialization change can
/// never move an already-approved digest.
const FANOUT_PLAN_DIGEST_DOMAIN: &[u8] = b"oneiron.fanout.plan.v1\0";

/// Surface component a fan-out pause is rendered as.
const FANOUT_SURFACE_COMPONENT: &str = "fanout_approve";

/// Prefix of the stable pause-row ref.
const FANOUT_ROW_PREFIX: &str = "fanout_row";

/// Surface component an exceptional-width question is rendered as.
const FANOUT_CHECK_COMPONENT: &str = "fanout_check";

/// Prefix of the stable width-question row ref.
const FANOUT_CHECK_ROW_PREFIX: &str = "fanout_check_row";

/// Verb class a remembered fan-out approval is persisted under. It reuses the
/// existing standing-grant vocabulary; this module mints no policy-row schema
/// of its own.
const FANOUT_VERB_CLASS: &str = "consult";

/// Empty neighbour list for peers that send to nobody.
const NO_PEERS: &[&str] = &[];

/// The r5v2 approval ladder, spelled with the existing wire tokens (`auto`,
/// `full-access`, `manual`) but kept as a fan-out-specific enum so a ladder
/// move on one axis cannot silently move the other.
///
/// `Default` is derived rather than hand-written only because a hand-written
/// impl is a denied clippy lint here; the default is `auto` either way.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FanoutApprovalMode {
    #[default]
    Auto,
    FullAccess,
    Manual,
}

impl FanoutApprovalMode {
    /// The canonical wire token. It is also the token hashed into the plan
    /// digest, so the mode cannot change under an approval.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::FullAccess => "full-access",
            Self::Manual => "manual",
        }
    }
}

/// One directed consult edge with the count it plans to spend.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct FanoutPlanEdge {
    pub(crate) from_peer_ref: String,
    pub(crate) to_peer_ref: String,
    pub(crate) count: u32,
}

/// A fully resolved plan graph, handed over before any peer call or per-peer
/// TASK is created. Edges are explicit and directed; nothing here is inferred.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct FanoutPlan {
    pub(crate) plan_ref: String,
    pub(crate) brief_ref: String,
    pub(crate) actor_ref: String,
    pub(crate) mode: FanoutApprovalMode,
    pub(crate) edges: Vec<FanoutPlanEdge>,
}

/// Metering output: the deterministic total, the per-peer breakdown keyed by
/// the peer that RECEIVES the consults (so `total_count` is exactly the sum of
/// `per_peer`), and the frozen digest of the plan that produced them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct FanoutEstimate {
    pub(crate) total_count: u32,
    pub(crate) per_peer: BTreeMap<String, u32>,
    pub(crate) plan_digest: [u8; 32],
}

/// Rate evidence for one peer, supplied from existing receipts or link
/// handshake telemetry. Absence of a snapshot is absence of evidence, never an
/// implicit per-peer cap.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct PeerRateSnapshot {
    pub(crate) peer_ref: String,
    pub(crate) window_secs: u64,
    pub(crate) observed_count: u32,
    pub(crate) spike_at: u32,
}

/// The closed, surfaced pathology vocabulary. Every arm pauses for judgment
/// and carries the evidence a human needs to rule on it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum FanoutPathology {
    ConsultCycle {
        peer_path: Vec<String>,
    },
    PerPeerRateSpike {
        peer_ref: String,
        projected_count: u32,
        spike_at: u32,
        window_secs: u64,
    },
}

impl FanoutPathology {
    /// The stable receipt/wire spelling of this arm, matching the serde tag.
    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::ConsultCycle { .. } => "consult_cycle",
            Self::PerPeerRateSpike { .. } => "per_peer_rate_spike",
        }
    }
}

/// What an injected classifier may answer for an `auto`-mode plan above the
/// threshold. There is no third answer: a classifier cannot cancel a fan-out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FanoutAutoDisposition {
    Allow,
    SurfaceHuman,
}

/// The injected `auto`-rung classifier. Admission does not care where the
/// verdict comes from, and treats every failure as [`SurfaceHuman`].
///
/// [`SurfaceHuman`]: FanoutAutoDisposition::SurfaceHuman
pub(crate) trait FanoutAutoDecider {
    /// Rules on one metered plan.
    ///
    /// # Errors
    ///
    /// Any error — including "no model available" — escalates to a human.
    fn decide(&self, plan: &FanoutPlan, estimate: &FanoutEstimate)
    -> Result<FanoutAutoDisposition>;
}

/// The receiptable choices a surfaced fan-out row offers. A pause row offers
/// the first three; a width-question row offers only `Ack` and
/// `AckAndRemember`, because there is nothing to keep paused or release.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FanoutApprovalChoice {
    ApproveOnce,
    ApproveAndRememberBriefVerb,
    KeepPaused,
    Ack,
    AckAndRemember,
}

impl FanoutApprovalChoice {
    /// The stable per-choice action id carried on the surfaced row.
    pub(crate) const fn action_id(&self) -> &'static str {
        match self {
            Self::ApproveOnce => "fanout_approve_once",
            Self::ApproveAndRememberBriefVerb => "fanout_approve_and_remember_brief_verb",
            Self::KeepPaused => "fanout_keep_paused",
            Self::Ack => "fanout_check_ack",
            Self::AckAndRemember => "fanout_check_ack_and_remember",
        }
    }

    /// The receipt outcome this choice is recorded under.
    pub(crate) const fn outcome(&self) -> &'static str {
        match self {
            Self::ApproveOnce => "approved_once",
            Self::ApproveAndRememberBriefVerb => "grant_mint_intent",
            Self::KeepPaused => "kept_paused",
            Self::Ack => "acknowledged",
            Self::AckAndRemember => "acknowledged_and_remembered",
        }
    }
}

/// One offered choice, bound to the action id the surface will echo back.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct FanoutApprovalAction {
    pub(crate) choice: FanoutApprovalChoice,
    pub(crate) action_id: String,
}

/// The serializable pause row. It freezes identity (`row_ref`, `component_id`,
/// `plan_digest`) so an approval for one estimate can never release a changed
/// plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct FanoutApprovalRow {
    pub(crate) row_ref: String,
    pub(crate) component_id: String,
    pub(crate) plan_ref: String,
    pub(crate) plan_digest: [u8; 32],
    pub(crate) estimate: FanoutEstimate,
    pub(crate) mode: FanoutApprovalMode,
    /// `Some` when the pause is a pathology; `None` when it is the approval
    /// ladder asking about size alone.
    pub(crate) pathology: Option<FanoutPathology>,
    pub(crate) actions: Vec<FanoutApprovalAction>,
    pub(crate) created_at_ms: u64,
    /// The fan-out statement shown with the row. The caller attaches it; this
    /// module never prices a plan.
    pub(crate) statement: Option<crate::agent_dispatch::FanoutStatement>,
}

/// How the exceptional-width check of a plan that proceeds was classified.
/// No arm holds it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FanoutWidthClass {
    /// `auto`: the classifier allowed the plan.
    AutoClear,
    /// `full-access`: no classifier is asked; the next role is asked on this
    /// non-blocking question row.
    Asked { row: Box<FanoutApprovalRow> },
}

/// The exceptional-width check a proceeding plan above the threshold raises.
/// A check, never a limit: the plan carrying it proceeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FanoutWidthCheck {
    pub(crate) threshold: u32,
    pub(crate) class: FanoutWidthClass,
}

/// Durable home for pause rows and choice receipts. This module owns neither:
/// it requires the sink so a pause cannot succeed without a durable ref.
pub(crate) trait FanoutSurfaceSink {
    /// Persists one pause row and returns its durable ref.
    ///
    /// # Errors
    ///
    /// Any failure to durably surface the pause. Admission propagates it: a
    /// pause that cannot be surfaced never degrades into a proceed.
    fn persist_pause_row(&mut self, row: &FanoutApprovalRow) -> Result<String>;

    /// Persists one choice receipt and returns its durable ref.
    ///
    /// # Errors
    ///
    /// Any failure to durably record the choice. Resume propagates it, so an
    /// unreceipted approval never releases a plan.
    fn persist_choice_receipt(&mut self, receipt: &ReceiptRecord) -> Result<String>;

    /// Records the exceptional-width check of a plan that proceeds and, when
    /// it asks, persists its question row and returns that row's durable ref.
    /// The plan proceeds once this returns: the row asks, it never holds.
    ///
    /// The default is for a sink with one row family: it keeps a question row
    /// beside its pause rows and records nothing else.
    ///
    /// # Errors
    ///
    /// Any failure to durably record the check. Admission propagates it, so
    /// a question that cannot be surfaced is never silently dropped.
    fn persist_width_check(&mut self, check: &FanoutWidthCheck) -> Result<Option<String>> {
        match &check.class {
            FanoutWidthClass::Asked { row } => self.persist_pause_row(row).map(Some),
            FanoutWidthClass::AutoClear => Ok(None),
        }
    }
}

/// The admission answer. Both arms carry the metering, because metering is
/// free and unconditional. A plan above the threshold that proceeds has
/// handed its width check to the sink first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FanoutAdmission {
    Proceed {
        estimate: FanoutEstimate,
    },
    Paused {
        estimate: FanoutEstimate,
        row: Box<FanoutApprovalRow>,
        surface_ref: String,
    },
}

/// What a human approval releases: the frozen digest it released, the receipt
/// the choice was recorded under, and — for a remembered approval — the grant
/// intent the caller may persist as a standing outbound grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FanoutResume {
    pub(crate) plan_digest: [u8; 32],
    pub(crate) choice_receipt_ref: String,
    pub(crate) grant_mint_intent: Option<GrantMintIntent>,
}

/// Typed failure surface for resuming a surfaced fan-out pause.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FanoutApprovalError {
    #[error(transparent)]
    Engine(#[from] Error),
    #[error("fanout plan digest changed after approval was surfaced")]
    StalePlanDigest,
}

type FanoutApprovalResult<T> = std::result::Result<T, FanoutApprovalError>;

/// The frozen digest of one plan.
///
/// The preimage is domain-separated and length-prefixed by hand: a big-endian
/// length precedes every variable string, collection lengths are included, and
/// the edge count is fixed-width. Peers are the unique sorted ref set and edges
/// are sorted by `(from_peer_ref, to_peer_ref, count)`, so two shuffled but
/// equivalent edge lists hash identically.
///
/// # Errors
///
/// Blank or non-canonical refs, zero counts, and count overflow — validated
/// before any byte is hashed, so a malformed plan never produces a digest to
/// approve.
pub(crate) fn fanout_plan_digest(plan: &FanoutPlan) -> Result<[u8; 32]> {
    Ok(plan_digest_of(&canonicalize(plan)?))
}

/// Meters one plan without admitting it. Always available and free, including
/// for plans that will proceed silently.
///
/// # Errors
///
/// The same malformed-plan cases as [`fanout_plan_digest`].
pub(crate) fn fanout_estimate(plan: &FanoutPlan) -> Result<FanoutEstimate> {
    Ok(estimate_of(&canonicalize(plan)?))
}

/// Decides whether one fan-out plan may begin executing.
///
/// Metering runs first and always. Pathology is detected before any threshold
/// or ladder logic and pauses on its own. Then the approval mode rules at any
/// width: `manual` pauses, `auto` proceeds only on the classifier's allow and
/// otherwise pauses for the escalated role, and `full-access` proceeds. Size
/// never holds a plan: above the caller-provided manifest `threshold` a
/// proceeding plan hands its exceptional-width check to the sink (cleared by
/// the allow under `auto`, a non-blocking question row under `full-access`),
/// and a paused plan's row carries it. Every paused branch returns before any
/// callback that could create a peer TASK or reach transport.
///
/// # Errors
///
/// Malformed plan data (blank refs, zero counts, overflow), malformed rate
/// telemetry, or a surface sink that cannot durably record a pause or a width
/// check. None of those are ever treated as an approved or silently skipped
/// fan-out.
pub(crate) fn admit_fanout_plan(
    plan: &FanoutPlan,
    threshold: Option<u32>,
    peer_rates: &[PeerRateSnapshot],
    auto: &dyn FanoutAutoDecider,
    surface: &mut dyn FanoutSurfaceSink,
    now_ms: u64,
) -> Result<FanoutAdmission> {
    let canonical = canonicalize(plan)?;
    let estimate = estimate_of(&canonical);

    if let Some(pathology) = detect_pathology(&canonical, peer_rates)? {
        return pause(&canonical, estimate, Some(pathology), surface, now_ms);
    }

    let threshold = threshold.ok_or_else(|| {
        Error::InvalidConfig("fan-out approval threshold policy row missing".into())
    })?;
    // The mode gates the plan at any width. `true`: the classifier allowed it.
    let cleared = match canonical.mode {
        FanoutApprovalMode::Manual => return pause(&canonical, estimate, None, surface, now_ms),
        // A classifier that is missing, unreachable, or wrong is not authority
        // to start a fan-out, and is not authority to cancel one either: both
        // failure and refusal land on the same human surface.
        FanoutApprovalMode::Auto => match auto.decide(plan, &estimate) {
            Ok(FanoutAutoDisposition::Allow) => true,
            Ok(FanoutAutoDisposition::SurfaceHuman) | Err(_) => {
                return pause(&canonical, estimate, None, surface, now_ms);
            }
        },
        FanoutApprovalMode::FullAccess => false,
    };
    if estimate.total_count <= threshold {
        return Ok(FanoutAdmission::Proceed { estimate });
    }
    let class = if cleared {
        FanoutWidthClass::AutoClear
    } else {
        FanoutWidthClass::Asked {
            row: Box::new(surfaced_row(
                &canonical,
                &estimate,
                None,
                RowFamily::WidthCheck,
                now_ms,
            )),
        }
    };
    let check = FanoutWidthCheck { threshold, class };
    if let Some(surface_ref) = surface.persist_width_check(&check)? {
        durable_ref(
            surface_ref,
            "fan-out width check surface returned a blank durable row ref",
        )?;
    }
    Ok(FanoutAdmission::Proceed { estimate })
}

/// The width-question row of a plan that went out with no hold, for a
/// caller that classified the check itself: bound to the plan digest,
/// offering only `Ack` and `AckAndRemember`, and named by the caller's
/// durable `row_ref`, which the caller persists.
///
/// # Errors
///
/// The same malformed-plan cases as [`fanout_plan_digest`], and a blank
/// `row_ref`.
pub(crate) fn fanout_width_check_row(
    plan: &FanoutPlan,
    row_ref: String,
    now_ms: u64,
) -> Result<FanoutApprovalRow> {
    let canonical = canonicalize(plan)?;
    let estimate = estimate_of(&canonical);
    let mut row = surfaced_row(&canonical, &estimate, None, RowFamily::WidthCheck, now_ms);
    row.row_ref = durable_ref(row_ref, "fan-out width check row ref is blank")?;
    Ok(row)
}

/// Records one human answer to a surfaced width-question row.
///
/// The same exact-digest binding as a pause: the digest is recomputed from
/// `current_plan` and compared to the frozen row BEFORE the answer receipt is
/// written. Only `Ack` and `AckAndRemember` answer a check; a hold or a
/// release is refused, because nothing was held. Returns the answer receipt's
/// durable ref; persisting a remembered ruling is the caller's.
///
/// # Errors
///
/// [`FanoutApprovalError::StalePlanDigest`] when the plan changed under the
/// row, and [`FanoutApprovalError::Engine`] for malformed input, an answer
/// that is not an acknowledgement or that the row never offered, or a sink
/// that cannot record it.
pub(crate) fn answer_fanout_width_check(
    current_plan: &FanoutPlan,
    row: &FanoutApprovalRow,
    choice: FanoutApprovalChoice,
    origin_action_id: &str,
    principal_ref: &str,
    surface: &mut dyn FanoutSurfaceSink,
    now_ms: u64,
) -> FanoutApprovalResult<String> {
    let principal_ref = canonical_ref("approval principal_ref", principal_ref)?;
    if !matches!(
        choice,
        FanoutApprovalChoice::Ack | FanoutApprovalChoice::AckAndRemember
    ) {
        return Err(Error::InvalidConfig(
            "a fan-out width check is acknowledged, never held or released".to_owned(),
        )
        .into());
    }
    let canonical = offered_choice(current_plan, row, &choice, origin_action_id)?;
    let receipt = choice_receipt(
        &canonical,
        row,
        &choice,
        origin_action_id,
        &principal_ref,
        now_ms,
    );
    Ok(durable_ref(
        surface.persist_choice_receipt(&receipt)?,
        "fan-out choice receipt sink returned a blank ref",
    )?)
}

/// The canonical plan, once the digest still matches the frozen row and the
/// row offered this exact choice.
fn offered_choice(
    current_plan: &FanoutPlan,
    row: &FanoutApprovalRow,
    choice: &FanoutApprovalChoice,
    origin_action_id: &str,
) -> FanoutApprovalResult<CanonicalPlan> {
    let canonical = canonicalize(current_plan)?;
    if plan_digest_of(&canonical) != row.plan_digest {
        return Err(FanoutApprovalError::StalePlanDigest);
    }
    if !row
        .actions
        .iter()
        .any(|action| action.choice == *choice && action.action_id == origin_action_id)
    {
        return Err(Error::InvalidConfig(
            "fan-out approval action is not one the surfaced row offered".to_owned(),
        )
        .into());
    }
    Ok(canonical)
}

/// Applies one human choice to a surfaced pause.
///
/// This is transaction-authoritative about the plan, not just the row: the
/// digest is recomputed from `current_plan` with the pinned algorithm and
/// compared to the frozen row BEFORE a choice receipt is written or a grant
/// intent is minted. `Ok(None)` means the row stays live (the human kept it
/// paused); `Ok(Some(_))` releases exactly the plan whose digest was frozen.
///
/// # Errors
///
/// [`FanoutApprovalError::StalePlanDigest`] when the plan changed under the
/// approval, and [`FanoutApprovalError::Engine`] for malformed input, an
/// action the row never offered, or a sink that cannot record the choice.
pub(crate) fn approve_and_resume_fanout(
    current_plan: &FanoutPlan,
    row: &FanoutApprovalRow,
    choice: FanoutApprovalChoice,
    origin_action_id: &str,
    principal_ref: &str,
    surface: &mut dyn FanoutSurfaceSink,
    now_ms: u64,
) -> FanoutApprovalResult<Option<FanoutResume>> {
    let principal_ref = canonical_ref("approval principal_ref", principal_ref)?;
    let canonical = offered_choice(current_plan, row, &choice, origin_action_id)?;
    let plan_digest = row.plan_digest;

    let receipt = choice_receipt(
        &canonical,
        row,
        &choice,
        origin_action_id,
        &principal_ref,
        now_ms,
    );
    let choice_receipt_ref = durable_ref(
        surface.persist_choice_receipt(&receipt)?,
        "fan-out choice receipt sink returned a blank ref",
    )?;

    match choice {
        // A pause row never offers a width-check answer, so the offer check
        // above already refused it.
        FanoutApprovalChoice::Ack | FanoutApprovalChoice::AckAndRemember => {
            Err(Error::InvariantViolation("a pause row offers no width-check answer").into())
        }
        // The row stays live. The choice is still receipted: "not yet" is a
        // ruling, and an unrecorded ruling is how a pause becomes a drop.
        FanoutApprovalChoice::KeepPaused => Ok(None),
        FanoutApprovalChoice::ApproveOnce => Ok(Some(FanoutResume {
            plan_digest,
            choice_receipt_ref,
            grant_mint_intent: None,
        })),
        FanoutApprovalChoice::ApproveAndRememberBriefVerb => {
            let grant_mint_intent = GrantMintIntent {
                principal_ref,
                origin_component_id: row.component_id.clone(),
                origin_action_id: origin_action_id.to_owned(),
                origin_receipt_ref: Some(choice_receipt_ref.clone()),
                scope: GrantMintIntentScope::BriefVerbClass {
                    brief_ref: canonical.brief_ref,
                    verb_class: FANOUT_VERB_CLASS.to_owned(),
                },
            };
            Ok(Some(FanoutResume {
                plan_digest,
                choice_receipt_ref,
                grant_mint_intent: Some(grant_mint_intent),
            }))
        }
    }
}

/// One plan validated once and reduced to canonical form: validated refs, the
/// unique sorted peer set, edges sorted by `(from, to, count)`, and the
/// metering that falls out of the same walk.
struct CanonicalPlan {
    plan_ref: String,
    brief_ref: String,
    actor_ref: String,
    mode: FanoutApprovalMode,
    peers: Vec<String>,
    edges: Vec<(String, String, u32)>,
    per_peer: BTreeMap<String, u32>,
    total_count: u32,
}

fn canonicalize(plan: &FanoutPlan) -> Result<CanonicalPlan> {
    let plan_ref = canonical_ref("plan plan_ref", &plan.plan_ref)?;
    let brief_ref = canonical_ref("plan brief_ref", &plan.brief_ref)?;
    let actor_ref = canonical_ref("plan actor_ref", &plan.actor_ref)?;

    let mut peers = BTreeSet::new();
    let mut per_peer: BTreeMap<String, u32> = BTreeMap::new();
    let mut edges = Vec::with_capacity(plan.edges.len());
    let mut total_count: u32 = 0;
    for edge in &plan.edges {
        let from = canonical_ref("plan edge from_peer_ref", &edge.from_peer_ref)?;
        let to = canonical_ref("plan edge to_peer_ref", &edge.to_peer_ref)?;
        if edge.count == 0 {
            return Err(Error::InvalidConfig(
                "fan-out plan edges must carry a nonzero count".to_owned(),
            ));
        }
        total_count = total_count
            .checked_add(edge.count)
            .ok_or(Error::ArithmeticOverflow("fan-out plan total count"))?;
        let inbound = per_peer.entry(to.clone()).or_insert(0);
        *inbound = inbound
            .checked_add(edge.count)
            .ok_or(Error::ArithmeticOverflow("fan-out per-peer count"))?;
        peers.insert(from.clone());
        peers.insert(to.clone());
        edges.push((from, to, edge.count));
    }
    // Tuple order IS the pinned digest order: (from, to, count).
    edges.sort_unstable();

    Ok(CanonicalPlan {
        plan_ref,
        brief_ref,
        actor_ref,
        mode: plan.mode,
        peers: peers.into_iter().collect(),
        edges,
        per_peer,
        total_count,
    })
}

fn plan_digest_of(plan: &CanonicalPlan) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FANOUT_PLAN_DIGEST_DOMAIN);
    for scalar in [
        plan.plan_ref.as_str(),
        plan.brief_ref.as_str(),
        plan.actor_ref.as_str(),
        plan.mode.as_str(),
    ] {
        update_len_prefixed(&mut hasher, scalar.as_bytes());
    }
    hasher.update(&(plan.peers.len() as u64).to_be_bytes());
    for peer in &plan.peers {
        update_len_prefixed(&mut hasher, peer.as_bytes());
    }
    hasher.update(&(plan.edges.len() as u64).to_be_bytes());
    for (from, to, count) in &plan.edges {
        update_len_prefixed(&mut hasher, from.as_bytes());
        update_len_prefixed(&mut hasher, to.as_bytes());
        hasher.update(&count.to_be_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn update_len_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn estimate_of(plan: &CanonicalPlan) -> FanoutEstimate {
    FanoutEstimate {
        total_count: plan.total_count,
        per_peer: plan.per_peer.clone(),
        plan_digest: plan_digest_of(plan),
    }
}

fn detect_pathology(
    plan: &CanonicalPlan,
    peer_rates: &[PeerRateSnapshot],
) -> Result<Option<FanoutPathology>> {
    if let Some(peer_path) = first_consult_cycle(plan) {
        return Ok(Some(FanoutPathology::ConsultCycle { peer_path }));
    }
    first_rate_spike(plan, peer_rates)
}

/// Deterministic DFS over canonical peer refs, returning the concrete cycle
/// path (entry hop … repeated entry hop) of the first cycle found. Roots and
/// neighbours are walked in sorted order, so the answer never depends on input
/// ordering. The walk is iterative: a consult chain has no depth limit.
fn first_consult_cycle(plan: &CanonicalPlan) -> Option<Vec<String>> {
    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (from, to, _) in &plan.edges {
        adjacency
            .entry(from.as_str())
            .or_default()
            .push(to.as_str());
    }
    // Edges arrive canonically sorted, so each neighbour list is already
    // sorted and only adjacent duplicates (same pair, different counts) exist.
    for neighbours in adjacency.values_mut() {
        neighbours.dedup();
    }

    let mut visit: BTreeMap<&str, Visit> = BTreeMap::new();
    for start in &plan.peers {
        if visit.contains_key(start.as_str()) {
            continue;
        }
        let mut path: Vec<&str> = vec![start.as_str()];
        let mut stack: Vec<(&str, usize)> = vec![(start.as_str(), 0)];
        visit.insert(start.as_str(), Visit::Open);
        while let Some(&(node, cursor)) = stack.last() {
            let neighbours = adjacency.get(node).map_or(NO_PEERS, Vec::as_slice);
            let Some(&next) = neighbours.get(cursor) else {
                visit.insert(node, Visit::Done);
                path.pop();
                stack.pop();
                continue;
            };
            if let Some(frame) = stack.last_mut() {
                frame.1 = cursor + 1;
            }
            match visit.get(next) {
                Some(Visit::Open) => {
                    // `Open` means `next` is on the current path by
                    // construction, so the search always finds it; the
                    // fallback keeps the surfaced path a real walk instead of
                    // panicking on a broken invariant.
                    let entry = path.iter().position(|hop| *hop == next).unwrap_or(0);
                    let mut peer_path: Vec<String> =
                        path[entry..].iter().map(|hop| (*hop).to_owned()).collect();
                    peer_path.push(next.to_owned());
                    return Some(peer_path);
                }
                Some(Visit::Done) => {}
                None => {
                    visit.insert(next, Visit::Open);
                    path.push(next);
                    stack.push((next, 0));
                }
            }
        }
    }
    None
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Visit {
    Open,
    Done,
}

/// Compares each peer's projected inbound count against the spike threshold
/// that peer's own supplied snapshot carries. A peer without a snapshot is a
/// peer without rate evidence — it is skipped, never capped.
fn first_rate_spike(
    plan: &CanonicalPlan,
    peer_rates: &[PeerRateSnapshot],
) -> Result<Option<FanoutPathology>> {
    let mut snapshots: BTreeMap<String, &PeerRateSnapshot> = BTreeMap::new();
    for snapshot in peer_rates {
        let peer_ref = canonical_ref("peer rate snapshot peer_ref", &snapshot.peer_ref)?;
        if snapshot.window_secs == 0 || snapshot.spike_at == 0 {
            return Err(Error::InvalidConfig(
                "fan-out peer rate snapshot needs a nonzero window_secs and spike_at".to_owned(),
            ));
        }
        if snapshots.insert(peer_ref, snapshot).is_some() {
            return Err(Error::InvalidConfig(
                "fan-out peer rate snapshots must name each peer at most once".to_owned(),
            ));
        }
    }

    for (peer_ref, planned) in &plan.per_peer {
        let Some(snapshot) = snapshots.get(peer_ref) else {
            continue;
        };
        let projected_count =
            snapshot
                .observed_count
                .checked_add(*planned)
                .ok_or(Error::ArithmeticOverflow(
                    "fan-out projected per-peer count",
                ))?;
        if projected_count >= snapshot.spike_at {
            return Ok(Some(FanoutPathology::PerPeerRateSpike {
                peer_ref: peer_ref.clone(),
                projected_count,
                spike_at: snapshot.spike_at,
                window_secs: snapshot.window_secs,
            }));
        }
    }
    Ok(None)
}

/// Which surfaced row a plan gets: a pause, or a width question.
#[derive(Clone, Copy)]
enum RowFamily {
    Pause,
    WidthCheck,
}

/// One surfaced row, bound to the plan digest. Both families share identity
/// and binding; they differ in component, ref prefix and offered actions.
fn surfaced_row(
    plan: &CanonicalPlan,
    estimate: &FanoutEstimate,
    pathology: Option<FanoutPathology>,
    family: RowFamily,
    now_ms: u64,
) -> FanoutApprovalRow {
    let digest_hex = bytes_to_hex_lower(&estimate.plan_digest);
    let (component, prefix, choices): (&str, &str, &[FanoutApprovalChoice]) = match family {
        RowFamily::Pause => (
            FANOUT_SURFACE_COMPONENT,
            FANOUT_ROW_PREFIX,
            &[
                FanoutApprovalChoice::ApproveOnce,
                FanoutApprovalChoice::ApproveAndRememberBriefVerb,
                FanoutApprovalChoice::KeepPaused,
            ],
        ),
        RowFamily::WidthCheck => (
            FANOUT_CHECK_COMPONENT,
            FANOUT_CHECK_ROW_PREFIX,
            &[
                FanoutApprovalChoice::Ack,
                FanoutApprovalChoice::AckAndRemember,
            ],
        ),
    };
    FanoutApprovalRow {
        row_ref: format!("{prefix}:{digest_hex}"),
        component_id: format!("{component}:{digest_hex}"),
        plan_ref: plan.plan_ref.clone(),
        plan_digest: estimate.plan_digest,
        estimate: estimate.clone(),
        mode: plan.mode,
        pathology,
        actions: choices
            .iter()
            .cloned()
            .map(|choice| FanoutApprovalAction {
                action_id: choice.action_id().to_owned(),
                choice,
            })
            .collect(),
        created_at_ms: now_ms,
        statement: None,
    }
}

fn pause(
    plan: &CanonicalPlan,
    estimate: FanoutEstimate,
    pathology: Option<FanoutPathology>,
    surface: &mut dyn FanoutSurfaceSink,
    now_ms: u64,
) -> Result<FanoutAdmission> {
    let row = surfaced_row(plan, &estimate, pathology, RowFamily::Pause, now_ms);
    let surface_ref = durable_ref(
        surface.persist_pause_row(&row)?,
        "fan-out pause surface returned a blank durable row ref",
    )?;
    Ok(FanoutAdmission::Paused {
        estimate,
        row: Box::new(row),
        surface_ref,
    })
}

fn choice_receipt(
    plan: &CanonicalPlan,
    row: &FanoutApprovalRow,
    choice: &FanoutApprovalChoice,
    action_id: &str,
    principal_ref: &str,
    now_ms: u64,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert("component_id".to_owned(), row.component_id.clone());
    fields.insert("row_ref".to_owned(), row.row_ref.clone());
    fields.insert("action_id".to_owned(), action_id.to_owned());
    fields.insert("plan_ref".to_owned(), plan.plan_ref.clone());
    fields.insert("brief_ref".to_owned(), plan.brief_ref.clone());
    fields.insert("actor_ref".to_owned(), plan.actor_ref.clone());
    fields.insert(
        "plan_digest".to_owned(),
        bytes_to_hex_lower(&row.plan_digest),
    );
    fields.insert("total_count".to_owned(), plan.total_count.to_string());
    fields.insert("mode".to_owned(), plan.mode.as_str().to_owned());
    // Milliseconds, like every other absolute time this primitive carries.
    fields.insert("decided_at_ms".to_owned(), now_ms.to_string());
    fields.insert("surfaced_at_ms".to_owned(), row.created_at_ms.to_string());

    let mut policy_trace = vec![format!("fanout_mode:{}", plan.mode.as_str())];
    if matches!(
        choice,
        FanoutApprovalChoice::Ack | FanoutApprovalChoice::AckAndRemember
    ) {
        policy_trace.push("fanout_width_check".to_owned());
    }
    if let Some(pathology) = row.pathology.as_ref() {
        fields.insert("pathology".to_owned(), pathology.kind().to_owned());
        policy_trace.push(format!("fanout_pathology:{}", pathology.kind()));
    }

    ReceiptRecord {
        receipt_id: format!("fanout:{}:{}:{now_ms}", row.row_ref, action_id),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: now_ms,
        actor: Some(principal_ref.to_owned()),
        on_behalf_of: None,
        outcome: choice.outcome().to_owned(),
        job_ref: None,
        trigger_ref: Some(row.component_id.clone()),
        policy_trace,
        fields,
    }
}

fn canonical_ref(field: &'static str, value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "fan-out {field} must not be blank"
        )));
    }
    if value != trimmed {
        return Err(Error::InvalidConfig(format!(
            "fan-out {field} must be canonical (no surrounding whitespace)"
        )));
    }
    Ok(value.to_owned())
}

fn durable_ref(value: String, blank: &'static str) -> Result<String> {
    if value.trim().is_empty() {
        return Err(Error::InvariantViolation(blank));
    }
    Ok(value)
}

#[cfg(test)]
mod tests;

mod history;
pub(crate) use history::{FanoutHistory, admit_fanout_with_history, fanout_history_pathology};
