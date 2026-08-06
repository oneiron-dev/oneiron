//! ED-07 (ONE-1763, ARCH-0056 §8): the routing loop — what a judged amendment
//! says about the MODEL GENERATION that drafted the proposal.
//!
//! ED-03 ([`crate::edit_distance::attribution`]) answers *who owns this
//! amendment*. This module asks a different question of the same receipts: how
//! much editing does a given model generation cost the decider, in a given kind
//! of work. The aggregate is keyed `(model_version, task_class)` and folds
//! exactly two facts per judged amendment — the edit mass, and whether the
//! proposal was SOUND. That pair is the entire state behind every number here.
//!
//! # Relative, never absolute
//!
//! A raw mean edit cost is not a fact about a model, it is a fact about the
//! work: prose gets edited more than a calendar entry, and a generation that
//! only ever drafts prose would look terrible beside one that only ever drafts
//! calendar entries. Every exported score is therefore PGR-style RELATIVE —
//! this generation's mean against the mean of ALL generations' runs in the SAME
//! task class. `1.0` is par. A generation with no peers scores exactly par,
//! which is the honest answer to "compared to what".
//!
//! # A swap is a new generation, not a new datapoint
//!
//! [`RoutingScopeKey::model_version`] is a `ModelStack` identity, resolved from
//! a [`ModelId`] HERE (`settings::model_versioning` stays read-only prior art).
//! Swapping the serving model therefore starts a FRESH aggregate: the old row
//! is retained as history and never merged into the new one. Blending two
//! generations' edit mass would produce a number that describes neither, and it
//! would do so silently — the failure this keying exists to make impossible.
//!
//! Which generation a run belongs to is not re-derivable after the fact, so it
//! is recorded: [`record_judged_amendment`] writes a membership row binding the
//! receipt to the version that was serving. That ledger is what makes
//! [`rebuild_routing_projection`] an identity rather than a re-attribution.
//!
//! # The rollout ladder
//!
//! Per task class, owner-promoted, never automatic:
//!
//! | rung | computes | visible | feeds routing |
//! |---|---|---|---|
//! | [`RolloutRung::Shadow`] (default) | yes | no | no |
//! | [`RolloutRung::DataBar`] | yes | [`routing_data_bar`] | no |
//! | [`RolloutRung::Graduated`] | yes | yes | [`routing_weight_hint`] |
//!
//! Shadow is the default and it is not a formality: a scope nobody promoted
//! has its numbers computed and persisted and reaching nothing, so the ladder
//! can be climbed on evidence that already exists.
//!
//! # The Goodhart guard is the type, not a warning
//!
//! [`routing_weight_hint`] returns [`WeightHint`], which carries the relative
//! edit cost and the paired OUTCOME score together, and there is no accessor
//! that yields one without the other. The reason is that they come apart in
//! exactly the way that matters: a big Δ from pure preference is a sound
//! proposal that cost a lot to land, and a tiny Δ correcting a real defect is
//! an unsound one that cost almost nothing. Optimizing the cost alone would
//! select for proposals that are cheap to accept rather than right — so the
//! cost is never readable alone.
//!
//! For the same reason there is no `is_banned`, no exclusion list, and no door
//! that removes a model from consideration. The hint informs a WEIGHT. A
//! generation that should not be served is a settings decision, made by the
//! owner, somewhere else.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::edit_distance::attribution::{AmendmentClass, AmendmentJudgment, amendment_judgments};
use crate::error::{Error, Result};
use crate::llm::{LlmRole, ModelId};
use crate::settings::{ModelStack, ModelStackRegistry, default_model_stack_registry};

// ---------------------------------------------------------------------------
// Keyspace + pinned strings
// ---------------------------------------------------------------------------

/// `vault_meta` prefix of the per-scope aggregates. The full key is this
/// prefix ‖ task class ‖ `0x00` ‖ model version — task class FIRST, because
/// the peer distribution behind every relative score is exactly one
/// task-class-prefixed scan.
const AGGREGATE_KEY_PREFIX: &[u8] = b"edit_distance/routing_aggregate/v1\0";

/// `vault_meta` prefix of the run→generation binding, keyed by receipt id.
const MEMBER_KEY_PREFIX: &[u8] = b"edit_distance/routing_member/v1\0";

/// `vault_meta` prefix of the per-task-class rollout rung.
const RUNG_KEY_PREFIX: &[u8] = b"edit_distance/routing_rung/v1\0";

/// `vault_meta` key holding the model version new folds are stamped with —
/// the house pattern of a per-feature key const over `vault_meta`
/// (`inbox::INBOX_REVIEW_DIAL_KEY`), because `settings.rs` is UI customization
/// and this is not.
const SERVING_MODEL_KEY: &[u8] = b"edit_distance/routing_serving_model/v1";

/// Only accepted schema version for any row this module stores.
const ROW_VERSION: u8 = 1;

const AGGREGATE_ROW_LABEL: &str = "routing aggregate row";
const MEMBER_ROW_LABEL: &str = "routing membership row";
const RUNG_ROW_LABEL: &str = "routing rollout rung row";
const SERVING_MODEL_ROW_LABEL: &str = "routing serving model row";

/// Separator between a key's task class and its model version. Neither half
/// may contain it, which the key builder enforces rather than assumes.
const KEY_SEPARATOR: u8 = 0;

/// Longest accepted task class — the ED lane's scope bound, shared with
/// `edit_distance::attribution` so one scope string means one thing lane-wide.
const MAX_TASK_CLASS_LEN: usize = crate::consent::MAX_CONSENT_REF_LEN;

/// The role whose model drafts the proposals this projection measures, and so
/// the role whose default names the generation serving an unconfigured vault.
const DRAFTING_ROLE: LlmRole = LlmRole::Orchestrator;

/// The compiled stack table, read-only prior art consulted on every version
/// resolution.
static MODEL_STACK_REGISTRY: LazyLock<ModelStackRegistry> =
    LazyLock::new(default_model_stack_registry);

const fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The axis one aggregate is keyed on: a model generation, and a kind of work.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoutingScopeKey {
    /// `ModelStack` identity of the generation that drafted the proposals —
    /// see [`RoutingScopeKey::for_model`] for how a [`ModelId`] becomes one.
    pub model_version: String,
    /// The amendment scope the judgments were recorded in, which is the same
    /// string ED-03 keys its cost rows on.
    pub task_class: String,
}

impl RoutingScopeKey {
    /// The scope for an already-resolved version token.
    #[must_use]
    pub fn new(model_version: impl Into<String>, task_class: impl Into<String>) -> Self {
        Self {
            model_version: model_version.into(),
            task_class: task_class.into(),
        }
    }

    /// The scope a given model would be read under.
    ///
    /// This is the one direction the consumer needs: a router holds a
    /// [`ModelId`] and wants what is known about it. The token is
    /// `stack:<id>` when a registered stack claims the model, and
    /// `model:<id>` when none does — two namespaces that cannot collide, so
    /// an unregistered model gets its own aggregate rather than quietly
    /// sharing one.
    #[must_use]
    pub fn for_model(model: &ModelId, task_class: impl Into<String>) -> Self {
        Self::new(model_version_token(model), task_class)
    }
}

/// How far a task class has climbed the rollout ladder.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RolloutRung {
    /// Compute and persist; reach nothing. The default for every scope.
    #[default]
    Shadow,
    /// Informational: visible on [`routing_data_bar`], still feeding nothing.
    DataBar,
    /// [`routing_weight_hint`] answers for this task class.
    Graduated,
}

impl RolloutRung {
    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::DataBar => "data_bar",
            Self::Graduated => "graduated",
        }
    }

    /// Parses a pinned on-disk token.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "shadow" => Some(Self::Shadow),
            "data_bar" => Some(Self::DataBar),
            "graduated" => Some(Self::Graduated),
            _ => None,
        }
    }
}

/// What routing is told about a scope — cost and outcome, inseparably.
///
/// Both fields are populated from the same aggregate in the same read, and no
/// door on this module hands out one alone. See the module header for why that
/// is a type and not a comment.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WeightHint {
    /// This generation's mean edit mass over the mean of every generation's
    /// runs in the same task class. `1.0` is par; below par is cheaper to
    /// land than peers, above par is dearer.
    pub relative_edit_cost: f32,
    /// The share of this scope's amendments whose proposal was SOUND —
    /// amended for an external change or the decider's taste rather than
    /// because it was wrong. `1.0` means nothing this generation proposed was
    /// ever judged a defect.
    pub outcome_score: f32,
}

/// One row of the informational read surface.
#[derive(Debug, Clone, PartialEq)]
pub struct RoutingScopeStats {
    pub key: RoutingScopeKey,
    pub rung: RolloutRung,
    /// Judged amendments folded into this scope.
    pub runs: u64,
    /// The same pair [`routing_weight_hint`] would return, shown here whether
    /// or not the scope has graduated.
    pub hint: WeightHint,
}

// ---------------------------------------------------------------------------
// Stored rows
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
struct StoredAggregate {
    v: u8,
    /// Judged amendments folded in.
    runs: u64,
    /// Total edit mass, in `f64` because a sum of thousands of `f32` masses is
    /// not the number any of them were.
    d_norm_sum: f64,
    /// How many of `runs` were judged sound.
    sound: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredModelVersion {
    v: u8,
    model_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredRung {
    v: u8,
    rung: String,
}

// ---------------------------------------------------------------------------
// Model version resolution
// ---------------------------------------------------------------------------

/// The generation token for `model` — see [`RoutingScopeKey::for_model`].
///
/// A model claimed by the current default stack takes that stack's identity
/// even if an older generation also lists it, so the common case needs no
/// tie-break at all. Otherwise the newest generation claiming it wins.
fn model_version_token(model: &ModelId) -> String {
    let registry = &*MODEL_STACK_REGISTRY;
    let current = registry.current_default();
    if stack_claims(current, model) {
        return format!("stack:{}", current.id);
    }
    registry
        .stacks
        .values()
        .filter(|stack| stack_claims(stack, model))
        .max_by_key(|stack| stack.generation)
        .map_or_else(
            || format!("model:{}", model.as_str()),
            |stack| format!("stack:{}", stack.id),
        )
}

fn stack_claims(stack: &ModelStack, model: &ModelId) -> bool {
    stack
        .models
        .iter()
        .any(|entry| entry.model.as_str() == model.as_str())
}

/// The generation [`record_judged_amendment`] stamps new folds with.
///
/// Unset resolves to the drafting role's compiled default, which is what the
/// consumer side would build a key from — so an unconfigured vault records and
/// reads under the same token instead of silently missing itself.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn serving_model_version(vault: &Vault) -> Result<String> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, SERVING_MODEL_KEY)? else {
        return Ok(model_version_token(&DRAFTING_ROLE.default_model_id()));
    };
    let row: StoredModelVersion = decode_row(&raw, SERVING_MODEL_ROW_LABEL)?;
    if row.v != ROW_VERSION {
        return Err(Error::CorruptedIndex(SERVING_MODEL_ROW_LABEL));
    }
    Ok(row.model_version)
}

/// Declares which model is serving, and so which generation later folds belong
/// to.
///
/// Already-folded runs are untouched by design: they happened under the
/// generation that was serving when they happened, and a swap is not new
/// information about them.
///
/// # Errors
///
/// Storage errors.
pub fn set_serving_model(vault: &Vault, model: &ModelId) -> Result<()> {
    let encoded = encode_row(
        &StoredModelVersion {
            v: ROW_VERSION,
            model_version: model_version_token(model),
        },
        SERVING_MODEL_ROW_LABEL,
    )?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, SERVING_MODEL_KEY, &encoded)?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// The rollout ladder
// ---------------------------------------------------------------------------

/// How far `task_class` has been promoted. [`RolloutRung::Shadow`] until an
/// owner says otherwise.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] on an unusable task class; storage errors;
/// [`Error::CorruptedIndex`] on an undecodable row.
pub fn rollout_rung(vault: &Vault, task_class: &str) -> Result<RolloutRung> {
    let key = meta_key(RUNG_KEY_PREFIX, normalized_task_class(task_class)?.as_bytes());
    let rtxn = vault.store.env.read_txn()?;
    rung_in_txn(vault, &rtxn, &key)
}

/// Promotes or demotes `task_class` on the rollout ladder.
///
/// The ladder moves ONLY through this door — nothing in this module promotes a
/// scope because its numbers looked convincing.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] on an unusable task class; storage errors.
pub fn set_rollout_rung(vault: &Vault, task_class: &str, rung: RolloutRung) -> Result<()> {
    let key = meta_key(RUNG_KEY_PREFIX, normalized_task_class(task_class)?.as_bytes());
    let encoded = encode_row(
        &StoredRung {
            v: ROW_VERSION,
            rung: rung.as_str().to_owned(),
        },
        RUNG_ROW_LABEL,
    )?;
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok(())
    })
}

fn rung_in_txn(vault: &Vault, rtxn: &heed::RoTxn<'_>, key: &[u8]) -> Result<RolloutRung> {
    let Some(raw) = vault.store.vault_meta.get(rtxn, key)? else {
        return Ok(RolloutRung::Shadow);
    };
    let row: StoredRung = decode_row(&raw, RUNG_ROW_LABEL)?;
    if row.v != ROW_VERSION {
        return Err(Error::CorruptedIndex(RUNG_ROW_LABEL));
    }
    RolloutRung::parse(&row.rung).ok_or(Error::CorruptedIndex(RUNG_ROW_LABEL))
}

// ---------------------------------------------------------------------------
// The write door
// ---------------------------------------------------------------------------

/// Folds the amendment judged against `delta_receipt` into its scope.
///
/// **Receipt-bound.** The one argument is the receipt; the scope, the edit mass
/// and the outcome are all read back out of ED-03's judgment for it. There is
/// no path here for a caller to supply the numbers it would like folded, and
/// the ledger stays rebuildable from receipts alone (CID-7).
///
/// **First fold wins.** A run happened under exactly one generation, so a
/// receipt already bound to one is never re-folded — a second call after a
/// model swap would otherwise count the same amendment twice, once against a
/// generation that did not produce it. Re-judging a receipt is reflected by
/// [`rebuild_routing_projection`], which re-reads the ledger against the
/// bindings already recorded.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the receipt carries no judgment, or its
/// judgment's scope or edit mass is unusable; storage errors.
pub fn record_judged_amendment(vault: &Vault, delta_receipt: &str) -> Result<()> {
    let Some(judgment) = judgment_for(vault, delta_receipt)? else {
        return Err(invalid("routing projection cites an unjudged receipt"));
    };
    let member_key = meta_key(MEMBER_KEY_PREFIX, delta_receipt.as_bytes());
    {
        let rtxn = vault.store.env.read_txn()?;
        if vault.store.vault_meta.get(&rtxn, &member_key)?.is_some() {
            return Ok(());
        }
    }

    let model_version = serving_model_version(vault)?;
    let fold = fold_of(&judgment)?;
    let scope = RoutingScopeKey::new(model_version.clone(), judgment.scope);
    let scope_row_key = aggregate_key(&scope)?;
    let member = encode_row(
        &StoredModelVersion {
            v: ROW_VERSION,
            model_version,
        },
        MEMBER_ROW_LABEL,
    )?;

    vault.with_write_txn(|wtxn| {
        let mut aggregate = match vault.store.vault_meta.get(&*wtxn, &scope_row_key)? {
            Some(raw) => decoded_aggregate(&raw)?,
            None => StoredAggregate::default(),
        };
        apply_fold(&mut aggregate, fold)?;
        let encoded = encode_row(&aggregate, AGGREGATE_ROW_LABEL)?;
        vault.store.vault_meta.put(wtxn, &scope_row_key, &encoded)?;
        vault.store.vault_meta.put(wtxn, &member_key, &member)?;
        Ok(())
    })
}

/// One judgment's contribution: its edit mass, and whether it was sound.
#[derive(Debug, Clone, Copy)]
struct Fold {
    d_norm: f64,
    sound: bool,
}

/// What one judgment contributes.
///
/// A proposal is SOUND when the amendment says nothing was wrong with it — the
/// world moved ([`AmendmentClass::Environment`]) or the decider wanted it
/// otherwise ([`AmendmentClass::PreferenceShift`]). Every other class routes
/// from "the proposal was wrong on its own terms", including
/// [`AmendmentClass::Discovery`], which charges nobody but does not mean the
/// draft stood.
fn fold_of(judgment: &AmendmentJudgment) -> Result<Fold> {
    let d_norm = f64::from(judgment.d_norm);
    if !d_norm.is_finite() || d_norm < 0.0 {
        return Err(invalid("a routing fold needs a finite non-negative edit mass"));
    }
    Ok(Fold {
        d_norm,
        sound: matches!(
            judgment.class,
            AmendmentClass::Environment | AmendmentClass::PreferenceShift
        ),
    })
}

fn apply_fold(aggregate: &mut StoredAggregate, fold: Fold) -> Result<()> {
    aggregate.v = ROW_VERSION;
    aggregate.runs = aggregate
        .runs
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("routing aggregate runs"))?;
    aggregate.d_norm_sum += fold.d_norm;
    // `sound` counts a subset of `runs`, so the bound above is its bound too.
    aggregate.sound += u64::from(fold.sound);
    Ok(())
}

fn judgment_for(vault: &Vault, receipt_id: &str) -> Result<Option<AmendmentJudgment>> {
    Ok(amendment_judgments(vault)?
        .into_iter()
        .find(|judgment| judgment.receipt_id == receipt_id))
}

// ---------------------------------------------------------------------------
// The read doors
// ---------------------------------------------------------------------------

/// What routing may be told about `key` — `None` unless the task class has
/// GRADUATED, and `None` when the scope has no runs to speak from.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] on an unusable scope; storage errors;
/// [`Error::CorruptedIndex`] on an undecodable row.
pub fn routing_weight_hint(vault: &Vault, key: &RoutingScopeKey) -> Result<Option<WeightHint>> {
    if rollout_rung(vault, &key.task_class)? != RolloutRung::Graduated {
        return Ok(None);
    }
    let aggregate_key = aggregate_key(key)?;
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &aggregate_key)? else {
        return Ok(None);
    };
    let own = decoded_aggregate(&raw)?;
    let peers = peer_totals(vault, &rtxn, &key.task_class)?;
    Ok(hint_of(own, peers))
}

/// Every scope a task class has promoted to at least [`RolloutRung::DataBar`],
/// in task-class then model-version order.
///
/// Shadow scopes are absent on purpose: their numbers exist and reach nothing,
/// which is what shadow MEANS. Graduated scopes stay listed — a scope that
/// feeds routing is exactly the one worth being able to see.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn routing_data_bar(vault: &Vault) -> Result<Vec<RoutingScopeStats>> {
    let rtxn = vault.store.env.read_txn()?;
    let rows = aggregates(vault, &rtxn)?;
    let mut peers: BTreeMap<String, (f64, u64)> = BTreeMap::new();
    for (key, aggregate) in &rows {
        let totals = peers.entry(key.task_class.clone()).or_default();
        totals.0 += aggregate.d_norm_sum;
        totals.1 += aggregate.runs;
    }

    let mut rungs: BTreeMap<String, RolloutRung> = BTreeMap::new();
    let mut out = Vec::new();
    for (key, aggregate) in rows {
        let rung = match rungs.get(&key.task_class) {
            Some(rung) => *rung,
            None => {
                let rung_key = meta_key(RUNG_KEY_PREFIX, key.task_class.as_bytes());
                let rung = rung_in_txn(vault, &rtxn, &rung_key)?;
                rungs.insert(key.task_class.clone(), rung);
                rung
            }
        };
        if rung == RolloutRung::Shadow {
            continue;
        }
        let totals = peers.get(&key.task_class).copied().unwrap_or_default();
        let Some(hint) = hint_of(aggregate, totals) else {
            continue;
        };
        out.push(RoutingScopeStats {
            key,
            rung,
            runs: aggregate.runs,
            hint,
        });
    }
    Ok(out)
}

/// The pair, computed against a task class's whole peer distribution.
///
/// The peer set INCLUDES the scope itself: a lone generation is then exactly at
/// par, which is the truthful reading of "no peer has ever done this work".
/// Excluding self would leave it dividing by nothing and inventing a verdict.
fn hint_of(own: StoredAggregate, peers: (f64, u64)) -> Option<WeightHint> {
    if own.runs == 0 {
        return None;
    }
    let own_mean = own.d_norm_sum / runs_as_f64(own.runs);
    let peer_mean = if peers.1 == 0 {
        0.0
    } else {
        peers.0 / runs_as_f64(peers.1)
    };
    // A task class nobody has ever had to edit is at par by every reading, and
    // the alternative is a division that means nothing.
    let relative = if peer_mean > 0.0 {
        own_mean / peer_mean
    } else {
        1.0
    };
    let outcome = runs_as_f64(own.sound) / runs_as_f64(own.runs);
    Some(WeightHint {
        relative_edit_cost: relative as f32,
        outcome_score: outcome as f32,
    })
}

/// Run counts live far below `f64`'s exact-integer range, so this cast is the
/// identity every caller here means by it.
fn runs_as_f64(runs: u64) -> f64 {
    runs as f64
}

fn peer_totals(vault: &Vault, rtxn: &heed::RoTxn<'_>, task_class: &str) -> Result<(f64, u64)> {
    let prefix = task_class_prefix(task_class)?;
    let mut sum = 0.0;
    let mut runs = 0_u64;
    for entry in vault.store.vault_meta.prefix_iter(rtxn, &prefix)? {
        let (_, raw) = entry?;
        let aggregate = decoded_aggregate(&raw)?;
        sum += aggregate.d_norm_sum;
        runs += aggregate.runs;
    }
    Ok((sum, runs))
}

fn aggregates(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> Result<Vec<(RoutingScopeKey, StoredAggregate)>> {
    let mut out = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(rtxn, AGGREGATE_KEY_PREFIX)?
    {
        let (key, raw) = entry?;
        out.push((scope_key_of(&key)?, decoded_aggregate(&raw)?));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The rebuild door (CID-7)
// ---------------------------------------------------------------------------

/// Recomputes every aggregate from ED-03's judgment ledger and the recorded
/// generation bindings, replacing what is stored.
///
/// This is the identity that makes the aggregates a PROJECTION rather than a
/// second source of truth: nothing here reads its own previous output. Two
/// things do change across a rebuild, and both are corrections rather than
/// drift — a re-judged receipt folds its new mass and class, and a receipt
/// whose judgment was WITHDRAWN loses its fold and its binding, because a run
/// nobody stands behind must not keep weighing on a generation.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn rebuild_routing_projection(vault: &Vault) -> Result<()> {
    let judged: BTreeMap<String, AmendmentJudgment> = amendment_judgments(vault)?
        .into_iter()
        .map(|judgment| (judgment.receipt_id.clone(), judgment))
        .collect();

    let mut rebuilt: BTreeMap<Vec<u8>, StoredAggregate> = BTreeMap::new();
    let mut stale_members = Vec::new();
    let mut stale_aggregates = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for entry in vault.store.vault_meta.prefix_iter(&rtxn, MEMBER_KEY_PREFIX)? {
            let (key, raw) = entry?;
            let receipt_id = key_tail(&key, MEMBER_KEY_PREFIX, MEMBER_ROW_LABEL)?;
            let Some(judgment) = judged.get(&receipt_id) else {
                stale_members.push(key.to_vec());
                continue;
            };
            let row: StoredModelVersion = decode_row(&raw, MEMBER_ROW_LABEL)?;
            if row.v != ROW_VERSION {
                return Err(Error::CorruptedIndex(MEMBER_ROW_LABEL));
            }
            let scope = RoutingScopeKey::new(row.model_version, judgment.scope.clone());
            let fold = fold_of(judgment)?;
            apply_fold(rebuilt.entry(aggregate_key(&scope)?).or_default(), fold)?;
        }
        for entry in vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, AGGREGATE_KEY_PREFIX)?
        {
            let (key, _) = entry?;
            if !rebuilt.contains_key(key.as_ref()) {
                stale_aggregates.push(key.into_owned());
            }
        }
    }

    vault.with_write_txn(|wtxn| {
        for key in stale_members.iter().chain(&stale_aggregates) {
            vault.store.vault_meta.delete(wtxn, key)?;
        }
        for (key, aggregate) in &rebuilt {
            let encoded = encode_row(aggregate, AGGREGATE_ROW_LABEL)?;
            vault.store.vault_meta.put(wtxn, key, &encoded)?;
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Keys + rows
// ---------------------------------------------------------------------------

fn encode_row<T: Serialize>(row: &T, label: &'static str) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row).map_err(|_| Error::InvariantViolation(label))
}

fn decode_row<T: serde::de::DeserializeOwned>(raw: &[u8], label: &'static str) -> Result<T> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex(label))
}

fn decoded_aggregate(raw: &[u8]) -> Result<StoredAggregate> {
    let row: StoredAggregate = decode_row(raw, AGGREGATE_ROW_LABEL)?;
    if row.v != ROW_VERSION {
        return Err(Error::CorruptedIndex(AGGREGATE_ROW_LABEL));
    }
    Ok(row)
}

fn meta_key(prefix: &[u8], handle: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + handle.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(handle);
    key
}

fn key_tail(key: &[u8], prefix: &[u8], label: &'static str) -> Result<String> {
    let tail = key
        .get(prefix.len()..)
        .ok_or(Error::CorruptedIndex(label))?;
    String::from_utf8(tail.to_vec()).map_err(|_| Error::CorruptedIndex(label))
}

fn task_class_prefix(task_class: &str) -> Result<Vec<u8>> {
    let mut prefix = meta_key(
        AGGREGATE_KEY_PREFIX,
        normalized_task_class(task_class)?.as_bytes(),
    );
    prefix.push(KEY_SEPARATOR);
    Ok(prefix)
}

fn aggregate_key(scope: &RoutingScopeKey) -> Result<Vec<u8>> {
    if scope.model_version.is_empty() || scope.model_version.as_bytes().contains(&KEY_SEPARATOR) {
        return Err(invalid("a routing model version must be a usable key"));
    }
    let mut key = task_class_prefix(&scope.task_class)?;
    key.extend_from_slice(scope.model_version.as_bytes());
    Ok(key)
}

fn scope_key_of(key: &[u8]) -> Result<RoutingScopeKey> {
    let tail = key
        .get(AGGREGATE_KEY_PREFIX.len()..)
        .ok_or(Error::CorruptedIndex(AGGREGATE_ROW_LABEL))?;
    let split = tail
        .iter()
        .position(|byte| *byte == KEY_SEPARATOR)
        .ok_or(Error::CorruptedIndex(AGGREGATE_ROW_LABEL))?;
    let decode = |bytes: &[u8]| {
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::CorruptedIndex(AGGREGATE_ROW_LABEL))
    };
    Ok(RoutingScopeKey {
        task_class: decode(&tail[..split])?,
        model_version: decode(&tail[split + 1..])?,
    })
}

/// The trimmed task class, or the reason it is not one — ED-03's scope rule,
/// so one scope string means one thing lane-wide.
fn normalized_task_class(task_class: &str) -> Result<&str> {
    let trimmed = task_class.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_TASK_CLASS_LEN
        || trimmed.as_bytes().contains(&KEY_SEPARATOR)
    {
        return Err(invalid(
            "a routing task class must be non-empty, separator-free and within the consent-ref bound",
        ));
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests;
