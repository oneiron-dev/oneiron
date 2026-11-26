//! The owner's relevance bar for the lines a recall pushes into a session
//! (RECALL-CARRIER-THRESHOLD). The owner, 26 Nov 2026: "Can we just skip the recall if nothing
//! useful? To not pester" (18:53); "I think it's ok to keep line by line but with some
//! relevance threshold (adjustable)" (18:59).
//!
//! A recall that asks the bar ([`RecallBarAsk`]) has each candidate judged on its final id,
//! after the MESSAGE->TURN fold and before any budget or cut, so a line under the bar takes no
//! slot. The score is the raw cosine of the line's stored vector and the query's in the vault's
//! embedding space: never a fused, blended or reranked score, and never a confidence. On a
//! vault with no embedder the rule is a direct match ([`BarJudge::DirectMatch`]). The owner
//! sets the rule per source (`recall.bar.start`, `recall.bar.carrier`, `recall.bar.pull`), per
//! harness (the row's item) and per project (the row's scope); see [`setting_keys`].

pub(crate) mod setting_keys;

use std::collections::{BTreeSet, HashMap};

use heed::RoTxn;
use oneiron_retrieval::pipeline::ScoredEntity;
use serde::{Deserialize, Serialize};

use super::{RecallBarAsk, RecallBarOutcome, RecallBarRule, RecallSource};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::setting::{SettingScope, SettingSource, SettingValue};
use crate::store::ManifestDbs;

/// A query term is distinctive when at most one in this many of the vault's documents hold
/// it (at least one document).
const DISTINCTIVE_SHARE: u32 = 20;

/// The value of `recall.bar.<source>`: the rule one source's lines are judged by.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RecallBar {
    /// The bar the host measured for the vault's embedding space: set only by a host that
    /// runs the space's model at the exact revision and on the profile it was measured with
    /// ([`Vault::set_measured_recall_bar`]; 0.52 for pplx-embed-v1-0.6b, RECALL-AB-THRESHOLD-
    /// DATA). On a vault with no embedder, a direct match; quiet in every other case.
    Measured,
    /// No bar: every line the recall found.
    Open,
    /// No line.
    Quiet,
    /// A line passes when it holds a distinctive term of the query, or, for a query of two or
    /// more terms, every one of them.
    DirectMatch,
    /// A line passes when the raw cosine of its vector and the query's is at least `floor`,
    /// `0 <= floor <= 1`. Only in `model`'s space (`org/name@revision`): in another the
    /// floor means nothing, so the bar is quiet there.
    Cosine { floor: f64, model: String },
}

impl RecallBar {
    fn measured() -> Self {
        Self::Measured
    }

    fn open() -> Self {
        Self::Open
    }

    fn quiet() -> Self {
        Self::Quiet
    }
}

impl SettingValue for RecallBar {
    /// Closed: a rule name, a number and a model id, the name of an embedding space.
    const CLOSED: bool = true;

    /// A floor outside `0 <= floor <= 1`, or not a number, and a model that is not a model
    /// id are refused, never clamped.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` naming the floor or the model.
    fn check(self) -> Result<Self> {
        if let Self::Cosine { floor, model } = &self {
            if !floor.is_finite() || !(0.0..=1.0).contains(floor) {
                return Err(Error::InvalidConfig(format!(
                    "recall.bar: a cosine floor must satisfy 0 <= floor <= 1, got {floor}"
                )));
            }
            crate::store::validate_embedding_model_id(model)?;
        }
        Ok(self)
    }
}

/// Whether `item` names a harness a bar row may be set for.
fn is_harness_item(item: &str) -> bool {
    super::is_harness_name(item)
}

/// How a recall's pipeline judges each candidate, resolved once per recall
/// ([`resolve`]); `None` there is no bar.
#[derive(Debug, Clone)]
pub(crate) enum BarJudge {
    /// No candidate passes.
    Quiet,
    /// A candidate passes when it holds a distinctive term of `query`, or, for a query of
    /// two or more terms, every one of them.
    DirectMatch { query: String },
    /// A candidate passes when the raw cosine of its stored vector and `query` is at least
    /// `floor`.
    Cosine { floor: f64, query: Vec<f32> },
}

/// A recall's bar: what its pipeline judges candidates by, and what its pack reports.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedBar {
    pub(crate) judge: Option<BarJudge>,
    pub(crate) outcome: RecallBarOutcome,
}

/// What a recall that asks `ask` is judged by, read in `txn`: the owner's row for its source,
/// at `project` (the session's project, or the one project the recall names) over the vault,
/// the harness's own row before the row that names none. `project_scoped`: the recall reads
/// inside named or bound projects only. `query_vector` is the query's vector in the vault's
/// text index, when it was embedded.
///
/// Quiet, and never wider, when: a push reads outside any project; the row does not read; the
/// rule compares cosines and the query has no vector, or the vault's vectors are in another
/// space than the rule's, or in a declared text space (none is measured yet).
pub(crate) fn resolve(
    vault: &Vault,
    txn: &RoTxn<'_>,
    ask: &RecallBarAsk,
    query: &str,
    (project, project_scoped): (Option<EntityId>, bool),
    query_vector: Option<&[f32]>,
) -> ResolvedBar {
    let quiet = |reason: &str| {
        (
            Some(BarJudge::Quiet),
            RecallBarRule::Quiet {
                reason: reason.to_owned(),
            },
        )
    };
    let scopes: Vec<SettingScope> = project.map(SettingScope::Project).into_iter().collect();
    let harness = ask.harness.as_deref();
    let receipt = setting_keys::RECALL_BAR_EMPTY_RECEIPT
        .read_in_txn(vault, txn, &scopes, harness)
        .is_ok_and(|resolved| resolved.value);
    let key = match ask.source {
        RecallSource::Start => &setting_keys::RECALL_BAR_START,
        RecallSource::Carrier => &setting_keys::RECALL_BAR_CARRIER,
        RecallSource::Pull => &setting_keys::RECALL_BAR_PULL,
    };
    let space = vault.evidence_space();
    let declared_text_space = crate::embed::kind_slot_bindings_in_txn(&vault.store, txn)
        .map_or(true, |bindings| bindings.text.is_some());
    let cosine = |floor: f64, model: &str| match query_vector {
        Some(vector) if vector.len() == vault.config.dimensions => (
            Some(BarJudge::Cosine {
                floor,
                query: vector.to_vec(),
            }),
            RecallBarRule::Cosine {
                floor: floor as f32,
                model: model.to_owned(),
            },
        ),
        _ => quiet("no_query_vector"),
    };
    let (judge, rule) = if ask.source.pushes() && !project_scoped {
        quiet("no_project")
    } else {
        match key.read_in_txn(vault, txn, &scopes, harness) {
            Err(_) => quiet("unreadable"),
            Ok(resolved) if matches!(resolved.source, SettingSource::Unreadable(_)) => {
                quiet("unreadable")
            }
            Ok(resolved) => match resolved.value {
                RecallBar::Open => (None, RecallBarRule::Open),
                RecallBar::Quiet => quiet("owner"),
                RecallBar::DirectMatch => (
                    Some(BarJudge::DirectMatch {
                        query: query.to_owned(),
                    }),
                    RecallBarRule::DirectMatch,
                ),
                RecallBar::Cosine { .. } if declared_text_space => quiet("declared_space"),
                RecallBar::Cosine { floor, model } if model == space => cosine(floor, &model),
                RecallBar::Cosine { .. } => quiet("other_space"),
                RecallBar::Measured if declared_text_space => quiet("declared_space"),
                RecallBar::Measured if space.is_empty() => (
                    Some(BarJudge::DirectMatch {
                        query: query.to_owned(),
                    }),
                    RecallBarRule::DirectMatch,
                ),
                RecallBar::Measured => match vault.measured_recall_bar() {
                    Some(floor) => cosine(f64::from(floor), space),
                    None => quiet("unmeasured"),
                },
            },
        }
    };
    ResolvedBar {
        judge,
        outcome: RecallBarOutcome {
            source: ask.source,
            rule,
            receipt,
        },
    }
}

impl crate::memory::Memory<'_> {
    /// The bar a recall of `query` in `scope` that asks `ask` is judged by ([`resolve`]): its
    /// project is the one `scope` names (repeated refs to the same project still name one),
    /// else the project bound to the session's folder; a scope that names several distinct
    /// projects reads the rows that name no project.
    pub(super) fn resolve_recall_bar(
        &self,
        ask: &RecallBarAsk,
        query: &str,
        scope: &super::RecallScope,
        query_vector: Option<&[f32]>,
    ) -> crate::memory::MemoryResult<ResolvedBar> {
        let session = self
            .session_projects
            .as_ref()
            .and_then(crate::session_project::SessionProjects::project);
        let project = match scope.project_refs.as_slice() {
            [] => (session, session.is_some()),
            [one] => (Some(self.resolve_ref(one)?), true),
            many => {
                // [P, P] names one project: resolve and dedupe before counting one against
                // several, so a repeated ref is judged by its project's own row (REVIEW-10566
                // round 1). A ref that fails to resolve keeps today's behaviour: the vault's
                // row, as an unresolvable repeat did when several refs resolved to nothing.
                let mut distinct = BTreeSet::new();
                let mut unresolved = false;
                for reference in many {
                    match self.resolve_ref(reference) {
                        Ok(id) => {
                            distinct.insert(id);
                        }
                        Err(_) => {
                            unresolved = true;
                            break;
                        }
                    }
                }
                if !unresolved && distinct.len() == 1 {
                    (distinct.into_iter().next(), true)
                } else {
                    (None, true)
                }
            }
        };
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        Ok(resolve(self.vault, &txn, ask, query, project, query_vector))
    }
}

impl BarJudge {
    /// Keeps, in their order, the rows of `scores` that clear the bar, read in `rtxn`, and
    /// answers each kept row's cosine when the bar compares cosines. `hidden_row` hides a row
    /// the reader may not read from a term's document count (the text channel's own-row
    /// test).
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn retain_passing(
        &self,
        scores: &mut Vec<ScoredEntity>,
        vault: &Vault,
        store: &impl ManifestDbs,
        rtxn: &RoTxn<'_>,
        hidden_row: Option<&mut (dyn FnMut(&EntityId) -> Result<bool> + '_)>,
    ) -> Result<HashMap<EntityId, f32>> {
        let mut similarity = HashMap::new();
        match self {
            Self::Quiet => scores.clear(),
            Self::Cosine { floor, query } => {
                let mut kept = Vec::with_capacity(scores.len());
                for row in scores.drain(..) {
                    let Some(vector) = vault.vector_in_txn(store, rtxn, &row.id)? else {
                        continue;
                    };
                    let cosine = oneiron_retrieval::distance::cosine_similarity(query, &vector);
                    if cosine.is_finite() && f64::from(cosine) >= *floor {
                        similarity.insert(row.id, cosine);
                        kept.push(row);
                    }
                }
                *scores = kept;
            }
            Self::DirectMatch { query } => {
                let terms = query_terms(vault, query);
                let distinctive = distinctive_terms(store, rtxn, &terms, hidden_row)?;
                let mut kept = Vec::with_capacity(scores.len());
                for row in scores.drain(..) {
                    if direct_match(store, rtxn, &terms, &distinctive, &row.id)? {
                        kept.push(row);
                    }
                }
                *scores = kept;
            }
        }
        Ok(similarity)
    }
}

/// The query's terms as the text index analyzes a query, each once, without the final token's
/// prefix completions: a direct match is of the words asked.
fn query_terms(vault: &Vault, query: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    vault.analyzer.analyze(
        query,
        &crate::analyzer::AnalyzerContext::for_query(),
        &mut tokens,
    );
    let mut terms: Vec<String> = tokens.iter().map(|token| token.term.to_string()).collect();
    terms.sort_unstable();
    terms.dedup();
    terms
}

/// Of `terms`, those at most one in [`DISTINCTIVE_SHARE`] of the vault's documents hold (at
/// least one document), counting no row `hidden_row` hides.
fn distinctive_terms(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    terms: &[String],
    mut hidden_row: Option<&mut (dyn FnMut(&EntityId) -> Result<bool> + '_)>,
) -> Result<Vec<String>> {
    let total = crate::bm25::read_total_docs(store, rtxn)?;
    let cap = (total / DISTINCTIVE_SHARE).max(1);
    let mut distinctive = Vec::new();
    for term in terms {
        if crate::bm25::term_rows_at_most(store, rtxn, term, cap, hidden_row.as_deref_mut())? {
            distinctive.push(term.clone());
        }
    }
    Ok(distinctive)
}

/// Whether the row `id` holds one of `distinctive`, or, for two or more `terms`, every one.
/// One common word never passes.
fn direct_match(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    terms: &[String],
    distinctive: &[String],
    id: &EntityId,
) -> Result<bool> {
    for term in distinctive {
        if crate::bm25::row_holds_term(store, rtxn, term, id)? {
            return Ok(true);
        }
    }
    if terms.len() < 2 {
        return Ok(false);
    }
    for term in terms {
        if !crate::bm25::row_holds_term(store, rtxn, term, id)? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cosine_floor_out_of_range_or_a_bad_model_is_refused() {
        let bar = |floor: f64, model: &str| {
            RecallBar::Cosine {
                floor,
                model: model.to_owned(),
            }
            .check()
        };
        assert!(bar(0.52, "perplexity-ai/pplx-embed-v1-0.6b@rev").is_ok());
        assert!(bar(1.000_000_01, "perplexity-ai/pplx-embed-v1-0.6b@rev").is_err());
        assert!(bar(-0.1, "perplexity-ai/pplx-embed-v1-0.6b@rev").is_err());
        assert!(bar(f64::NAN, "perplexity-ai/pplx-embed-v1-0.6b@rev").is_err());
        assert!(bar(0.5, "pplx-embed-v1-0.6b").is_err());
    }
}
