//! The owner's relevance bar for the lines a recall pushes into a session
//! (RECALL-CARRIER-THRESHOLD). The owner, 26 Nov 2026: "Can we just skip the recall if nothing
//! useful? To not pester" (18:53); "I think it's ok to keep line by line but with some
//! relevance threshold (adjustable)" (18:59).
//!
//! A recall that asks the bar ([`RecallBarAsk`]) has each candidate judged on its final id,
//! after the MESSAGE->TURN fold and before any budget or cut, so a line under the bar takes no
//! slot. The score is the raw cosine of the line's stored vector and the query's in the vault's
//! embedding space: never a fused, blended or reranked score, and never a confidence. On a
//! vault with no embedder the rule is a direct match ([`BarTest::DirectMatch`]). The owner
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
use crate::ingest::history::HookTranscriptSource;
use crate::ports::EntityStoreRead;
use crate::setting::{SettingScope, SettingSource, SettingValue};
use crate::store::{ManifestDbs, StoreRead};

/// A query term is distinctive when at most one in this many of the vault's documents hold
/// it.
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
    /// No relevance cut; push exclusions still apply.
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

/// A list of predicates or predicate families. The stored and wire value is a plain list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct ExcludedPredicates(Vec<String>);

impl ExcludedPredicates {
    fn bookkeeping() -> Self {
        Self(
            [
                "skill.hub_provenance",
                "skill.scan_verdict",
                "machine.capacity",
            ]
            .map(str::to_owned)
            .into(),
        )
    }

    fn matches(&self, predicate: &str) -> bool {
        self.0.iter().any(|entry| {
            predicate
                .strip_prefix(entry.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
        })
    }
}

impl SettingValue for ExcludedPredicates {
    fn check(self) -> Result<Self> {
        for entry in &self.0 {
            crate::claim::validate_predicate(entry, true).map_err(|error| {
                Error::InvalidConfig(format!("recall.bar.excluded_predicates: {error}"))
            })?;
        }
        Ok(self)
    }
}

/// How a recall's pipeline judges each final candidate, resolved once per recall.
#[derive(Debug, Clone)]
pub(crate) struct BarJudge {
    test: BarTest,
    excluded_predicates: ExcludedPredicates,
    excluded_conversation: Option<BTreeSet<EntityId>>,
}

#[derive(Debug, Clone)]
enum BarTest {
    /// No relevance cut.
    Open,
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
fn resolve(
    vault: &Vault,
    txn: &RoTxn<'_>,
    ask: &RecallBarAsk,
    query: &str,
    (project, project_scoped): (Option<EntityId>, bool),
    query_vector: Option<&[f32]>,
) -> Result<ResolvedBar> {
    let quiet = |reason: &str| {
        (
            BarTest::Quiet,
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
            BarTest::Cosine {
                floor,
                query: vector.to_vec(),
            },
            RecallBarRule::Cosine {
                floor: floor as f32,
                model: model.to_owned(),
            },
        ),
        _ => quiet("no_query_vector"),
    };
    let (mut test, mut rule) = if ask.source.pushes() && !project_scoped {
        quiet("no_project")
    } else {
        match key.read_in_txn(vault, txn, &scopes, harness) {
            Err(_) => quiet("unreadable"),
            Ok(resolved) if matches!(resolved.source, SettingSource::Unreadable(_)) => {
                quiet("unreadable")
            }
            Ok(resolved) => match resolved.value {
                RecallBar::Open => (BarTest::Open, RecallBarRule::Open),
                RecallBar::Quiet => quiet("owner"),
                RecallBar::DirectMatch => (
                    BarTest::DirectMatch {
                        query: query.to_owned(),
                    },
                    RecallBarRule::DirectMatch,
                ),
                RecallBar::Cosine { .. } if declared_text_space => quiet("declared_space"),
                RecallBar::Cosine { floor, model } if model == space => cosine(floor, &model),
                RecallBar::Cosine { .. } => quiet("other_space"),
                RecallBar::Measured if declared_text_space => quiet("declared_space"),
                RecallBar::Measured if space.is_empty() => (
                    BarTest::DirectMatch {
                        query: query.to_owned(),
                    },
                    RecallBarRule::DirectMatch,
                ),
                RecallBar::Measured => match vault.measured_recall_bar() {
                    Some(floor) => cosine(f64::from(floor), space),
                    None => quiet("unmeasured"),
                },
            },
        }
    };
    let mut excluded_predicates = ExcludedPredicates(Vec::new());
    let mut excluded_conversation = None;
    if ask.source.pushes() && !matches!(test, BarTest::Quiet) {
        match setting_keys::RECALL_BAR_EXCLUDED_PREDICATES.read_in_txn(vault, txn, &scopes, None) {
            Ok(resolved) => excluded_predicates = resolved.value,
            Err(_) => (test, rule) = quiet("unreadable"),
        }
        if let (Some(harness), Some(session)) = (harness, ask.session.as_deref()) {
            excluded_conversation = HookTranscriptSource::session_conversation(harness, session)?
                .map(|id| BTreeSet::from([id]));
        }
    }
    let judge = (!matches!(test, BarTest::Open)
        || !excluded_predicates.0.is_empty()
        || excluded_conversation.is_some())
    .then_some(BarJudge {
        test,
        excluded_predicates,
        excluded_conversation,
    });
    Ok(ResolvedBar {
        judge,
        outcome: RecallBarOutcome {
            source: ask.source,
            rule,
            receipt,
        },
    })
}

impl crate::memory::Memory<'_> {
    /// The bar a recall of `query` in `scope` that asks `ask` is judged by ([`resolve`]): its
    /// project is the one `scope` names (repeated refs to the same project still name one, as
    /// does a root named beside its own descendant, which reads the same corpus), else the
    /// project bound to the session's folder; a scope that names several distinct projects
    /// reads the rows that name no project. A push never takes the reserved default stamp
    /// ([`crate::claim::default_project_id`]) as its project: naming only that ref reads as
    /// naming none, quiet when no session project binds the push.
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
        let pushes = ask.source.pushes();
        let project = match scope.project_refs.as_slice() {
            [] => (session, session.is_some()),
            [one] => {
                let id = self.resolve_ref(one)?;
                if pushes && id == crate::claim::default_project_id() {
                    // The reserved unscoped stamp is no project a push is inside of
                    // (REVIEW-10566 round 2): the push reads as one that names none.
                    (session, session.is_some())
                } else {
                    (Some(id), true)
                }
            }
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
                if pushes {
                    distinct.remove(&crate::claim::default_project_id());
                }
                if !unresolved && distinct.len() > 1 {
                    // [P, C] with C below P reads the same corpus as [P], so it reads the
                    // same row: drop every named root another named root's closure already
                    // contains, in the same closure the read uses, before counting one
                    // against several (REVIEW-10566 round 2).
                    let roots: Vec<EntityId> = distinct.iter().copied().collect();
                    let mut minimal = BTreeSet::new();
                    for (index, root) in roots.iter().enumerate() {
                        let others: Vec<EntityId> = roots[..index]
                            .iter()
                            .chain(roots[index + 1..].iter())
                            .copied()
                            .collect();
                        let closure =
                            crate::memory::project_descendant_closure_of(self.vault, others)?;
                        if !closure.contains(root) {
                            minimal.insert(*root);
                        }
                    }
                    distinct = minimal;
                }
                if !unresolved && distinct.len() == 1 {
                    (distinct.into_iter().next(), true)
                } else if !unresolved && distinct.is_empty() && pushes {
                    // Only the reserved stamp, named once or repeated: no named project, as
                    // above.
                    (session, session.is_some())
                } else {
                    (None, true)
                }
            }
        };
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        Ok(resolve(
            self.vault,
            &txn,
            ask,
            query,
            project,
            query_vector,
        )?)
    }
}

impl BarJudge {
    pub(crate) fn is_direct_match(&self) -> bool {
        matches!(self.test, BarTest::DirectMatch { .. })
    }

    /// Keeps final ids that clear the relevance test and the push exclusions, in order.
    /// Returns the raw cosine of each kept row when the bar compares cosines. `hidden_row`
    /// hides rows the reader may not read from a term's document count.
    pub(crate) fn retain_passing(
        &self,
        scores: &mut Vec<ScoredEntity>,
        vault: &Vault,
        store: &StoreRead<'_>,
        rtxn: &RoTxn<'_>,
        hidden_row: Option<&mut (dyn FnMut(&EntityId) -> Result<bool> + '_)>,
    ) -> Result<HashMap<EntityId, f32>> {
        let mut similarity = HashMap::new();
        if matches!(self.test, BarTest::Quiet) {
            scores.clear();
            return Ok(similarity);
        }
        let (terms, distinctive) = if let BarTest::DirectMatch { query } = &self.test {
            let terms = query_terms(vault, query);
            let distinctive = distinctive_terms(store, rtxn, &terms, hidden_row)?;
            (terms, distinctive)
        } else {
            (Vec::new(), Vec::new())
        };

        let mut kept = Vec::with_capacity(scores.len());
        for row in scores.drain(..) {
            if self.excludes(vault, store, rtxn, &row.id)? {
                continue;
            }
            match &self.test {
                BarTest::Cosine { floor, query } => {
                    let Some(vector) = vault.vector_in_txn(store, rtxn, &row.id)? else {
                        continue;
                    };
                    let cosine = oneiron_retrieval::distance::cosine_similarity(query, &vector);
                    if !cosine.is_finite() || f64::from(cosine) < *floor {
                        continue;
                    }
                    similarity.insert(row.id, cosine);
                }
                BarTest::DirectMatch { .. } => {
                    if !direct_match(store, rtxn, &terms, &distinctive, &row.id)? {
                        continue;
                    }
                }
                BarTest::Open => {}
                BarTest::Quiet => unreachable!("quiet cleared the candidates"),
            }
            kept.push(row);
        }
        *scores = kept;
        Ok(similarity)
    }

    /// The pipeline already admitted this final id. Test the stored predicate and
    /// negate only the conversation membership test, never the admission gate.
    fn excludes(
        &self,
        vault: &Vault,
        store: &StoreRead<'_>,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        if !self.excluded_predicates.0.is_empty()
            && store.port_entity_with_raw(txn, id, |raw| {
                if raw.first() != Some(&crate::registry::ENTITY_TYPE_CLAIM) {
                    return Ok(false);
                }
                let Some(bytes) = raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..) else {
                    return Ok(false);
                };
                let body = crate::claim::decode_claim_body(bytes, true)?;
                Ok(self.excluded_predicates.matches(&body.predicate))
            })? == Some(true)
        {
            return Ok(true);
        }
        if self.excluded_conversation.is_some() {
            return super::conversation_candidate_admits(
                vault,
                store,
                txn,
                id,
                &self.excluded_conversation,
            );
        }
        Ok(false)
    }
}

/// The query's terms as the text index analyzes a query, each once, without the final token's
/// prefix completions: a direct match is of the words asked.
pub(crate) fn query_terms(vault: &Vault, query: &str) -> Vec<String> {
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

/// Of `terms`, those at most one in [`DISTINCTIVE_SHARE`] of the vault's documents hold,
/// counting no row `hidden_row` hides. With fewer than [`DISTINCTIVE_SHARE`] documents the cap
/// is zero, so no term is distinctive by rarity there (REVIEW-10566 round 2); the every-term
/// rule still passes a line holding every term of a longer query.
fn distinctive_terms(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    terms: &[String],
    mut hidden_row: Option<&mut (dyn FnMut(&EntityId) -> Result<bool> + '_)>,
) -> Result<Vec<String>> {
    let total = crate::bm25::read_total_docs(store, rtxn)?;
    let cap = total / DISTINCTIVE_SHARE;
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
