//! Retrieval-only gold-span protocol. A retriever receives the corpus and
//! question, never gold answers, held-out membership, or a generator interface.
use super::{BeamError, BeamResult};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KnowledgeFixture {
    version: u32,
    documents: Vec<Document>,
    spans: Vec<KnownSpan>,
    questions: Vec<GoldQuestion>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    id: String,
    source: String,
    text: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KnownSpan {
    id: String,
    document: String,
    start: usize,
    end: usize,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoldQuestion {
    id: String,
    text: String,
    answers: Vec<String>,
    gold_spans: Vec<String>,
    held_out: bool,
}

struct RetrievalQuestion<'a> {
    text: &'a str,
}
struct RetrievedSpan {
    id: String,
    depth: usize,
}
struct Retrieval {
    spans: Vec<RetrievedSpan>,
    summary_citations: Vec<String>,
}
trait SpanRetriever {
    fn retrieve(
        &mut self,
        question: RetrievalQuestion<'_>,
        corpus: &BTreeMap<String, String>,
    ) -> BeamResult<Retrieval>;
}

#[derive(Debug, Default, Serialize)]
pub(super) struct SliceMetrics {
    questions: usize,
    answered: usize,
    retrieved_spans: usize,
    gold_hits: usize,
    tokens: u64,
    max_expansion_depth: usize,
    sufficient_summaries: usize,
    span_hit_precision: Option<f64>,
    tokens_per_answer: Option<f64>,
    summary_sufficiency: Option<f64>,
}
#[derive(Debug, Serialize)]
pub(super) struct KnowledgeReport {
    protocol: &'static str,
    development: SliceMetrics,
    held_out: SliceMetrics,
}

fn invalid(reason: &str) -> BeamError {
    BeamError::InvalidFixture {
        fixture_id: "knowledge-spans-v1".into(),
        reason: reason.into(),
    }
}

fn evaluate(
    fixture: &KnowledgeFixture,
    retriever: &mut impl SpanRetriever,
) -> BeamResult<KnowledgeReport> {
    if fixture.version != 1
        || !fixture.questions.iter().any(|q| q.held_out)
        || !fixture.questions.iter().any(|q| !q.held_out)
    {
        return Err(invalid("protocol requires development and held-out slices"));
    }
    let mut documents = BTreeMap::new();
    for doc in &fixture.documents {
        if doc.id.is_empty()
            || doc.source.is_empty()
            || documents.insert(&doc.id, &doc.text).is_some()
        {
            return Err(invalid("invalid document identity/source"));
        }
    }
    let mut corpus = BTreeMap::new();
    for span in &fixture.spans {
        let text = documents
            .get(&span.document)
            .and_then(|text| text.get(span.start..span.end))
            .filter(|text| !text.is_empty())
            .ok_or_else(|| invalid("gold span is not a known UTF-8 range"))?;
        if corpus.insert(span.id.clone(), text.to_owned()).is_some() {
            return Err(invalid("duplicate span"));
        }
    }
    let mut report = KnowledgeReport {
        protocol: "known-spans/cold-replay/v1",
        development: SliceMetrics::default(),
        held_out: SliceMetrics::default(),
    };
    let mut question_ids = BTreeSet::new();
    for q in &fixture.questions {
        if !question_ids.insert(&q.id)
            || q.answers.is_empty()
            || q.answers.iter().any(|a| a.trim().is_empty())
            || q.gold_spans.is_empty()
            || q.gold_spans.iter().any(|id| !corpus.contains_key(id))
        {
            return Err(invalid(
                "question needs unique identity, answers and known anchors",
            ));
        }
        let retrieval = retriever.retrieve(RetrievalQuestion { text: &q.text }, &corpus)?;
        let metrics = if q.held_out {
            &mut report.held_out
        } else {
            &mut report.development
        };
        let mut retrieved = BTreeSet::new();
        for span in &retrieval.spans {
            let text = corpus
                .get(&span.id)
                .ok_or_else(|| invalid("retriever returned an unknown span"))?;
            if !retrieved.insert(&span.id) {
                return Err(invalid("duplicate retrieved span"));
            }
            metrics.tokens += oneiron::count_context_pack_tokens(text) as u64;
            metrics.max_expansion_depth = metrics.max_expansion_depth.max(span.depth);
            metrics.gold_hits += usize::from(q.gold_spans.contains(&span.id));
        }
        if retrieval
            .summary_citations
            .iter()
            .any(|id| !retrieved.contains(id))
        {
            return Err(invalid("summary cites unretrieved evidence"));
        }
        metrics.questions += 1;
        metrics.retrieved_spans += retrieved.len();
        metrics.answered += usize::from(q.gold_spans.iter().all(|id| retrieved.contains(id)));
        metrics.sufficient_summaries += usize::from(
            q.gold_spans
                .iter()
                .all(|id| retrieval.summary_citations.contains(id)),
        );
    }
    for metrics in [&mut report.development, &mut report.held_out] {
        metrics.span_hit_precision = (metrics.retrieved_spans > 0)
            .then(|| metrics.gold_hits as f64 / metrics.retrieved_spans as f64);
        metrics.tokens_per_answer =
            (metrics.answered > 0).then(|| metrics.tokens as f64 / metrics.answered as f64);
        metrics.summary_sufficiency = (metrics.questions > 0)
            .then(|| metrics.sufficient_summaries as f64 / metrics.questions as f64);
    }
    Ok(report)
}

struct ColdLexicalRetriever {
    k: usize,
}
impl SpanRetriever for ColdLexicalRetriever {
    fn retrieve(
        &mut self,
        question: RetrievalQuestion<'_>,
        corpus: &BTreeMap<String, String>,
    ) -> BeamResult<Retrieval> {
        // A fresh vault per question: neither previous query results nor a
        // generator's output can become retrieval evidence.
        let dir = tempfile::tempdir()?;
        let mut config = super::util::beam_vault_config();
        config.embedding_model = None;
        let vault = oneiron::Vault::open(dir.path(), config)?;
        let mut source_ids = BTreeMap::new();
        for (i, (id, text)) in corpus.iter().enumerate() {
            let mut bytes = [1u8; 16];
            bytes[8..].copy_from_slice(&(i as u64).to_be_bytes());
            let entity = oneiron::EntityId::from_bytes(bytes)?;
            let at = oneiron::TimeRange { start: 1, end: 1 };
            vault
                .batch()
                .put(
                    &entity,
                    oneiron::registry::ENTITY_TYPE_TURN,
                    at,
                    1,
                    text.as_bytes(),
                )
                .text(&entity, &[("body", text)])
                .commit()?;
            source_ids.insert(entity, id.clone());
        }
        let result = vault
            .query()
            .search_text(question.text, self.k)
            .limit(self.k)
            .run()?;
        Ok(Retrieval {
            spans: result
                .into_iter()
                .map(|s| RetrievedSpan {
                    id: source_ids[&s.id].clone(),
                    depth: 0,
                })
                .collect(),
            summary_citations: Vec::new(),
        })
    }
}

pub(super) fn run(path: &Path) -> BeamResult<KnowledgeReport> {
    let fixture: KnowledgeFixture = serde_json::from_slice(&std::fs::read(path)?)?;
    evaluate(&fixture, &mut ColdLexicalRetriever { k: 4 })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_span_protocol_keeps_held_out_and_generator_separate() -> BeamResult<()> {
        let fixture: KnowledgeFixture =
            serde_json::from_str(include_str!("../../fixtures/retrieval_knowledge.v1.json"))?;
        let report = evaluate(&fixture, &mut ColdLexicalRetriever { k: 4 })?;
        assert_eq!(report.development.questions, 2);
        assert_eq!(report.held_out.questions, 2);
        assert!(report.development.tokens > 0);
        assert!(report.held_out.answered > 0);
        assert!(report.held_out.tokens_per_answer.unwrap() > 0.0);
        assert_eq!(report.held_out.summary_sufficiency, Some(0.0));
        Ok(())
    }
    #[test]
    fn unknown_anchor_fails_protocol() -> BeamResult<()> {
        let mut fixture: KnowledgeFixture =
            serde_json::from_str(include_str!("../../fixtures/retrieval_knowledge.v1.json"))?;
        fixture.spans[0].end = usize::MAX;
        assert!(evaluate(&fixture, &mut ColdLexicalRetriever { k: 4 }).is_err());
        Ok(())
    }
}
