//! JointIE inside a consolidation child (ARCH-0026 `#wake-model`: "Inside
//! the child JointIE extracts claims"; L2-03, HOME = A, SWITCH = A). The
//! tagger's relation head runs at ingest, and its relations are saved with
//! each turn's tag set; the tagger authors no claim (ARCH-0036). A slice is
//! covered when the host's relation table maps a label and every TURN the
//! slice labels holds a fresh tag set the armed tagger made with relations,
//! all under one model and stack. A covered slice's extraction step is a
//! reply the engine authors from those relations, run through the same
//! durable step, reply check and decode as a model's reply, so replay,
//! citations, corrections and the write door run as they do. No text leaves
//! the process and no model is called. Any other slice keeps the extraction
//! model's step, so nothing drops. A covered slice files only the relations
//! its table maps, and never falls back to generation.
//!
//! A relation files a candidate when its head mention links exactly one
//! entity the call lists (its subject, by that label), or is a person the
//! save only minted, named by its own words (declared as a new person, as a
//! model declares one). Its predicate is the table's, its value the tail
//! span's words as written, and its evidence the TURN byte range of the two
//! spans in the slice's own pinned text: each span's MESSAGE offsets move
//! through that text's layout and must hold the same bytes there, never
//! found by a search. Anything else files nothing and is counted. The
//! correction pack and the merge questions run on the candidates as on a
//! model's: the relation head answers no typed question.

use std::collections::BTreeMap;

use super::call_labels::{CallLabel, CallLabelMap, LabelKind};
use super::executor::extraction::CitationCheck;
use super::extracted_people::MintNamespace;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::tagging::{TaggedMention, TaggingMarkerConfig, TurnTags};
use crate::vault::Vault;
use oneiron_model::llm::{
    BudgetLease, CallClass, CallEnvelope, CallPurpose, ContentPart, FatalLlmError, FinishReason,
    LlmBackend, LlmCapability, LlmError, LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest,
    LlmResponse, LlmStreamResult, LlmUsage, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    Scope, TierPrecedence, UnsupportedCapability,
};

/// The finish a relation reply carries: the engine's own, never a
/// provider's (`authored:`, so decode reads its authored ref shape).
const RELATION_FINISH: &str = "authored:relations";
/// The request's memo-identity entry in the host's provider options.
const RELATIONS_KEY: &str = "relations";
const RELATIONS_VERSION: u32 = 1;

/// A covered slice's reply, and what its step's identity binds.
pub(super) struct RelationReply {
    /// The reply, in the extraction contract's shape.
    text: String,
    /// Each tag set it was read from and the reply's digest.
    identity: serde_json::Value,
    /// The relation head at the tagger's checkpoint, as the request names it.
    model: ModelId,
}

impl RelationReply {
    /// The covered slice's request: its transcript, scope and labels bound as
    /// the model step binds them, under the relation head, with the tag sets
    /// and the reply in its memo key, so a re-tag, a new table or a changed
    /// link asks again. It names this device and no paid route, since its
    /// reply is authored here and nothing is sent: no role's locality,
    /// authorization or reasoning binding is read.
    pub(super) fn request(
        &self,
        transcript: &str,
        labels: &CallLabelMap,
        scope: &Scope,
        namespace: &MintNamespace,
    ) -> LlmRequest {
        let mut request = LlmRequest {
            model: self.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: scope.clone(),
                purpose: CallPurpose::Extraction,
                // An authored reply meets no provider failure, so it names no
                // fallback.
                class: CallClass::BestEffort,
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::Extraction,
                    ModelTierRef("consolidation".into()),
                ),
                response_format: ResponseFormat::Text,
                locality: ModelLocality::OnDevice,
                host_keyless: true,
                host_paid: false,
            }
            .with_purpose_defaults(),
            messages: vec![LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: transcript.to_owned(),
                    signature: None,
                }],
            }],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
            host_segments: None,
        };
        labels.bind_request(&mut request, Some(&namespace.identity()));
        if let Some(serde_json::Value::Object(options)) = request
            .provider_options
            .get_mut(crate::code_run::HOST_PROVIDER_OPTIONS)
        {
            options.insert(RELATIONS_KEY.to_owned(), self.identity.clone());
        }
        request
    }

    /// The in-process backend that answers the covered slice's step with the
    /// reply.
    pub(super) fn backend(&self) -> RelationReplyBackend {
        RelationReplyBackend {
            text: self.text.clone(),
        }
    }
}

/// Answers a covered slice's step with its prebuilt reply, at no cost.
pub(super) struct RelationReplyBackend {
    text: String,
}

impl LlmBackend for RelationReplyBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let response = LlmResponse {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: self.text.clone(),
                    signature: None,
                }],
            },
            usage: LlmUsage::zero(),
            finish_reason: FinishReason::Other {
                name: RELATION_FINISH.to_owned(),
            },
            reply_assertions: Default::default(),
            token_scores: None,
        };
        Box::pin(async move { Ok(response) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(LlmError::Fatal(FatalLlmError::Unsupported(
            UnsupportedCapability {
                capability: LlmCapability::Streaming,
                model: None,
                reason: None,
            },
        )))
    }
}

/// The relation reply of the slice whose call labels are `labels`, when the
/// slice is covered; `None` sends it to the extraction model. Read in one
/// snapshot; its TURN texts are `citations`', the slice's own pinned texts.
pub(super) fn relation_reply(
    vault: &Vault,
    labels: &CallLabelMap,
    citations: &CitationCheck,
) -> Result<Option<RelationReply>> {
    let Some(config) = vault.tagging_marker_config() else {
        return Ok(None);
    };
    if config.relations.is_empty() {
        return Ok(None);
    }
    let turns: Vec<(CallLabel, EntityId)> = labels.labelled(LabelKind::Turn).collect();
    if turns.is_empty() {
        return Ok(None);
    }
    let txn = super::turn_text::snapshot(vault)?;
    let mut sets = Vec::with_capacity(turns.len());
    for (label, turn) in turns {
        let Some(tags) = covered_set_in_txn(vault, &txn, &turn, &config)? else {
            return Ok(None);
        };
        sets.push((label, turn, tags));
    }
    let (_, _, first) = &sets[0];
    if sets.iter().any(|(_, _, tags)| {
        tags.envelope.model_id != first.envelope.model_id
            || tags.envelope.stack != first.envelope.stack
    }) {
        return Ok(None);
    }
    let model = ModelId::new(format!("oneironer/relations@{}", config.checkpoint))
        .map_err(|error| Error::InvalidConfig(format!("relation head model id: {error}")))?;
    let mut reply = ReplyBuilder::new(labels, citations);
    for (label, turn, tags) in &sets {
        reply.add_turn(vault, &txn, *label, *turn, tags, &config)?;
    }
    let ReplyBuilder {
        candidates,
        persons,
        counts,
        ..
    } = reply;
    tracing::debug!(
        target: "oneiron::dreamer",
        filed = counts.filed,
        unmapped = counts.unmapped,
        no_subject = counts.no_subject,
        unplaced = counts.unplaced,
        "relation step"
    );
    let text = serde_json::json!({
        "candidates": candidates,
        "persons": persons.into_values().collect::<Vec<_>>(),
    })
    .to_string();
    let identity = serde_json::json!({
        "version": RELATIONS_VERSION,
        "sets": sets
            .iter()
            .map(|(_, turn, tags)| {
                serde_json::json!({
                    "turn": turn.to_hex(),
                    "content_hash": tags.envelope.content_hash,
                    "model_id": tags.envelope.model_id,
                    "stack": tags.envelope.stack,
                    "text_hash": tags.envelope.text_hash,
                    "version": tags.envelope.version,
                    "params_hash": tags.envelope.params_hash,
                })
            })
            .collect::<Vec<_>>(),
        "reply": bytes_to_hex_lower(blake3::hash(text.as_bytes()).as_bytes()),
    });
    Ok(Some(RelationReply {
        text,
        identity,
        model,
    }))
}

/// `turn`'s tag set, when it covers the turn: readable, fresh (neither
/// stale nor owed a retag), made by the armed tagger, and holding the
/// relations its model returned.
fn covered_set_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    config: &TaggingMarkerConfig,
) -> Result<Option<TurnTags>> {
    let Some(tags) = crate::tagging::readable_view_in_txn(&vault.store, txn, turn)? else {
        return Ok(None);
    };
    let freshness = crate::tagging::tagging_freshness_in_txn(vault, txn, turn, &tags)?;
    let covered = !freshness.stale
        && !freshness.pending_retag
        && tags.envelope.made_by_tagger(config)
        && tags.relations.is_some();
    Ok(covered.then_some(tags))
}

/// What the relations of a covered slice came to.
#[derive(Default)]
struct Counts {
    filed: usize,
    /// A label the table does not map.
    unmapped: usize,
    /// A head naming no one listed entity and no minted person.
    no_subject: usize,
    /// A span whose words do not sit verbatim in the pinned TURN text.
    unplaced: usize,
}

/// The reply a covered slice's relations build, turn by turn.
struct ReplyBuilder<'c> {
    labels: &'c CallLabelMap,
    citations: &'c CitationCheck,
    candidates: Vec<serde_json::Value>,
    /// Each new person the reply declares, by its name: its declaration.
    persons: BTreeMap<String, serde_json::Value>,
    counts: Counts,
}

impl<'c> ReplyBuilder<'c> {
    fn new(labels: &'c CallLabelMap, citations: &'c CitationCheck) -> Self {
        Self {
            labels,
            citations,
            candidates: Vec::new(),
            persons: BTreeMap::new(),
            counts: Counts::default(),
        }
    }

    /// One candidate for each relation of `turn`'s set that files.
    fn add_turn(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        label: CallLabel,
        turn: EntityId,
        tags: &TurnTags,
        config: &TaggingMarkerConfig,
    ) -> Result<()> {
        let mut texts = BTreeMap::new();
        for relation in tags.relations.iter().flatten() {
            let Some(predicate) = config.relations.get(&relation.label) else {
                self.counts.unmapped += 1;
                continue;
            };
            let (Some(head), Some(tail)) = (
                tags.mentions.get(relation.head),
                tags.mentions.get(relation.tail),
            ) else {
                self.counts.unplaced += 1;
                continue;
            };
            let (Some(head_place), Some(tail_place)) = (
                self.place(vault, txn, &mut texts, turn, head)?,
                self.place(vault, txn, &mut texts, turn, tail)?,
            ) else {
                self.counts.unplaced += 1;
                continue;
            };
            let Some(subject) = self.subject(vault, txn, label, head, &head_place.words)? else {
                self.counts.no_subject += 1;
                continue;
            };
            let range = |place: &Place| serde_json::json!([place.start, place.end]);
            let evidence_refs = if head.message == tail.message {
                vec![serde_json::json!({
                    "source_id": turn.to_hex(),
                    "byte_range": [
                        head_place.start.min(tail_place.start),
                        head_place.end.max(tail_place.end),
                    ],
                })]
            } else {
                [&head_place, &tail_place]
                    .into_iter()
                    .map(|place| {
                        serde_json::json!({
                            "source_id": turn.to_hex(),
                            "byte_range": range(place),
                        })
                    })
                    .collect()
            };
            self.candidates.push(serde_json::json!({
                "subject": subject,
                "predicate": predicate,
                "value": tail_place.words,
                "confidence": relation.confidence,
                "evidence_refs": evidence_refs,
            }));
            self.counts.filed += 1;
        }
        Ok(())
    }

    /// Where `mention`'s words sit in `turn`'s pinned text: its MESSAGE's
    /// offset there plus the span's own, holding the bytes the tagger read
    /// at those offsets. `None` when the pinned text does not project the
    /// MESSAGE, or holds other bytes there.
    fn place(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        texts: &mut BTreeMap<EntityId, Option<String>>,
        turn: EntityId,
        mention: &TaggedMention,
    ) -> Result<Option<Place>> {
        let read = match texts.get(&mention.message) {
            Some(read) => read.clone(),
            None => {
                let read =
                    crate::tagging::message_text_in_txn(vault, txn, &turn, &mention.message)?;
                texts.insert(mention.message, read.clone());
                read
            }
        };
        let Some(words) = read
            .as_deref()
            .and_then(|text| text.get(mention.start..mention.end))
        else {
            return Ok(None);
        };
        let (Some(cited), Some(offset)) = (
            self.citations.cited_text(&turn),
            self.citations.message_offset(&turn, &mention.message),
        ) else {
            return Ok(None);
        };
        let (start, end) = (offset + mention.start, offset + mention.end);
        if words.is_empty() || cited.get(start..end) != Some(words) {
            return Ok(None);
        }
        Ok(Some(Place {
            start,
            end,
            words: words.to_owned(),
        }))
    }

    /// The candidate's subject for a relation whose head is `head`: the
    /// label of the one entity its saved link names, when the call lists
    /// it; else, for a person the save only minted and its own words name,
    /// a person the reply declares under that name, sourced to the TURN
    /// `label`. A head linked through a pronoun, a speaker or an antecedent
    /// names no one by its own words, so it declares no one.
    fn subject(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        label: CallLabel,
        head: &TaggedMention,
        words: &str,
    ) -> Result<Option<String>> {
        let [entity] = head.link.entities() else {
            return Ok(None);
        };
        if let Some(listed) = self.labels.label(LabelKind::Entity, *entity) {
            return Ok(Some(listed.to_string()));
        }
        let minted = crate::tagging::provisional_in_txn(&vault.store, txn, entity)?.is_some();
        let own_name = head.reference.is_none() && head.antecedent.is_none();
        if !(minted && own_name && head.link.kind() == Some(ENTITY_TYPE_PERSON)) {
            return Ok(None);
        }
        let number = self.persons.len() + 1;
        let declared = self.persons.entry(words.to_owned()).or_insert_with(|| {
            serde_json::json!({
                "id": format!("new:P{number}"),
                "name": words,
                "evidence_turn_refs": [label.to_string()],
            })
        });
        Ok(declared
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned))
    }
}

/// A span's place in its TURN's pinned text, and the words there.
struct Place {
    start: usize,
    end: usize,
    words: String,
}
