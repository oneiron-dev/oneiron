//! The extraction reply's wire (FIX 7506, ARCH-0026 row 1): its contract's
//! shape, and how a reply's call-local labels and quotes bind to ids and
//! byte ranges through its call's own map and the text the call showed. A
//! shape fault refuses a reply as malformed hex did; a well-formed label or
//! quote that binds nothing is a named result, filed where an unadmitted id
//! or a bad range was filed before. No model-chosen id reaches a candidate.

use super::ParsedCandidate;
use super::quote_binding::{QuoteBinding, bind_quote};
use crate::dreamer_consolidation::call_labels::{
    CallLabel, CallLabelMap, CallSources, CandidateRel, LabelKind, SourceShown, SubjectLabel,
    new_person,
};
use crate::dreamer_consolidation::evidence::EvidenceLocator;
use crate::dreamer_consolidation::extracted_people::PersonBindings;
use crate::dreamer_consolidation::resources::{BranchPins, BranchResources};
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::llm::{ContentPart, FinishReason, LlmResponse, Scope};

/// An extraction reply in its contract's shape: an object whose
/// `candidates`, when present, are objects, and whose `persons`, when
/// present, each declare a `new:P<n>` id, a name and at least one source
/// label. Other keys are outside the contract: a NOTE review reads its own
/// (`note_classification`), and no one else reads them.
#[derive(serde::Deserialize)]
pub(in crate::dreamer_consolidation) struct ExtractionReply {
    #[serde(default, deserialize_with = "objects")]
    pub(in crate::dreamer_consolidation) candidates: Vec<serde_json::Value>,
    #[serde(default)]
    pub(in crate::dreamer_consolidation) persons: Vec<ExtractedPerson>,
}

/// One person a reply declares: its reply-local `new:P<n>` id (never an
/// entity id), its name as written, and the labels of the sources naming it.
#[derive(serde::Deserialize)]
pub(in crate::dreamer_consolidation) struct ExtractedPerson {
    pub(in crate::dreamer_consolidation) id: String,
    pub(in crate::dreamer_consolidation) name: String,
    pub(in crate::dreamer_consolidation) evidence_turn_refs: Vec<String>,
}

fn objects<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<serde_json::Value>, D::Error> {
    let items: Vec<serde_json::Map<String, serde_json::Value>> =
        serde::Deserialize::deserialize(deserializer)?;
    Ok(items.into_iter().map(serde_json::Value::Object).collect())
}

/// `response`'s extraction reply, refused unless it has the contract's
/// shape. Its candidates' fields are [`check_extraction_reply`]'s, so a
/// reply stored before that check still reads here.
///
/// One narrow repair runs first: a reply that stopped one `}` short (it
/// parses to the end and ends on the candidates' `]`) gets exactly one `}`
/// appended, and the result must still parse and meet the contract. No
/// other text is mended.
pub(in crate::dreamer_consolidation) fn extraction_reply(
    response: &LlmResponse,
) -> Result<ExtractionReply> {
    contract_reply(reply_json(response)?)
}

/// `response`'s text as JSON, mended only as [`extraction_reply`] says.
pub(in crate::dreamer_consolidation) fn reply_json(
    response: &LlmResponse,
) -> Result<serde_json::Value> {
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let text = text.trim();
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(reply) => Ok(reply),
        Err(error)
            if error.is_eof()
                && response.finish_reason == FinishReason::Stop
                && text.starts_with('{')
                && text.ends_with(']') =>
        {
            serde_json::from_str(&format!("{text}}}"))
                .map_err(|_| invalid_consolidation("extraction response must be JSON"))
        }
        Err(_) => Err(invalid_consolidation("extraction response must be JSON")),
    }
}

/// `reply` as an extraction reply, refused unless it has the contract's
/// shape: each person's id a `new:P<n>` declaration, its name not empty,
/// and one or more well-formed source labels.
pub(in crate::dreamer_consolidation) fn contract_reply(
    reply: serde_json::Value,
) -> Result<ExtractionReply> {
    // A derived struct also reads a JSON array positionally; the contract
    // names objects only.
    let objects = reply.is_object()
        && reply
            .get("persons")
            .and_then(serde_json::Value::as_array)
            .is_none_or(|people| people.iter().all(serde_json::Value::is_object));
    if !objects {
        return Err(invalid_consolidation(
            "extraction response breaks its contract",
        ));
    }
    let reply: ExtractionReply = serde_json::from_value(reply)
        .map_err(|_| invalid_consolidation("extraction response breaks its contract"))?;
    if !reply.persons.iter().all(|person| {
        new_person(&person.id).is_some()
            && !person.name.is_empty()
            && !person.evidence_turn_refs.is_empty()
            && person
                .evidence_turn_refs
                .iter()
                .all(|source| CallLabel::parse(source).is_some())
    }) {
        return Err(invalid_consolidation(
            "extraction response breaks its contract",
        ));
    }
    Ok(reply)
}

/// The extraction step's check: the reply meets the contract, each of its
/// candidates included, or it is refused and never memoized, so the next
/// run asks again. A candidate names a `subject` label (a listed `P<n>` or
/// a declared `new:P<n>`), a string `predicate`, a `value` that is not
/// null, a `confidence` from 0 to 1, and one or more evidence refs of the
/// shape decode reads. A candidate that meets them but breaks a rule (the
/// predicate grammar, a label its call did not show, a source or project the
/// branch must hold) is decode's to skip, never a refusal here.
pub(in crate::dreamer_consolidation) fn check_extraction_reply(
    response: &LlmResponse,
) -> std::result::Result<(), String> {
    let reply = extraction_reply(response).map_err(|error| error.to_string())?;
    for (index, candidate) in reply.candidates.iter().enumerate() {
        if let Some(field) = contract_fault(candidate) {
            return Err(format!(
                "extraction candidate {index} breaks its contract at {field}"
            ));
        }
    }
    Ok(())
}

/// The first contract field `candidate` gets wrong, if any.
fn contract_fault(candidate: &serde_json::Value) -> Option<&'static str> {
    let confidence = candidate
        .get("confidence")
        .and_then(serde_json::Value::as_f64);
    let refs = candidate
        .get("evidence_refs")
        .and_then(serde_json::Value::as_array);
    [
        (
            "subject",
            candidate
                .get("subject")
                .and_then(serde_json::Value::as_str)
                .and_then(SubjectLabel::parse)
                .is_some(),
        ),
        (
            "predicate",
            candidate
                .get("predicate")
                .is_some_and(serde_json::Value::is_string),
        ),
        (
            "value",
            candidate.get("value").is_some_and(|value| !value.is_null()),
        ),
        (
            "confidence",
            confidence.is_some_and(|confidence| (0.0..=1.0).contains(&confidence)),
        ),
        (
            "evidence_refs",
            refs.is_some_and(|refs| {
                !refs.is_empty() && refs.iter().all(|cited| wire_ref(cited).is_ok())
            }),
        ),
        (
            "prospective_queries",
            prospective_queries(candidate).is_ok(),
        ),
    ]
    .into_iter()
    .find_map(|(field, met)| (!met).then_some(field))
}

fn prospective_queries(candidate: &serde_json::Value) -> Result<Vec<String>> {
    let Some(queries) = candidate.get("prospective_queries") else {
        return Ok(Vec::new());
    };
    let queries = queries
        .as_array()
        .ok_or_else(|| invalid_consolidation("prospective_queries must be strings"))?;
    let hints = queries
        .iter()
        .map(|query| {
            query
                .as_str()
                .ok_or_else(|| invalid_consolidation("prospective_queries must be strings"))
        })
        .collect::<Result<Vec<_>>>()?;
    crate::claim::normalize_lexical_query_hints(&hints)
}

/// A 32-hex id. Only a candidate's `rel` that names no listed relationship
/// label still reads one (FIX 7575).
pub(super) fn entity_id_from_hex(hex: &str) -> Option<EntityId> {
    let hex = hex.trim();
    if hex.len() != 32 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut raw = [0_u8; 16];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        raw[index] = (high << 4) | low;
    }
    EntityId::from_bytes(raw).ok()
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// A TURN extraction call's sources: its labels over its branch's pinned
/// sources and the texts its transcript showed.
#[derive(Clone, Copy)]
pub(in crate::dreamer_consolidation) struct CallPins<'r> {
    pub(in crate::dreamer_consolidation) labels: &'r CallLabelMap,
    pub(in crate::dreamer_consolidation) pins: BranchPins<'r>,
}

impl CallSources for CallPins<'_> {
    fn labels(&self) -> &CallLabelMap {
        self.labels
    }

    fn shown(&self, id: EntityId) -> Option<SourceShown<'_>> {
        self.pins.source_version(&id).ok()?;
        Some(SourceShown {
            text: self.pins.cited_text(&id),
            project: self.pins.evidence_project(&[id]).ok().flatten(),
        })
    }
}

/// What one TURN extraction reply is read against: its call's sources and
/// the people the reply declared, bound once for the whole reply.
#[derive(Clone, Copy)]
pub(in crate::dreamer_consolidation) struct ReplyContext<'r> {
    pub(in crate::dreamer_consolidation) call: CallPins<'r>,
    pub(in crate::dreamer_consolidation) people: &'r PersonBindings,
}

/// One evidence ref as the engine binds it.
pub(in crate::dreamer_consolidation) struct BoundRef {
    /// The source its label names, when its call showed one.
    pub(in crate::dreamer_consolidation) source: Option<EntityId>,
    /// Its locator, or the named result it binds none with.
    pub(in crate::dreamer_consolidation) locator:
        std::result::Result<EvidenceLocator, QuoteBinding>,
}

/// An evidence ref's shape: `{"source": label, "quote": words}` with words
/// that are not empty, or `{"claim": label}`; never both, never neither,
/// each label well formed.
enum WireRef<'v> {
    Quote { source: &'v str, quote: &'v str },
    Claim(&'v str),
}

fn wire_ref(value: &serde_json::Value) -> Result<WireRef<'_>> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_consolidation("evidence ref must be an object"))?;
    let quote = object
        .get("quote")
        .map(|quote| {
            quote
                .as_str()
                .ok_or_else(|| invalid_consolidation("evidence quote must be a string"))
        })
        .transpose()?;
    match (
        label_field(object, "source")?,
        quote,
        label_field(object, "claim")?,
    ) {
        (Some(_), Some(""), None) => Err(invalid_consolidation(QuoteBinding::EmptyQuote.name())),
        (Some(source), Some(quote), None) => Ok(WireRef::Quote { source, quote }),
        (None, None, Some(claim)) => Ok(WireRef::Claim(claim)),
        _ => Err(invalid_consolidation(
            "evidence must cite a quote or a claim",
        )),
    }
}

/// `object`'s `key`, when present: a well-formed label, or a shape fault.
fn label_field<'v>(
    object: &'v serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<&'v str>> {
    object
        .get(key)
        .map(|value| {
            value
                .as_str()
                .filter(|text| CallLabel::parse(text).is_some())
                .ok_or_else(|| invalid_consolidation("invalid evidence label"))
        })
        .transpose()
}

/// `value` as an evidence ref bound through `sources`: a quote to the one
/// byte range of its source's shown text it names (an existing TURN text
/// range), a claim label to its listed claim. `Err` is a shape fault; a ref
/// that binds nothing carries its named result.
pub(in crate::dreamer_consolidation) fn decode_ref(
    value: &serde_json::Value,
    sources: &dyn CallSources,
) -> Result<BoundRef> {
    match wire_ref(value)? {
        WireRef::Claim(label) => {
            let claim = sources.labels().resolve_as(LabelKind::Claim, label);
            let locator = match claim {
                Some(claim) => Ok(EvidenceLocator::claim(claim, claim)?),
                None => Err(QuoteBinding::UnknownSourceLabel),
            };
            Ok(BoundRef {
                source: claim,
                locator,
            })
        }
        WireRef::Quote { source, quote } => {
            let named = sources.named(source);
            let source = named.as_ref().map(|(id, _)| *id);
            let locator = match bind_quote(named, quote) {
                QuoteBinding::Bound { source, start, end } => {
                    Ok(EvidenceLocator::turn_range(source, start, end)?)
                }
                fault => Err(fault),
            };
            Ok(BoundRef { source, locator })
        }
    }
}

/// The subject `item` names: a listed entity's label, or a person the reply
/// declared. A well-formed label the call did not list is not admitted, as
/// a person whose declaration bound no id is not (`PersonBindingUnavailable`).
pub(in crate::dreamer_consolidation) fn resolve_subject(
    item: &serde_json::Value,
    labels: &CallLabelMap,
    people: &PersonBindings,
) -> Result<EntityId> {
    let subject = item
        .get("subject")
        .and_then(serde_json::Value::as_str)
        .and_then(SubjectLabel::parse)
        .ok_or_else(|| invalid_consolidation("extracted candidate names no subject"))?;
    match subject {
        SubjectLabel::Listed(label) if label.kind() == LabelKind::Entity => labels
            .resolve(label)
            .ok_or_else(|| invalid_consolidation("extracted candidate names an unlisted subject")),
        SubjectLabel::Listed(_) => Err(invalid_consolidation(
            "extracted candidate names an unlisted subject",
        )),
        SubjectLabel::NewPerson(number) => people.subject(number),
    }
}

/// One candidate's reading of the reply and of the branch's pinned
/// resources, its evidence bound through its call, with the first named
/// result of a ref that bound nothing. The candidate keeps only the refs
/// that bound; the sources of those that did not still face the source and
/// project admission, so a caller can tell whether it would build. An error
/// is this candidate's alone.
pub(in crate::dreamer_consolidation) fn read_candidate<'s>(
    item: &serde_json::Value,
    ctx: ReplyContext<'_>,
    scope: &'s Scope,
) -> Result<(ParsedCandidate<'s>, Option<&'static str>)> {
    // A candidate that names no value carries no claim.
    let value = item
        .get("value")
        .filter(|value| !value.is_null())
        .ok_or_else(|| invalid_consolidation("extracted candidate names no value"))?
        .clone();
    let subject = resolve_subject(item, ctx.call.labels, ctx.people)?;
    // The contract's predicate rule is the claim grammar's.
    let predicate = item
        .get("predicate")
        .and_then(|value| value.as_str())
        .filter(|predicate| crate::claim::validate_predicate(predicate, false).is_ok())
        .map(str::to_owned);
    let confidence = item
        .get("confidence")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.5) as f32;
    let refs = item
        .get("evidence_refs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid_consolidation("candidate evidence_refs must be an array"))?;
    let mut locators = Vec::new();
    let mut sources = Vec::new();
    let mut fault = None;
    for cited in refs {
        let bound = decode_ref(cited, &ctx.call)?;
        sources.extend(bound.source);
        match bound.locator {
            Ok(locator) => locators.push(locator),
            Err(binding) => {
                fault.get_or_insert(binding.name());
            }
        }
    }
    sources.sort_unstable();
    sources.dedup();
    for id in &sources {
        if !scope.allows_read(&ctx.call.pins.source_version(id)?) {
            return Err(invalid_consolidation(
                "extracted evidence crossed its child slice",
            ));
        }
    }
    // A claim drawn from two projects' turns has no one audience, and a
    // project-bound branch writes only its own project's.
    let project = ctx.call.pins.evidence_project(&sources)?.ok_or_else(|| {
        invalid_consolidation("extracted candidate's sources share no one branch project")
    })?;
    let mut evidence_turn_refs: Vec<_> = locators.iter().map(|entry| entry.source_id()).collect();
    evidence_turn_refs.sort_unstable();
    evidence_turn_refs.dedup();
    let parsed = ParsedCandidate {
        scope,
        subject,
        predicate,
        value,
        confidence,
        rel: item
            .get("rel")
            .filter(|value| !value.is_null())
            .map(|value| CandidateRel::read(value, ctx.call.labels)),
        topic: item
            .get("topic_key")
            .filter(|value| !value.is_null())
            .cloned(),
        locators,
        evidence_turn_refs,
        project,
        prospective_queries: prospective_queries(item)?,
    };
    Ok((parsed, fault))
}

/// [`read_candidate`] for decode: a candidate with a ref that bound nothing
/// is not written, under that ref's named result.
pub(in crate::dreamer_consolidation) fn parse_candidate<'s>(
    item: &serde_json::Value,
    ctx: ReplyContext<'_>,
    scope: &'s Scope,
) -> Result<ParsedCandidate<'s>> {
    let (parsed, fault) = read_candidate(item, ctx, scope)?;
    match fault {
        Some(name) => Err(invalid_consolidation(name)),
        None => Ok(parsed),
    }
}

/// A diagnostic side channel for out-of-contract hashes in the raw model
/// response, keyed by the source's call label. The typed child return
/// cannot carry them as evidence authority.
pub(in crate::dreamer_consolidation) fn disagreeing_child_hashes(
    resources: &BranchResources<'_>,
    sources: &dyn CallSources,
    items: &[serde_json::Value],
) -> Vec<EntityId> {
    let mut disagreements = Vec::new();
    for item in items {
        let Some(hashes) = item
            .get("evidence_hashes")
            .and_then(serde_json::Value::as_object)
        else {
            continue;
        };
        let locators: Vec<_> = item
            .get("evidence_refs")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|value| decode_ref(value, sources).ok()?.locator.ok())
            .collect();
        for (key, value) in hashes {
            let id = CallLabel::parse(key).and_then(|label| sources.labels().resolve(label));
            let (Some(id), Some(reported)) = (id, value.as_str()) else {
                continue;
            };
            // A diagnostic is never a new citation and cannot veto a valid
            // judgement. Match only typed citations that the parent can read
            // at its ledger pin; CLAIMs and TURN ranges retain their kind.
            let cited: Vec<_> = locators
                .iter()
                .copied()
                .filter(|locator| locator.source_id() == id)
                .map(EvidenceLocator::reference)
                .collect();
            let Ok(verified) = resources.verify_evidence_refs(&cited) else {
                continue;
            };
            if !verified.is_empty()
                && verified.iter().all(|entry| {
                    !reported.eq_ignore_ascii_case(&bytes_to_hex_lower(&entry.content_hash))
                })
            {
                disagreements.push(id);
            }
        }
    }
    disagreements.sort_unstable();
    disagreements.dedup();
    disagreements
}
