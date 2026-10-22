//! Call-local labels (FIX 7506, ARCH-0026 row 1): what one model call shows
//! in place of every id. The engine owns every id. A call's prompt names each
//! listed entity, claim, turn, note, conversation or other source by a short
//! label (`P1`, `C1`, `T1`, `N1`, `V1`, `S1`), numbered from 1 per prefix in
//! the order the call renders them, and its reply's labels are read back
//! through the SAME map, built from the call's admitted, pinned inputs before
//! they rendered. A label is never a durable id, never allocated beyond its
//! call, and never confers a read: it names only what its call showed.
//!
//! A reply declares a new person as `new:P1`, a namespace of its own, apart
//! from the listed `P1`; the engine binds each declaration to an id it
//! derives (`extracted_people::bindings`).
//!
//! An extraction call lists the relationships a candidate may hold within
//! as `R1`, `R2` (FIX 7575, [`relationships`]); a candidate's `rel` names
//! one by that label and reads back to its relationship id.
//!
//! A decision read (FIX 7506 P2) names its questions `Q1`, `Q2`, and shows a
//! choice's options as its call registered them, each listed claim by its
//! `C` label; the read answers the canonical option at the same index, so
//! questions, options, answers and receipts stay canonical.
//!
//! The map binds into its request's identity: a digest of its sorted
//! `(label, id)` table, the wire version and the person-mint namespace rides
//! in the host's own provider-options namespace, which no adapter reads. Two
//! calls that read alike but bind their labels to other ids are two requests,
//! so a memoized reply is never read against another call's map.

use std::collections::BTreeMap;
use std::fmt;

use crate::EntityId;
use crate::entity_id::bytes_to_hex_lower;
use crate::llm::LlmRequest;
use crate::llm::decision::DecisionWireLabels;

mod decision_rungs;
mod relationships;
pub(super) use decision_rungs::LabelledRungs;
pub(super) use relationships::{CandidateRel, relationship_lines};

/// The key a call's label binding rides under in the host's own
/// provider-options namespace.
const CALL_LABELS_KEY: &str = "call_labels";
/// The label wire's version: a new wire is a new request.
const CALL_LABELS_VERSION: u64 = 1;
/// The domain of a label map's digest.
const DIGEST_DOMAIN: &[u8] = b"oneiron:dreamer-call-labels:v1";
/// How a reply names a person it declares.
const NEW_PERSON: &str = "new:";

/// What a label names, by its one-letter prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum LabelKind {
    /// `P`: a listed entity, a person, an organisation or a place.
    Entity,
    /// `C`: a listed claim.
    Claim,
    /// `T`: a turn.
    Turn,
    /// `N`: a note.
    Note,
    /// `V`: the conversation.
    Conversation,
    /// `S`: another source, such as the MESSAGE a sieve span indexes.
    Source,
    /// `R`: a relationship a listed claim or the branch holds within.
    Relationship,
    /// `Q`: a decision read's question, its paired and person questions too.
    /// Only that read names one back ([`DecisionWireLabels`]); a reply's
    /// own label never parses as a question.
    Question,
}

impl LabelKind {
    const fn prefix(self) -> char {
        match self {
            Self::Entity => 'P',
            Self::Claim => 'C',
            Self::Turn => 'T',
            Self::Note => 'N',
            Self::Conversation => 'V',
            Self::Source => 'S',
            Self::Relationship => 'R',
            Self::Question => 'Q',
        }
    }

    const fn of(prefix: u8) -> Option<Self> {
        match prefix {
            b'P' => Some(Self::Entity),
            b'C' => Some(Self::Claim),
            b'T' => Some(Self::Turn),
            b'N' => Some(Self::Note),
            b'V' => Some(Self::Conversation),
            b'S' => Some(Self::Source),
            b'R' => Some(Self::Relationship),
            _ => None,
        }
    }
}

/// One label as a call writes it: a prefix letter, then its number from 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct CallLabel {
    kind: LabelKind,
    number: usize,
}

impl CallLabel {
    /// `text` as a label: one prefix letter, then a number from 1 in plain
    /// decimal (no sign, no leading zero). Whitespace around it is ignored,
    /// as it was around a hex id; anything else is no label.
    pub(super) fn parse(text: &str) -> Option<Self> {
        Self::parse_exact(text.trim())
    }

    fn parse_exact(text: &str) -> Option<Self> {
        let (&prefix, digits) = text.as_bytes().split_first()?;
        Self::numbered(LabelKind::of(prefix)?, digits)
    }

    /// `text`, exactly, as a label of `kind`.
    fn parse_kind(text: &str, kind: LabelKind) -> Option<Self> {
        let (&prefix, digits) = text.as_bytes().split_first()?;
        if char::from(prefix) != kind.prefix() {
            return None;
        }
        Self::numbered(kind, digits)
    }

    fn numbered(kind: LabelKind, digits: &[u8]) -> Option<Self> {
        if digits.first().is_none_or(|digit| *digit == b'0')
            || !digits.iter().all(u8::is_ascii_digit)
        {
            return None;
        }
        let number = std::str::from_utf8(digits).ok()?.parse().ok()?;
        Some(Self { kind, number })
    }

    pub(super) const fn kind(self) -> LabelKind {
        self.kind
    }
}

impl fmt::Display for CallLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.kind.prefix(), self.number)
    }
}

/// A claim's subject as a reply names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SubjectLabel {
    /// A label its call listed.
    Listed(CallLabel),
    /// `new:P<n>`: the person the reply itself declares as its `n`th.
    NewPerson(usize),
}

impl SubjectLabel {
    /// `text` as a subject, or `None` when it is neither a label nor a
    /// person declaration's.
    pub(super) fn parse(text: &str) -> Option<Self> {
        match new_person(text) {
            Some(number) => Some(Self::NewPerson(number)),
            None => CallLabel::parse(text).map(Self::Listed),
        }
    }
}

/// `text` as a person declaration's id, `new:P<n>`: its `n`.
pub(super) fn new_person(text: &str) -> Option<usize> {
    let label = CallLabel::parse_exact(text.trim().strip_prefix(NEW_PERSON)?)?;
    (label.kind == LabelKind::Entity).then_some(label.number)
}

/// One call's labels, both ways. Built per call from its admitted inputs,
/// never shared with another call and never stored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct CallLabelMap {
    /// Each kind's ids in the order their labels were assigned: the id at
    /// index `i` is labelled `i + 1`.
    ids: BTreeMap<LabelKind, Vec<EntityId>>,
    /// Each labelled id's number, by kind.
    numbers: BTreeMap<(LabelKind, EntityId), usize>,
    /// Each choice question's options as its call shows them, by index.
    choices: BTreeMap<EntityId, Vec<String>>,
}

impl CallLabelMap {
    /// `id`'s label of `kind`, assigned now when it has none: the next
    /// number of that kind, so labels follow the order the call renders.
    pub(super) fn assign(&mut self, kind: LabelKind, id: EntityId) -> CallLabel {
        if let Some(number) = self.numbers.get(&(kind, id)) {
            return CallLabel {
                kind,
                number: *number,
            };
        }
        let ids = self.ids.entry(kind).or_default();
        ids.push(id);
        let number = ids.len();
        self.numbers.insert((kind, id), number);
        CallLabel { kind, number }
    }

    /// `id`'s label of `kind`, when the call labelled it so.
    pub(super) fn label(&self, kind: LabelKind, id: EntityId) -> Option<CallLabel> {
        self.numbers.get(&(kind, id)).map(|number| CallLabel {
            kind,
            number: *number,
        })
    }

    /// Each id this call labelled as `kind`, with its label, in label order.
    pub(super) fn labelled(&self, kind: LabelKind) -> impl Iterator<Item = (CallLabel, EntityId)> {
        self.ids
            .get(&kind)
            .into_iter()
            .flatten()
            .enumerate()
            .map(move |(index, id)| {
                (
                    CallLabel {
                        kind,
                        number: index + 1,
                    },
                    *id,
                )
            })
    }

    /// The id `label` names in this call, when it names one.
    pub(super) fn resolve(&self, label: CallLabel) -> Option<EntityId> {
        self.ids
            .get(&label.kind)?
            .get(label.number.checked_sub(1)?)
            .copied()
    }

    /// The id `text` names as a label of `kind` in this call.
    pub(super) fn resolve_as(&self, kind: LabelKind, text: &str) -> Option<EntityId> {
        CallLabel::parse(text)
            .filter(|label| label.kind == kind)
            .and_then(|label| self.resolve(label))
    }

    /// Registers how the call shows `question`'s choice options: `shown[i]`
    /// in place of its option at index `i`.
    pub(super) fn show_choices(&mut self, question: EntityId, shown: Vec<String>) {
        self.choices.insert(question, shown);
    }

    /// Binds this map into `request`'s identity: the wire version and a
    /// digest of the person-mint namespace `mint` (when the reply may
    /// declare people) and of the sorted `(label, id)` table, in the host's
    /// own provider-options namespace. No id reaches the model's text.
    pub(super) fn bind_request(&self, request: &mut LlmRequest, mint: Option<&[u8]>) {
        let options = request
            .provider_options
            .entry(crate::code_run::HOST_PROVIDER_OPTIONS.to_owned())
            .or_insert(serde_json::Value::Null);
        if !options.is_object() {
            *options = serde_json::Value::Object(serde_json::Map::new());
        }
        if let serde_json::Value::Object(options) = options {
            options.insert(
                CALL_LABELS_KEY.to_owned(),
                serde_json::json!({
                    "version": CALL_LABELS_VERSION,
                    "digest": bytes_to_hex_lower(&self.digest(mint)),
                }),
            );
        }
    }

    fn digest(&self, mint: Option<&[u8]>) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DIGEST_DOMAIN);
        match mint {
            Some(mint) => {
                hasher.update(&[1]);
                hasher.update(&(mint.len() as u64).to_be_bytes());
                hasher.update(mint);
            }
            None => {
                hasher.update(&[0]);
            }
        }
        for (kind, ids) in &self.ids {
            for (index, id) in ids.iter().enumerate() {
                let label = CallLabel {
                    kind: *kind,
                    number: index + 1,
                }
                .to_string();
                hasher.update(&(label.len() as u64).to_be_bytes());
                hasher.update(label.as_bytes());
                hasher.update(id.as_bytes());
            }
        }
        // A map that shows no choice digests as it did before choices were
        // shown (FIX 7506 P1's extraction, NOTE and listing calls).
        for (question, shown) in &self.choices {
            hasher.update(b"choices");
            hasher.update(question.as_bytes());
            hasher.update(&(shown.len() as u64).to_be_bytes());
            for option in shown {
                hasher.update(&(option.len() as u64).to_be_bytes());
                hasher.update(option.as_bytes());
            }
        }
        *hasher.finalize().as_bytes()
    }
}

/// A decision read's wire through this call's map: its questions by their
/// `Q` labels, its choices as registered.
impl DecisionWireLabels for CallLabelMap {
    fn question_label(&self, question: EntityId) -> Option<String> {
        self.label(LabelKind::Question, question)
            .map(|label| label.to_string())
    }

    /// Exact: a reply key reads back only as the label the request wrote.
    fn question_for_label(&self, label: &str) -> Option<EntityId> {
        CallLabel::parse_kind(label, LabelKind::Question).and_then(|label| self.resolve(label))
    }

    fn choice_option(&self, question: EntityId, index: usize, _option: &str) -> Option<String> {
        self.choices.get(&question)?.get(index).cloned()
    }

    fn bind(&self, request: &mut LlmRequest) {
        self.bind_request(request, None);
    }
}

/// What a call showed of one source its labels name.
pub(super) struct SourceShown<'t> {
    /// The text the call showed: the text a quote binds against.
    pub(super) text: Option<&'t str>,
    /// The project the source is admitted under, when it has exactly one.
    pub(super) project: Option<EntityId>,
}

/// One call's labels over the sources it showed: what its reply's labels
/// and quotes bind against.
pub(super) trait CallSources {
    /// The call's labels.
    fn labels(&self) -> &CallLabelMap;

    /// What the call showed of `id`; `None` for an id it showed no source as.
    fn shown(&self, id: EntityId) -> Option<SourceShown<'_>>;

    /// The source a reply's `label` names: a turn, note or other source
    /// label of this call, with what the call showed of it.
    fn named(&self, label: &str) -> Option<(EntityId, SourceShown<'_>)> {
        let label = CallLabel::parse(label)?;
        if !matches!(
            label.kind,
            LabelKind::Turn | LabelKind::Note | LabelKind::Source
        ) {
            return None;
        }
        let id = self.labels().resolve(label)?;
        Some((id, self.shown(id)?))
    }
}
