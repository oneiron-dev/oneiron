//! The `.chat` answer verb (OF-228/OF-096): depth-as-cost tiers over
//! [`Memory::recall`], answering only with evidence it can show. Surface
//! re-exported by [`super`].
//!
//! A caller asks in prose and ONE wire value prices the retrieval. This file
//! is orchestration only — it maps [`ChatDepth`] onto the existing [`Effort`]
//! dial, gathers evidence exactly once, and either reads the answer straight
//! out of the returned [`MemoryPack`] (minimal) or hands that pack to a
//! host-injected composer (standard/deep). It never reproduces search limits,
//! scope resolution, PPR, the deep-lease policy, or field profiles: those live
//! in `recall` and stay there.
//!
//! Evidence arrives one of two ways, never both: [`ChatScope::Recall`] ranks
//! the vault through [`Memory::recall`], and [`ChatScope::Documents`] reads
//! the caller's own short-id allowlist through [`Memory::hydrate`] with no
//! fallback to ranked retrieval.
//!
//! Every call ends in exactly one [`ChatResponse`]. An `Answered` carries at
//! least one source short id that exists in the very pack the answer was built
//! from; anything else is a typed `Abstained`. The check is engine-side and
//! fail-closed — a composer that declines, returns blank text, cites nothing,
//! or cites something the pack does not contain abstains, and its answer text
//! never escapes. "Not in memory" is a value here, never an empty string.
//!
//! The engine carries no composition. [`ChatComposer`] is implemented
//! host-side, like `LlmBackend`, so no SDK, model id, prompt text, persona, or
//! product module enters this crate; prompt packages, model selection, and
//! localization remain host configuration.

use super::recall::truncate_text;
use super::*;

use serde::{Deserialize, Serialize};

use crate::context_pack::DEFAULT_MAX_FIELD_CHARS;
use crate::llm::BudgetLease;

/// Wire depth for [`Memory::chat`] — the single cost gate a caller turns.
///
/// Canonical serialization is always `minimal | standard | deep`;
/// [`ChatDepth::parse`] additionally accepts `low | med | high` as INPUT
/// aliases. Deliberately distinct from the `llm.rs` `ReasoningEffort` (the LLM
/// dial) and from `context_pack.rs` `FieldProfile`: this is the retrieval
/// price, expressed in the one [`Effort`] enum it maps onto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatDepth {
    /// Zero-model extractive tier: the pack answers for itself and the
    /// composer is never invoked, so the call reports zero tokens used.
    Minimal,
    /// Graph-expanded retrieval followed by exactly one composer call.
    Standard,
    /// Lease-gated retrieval followed by exactly one composer call. The deep
    /// executor has not landed, so `recall` runs the standard body and stamps
    /// `retrieval_meta.deep_pending`, which travels out untouched.
    Deep,
}

impl ChatDepth {
    /// Parses the wire form, accepting `low | med | high` as aliases for the
    /// canonical values. Exact match, mirroring [`Effort::parse`]: no
    /// trimming and no case folding, so anything else is `None`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "minimal" | "low" => Some(Self::Minimal),
            "standard" | "med" => Some(Self::Standard),
            "deep" | "high" => Some(Self::Deep),
            _ => None,
        }
    }

    /// The canonical string form. Aliases never round-trip back out.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Standard => "standard",
            Self::Deep => "deep",
        }
    }

    /// The retrieval effort this depth prices. `low`/`med`/`high` are aliases
    /// INTO this mapping — never a second effort enum.
    #[must_use]
    pub const fn effort(self) -> Effort {
        match self {
            Self::Minimal => Effort::Minimal,
            Self::Standard => Effort::Standard,
            Self::Deep => Effort::Deep,
        }
    }
}

/// Where one [`Memory::chat`] answer may take its evidence from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatScope {
    /// Ranked retrieval: [`Memory::recall`] picks the evidence under this
    /// scope, forwarded verbatim.
    Recall(RecallScope),
    /// An allowlist: ONLY these documents are read, and only they may be
    /// cited. There is no fallback to ranked retrieval, so a question the
    /// named set cannot answer abstains rather than quietly widening.
    Documents {
        /// OF-096 refs — short refs (`"ms3:a1"`) or 32-hex ids — deduped on
        /// first appearance. Ones that resolve to nothing become gaps.
        source_short_ids: Vec<String>,
    },
}

/// Everything [`Memory::chat`] forwards to its evidence pass, plus the
/// composer the answering tiers need.
pub struct ChatOptions<'a> {
    /// Where the answer may draw evidence from.
    pub scope: ChatScope,
    /// Item ceiling, forwarded verbatim; must be at least 1.
    pub limit: usize,
    /// OF-096 pack format (`toon|md|json|yaml|txt`), forwarded verbatim. When
    /// set, the rendered pack is also the minimal-depth answer. Document
    /// scope renders nothing, but still refuses a format it does not know.
    pub format: Option<&'a str>,
    /// Budget lease, forwarded verbatim to `recall`'s `Deep` gate and to the
    /// composer. Chat is a lease READER: it never settles or aborts one.
    pub lease: Option<&'a BudgetLease>,
    /// Host-injected composer. Required at standard/deep, ignored at minimal.
    pub composer: Option<&'a dyn ChatComposer>,
}

/// What the host composer is handed: the question and the retrieved pack, and
/// nothing else. No vault handle crosses this seam.
pub struct ChatComposeRequest<'a> {
    /// The caller's prose question, exactly as asked.
    pub question: &'a str,
    /// The depth that priced this retrieval.
    pub depth: ChatDepth,
    /// The full pack the evidence pass produced, provenance included. This
    /// exact pack is what the answer's citations are checked against, so an
    /// id it does not carry is an id the answer may not stand on.
    pub pack: &'a MemoryPack,
}

/// What a composer returns: the answer text, the evidence it stands on, what
/// it could not cover, its own token accounting, and its right to refuse.
#[derive(Debug, Clone, PartialEq)]
pub struct ComposedChatAnswer {
    /// The composed answer text. Blank text is never answered.
    pub answer: String,
    /// The short ids the answer cites. The engine validates them against the
    /// pack it handed over; proposing is the composer's whole part in it.
    pub source_short_ids: Vec<String>,
    /// What the evidence could not cover, surfaced verbatim.
    pub gaps: Vec<String>,
    /// Tokens the composer spent. Surfaced verbatim; chat takes no budgeting
    /// action on it.
    pub tokens_used: u32,
    /// The composer's own refusal to answer, which is a typed abstention
    /// ([`ChatAbstentionReason::BackendDeclined`]) and never an error.
    pub declined: bool,
}

/// The host-injected, provider-neutral composition seam.
///
/// Implementations live above the engine (the `LlmBackend` precedent). The
/// lease arrives as the opaque admission token the caller already held; the
/// implementation must not settle or abort it either.
pub trait ChatComposer: Send + Sync {
    /// Turns one retrieved pack into one answer. Called at most once per
    /// [`Memory::chat`] call, and never at minimal depth.
    fn compose(
        &self,
        request: &ChatComposeRequest<'_>,
        lease: Option<&BudgetLease>,
    ) -> MemoryResult<ComposedChatAnswer>;
}

/// Why a `.chat` call answered nothing. Each reason is a fact about the
/// evidence or the composer, so a caller can tell "the vault does not know"
/// apart from "the host would not say".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatAbstentionReason {
    /// The retrieval carried nothing, or the proposed answer could not be
    /// tied to the pack it was built from.
    InsufficientEvidence,
    /// Document scope: not one of the named refs resolved, so there was
    /// nothing in scope to read — and ranked retrieval is not a fallback.
    NoInScopeDocuments,
    /// The composer declined to answer.
    BackendDeclined,
}

/// One `.chat` outcome: answered with its evidence, or abstained with a
/// reason. There is no third state and no ambiguous empty answer.
///
/// `Answered.retrieval` carries the WHOLE [`MemoryPack`] — items, scope
/// honesty, retrieval accounting, provenance — because an answer a caller
/// cannot audit is not an answer, and every id in `source_short_ids` is one of
/// that pack's own item short ids, hydratable through [`Memory::hydrate`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ChatResponse {
    /// An answer that shows its sources.
    Answered {
        /// The answer text: extractive at minimal, composed at standard/deep.
        /// Never blank.
        answer: String,
        /// The pack item short ids this answer cites, deduped in first
        /// appearance order. Never empty.
        #[serde(rename = "sourceShortIds")]
        source_short_ids: Vec<String>,
        /// What the evidence did not cover.
        gaps: Vec<String>,
        /// Zero at minimal; the composer's own figure at standard/deep.
        #[serde(rename = "tokensUsed")]
        tokens_used: u32,
        /// The depth that priced this call.
        depth: ChatDepth,
        /// The retrieval this answer stands on.
        retrieval: MemoryPack,
    },
    /// A refusal to answer, typed rather than empty.
    Abstained {
        /// Why nothing was answered.
        reason: ChatAbstentionReason,
        /// What was missing: unresolved documents, and any gap the composer
        /// reported before it was set aside.
        gaps: Vec<String>,
        /// Zero when no composer ran; the composer's own figure when one did.
        #[serde(rename = "tokensUsed")]
        tokens_used: u32,
    },
}

impl Memory<'_> {
    /// Answers `question` at the requested [`ChatDepth`], or abstains.
    ///
    /// A thin orchestration, in this order: validate (nonblank question,
    /// `limit >= 1`, composer present at standard/deep), gather the evidence
    /// exactly once — [`Memory::recall`] with the mapped [`Effort`] under
    /// [`ChatScope::Recall`], the caller's own allowlist under
    /// [`ChatScope::Documents`] — then derive the answer from THAT pack.
    ///
    /// Evidence comes first and the composer runs only behind it: an empty
    /// pack abstains before any composition is attempted, so a host is never
    /// handed the chance to answer from nothing. Minimal reads the pack —
    /// rendered text when a format was requested, else the first item's
    /// `value_text` — cites every item in it, and never touches the composer.
    /// Standard and deep call the composer exactly once, after retrieval.
    ///
    /// Whatever proposed the answer, its citations are checked against the
    /// pack that was actually supplied: an answer that cannot show a source
    /// out of that pack abstains and its text is dropped here.
    ///
    /// The composer requirement is checked BEFORE any retrieval, so a
    /// misconfigured host pays nothing for the refusal. The lease rule is NOT
    /// checked here: deep recall forwards the lease and `recall`'s own typed
    /// `LEASE_REQUIRED` gate decides, keeping one authority for it. Document
    /// scope buys no ranked retrieval at any depth, so that gate — which
    /// prices retrieval — is not on its path.
    pub fn chat(
        &self,
        question: &str,
        depth: ChatDepth,
        options: ChatOptions<'_>,
    ) -> MemoryResult<ChatResponse> {
        if question.trim().is_empty() {
            return Err(MemoryError::bad_request_with(
                "chat question must not be blank",
                &["Send the caller's question text with the request."],
            ));
        }
        if options.limit == 0 {
            return Err(MemoryError::bad_request_with(
                "chat limit must be at least 1",
                &["Ask for at least one memory item."],
            ));
        }
        // Resolved before retrieval: at standard/deep a missing composer is a
        // request the host cannot answer at any price, and at minimal the
        // composer is structurally out of reach even when one is supplied.
        let composer = match depth {
            ChatDepth::Minimal => None,
            ChatDepth::Standard | ChatDepth::Deep => match options.composer {
                Some(composer) => Some(composer),
                None => {
                    return Err(MemoryError::bad_request_with(
                        format!("{} chat requires a composer", depth.as_str()),
                        &[
                            "Inject a ChatComposer as ChatOptions.composer.",
                            "Or ask at minimal depth for a zero-model extractive answer.",
                        ],
                    ));
                }
            },
        };

        let (pack, mut gaps) = match &options.scope {
            ChatScope::Recall(scope) => {
                let pack = self.recall(
                    question,
                    depth.effort(),
                    scope,
                    options.limit,
                    options.format,
                    options.lease,
                )?;
                (pack, Vec::new())
            }
            ChatScope::Documents { source_short_ids } => {
                self.document_pack(source_short_ids, options.limit, options.format)?
            }
        };

        // The evidence floor, ahead of every composer: nothing retrieved is
        // nothing to answer from, and which emptiness it was stays visible.
        if pack.items.is_empty() {
            let reason = match &options.scope {
                ChatScope::Recall(_) => ChatAbstentionReason::InsufficientEvidence,
                ChatScope::Documents { .. } => ChatAbstentionReason::NoInScopeDocuments,
            };
            return Ok(ChatResponse::Abstained {
                reason,
                gaps,
                tokens_used: 0,
            });
        }

        let (answer, proposed, tokens_used): (String, Vec<String>, u32) = match composer {
            None => (extractive_answer(&pack), pack_short_ids(&pack), 0),
            Some(composer) => {
                let composed = composer.compose(
                    &ChatComposeRequest {
                        question,
                        depth,
                        pack: &pack,
                    },
                    options.lease,
                )?;
                gaps.extend(composed.gaps);
                if composed.declined {
                    return Ok(ChatResponse::Abstained {
                        reason: ChatAbstentionReason::BackendDeclined,
                        gaps,
                        tokens_used: composed.tokens_used,
                    });
                }
                let tokens_used = composed.tokens_used;
                (composed.answer, composed.source_short_ids, tokens_used)
            }
        };

        // Fail-closed, and the answer text stops here when it fails: text with
        // nothing to stand on is the exact outcome this verb exists to refuse.
        if answer.trim().is_empty() {
            return Ok(ChatResponse::Abstained {
                reason: ChatAbstentionReason::InsufficientEvidence,
                gaps,
                tokens_used,
            });
        }
        let Some(source_short_ids) = validate_answer_sources(&pack, &proposed) else {
            return Ok(ChatResponse::Abstained {
                reason: ChatAbstentionReason::InsufficientEvidence,
                gaps,
                tokens_used,
            });
        };

        Ok(ChatResponse::Answered {
            answer,
            source_short_ids,
            gaps,
            tokens_used,
            depth,
            retrieval: pack,
        })
    }

    /// The [`ChatScope::Documents`] evidence: the caller's own refs, read
    /// through the existing [`Memory::hydrate`] surface and nothing else.
    ///
    /// Refs are deduped on first appearance and read in that order up to
    /// `limit`. A well-formed ref that resolves to nothing is a gap rather
    /// than an error, so one stale id cannot sink a question the rest of the
    /// set answers; a ref that is no OF-096 ref at all stays the caller's own
    /// typed refusal. No ranked retrieval runs on this path, so the pack is
    /// typed-only — as on recall's facet-strict path — and claims no
    /// retrieval accounting it did not earn.
    fn document_pack(
        &self,
        source_short_ids: &[String],
        limit: usize,
        format: Option<&str>,
    ) -> MemoryResult<(MemoryPack, Vec<String>)> {
        if let Some(format) = format {
            ensure_pack_format(format)?;
        }
        let mut requested: Vec<&String> = Vec::new();
        for reference in source_short_ids {
            if !requested.contains(&reference) {
                requested.push(reference);
            }
        }

        let mut items: Vec<MemoryItem> = Vec::new();
        let mut gaps: Vec<String> = Vec::new();
        for (index, reference) in requested.iter().enumerate() {
            if items.len() == limit {
                for unread in &requested[index..] {
                    gaps.push(format!("document {unread:?} past the limit of {limit}"));
                }
                break;
            }
            match self.hydrate(std::slice::from_ref(*reference)) {
                Ok(views) => items.extend(views.iter().map(document_item)),
                Err(err) if err.code == MEMORY_CODE_NOT_FOUND => {
                    gaps.push(format!("document {reference:?} does not resolve"));
                }
                Err(err) => return Err(err),
            }
        }

        let claims_returned = items.iter().filter(|item| item.kind == "CLAIM").count() as u64;
        let total_candidates = items.len() as u64;
        Ok((
            MemoryPack {
                items,
                scope_honesty: ScopeHonesty::default(),
                retrieval_meta: RetrievalMeta {
                    sparse: None,
                    total_candidates,
                    claims_returned,
                    deep_pending: None,
                },
                pack_version: MEMORY_PACK_VERSION,
                rendered: None,
            },
            gaps,
        ))
    }
}

/// The minimal-depth answer: rendered pack, else the first item's text. Blank
/// text abstains at the call site, so an empty pack never becomes an answer.
fn extractive_answer(pack: &MemoryPack) -> String {
    if let Some(rendered) = &pack.rendered {
        return rendered.clone();
    }
    match pack.items.first() {
        Some(item) => item.value_text.clone(),
        None => String::new(),
    }
}

/// The citation gate: every proposed short id must be one the supplied pack
/// actually carries, and at least one must remain. `None` means "this answer
/// cannot be shown", and the caller abstains.
///
/// All-or-nothing on purpose. An unknown or blank citation is not quietly
/// dropped to salvage the rest, because a composer citing something the pack
/// never contained has already shown that its sourcing cannot be trusted for
/// the citations that happen to match. Survivors keep first appearance and
/// duplicates collapse.
fn validate_answer_sources(pack: &MemoryPack, proposed: &[String]) -> Option<Vec<String>> {
    let items = &pack.items;
    let mut sources: Vec<String> = Vec::new();
    for candidate in proposed {
        if candidate.trim().is_empty() {
            return None;
        }
        if !items.iter().any(|item| item.short_id == *candidate) {
            return None;
        }
        if !sources.contains(candidate) {
            sources.push(candidate.clone());
        }
    }
    if sources.is_empty() {
        return None;
    }
    Some(sources)
}

/// Every short id the pack carries, in pack order: what an extractive answer
/// cites, since it was read out of the pack as a whole.
fn pack_short_ids(pack: &MemoryPack) -> Vec<String> {
    let mut short_ids = Vec::with_capacity(pack.items.len());
    for item in &pack.items {
        short_ids.push(item.short_id.clone());
    }
    short_ids
}

/// One in-scope document as a pack item, mirroring `recall`'s own non-claim
/// item: the entity's content text, `record` provenance, and the revision it
/// was read at. The caller named this document, so nothing here is a ranked
/// guess and no score is invented for it.
fn document_item(view: &EntityView) -> MemoryItem {
    let content = view.body.as_ref().and_then(|body| body.get("content"));
    let value_text = match (content.and_then(serde_json::Value::as_str), &view.body) {
        (Some(text), _) => text.to_owned(),
        (None, Some(body)) => serde_json::to_string(body).unwrap_or_default(),
        (None, None) => String::new(),
    };
    let short_id = match &view.short_ref {
        Some(short_ref) => short_ref.clone(),
        None => view.id_hex.clone(),
    };
    MemoryItem {
        short_id,
        kind: view.kind.clone(),
        predicate: None,
        value_text: truncate_text(&value_text, DEFAULT_MAX_FIELD_CHARS),
        confidence: 1.0,
        // The bucket recall stamps for a structural record's certainty of 1.0.
        hedge_bucket: "confident".to_owned(),
        provenance: MemoryProvenance {
            source: "record".to_owned(),
            source_revision_ids: vec![view.id_hex.clone()],
            evidence_turn_ids: Vec::new(),
        },
        world: None,
        facet: None,
        salience: None,
    }
}

/// The OF-096 format vocabulary, refused in `recall`'s own words.
///
/// Document scope renders nothing, but a format the engine does not know is
/// still the same typed refusal on both scopes rather than an argument
/// silently ignored.
fn ensure_pack_format(format: &str) -> MemoryResult<()> {
    match format {
        "toon" | "md" | "json" | "yaml" | "txt" => Ok(()),
        other => Err(MemoryError::bad_request_with(
            format!("unknown pack format {other:?}"),
            &["Use one of: toon, md, json, yaml, txt."],
        )),
    }
}

#[cfg(test)]
mod tests;
