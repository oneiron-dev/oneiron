//! The `.chat` answer verb (OF-228): depth-as-cost tiers over
//! [`Memory::recall`]. Surface re-exported by [`super`].
//!
//! A caller asks in prose and ONE wire value prices the retrieval. This file
//! is orchestration only — it maps [`ChatDepth`] onto the existing [`Effort`]
//! dial, calls [`Memory::recall`] exactly once, and either reads the answer
//! straight out of the returned [`MemoryPack`] (minimal) or hands that pack to
//! a host-injected composer (standard/deep). It never reproduces search
//! limits, scope resolution, PPR, the deep-lease policy, or field profiles:
//! those live in `recall` and stay there.
//!
//! The engine carries no composition. [`ChatComposer`] is implemented
//! host-side, like `LlmBackend`, so no SDK, model id, prompt text, persona, or
//! product module enters this crate; prompt packages, model selection, and
//! localization remain host configuration.

use super::*;

use serde::{Deserialize, Serialize};

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

/// Everything [`Memory::chat`] forwards to [`Memory::recall`], plus the
/// composer the answering tiers need.
pub struct ChatOptions<'a> {
    /// Recall scope, forwarded verbatim.
    pub scope: &'a RecallScope,
    /// Item ceiling, forwarded verbatim; must be at least 1.
    pub limit: usize,
    /// OF-096 pack format (`toon|md|json|yaml|txt`), forwarded verbatim. When
    /// set, the rendered pack is also the minimal-depth answer.
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
    /// The full pack `recall` returned, provenance included.
    pub pack: &'a MemoryPack,
}

/// What a composer returns: the answer text and its own token accounting.
#[derive(Debug, Clone, PartialEq)]
pub struct ComposedChatDraft {
    /// The composed answer text.
    pub answer: String,
    /// Tokens the composer spent. Surfaced verbatim; chat takes no budgeting
    /// action on it.
    pub tokens_used: u32,
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
    ) -> MemoryResult<ComposedChatDraft>;
}

/// One `.chat` answer.
///
/// `retrieval` carries the WHOLE [`MemoryPack`] — items, scope honesty,
/// retrieval accounting, provenance — because an answer a caller cannot audit
/// is not an answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatDraft {
    /// The answer text: extractive at minimal, composed at standard/deep.
    pub answer: String,
    /// The depth that priced this call.
    pub depth: ChatDepth,
    /// The retrieval this answer stands on.
    pub retrieval: MemoryPack,
    /// Zero at minimal; the composer's own figure at standard/deep.
    pub tokens_used: u32,
}

impl Memory<'_> {
    /// Answers `question` at the requested [`ChatDepth`].
    ///
    /// A thin orchestration, in this order: validate (nonblank question,
    /// `limit >= 1`, composer present at standard/deep), call
    /// [`Memory::recall`] exactly once with the mapped [`Effort`], then derive
    /// the answer. Minimal reads the pack — rendered text when a format was
    /// requested, else the first item's `value_text`, else the empty string —
    /// and never touches the composer. Standard and deep call the composer
    /// exactly once, after retrieval.
    ///
    /// The composer requirement is checked BEFORE any retrieval, so a
    /// misconfigured host pays nothing for the refusal. The lease rule is NOT
    /// checked here: deep forwards the lease and `recall`'s own typed
    /// `LEASE_REQUIRED` gate decides, keeping one authority for it.
    pub fn chat(
        &self,
        question: &str,
        depth: ChatDepth,
        options: ChatOptions<'_>,
    ) -> MemoryResult<ChatDraft> {
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

        let pack = self.recall(
            question,
            depth.effort(),
            options.scope,
            options.limit,
            options.format,
            options.lease,
        )?;

        let (answer, tokens_used) = match composer {
            None => (extractive_answer(&pack), 0),
            Some(composer) => {
                let composed = composer.compose(
                    &ChatComposeRequest {
                        question,
                        depth,
                        pack: &pack,
                    },
                    options.lease,
                )?;
                (composed.answer, composed.tokens_used)
            }
        };

        Ok(ChatDraft {
            answer,
            depth,
            retrieval: pack,
            tokens_used,
        })
    }
}

/// The minimal-depth answer: rendered pack, else the first item's text, else
/// empty. An empty pack is a successful empty answer, never an error.
fn extractive_answer(pack: &MemoryPack) -> String {
    if let Some(rendered) = &pack.rendered {
        return rendered.clone();
    }
    match pack.items.first() {
        Some(item) => item.value_text.clone(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests;
