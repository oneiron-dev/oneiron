//! The `ContextSpec` descriptor, its bounds, normalization, and structural validation.

use serde::{Deserialize, Serialize};

use crate::error::{ArtifactError, Error, RecordError, Result};

/// Most layer names one projection may name.
pub const CONTEXT_SPEC_MAX_LAYERS: usize = 32;

/// Most memory domains one scoped projection may name.
pub const CONTEXT_SPEC_MAX_DOMAINS: usize = 32;

/// Byte cap on a layer name or memory domain token.
pub const CONTEXT_SPEC_MAX_LABEL_BYTES: usize = 256;

/// Byte cap on free-form descriptor text (briefing, annotation, instructions).
pub const CONTEXT_SPEC_MAX_TEXT_BYTES: usize = 8192;

/// Hard ceiling on a scoped memory projection's `limit`.
pub const CONTEXT_SPEC_MAX_MEMORY_LIMIT: usize = 256;

/// Hard ceiling on a recent-chat projection's `last_n`.
pub const CONTEXT_SPEC_MAX_CHAT_LAST_N: usize = 256;

/// Sections a `MemoryProjection::Default` resolves to at a root dispatch.
pub const CONTEXT_SPEC_DEFAULT_MEMORY_LIMIT: usize = 32;

/// Sections a `ChatProjection::Default` resolves to at a root dispatch.
pub const CONTEXT_SPEC_DEFAULT_CHAT_LAST_N: usize = 16;

/// A projection DESCRIPTOR. It names what a delegated agent may see; it never
/// carries the content itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextSpec {
    #[serde(default)]
    pub layers: Vec<String>,
    #[serde(default)]
    pub memory: MemoryProjection,
    #[serde(default)]
    pub chat: ChatProjection,
    #[serde(default)]
    pub briefing: Option<String>,
    /// Dev-only authoring note. Stripped at resolution — it never reaches a
    /// [`ResolvedContextProjection`] and therefore never reaches a prompt.
    #[serde(
        rename = "_annotation",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub annotation: Option<String>,
}

impl Default for ContextSpec {
    fn default() -> Self {
        Self {
            layers: Vec::new(),
            memory: MemoryProjection::Default,
            chat: ChatProjection::Default,
            briefing: None,
            annotation: None,
        }
    }
}

impl ContextSpec {
    /// The everything-excluded descriptor: the narrowest legal projection.
    #[must_use]
    pub fn excluded() -> Self {
        Self {
            layers: Vec::new(),
            memory: MemoryProjection::Exclude,
            chat: ChatProjection::Exclude,
            briefing: None,
            annotation: None,
        }
    }

    /// Adds parent-authored delegation text. Briefing grants no read scope.
    #[must_use]
    pub fn with_briefing(mut self, briefing: impl Into<String>) -> Self {
        self.briefing = Some(briefing.into());
        self
    }
}

/// How much of the parent's memory the delegate may project.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum MemoryProjection {
    /// Inherit the parent's projection verbatim (the widest legal request).
    #[default]
    Default,
    Exclude,
    Scoped {
        domains: Vec<String>,
        limit: usize,
    },
}

/// How much of the parent's chat history the delegate may project.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ChatProjection {
    #[default]
    Default,
    Exclude,
    Recent {
        last_n: usize,
    },
}

/// `self.context(spec)` — the identity call. It returns the spec as-is because
/// it IS a descriptor: resolution happens at dispatch time so data is fresh,
/// not stale. It reads no memory, consumes no budget, and resolves no text.
#[must_use]
pub fn context(spec: ContextSpec) -> ContextSpec {
    spec
}

/// Canonicalizes a descriptor without changing its meaning: trims tokens, drops
/// blanks, and dedupes while preserving caller order. Idempotent.
#[must_use]
pub fn normalize_context_spec(spec: ContextSpec) -> ContextSpec {
    ContextSpec {
        layers: normalize_tokens(spec.layers),
        memory: match spec.memory {
            MemoryProjection::Scoped { domains, limit } => MemoryProjection::Scoped {
                domains: normalize_tokens(domains),
                limit,
            },
            mode @ (MemoryProjection::Default | MemoryProjection::Exclude) => mode,
        },
        chat: spec.chat,
        briefing: normalize_text(spec.briefing),
        annotation: normalize_text(spec.annotation),
    }
}

/// Structural validation of one descriptor, independent of any parent.
pub fn validate_context_spec(spec: &ContextSpec) -> Result<()> {
    if spec.layers.len() > CONTEXT_SPEC_MAX_LAYERS {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            "context spec names too many layers",
        )));
    }
    for layer in &spec.layers {
        validate_label(
            layer,
            "context spec layer name must be non-empty and bounded",
        )?;
    }
    match &spec.memory {
        MemoryProjection::Default | MemoryProjection::Exclude => {}
        MemoryProjection::Scoped { domains, limit } => {
            if domains.is_empty() {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "scoped memory projection must name at least one domain",
                )));
            }
            if domains.len() > CONTEXT_SPEC_MAX_DOMAINS {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "scoped memory projection names too many domains",
                )));
            }
            for domain in domains {
                validate_label(
                    domain,
                    "memory domain must be non-empty, bounded, and separator-free",
                )?;
                if domain.contains(':') {
                    return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "memory domain must be non-empty, bounded, and separator-free",
                    )));
                }
            }
            if *limit == 0 || *limit > CONTEXT_SPEC_MAX_MEMORY_LIMIT {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "scoped memory projection limit is out of range",
                )));
            }
        }
    }
    match &spec.chat {
        ChatProjection::Default | ChatProjection::Exclude => {}
        ChatProjection::Recent { last_n } => {
            if *last_n == 0 || *last_n > CONTEXT_SPEC_MAX_CHAT_LAST_N {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "recent chat projection last_n is out of range",
                )));
            }
        }
    }
    validate_optional_text(
        spec.briefing.as_deref(),
        "context spec briefing is too long",
    )?;
    validate_optional_text(
        spec.annotation.as_deref(),
        "context spec annotation is too long",
    )
}

// ── helpers ────────────────────────────────────────────────────────────

fn normalize_tokens(tokens: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(tokens.len());
    for token in tokens {
        let trimmed = token.trim();
        if trimmed.is_empty() || out.iter().any(|known| known == trimmed) {
            continue;
        }
        out.push(trimmed.to_owned());
    }
    out
}

fn normalize_text(text: Option<String>) -> Option<String> {
    text.map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
}

fn validate_label(label: &str, reason: &'static str) -> Result<()> {
    if label.trim().is_empty() || label.len() > CONTEXT_SPEC_MAX_LABEL_BYTES {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            reason,
        )));
    }
    Ok(())
}

pub(super) fn validate_optional_text(text: Option<&str>, reason: &'static str) -> Result<()> {
    match text {
        Some(text) if text.len() > CONTEXT_SPEC_MAX_TEXT_BYTES => Err(Error::Artifact(
            ArtifactError::InvalidAgentDispatchInput(reason),
        )),
        Some(_) | None => Ok(()),
    }
}

pub(super) fn validate_panel_text(text: &str, _field: &'static str) -> Result<()> {
    if text.trim().is_empty() {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "panel spec text must be non-empty",
        )));
    }
    if text.len() > CONTEXT_SPEC_MAX_TEXT_BYTES {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "panel spec text is too long",
        )));
    }
    Ok(())
}
