//! The narrowing law: declared bounds against declared bounds, and a request against the resolved parent.

use super::resolution::ResolvedContextProjection;
use super::spec::{ChatProjection, ContextSpec, MemoryProjection, domain_contains};
use crate::error::{ArtifactError, Error, Result};

/// DECLARED-bound narrowing: the child's requested scope against the parent's
/// stored scope. `Default` inherits, so it is always admissible.
pub fn validate_spec_narrows(parent: &ContextSpec, child: &ContextSpec) -> Result<()> {
    for layer in &child.layers {
        if !parent.layers.iter().any(|known| known == layer) {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "child context spec requests a layer its parent does not carry",
            )));
        }
    }
    if let MemoryProjection::Scoped { domains, limit } = &child.memory {
        match &parent.memory {
            MemoryProjection::Exclude => {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "child memory projection cannot widen a parent that excludes memory",
                )));
            }
            MemoryProjection::Default => {}
            MemoryProjection::Scoped {
                domains: parent_domains,
                limit: parent_limit,
            } => {
                // A child may name its parent's domain or one under it
                // (FIX 7752).
                for domain in domains {
                    if !parent_domains
                        .iter()
                        .any(|known| domain_contains(known, domain))
                    {
                        return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                            "child memory projection requests a domain outside its parent scope",
                        )));
                    }
                }
                if limit > parent_limit {
                    return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "child memory projection raises its parent limit",
                    )));
                }
            }
        }
    }
    if let ChatProjection::Recent { last_n } = &child.chat {
        match &parent.chat {
            ChatProjection::Exclude => {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "child chat projection cannot widen a parent that excludes chat",
                )));
            }
            ChatProjection::Default => {}
            ChatProjection::Recent {
                last_n: parent_last_n,
            } => {
                if last_n > parent_last_n {
                    return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "child chat projection raises its parent bound",
                    )));
                }
            }
        }
    }
    Ok(())
}

/// RESOLVED-bound narrowing: the child's request against what the parent
/// actually resolved to. A row a member's own read lane left out of the
/// parent is not a bound (FIX 5416): the law reads the parent as it
/// resolved before that, so an omission never refuses a request.
pub fn validate_context_narrows(
    parent: &ResolvedContextProjection,
    child: &ContextSpec,
) -> Result<()> {
    for layer in &child.layers {
        if !parent.layers.iter().any(|known| known == layer) {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "child context spec requests a layer the parent did not project",
            )));
        }
    }
    if let MemoryProjection::Scoped { domains, limit } = &child.memory {
        if parent.memory_bound().is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "child memory projection cannot widen an empty parent projection",
            )));
        }
        let parent_domains = parent.bound_domains();
        // A child may name a domain the parent projected or one under it
        // (FIX 7752).
        for domain in domains {
            if !parent_domains
                .iter()
                .any(|known| domain_contains(known, domain))
            {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "child memory projection requests a domain the parent did not project",
                )));
            }
        }
        if *limit > parent.memory_bound().len() {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "child memory projection exceeds the parent's projected section count",
            )));
        }
    }
    if let ChatProjection::Recent { last_n } = &child.chat {
        if parent.chat_bound().is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "child chat projection cannot widen an empty parent projection",
            )));
        }
        if *last_n > parent.chat_bound().len() {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "child chat projection exceeds the parent's projected section count",
            )));
        }
    }
    Ok(())
}
