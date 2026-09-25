//! The engine-RECOGNIZED entries inside a claim's otherwise opaque `scope`
//! map, and their fail-closed structural checks.
//!
//! The `scope` body key stays opaque by design: the crate stores whatever a
//! writer put there and preserves unknown entries losslessly. A recognized
//! entry is different — once the engine reads an entry to make a retrieval
//! decision, an ambiguous or malformed one must never reach that decision
//! point. [`validate_known_claim_scope_entries`] is the chokepoint that keeps
//! those two properties compatible: it inspects ONLY the entries this crate
//! interprets and leaves every sibling untouched.
//!
//! Today that is exactly one entry — the corpus id
//! ([`crate::corpus::CLAIM_SCOPE_CORPUS_ID_KEY`]).

use rmpv::Value;

use super::ClaimBody;
use crate::corpus::{CorpusId, corpus_id_from_scope};
use crate::error::{Error, Result};

/// Reads the corpus a claim is scoped to.
///
/// `None` means unscoped/core — the claim belongs to every corpus, so corpus
/// selection keeps it. A malformed or duplicated corpus entry is a
/// fail-closed [`crate::Error::InvalidClaimBody`], never a silent `None`.
pub(crate) fn claim_corpus_id(body: &ClaimBody) -> Result<Option<CorpusId>> {
    corpus_id_from_scope(body.scope.as_ref())
}

/// Structural check for the recognized entries of a claim's `scope` map, run
/// from the body decoder so a duplicate or malformed corpus id can never be
/// written and can never be read back into a retrieval decision.
///
/// Scope of the check is deliberately narrow: an entry this crate does not
/// interpret is not validated, not reshaped and not rejected, and a `scope`
/// value that is not a map carries no recognized entry at all. Widening the
/// opaque contract is not a side effect of adding a recognized entry to it.
pub(super) fn validate_known_claim_scope_entries(scope: Option<&Value>) -> Result<()> {
    corpus_id_from_scope(scope)?;
    principal_id_from_scope(scope)?;
    if let Some(Value::Map(entries)) = scope {
        let mut facet_seen = false;
        let mut project_seen = false;
        for (key, value) in entries {
            let seen = match key.as_str() {
                Some("facet" | "facet_ref" | "facetRef") => &mut facet_seen,
                Some("scopeProjectId") => &mut project_seen,
                _ => continue,
            };
            if std::mem::replace(seen, true) {
                return Err(Error::InvalidClaimBody("duplicate scope selector"));
            }
            match value {
                Value::Binary(bytes) => {
                    crate::EntityId::from_bytes(
                        bytes
                            .as_slice()
                            .try_into()
                            .map_err(|_| Error::InvalidClaimBody("scope selector id"))?,
                    )
                    .map_err(|_| Error::InvalidClaimBody("scope selector id"))?;
                }
                Value::String(text) => {
                    crate::EntityId::from_hex(
                        text.as_str()
                            .ok_or(Error::InvalidClaimBody("scope selector id"))?,
                    )
                    .map_err(|_| Error::InvalidClaimBody("scope selector id"))?;
                }
                _ => return Err(Error::InvalidClaimBody("scope selector id")),
            }
        }
    }
    Ok(())
}

/// Principal audience for learned preferences. Missing is unknown, not everyone.
pub(crate) fn claim_principal_id(body: &ClaimBody) -> Result<Option<crate::entity_id::EntityId>> {
    principal_id_from_scope(body.scope.as_ref())
}

fn principal_id_from_scope(scope: Option<&Value>) -> Result<Option<crate::entity_id::EntityId>> {
    let Some(Value::Map(entries)) = scope else {
        return Ok(None);
    };
    let mut principal = None;
    for (key, value) in entries {
        if key.as_str() != Some("principal") {
            continue;
        }
        let invalid =
            || crate::error::Error::InvalidClaimBody("invalid or duplicate principal scope");
        if principal.is_some() {
            return Err(invalid());
        }
        let Value::Binary(bytes) = value else {
            return Err(invalid());
        };
        let bytes: [u8; 16] = bytes.as_slice().try_into().map_err(|_| invalid())?;
        principal = Some(crate::entity_id::EntityId::from_bytes(bytes).map_err(|_| invalid())?);
    }
    Ok(principal)
}
