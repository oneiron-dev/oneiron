//! Shared pre-dispatch caps for every transport, including embedded calls.
use super::super::caps::*;
use super::super::{MemoryError, MemoryResult};
use super::{FacadeRequest, FacadeScope, FacadeVerb};

impl FacadeRequest {
    /// Validates shared boundary caps without reading or writing the vault.
    pub fn validate(&self) -> MemoryResult<()> {
        match self {
            Self::Witness(body) => check_witness_turn(body)?,
            Self::ClaimUpsert(body) | Self::Remember(body) => check_claim_input(body)?,
            Self::Commit(body) | Self::SeedClaims(body) => {
                check_batch_len("claims", body.claims.len())?;
                for claim in &body.claims {
                    check_claim_input(claim)?;
                }
            }
            Self::ClaimList(body) => check_limit(body.limit)?,
            Self::ArtifactsBornFrom(body) => check_limit(body.limit)?,
            Self::ReactionPills(body) => {
                if body.message_refs.len()
                    > crate::conversation::reaction::GROUPED_PILLS_MAX_MESSAGES
                {
                    return Err(MemoryError::bad_request(
                        "reaction pills accept at most50 messages",
                    ));
                }
            }
            Self::PendingWrites(body) | Self::Receipts(body) => check_limit(body.limit)?,
            Self::Hydrate(body) => {
                if body.refs.len() > MAX_SEARCH_LIMIT {
                    return Err(MemoryError::bad_request("too many hydration references"));
                }
            }
            Self::QueryBm25(body) => {
                check_query(&body.query)?;
                check_limit(body.limit)?;
            }
            Self::Neighbors(body) => check_limit(body.opts.limit)?,
            Self::RecallView(body) => {
                check_query(&body.query)?;
                check_limit(body.limit)?;
            }
            Self::Recall(body) => {
                check_query(&body.query)?;
                check_limit(body.limit.unwrap_or(10))?;
            }
            Self::Search(body) => {
                check_query(&body.query)?;
                check_limit(body.limit.unwrap_or(10))?;
            }
            Self::Ask(body) => {
                check_query(&body.question)?;
                check_limit(body.limit.unwrap_or(10))?;
            }
            Self::Query(body) => {
                if let Some(query) = &body.query {
                    check_query(query)?;
                }
                check_limit(body.limit)?;
            }
            Self::ContextPack(body) => {
                if let Some(query) = &body.query {
                    check_query(query)?;
                }
                check_limit(body.limit)?;
            }
            Self::AppendBlobVersion(body) => {
                if body.content_base64.len() > MAX_BLOB_BASE64_LEN {
                    return Err(MemoryError::bad_request(
                        "blob content exceeds the base64 ceiling",
                    ));
                }
            }
            Self::Execute(body) => {
                check_batch_len("calls", body.calls.len())?;
                for call in &body.calls {
                    if call.verb() == FacadeVerb::Execute
                        || call.verb().scope() != FacadeScope::Read
                    {
                        return Err(MemoryError::bad_request(
                            "execute accepts non-nested read instructions only",
                        ));
                    }
                    call.validate()?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}
