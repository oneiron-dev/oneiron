//! Engine-side remember / forget / ask / search / execute verbs.

use super::super::caps::{check_limit, check_query};
use super::super::support::Memory;
use super::super::{ClaimInput, ClaimListFilter, CommitReceipt, MemoryError, MemoryResult};
use super::{
    AskRequest, ExecuteRequest, ExecuteResponse, FacadeScope, FacadeVerb, ForgetSelector,
    SearchHit, SearchRequest,
};

// ── engine-side remember / forget / ask / search / execute ────────────────

/// Paging width for the forget selector's list-then-retract loop.
const FORGET_PAGE_SIZE: usize = 64;

impl Memory<'_> {
    /// Typed remember: one claim upsert with auto-supersede.
    pub fn remember(&self, input: &ClaimInput) -> MemoryResult<CommitReceipt> {
        self.claim_upsert(input)
    }

    /// Typed forget: retract-with-receipt by short ref or subject+predicate.
    ///
    /// A `short_ref` retracts exactly that claim. Otherwise `subject_ref` and
    /// `predicate` must both be present, and every ACTIVE match retracts in
    /// list pages of 64. Sequential and non-atomic: a later
    /// retract can fail after earlier ones committed, and the caller sees the
    /// failure with the earlier receipts already landed.
    pub fn forget(&self, selector: &ForgetSelector) -> MemoryResult<Vec<CommitReceipt>> {
        if selector.short_ref.is_some()
            && (selector.subject_ref.is_some() || selector.predicate.is_some())
        {
            return Err(MemoryError::bad_request(
                "forget selectors are mutually exclusive",
            ));
        }
        if let Some(short_ref) = selector.short_ref.as_deref() {
            return Ok(vec![self.claim_retract(short_ref)?]);
        }
        let (Some(subject_ref), Some(predicate)) = (
            selector.subject_ref.as_deref(),
            selector.predicate.as_deref(),
        ) else {
            return Err(MemoryError::bad_request_with(
                "forget selector needs short_ref, or subject_ref + predicate",
                &["Pass a claim short_ref, or a subject_ref with a predicate."],
            ));
        };
        let mut receipts = Vec::new();
        let mut seen = std::collections::HashSet::new();
        loop {
            let matches = self.claim_list(&ClaimListFilter {
                subject_ref: Some(subject_ref.to_owned()),
                predicate: Some(predicate.to_owned()),
                lifecycle: Some("active".to_owned()),
                limit: FORGET_PAGE_SIZE,
            })?;
            if matches.is_empty() {
                break;
            }
            for claim in matches {
                if !seen.insert(claim.claim_ref.clone()) {
                    return Err(MemoryError::new(
                        super::super::MEMORY_CODE_INVALID_STATE,
                        "forget made no progress",
                        &["Resolve pending claims before retrying."],
                    ));
                }
                receipts.push(self.claim_retract(&claim.claim_ref)?);
            }
        }
        Ok(receipts)
    }

    /// Extractive ask over ranked recall at minimal depth.
    ///
    /// Runs [`Memory::chat`] with no composer: the pack answers for itself and
    /// the call reports zero tokens used. Standard/deep answering needs a
    /// host-injected composer the engine cannot hold, so this verb answers
    /// only what minimal retrieval can show.
    pub fn ask(&self, request: &AskRequest) -> MemoryResult<super::super::ChatResponse> {
        use super::super::{ChatDepth, ChatOptions, ChatScope};
        if request.question.trim().is_empty() {
            return Err(MemoryError::bad_request_with(
                "ask question must not be blank",
                &["Send the caller question text with the request."],
            ));
        }
        let limit = request.limit.unwrap_or(10);
        check_limit(limit)?;
        self.chat(
            &request.question,
            ChatDepth::Minimal,
            ChatOptions {
                scope: ChatScope::Recall(request.scope.clone().unwrap_or_default()),
                limit,
                format: request.format.as_deref(),
                lease: None,
                composer: None,
            },
        )
    }

    /// Typed SDK stub-documentation search over the verb table.
    ///
    /// Host-side metadata lookup, not a vault read: matches `query` (case
    /// insensitive substring) against each row's wire name, SDK name, and
    /// one-line doc, returning table rows in contract order.
    pub fn search(&self, request: &SearchRequest) -> MemoryResult<Vec<SearchHit>> {
        let limit = request.limit.unwrap_or(10);
        check_limit(limit)?;
        check_query(&request.query)?;
        let needle = request.query.to_lowercase();
        let mut hits = Vec::new();
        for verb in FacadeVerb::ALL {
            if hits.len() >= limit {
                break;
            }
            let doc = verb.doc();
            let scope = match verb.scope() {
                FacadeScope::Read => "read",
                FacadeScope::Write => "write",
            };
            let haystack =
                format!("{} {} {} {scope}", verb.wire_name(), verb.sdk_name(), doc).to_lowercase();
            if needle.is_empty() || haystack.contains(&needle) {
                hits.push(SearchHit {
                    wire: verb.wire_name().to_owned(),
                    sdk: verb.sdk_name().to_owned(),
                    scope: scope.to_owned(),
                    doc: doc.to_owned(),
                    request_type: verb.request_type().to_owned(),
                    response_type: verb.response_type().to_owned(),
                });
            }
        }
        Ok(hits)
    }

    /// Evaluates a bounded program of typed, read-only facade instructions.
    /// Validation of all instruction scopes happens before the first read.
    /// Nested programs and writes are rejected, so a read credential cannot
    /// use this verb to acquire write authority.
    pub fn execute(&self, request: &ExecuteRequest) -> MemoryResult<ExecuteResponse> {
        super::super::caps::check_batch_len("calls", request.calls.len())?;
        if request.calls.iter().any(|call| {
            call.verb().scope() != FacadeScope::Read || call.verb() == FacadeVerb::Execute
        }) {
            return Err(MemoryError::bad_request_with(
                "execute accepts non-nested read instructions only",
                &["Send writes through their named verb and write-scoped credential."],
            ));
        }
        let results = request
            .calls
            .iter()
            .cloned()
            .map(|call| call.run(self))
            .collect::<MemoryResult<Vec<_>>>()?;
        Ok(ExecuteResponse { results })
    }
}
