//! Explicit fresh review of a handle resolution. The old proposal and its
//! critiques stay untouched; only a proved redacted form reaches the new row.

use super::*;
use zeroize::{Zeroize, Zeroizing};

struct BoundValues(Vec<(String, Vec<u8>, EntityId, String)>);

impl Drop for BoundValues {
    fn drop(&mut self) {
        for (_, value, _, _) in &mut self.0 {
            value.zeroize();
        }
    }
}

impl Vault {
    /// Proposes a fresh review of `original`'s resolved ordinary file, without
    /// giving critics the resolved secret bytes. This is a trusted host door,
    /// like [`Self::propose_repo_mutation`], not owner or run authentication.
    ///
    /// `request` supplies the new actor, session, provenance, message and pin.
    /// It names the same repository and operation target; its content is filled
    /// with the proved redacted resolution. The new row has no old critiques or
    /// `resolves` link. The original remains Approved and unconsumed.
    ///
    /// # Errors
    /// Ordinary proposal/custody errors, a changed source or binding, or the
    /// existing resolution hold when no reversible, fully masked form is proved.
    pub fn propose_repo_rereview(
        &self,
        original: EntityId,
        mut request: RepoMutationRequest,
        catalog: LensCatalog,
    ) -> Result<RepoProposal> {
        let source = self.repo_proposal(original)?.ok_or(Error::EntityNotFound)?;
        if source.status != RepoProposalStatus::Approved
            || source.operation_seq.is_some()
            || source.merge_stack.is_some()
            || source.resolves.is_some()
        {
            return Err(invalid(
                "re-review requires an unconsumed standalone original",
            ));
        }
        if !crate::repo_mutation::oplog::same_repository(
            &RepoRef::parse(&source.repo)?,
            &request.repo_ref,
        ) {
            return Err(invalid("re-review names another repository"));
        }
        let (path, content) = source.ordinary_file()?;
        let spans = handle_spans(content);
        if spans.is_empty() {
            return Err(invalid("re-review source carries no secret handles"));
        }
        let values = BoundValues(spans_values(self, &spans)?);
        let ranges = resolved_span_ranges(&spans, &values.0)?;
        let resolved_len = ranges
            .last()
            .expect("nonempty handle spans have resolved ranges")
            .1
            .checked_add((content.len() - spans.last().expect("nonempty spans").1) as u64);
        if resolved_len.is_none_or(|len| len > 32 * 1024 * 1024) {
            return Err(invalid(
                "proposal requires bounded content and review lenses",
            ));
        }
        let resolved = Zeroizing::new(substitute(content, &spans, &values.0));
        std::str::from_utf8(&resolved)
            .map_err(|_| Error::InvalidClaimBody("code document requires UTF-8"))?;
        let projected = redacted_candidate(&resolved, &values)?;
        match (&source.operation, &mut request.operation) {
            (
                RepoProposalOperation::CommitFile,
                RepoMutationOperation::CommitFile {
                    path: target,
                    content,
                    ..
                },
            ) if target.as_str() == path => *content = projected,
            (
                RepoProposalOperation::ResolveConflictFile {
                    branch_subject: old_subject,
                    open_conflict_claim_id: old_conflict,
                    branch_name: old_branch,
                },
                RepoMutationOperation::ResolveConflictFile {
                    branch_subject,
                    open_conflict_claim_id,
                    branch_name,
                    path: target,
                    content,
                    ..
                },
            ) if target.as_str() == path
                && *branch_subject == *old_subject
                && *open_conflict_claim_id == *old_conflict
                && branch_name.as_str() == old_branch.as_str() =>
            {
                *content = projected
            }
            _ => return Err(invalid("re-review names another operation target")),
        }
        let expected_source = Zeroizing::new(PROPOSAL.encode_value(&source)?);
        let proposed = self.propose_repo_mutation_checked::<std::convert::Infallible>(
            request,
            RepoProposalReview::Explicit(catalog),
            ProposalBase::CurrentCheckout,
            None,
            None,
            |txn| {
                let current = PROPOSAL.get(&self.store, txn, &original)?
                    .ok_or(Error::EntityNotFound)?;
                let current_bytes = Zeroizing::new(PROPOSAL.encode_value(&current)?);
                if *current_bytes != *expected_source {
                    return Err(invalid("re-review source changed; submit a fresh proposal"));
                }
                for (text, value, custody, _) in &values.0 {
                    let (_, id) = crate::secret_custody::handle_record_in_txn(
                        &self.store, txn, text,
                    )?;
                    let live = Zeroizing::new(self
                        .get_secret_value_in_txn(txn, &id, REPO_LANDING_EFFECTOR)?
                        .ok_or(Error::EntityNotFound)?);
                    if id != *custody || live.as_slice() != value.as_slice() {
                        return Err(invalid(
                            "a handle's binding changed while resolving handles; submit a fresh proposal",
                        ));
                    }
                }
                Ok(Ok(()))
            },
        )?;
        Ok(proposed.unwrap_or_else(|never| match never {}))
    }
}

fn resolution_hold() -> Error {
    invalid("the resolved bytes are not the reviewed operation with its handles replaced")
}

fn redacted_candidate(resolved: &[u8], values: &BoundValues) -> Result<Vec<u8>> {
    // The equality helper supplies an UNTRUSTED candidate, never critic input
    // until both its roundtrip and original-byte coverage have been proved.
    let candidate = Zeroizing::new(reredact(resolved, &values.0)?);
    std::str::from_utf8(&candidate)
        .map_err(|_| Error::InvalidClaimBody("code document requires UTF-8"))?;
    let spans = handle_spans(&candidate);
    let mut ordered = BoundValues(Vec::new());
    for (_, _, text) in &spans {
        let known = values
            .0
            .iter()
            .find(|known| &known.0 == text)
            .ok_or_else(resolution_hold)?;
        if !ordered.0.iter().any(|known| &known.0 == text) {
            ordered.0.push(known.clone());
        }
    }
    let roundtrip = Zeroizing::new(substitute(&candidate, &spans, &ordered.0));
    if roundtrip.as_slice() != resolved {
        return Err(resolution_hold());
    }
    let covered = resolved_span_ranges(&spans, &ordered.0)?;
    for (_, value, _, _) in &values.0 {
        for span in crate::store::known_value_index::occurrences(resolved, value) {
            // Encoded spellings cannot resolve to their spelling bytes. Keeping
            // exact slices yields precisely the native matcher's raw hit set.
            if resolved.get(span.clone()) != Some(value.as_slice()) {
                continue;
            }
            let mut at = span.start as u64;
            let end = span.end as u64;
            let first = covered.partition_point(|(_, to)| *to <= at);
            for (from, to) in &covered[first..] {
                if *from > at || at >= end {
                    break;
                }
                at = at.max(*to);
            }
            if at < end {
                return Err(resolution_hold());
            }
        }
    }
    // A fresh row reads handles in its own encounter order. Prove that the
    // unchanged landing equality rule will accept that exact redacted form.
    let landing_form = Zeroizing::new(reredact(resolved, &ordered.0)?);
    if landing_form.as_slice() != candidate.as_slice() {
        return Err(resolution_hold());
    }
    Ok(candidate.to_vec())
}
