//! Credential-bound adapters. Text storage, grants and fork settlement stay in EntityDoc.

use super::public_types::*;
use crate::claim::{ClaimReadStatus, PointRead, ScopedReadResult};
use crate::conversation_dag::{ScopePath, ScopeSelector};
use crate::entity_doc::{AnchoredEdit, DocAuthorization, EditVerb, ForkRequest, SettleVerb};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::{EntityId, WriteActor};

fn side_id(value: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(value).map_err(|_| MemoryError::bad_request("expected a full hex id"))
}

fn absent() -> MemoryError {
    MemoryError::new(
        crate::memory::MEMORY_CODE_NOT_FOUND,
        "SUMMARY or proposal member is absent or not readable",
        &[],
    )
}

impl SummaryScope {
    fn selector(&self, memory: &Memory<'_>) -> MemoryResult<ScopeSelector> {
        let resolve = |value: &str| crate::memory::resolve_entity_ref(memory.vault(), value);
        Ok(ScopeSelector {
            conversation: resolve(&self.conversation_ref)?,
            session: self.session.as_deref().map(resolve).transpose()?,
            path: match &self.path {
                SummaryPath::Canonical => ScopePath::Canonical,
                SummaryPath::Branch(value) => ScopePath::Branch(resolve(value)?),
                SummaryPath::BranchSpan { after, through } => ScopePath::BranchSpan {
                    after: resolve(after)?,
                    through: resolve(through)?,
                },
                SummaryPath::SubSession(value) => ScopePath::SubSession(resolve(value)?),
            },
            include_forks: self.include_forks,
        })
    }
}

impl SummaryEdit {
    fn anchored(&self, actor: WriteActor, base: &[u8]) -> MemoryResult<AnchoredEdit> {
        let (anchor, verb) = match self {
            Self::AppendToSection { section, text } => (
                section,
                EditVerb::AppendToSection {
                    section: section.clone(),
                    text: text.clone(),
                },
            ),
            Self::ReplaceQuotedSpan { span, text } => (
                span,
                EditVerb::ReplaceQuotedSpan {
                    span: span.clone(),
                    text: text.clone(),
                },
            ),
            Self::InsertAfterAnchor { anchor, text } => (
                anchor,
                EditVerb::InsertAfterAnchor {
                    anchor: anchor.clone(),
                    text: text.clone(),
                },
            ),
        };
        if anchor.frontier() != base {
            return Err(MemoryError::bad_request(
                "edit anchor differs from its declared base",
            ));
        }
        Ok(AnchoredEdit {
            actor: Some(actor),
            verb,
        })
    }
}

impl Memory<'_> {
    /// The caller can declare only a scope it can read. The Dreamer's existing
    /// producer independently admits its evidence and alone mints the body.
    pub fn create_summary(&self, input: &SummaryCreateRequest) -> MemoryResult<SummaryQueued> {
        let scope = input.scope.selector(self)?;
        let resolved = self.vault().resolve_dag_scope(&scope)?;
        for record in resolved.records {
            self.require_summary_source(&record.to_hex())?;
        }
        self.require_summary_source(&scope.conversation.to_hex())?;
        if let Some(turn) = &input.land_on {
            self.require_summary_source(turn)?;
        }
        let request = super::ScopeSummaryRequest {
            target: super::ScopeSummaryTarget::Scope {
                scope,
                land_on: input
                    .land_on
                    .as_deref()
                    .map(|value| crate::memory::resolve_entity_ref(self.vault(), value))
                    .transpose()?,
                as_record: input.as_record,
            },
            requester: WriteActor::new(self.actor(), self.actor_class()),
        };
        let queued = match &input.purpose {
            Some(purpose) => self.vault().request_scope_summary_for(&request, purpose)?,
            None => self.vault().request_scope_summary(&request)?,
        };
        let attempt = crate::entity_id::bytes_to_hex_lower(queued.attempt.as_bytes());
        Ok(SummaryQueued {
            status: format!("/v1/core/summary-attempts/{attempt}"),
            attempt,
            coalesced: queued.coalesced,
        })
    }

    pub fn summary_status(
        &self,
        input: &SummaryStatusRequest,
    ) -> MemoryResult<super::ScopeSummaryStatus> {
        let id = side_id(&input.attempt)?;
        let attempt = crate::attempt_queue::AttemptId::from_bytes(id.as_bytes())?;
        let status = self.vault().scope_summary_status(attempt)?;
        if status.requester != self.actor().to_hex() {
            return Err(absent());
        }
        if let Some(result) = &status.result {
            self.summary_id(&result.summary)?;
        }
        Ok(status)
    }

    /// The document, keep, derivation and stable anchors share the scoped read's snapshot.
    pub fn read_summary(
        &self,
        input: &SummaryReadRequest,
    ) -> MemoryResult<ScopedReadResult<Option<SummaryReadView>>> {
        let summary = crate::memory::resolve_entity_ref(self.vault(), &input.summary_ref)?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        lane.read_projected(&[PointRead::id(summary)], None, |txn, rows| {
            let Some(row) = rows
                .into_iter()
                .next()
                .flatten()
                .filter(|row| row.body.is_some())
            else {
                return Ok::<_, MemoryError>(None);
            };
            if row.entity_type != crate::registry::ENTITY_TYPE_SUMMARY {
                return Err(MemoryError::bad_request("entity is not a SUMMARY"));
            }
            let view =
                crate::entity_doc::summary_read_in_txn(self.vault(), txn, &summary, &input.spans)?;
            let value = serde_json::to_value(&view)
                .map_err(|_| MemoryError::bad_request("SUMMARY view encoding"))?;
            let keys = crate::batch::secret_scan::LiftedKeys::of_json_in_txn(
                &self.vault().store,
                txn,
                &value,
            )?;
            self.produced_from([summary]);
            self.lifted_view(view, || Ok(keys)).map(Some)
        })
    }

    fn summary_id(&self, reference: &str) -> MemoryResult<EntityId> {
        self.read_summary(&SummaryReadRequest {
            summary_ref: reference.to_owned(),
            spans: Vec::new(),
        })?
        .value
        .ok_or_else(absent)?;
        crate::memory::resolve_entity_ref(self.vault(), reference)
    }

    fn require_summary_source(&self, reference: &str) -> MemoryResult<String> {
        if self.get_entity(reference)?.value.is_none() {
            return Err(absent());
        }
        Ok(crate::memory::resolve_entity_ref(self.vault(), reference)?.to_hex())
    }

    fn summary_authorization(&self) -> DocAuthorization<'_> {
        match self.owner_authorship() {
            Some(owner) => DocAuthorization::Owner(owner),
            None => DocAuthorization::StandingGrant,
        }
    }

    pub fn set_summary_keep(&self, input: &SummaryKeepRequest) -> MemoryResult<SummaryKeepResult> {
        let summary = self.summary_id(&input.summary_ref)?;
        self.vault().set_scope_summary_keep(
            &summary,
            &input.frontier,
            &input.keep,
            WriteActor::new(self.actor(), self.actor_class()),
            &self.summary_authorization(),
            self.vault().now_recorded_at(),
        )?;
        let view = self
            .read_summary(&SummaryReadRequest {
                summary_ref: summary.to_hex(),
                spans: Vec::new(),
            })?
            .value
            .ok_or_else(absent)?;
        Ok(SummaryKeepResult {
            summary_ref: view.summary_ref,
            frontier: view.frontier,
            keep: view.metadata.keep,
        })
    }

    /// An authored edit follows the same grant routing as a machine patch:
    /// permitted anchored edits merge, and the others wait in one proposal.
    pub fn edit_summary(&self, input: &SummaryEditRequest) -> MemoryResult<SummaryProposalView> {
        let summary = self.summary_id(&input.summary_ref)?;
        let actor = WriteActor::new(self.actor(), self.actor_class());
        let edits = input
            .edits
            .iter()
            .map(|edit| edit.anchored(actor, &input.base))
            .collect::<MemoryResult<Vec<_>>>()?;
        if edits.is_empty() {
            return Err(MemoryError::bad_request(
                "an anchored edit requires operations",
            ));
        }
        self.open_summary_fork(
            ForkRequest {
                entity: summary,
                base: input.base.clone(),
                actor,
                edits,
                rewrite: None,
            },
            None,
            &[],
        )
    }

    pub fn patch_summary(
        &self,
        input: &SummaryPatchRequest,
    ) -> MemoryResult<SummaryMutationResult> {
        let summary = self.summary_id(&input.summary_ref)?;
        let actor = WriteActor::new(self.actor(), self.actor_class());
        let edits = input
            .edits
            .iter()
            .map(|edit| edit.anchored(actor, &input.base))
            .collect::<MemoryResult<Vec<_>>>()?;
        if edits.is_empty() || input.read_refs.is_empty() {
            return Err(MemoryError::bad_request(
                "a patch requires anchored operations and the sources it read",
            ));
        }
        let proposal = self.open_summary_fork(
            ForkRequest {
                entity: summary,
                base: input.base.clone(),
                actor,
                edits,
                rewrite: None,
            },
            Some(&input.keep),
            &input.read_refs,
        )?;
        let read_refs = proposal
            .bundle
            .forks
            .iter()
            .flat_map(|fork| fork.read_refs.clone())
            .collect();
        Ok(SummaryMutationResult {
            proposal,
            read_refs,
        })
    }

    pub fn regenerate_summary(
        &self,
        input: &SummaryRegenerateRequest,
    ) -> MemoryResult<SummaryMutationResult> {
        let summary = self.summary_id(&input.summary_ref)?;
        if input.text.trim().is_empty() || input.read_refs.is_empty() {
            return Err(MemoryError::bad_request(
                "a regeneration requires text and the sources it read",
            ));
        }
        let proposal = self.open_summary_fork(
            ForkRequest {
                entity: summary,
                base: input.base.clone(),
                actor: WriteActor::new(self.actor(), self.actor_class()),
                edits: Vec::new(),
                rewrite: Some(input.text.clone()),
            },
            Some(&input.keep),
            &input.read_refs,
        )?;
        let read_refs = proposal
            .bundle
            .forks
            .iter()
            .flat_map(|fork| fork.read_refs.clone())
            .collect();
        Ok(SummaryMutationResult {
            proposal,
            read_refs,
        })
    }

    fn open_summary_fork(
        &self,
        request: ForkRequest,
        keep: Option<&str>,
        read_refs: &[String],
    ) -> MemoryResult<SummaryProposalView> {
        let bundle = crate::entity_doc::open_summary_proposal(
            self,
            &request,
            keep,
            read_refs,
            &self.summary_authorization(),
        )?;
        self.read_summary_proposal(&SummaryProposalRequest {
            proposal_ref: bundle.proposal,
        })
    }

    pub fn read_summary_proposal(
        &self,
        input: &SummaryProposalRequest,
    ) -> MemoryResult<SummaryProposalView> {
        let bundle = self
            .vault()
            .entity_text_proposal(&side_id(&input.proposal_ref)?)?;
        let mut entities = std::collections::BTreeSet::new();
        for fork in &bundle.forks {
            entities.insert(self.summary_id(&fork.entity)?);
        }
        let mut forks = Vec::new();
        for record in &bundle.forks {
            forks.push(SummaryForkView {
                text: self
                    .vault()
                    .entity_text_fork_text(&side_id(&record.fork)?)?,
                record: record.clone(),
            });
        }
        let mut receipts = Vec::new();
        for entity in entities {
            receipts.extend(
                self.vault()
                    .entity_text_receipts(&entity)?
                    .into_iter()
                    .filter(|receipt| receipt.proposal == bundle.proposal),
            );
        }
        let view = SummaryProposalView {
            bundle,
            forks,
            receipts,
        };
        let value = serde_json::to_value(&view)
            .map_err(|_| MemoryError::bad_request("SUMMARY proposal view encoding"))?;
        self.lifted_view(view, || {
            let txn = self.vault().store.env.read_txn()?;
            Ok(crate::batch::secret_scan::LiftedKeys::of_json_in_txn(
                &self.vault().store,
                &txn,
                &value,
            )?)
        })
    }

    pub fn settle_summary_proposal(
        &self,
        input: &SummaryProposalRequest,
        verb: SettleVerb,
    ) -> MemoryResult<SummaryProposalView> {
        self.read_summary_proposal(input)?;
        self.vault().settle_text_proposal(
            &side_id(&input.proposal_ref)?,
            verb,
            &self.summary_authorization(),
            WriteActor::new(self.actor(), self.actor_class()),
            self.vault().now_recorded_at(),
        )?;
        self.read_summary_proposal(input)
    }
}
