//! Borrowed historical inputs of a decoded native witness. No view is admission.

use super::content_source::ContentSource;
use super::{Door, SkillStateFact};
use crate::authority::{AuthorityEntryHash, NativeSkillCarrier};
use crate::claim::ClaimApprovalStatus;
use crate::error::Result;
use crate::skill::SkillLifecycle;

#[derive(Clone, Copy)]
pub(in crate::entity_doc) struct SkillStateFactView<'fact> {
    fact: &'fact SkillStateFact,
}

pub(in crate::entity_doc) struct SkillStateOperationView<'fact> {
    pub entity: &'fact [u8; 16],
    pub document: &'fact [u8; 16],
    pub birth_at: u64,
    pub source_core: &'fact [u8; 32],
    pub source_frontier: &'fact [u8],
    pub event: &'fact [u8; 16],
    pub recorded_at: u64,
    pub ordinal: u64,
    pub previous: Option<&'fact AuthorityEntryHash>,
    pub prior: (SkillLifecycle, ClaimApprovalStatus),
    pub state: (SkillLifecycle, ClaimApprovalStatus),
    pub door: SkillStateDoorView<'fact>,
    pub writer: Option<SkillStateWriterView<'fact>>,
    pub content_source: SkillStateContentSourceView<'fact>,
}

pub(in crate::entity_doc) enum SkillStateDoorView<'fact> {
    Update,
    Supersede {
        successor: &'fact [u8; 16],
        source_core: &'fact [u8; 32],
        logical_body: &'fact [u8; 32],
        document_pin: Option<(&'fact [u8; 16], &'fact [u8])>,
    },
}

pub(in crate::entity_doc) struct SkillStateWriterView<'fact> {
    pub token: &'fact [u8; 16],
    pub class: u8,
    pub authority_frontier: Option<&'fact AuthorityEntryHash>,
}

pub(in crate::entity_doc) enum SkillStateContentSourceView<'fact> {
    Unobserved,
    Personal,
    Shared {
        vault_id: u64,
        previous_scope: Option<&'fact [u8; 32]>,
        before: Option<SkillStateSharedSuccessView<'fact>>,
        after: Option<SkillStateSharedSuccessView<'fact>>,
    },
}

pub(in crate::entity_doc) struct SkillStateSharedSuccessView<'fact> {
    pub grant: &'fact [u8; 16],
    pub inputs_fingerprint: &'fact [u8; 32],
    pub expiry_checked_at: Option<u64>,
}

impl SkillStateFact {
    pub(in crate::entity_doc) fn view(&self) -> SkillStateFactView<'_> {
        SkillStateFactView { fact: self }
    }
}

impl<'fact> SkillStateFactView<'fact> {
    pub(in crate::entity_doc) fn operation(&self) -> Result<SkillStateOperationView<'fact>> {
        let operation = &self.fact.operation;
        Ok(SkillStateOperationView {
            entity: &operation.entity,
            document: &operation.document,
            birth_at: operation.birth_at,
            source_core: &operation.source_core,
            source_frontier: &operation.source_frontier,
            event: &operation.event,
            recorded_at: operation.recorded_at,
            ordinal: operation.ordinal,
            previous: operation.previous.as_ref(),
            prior: (operation.prior.lifecycle()?, operation.prior.approval),
            state: (operation.state.lifecycle()?, operation.state.approval),
            door: match &operation.door {
                Door::Update => SkillStateDoorView::Update,
                Door::Supersede {
                    successor,
                    source_core,
                    logical_body,
                    document_pin,
                } => SkillStateDoorView::Supersede {
                    successor,
                    source_core,
                    logical_body,
                    document_pin: document_pin
                        .as_ref()
                        .map(|(id, frontier)| (id, frontier.as_slice())),
                },
            },
            writer: operation
                .writer
                .as_ref()
                .map(|writer| SkillStateWriterView {
                    token: &writer.token,
                    class: writer.class,
                    authority_frontier: writer.authority_frontier.as_ref(),
                }),
            content_source: match &operation.content_source {
                ContentSource::Unobserved => SkillStateContentSourceView::Unobserved,
                ContentSource::Personal => SkillStateContentSourceView::Personal,
                ContentSource::Shared {
                    vault_id,
                    previous_scope,
                    before,
                    after,
                } => SkillStateContentSourceView::Shared {
                    vault_id: *vault_id,
                    previous_scope: previous_scope.as_ref(),
                    before: before.as_ref().map(|source| source.view()),
                    after: after.as_ref().map(|source| source.view()),
                },
            },
        })
    }

    pub(in crate::entity_doc) fn token(&self) -> Result<AuthorityEntryHash> {
        self.fact.token()
    }

    /// Signature and historical carrier data only, never native permission.
    pub(in crate::entity_doc) fn verified_carrier(&self) -> Result<Option<NativeSkillCarrier>> {
        self.fact.verified_carrier()
    }
}
