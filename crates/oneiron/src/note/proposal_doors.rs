//! Typed NOTE forks and explicit proposal sets over the existing NOTE engine doors.

use super::documents::{NoteDocument, invalid, load_head};
use super::proposals::{NOTE_FORK, NOTE_RECEIPT};
use super::{
    NoteAccessRequest, NoteActor, NoteFork, NoteProgramEdit, NoteReadRequest, NoteVerdict,
    NoteVersion,
};
use crate::EntityId;
use crate::claim::ScopedReadResult;
use crate::memory::{Memory, MemoryError, MemoryResult};
use serde::{Deserialize, Serialize};

/// Fork the exact live-head version a caller read, without changing that head.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteForkRequest {
    pub note_ref: String,
    pub base: NoteVersion,
    pub edit: NoteProgramEdit,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteForkReadRequest {
    pub note_ref: String,
    pub fork_ref: String,
    #[serde(default)]
    pub reason: Option<String>,
}

/// A fork identity is not an entity ref or an authority credential.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteProposalForkRef {
    pub note_ref: String,
    pub fork_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteProposalOpenRequest {
    pub forks: Vec<NoteProposalForkRef>,
    pub explainer: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteProposalRequest {
    pub proposal_ref: String,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Public provenance only; the engine's recovery merge basis is not a wire DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NoteForkRecordView {
    pub note_ref: String,
    pub fork_ref: String,
    pub parent: String,
    pub frontier: Vec<u8>,
    pub actor: Option<String>,
    pub rewrite: bool,
    pub proposal_ref: Option<String>,
    pub decided: bool,
}

impl From<NoteFork> for NoteForkRecordView {
    fn from(fork: NoteFork) -> Self {
        Self {
            note_ref: fork.note.to_hex(),
            fork_ref: fork.fork.to_hex(),
            parent: fork.parent.to_hex(),
            frontier: fork.frontier,
            actor: actor_ref(fork.actor),
            rewrite: fork.rewrite,
            proposal_ref: fork.proposal.map(|id| id.to_hex()),
            decided: fork.decided,
        }
    }
}

/// Deciding a fork can drop its proposal text. Its provenance stays readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NoteForkView {
    pub record: NoteForkRecordView,
    pub markdown: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NoteLandingView {
    pub receipt: String,
    pub note_ref: String,
    pub fork_ref: String,
    pub previous_head: String,
    pub head: String,
    pub verdict: NoteVerdict,
    pub actor: Option<String>,
    pub at: u64,
}

impl From<super::NoteLandingReceipt> for NoteLandingView {
    fn from(receipt: super::NoteLandingReceipt) -> Self {
        Self {
            receipt: receipt.id.to_hex(),
            note_ref: receipt.note.to_hex(),
            fork_ref: receipt.fork.to_hex(),
            previous_head: receipt.previous_head.to_hex(),
            head: receipt.head.to_hex(),
            verdict: receipt.verdict,
            actor: actor_ref(receipt.actor),
            at: receipt.at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NoteProposalView {
    pub proposal_ref: String,
    pub waiting: Vec<NoteForkView>,
    pub landed: Vec<NoteLandingView>,
    pub explainer: String,
}

/// Parent/frontier links and set membership survive the pending text's disposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NoteVersionTree {
    pub version: NoteVersion,
    pub birth_author: String,
    pub born_at: u64,
    pub forks: Vec<NoteForkRecordView>,
    pub receipts: Vec<NoteLandingView>,
}

fn actor_ref(actor: NoteActor) -> Option<String> {
    match actor {
        NoteActor::Actor(id) => Some(id.to_hex()),
        NoteActor::Erased => None,
    }
}

fn fork_view(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    fork: NoteFork,
) -> MemoryResult<NoteForkView> {
    let markdown = if fork.decided {
        None
    } else {
        Some(load_head(vault, txn, fork.note, fork.fork)?.text())
    };
    Ok(NoteForkView {
        record: fork.into(),
        markdown,
    })
}

fn side_id(reference: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(reference)
        .map_err(|_| MemoryError::bad_request("expected a fork or proposal hex id"))
}

fn withheld() -> MemoryError {
    MemoryError::new(
        crate::memory::MEMORY_CODE_NOT_FOUND,
        "NOTE proposal member is absent or not readable",
        &[],
    )
}

impl Memory<'_> {
    /// The caller's ordinary NOTE lane admits the source; the engine binds
    /// the actor and applies its existing content-write and shared-vault gates.
    pub fn fork_note(&self, input: &NoteForkRequest) -> MemoryResult<NoteForkView> {
        if self
            .read_note(&NoteReadRequest {
                note_ref: input.note_ref.clone(),
                reason: input.reason.clone(),
                version: Some(input.base.clone()),
                spans: Vec::new(),
            })?
            .value
            .is_none()
        {
            return Err(withheld());
        }
        let note = crate::memory::resolve_entity_ref(self.vault(), &input.note_ref)?;
        let fork = self.vault().fork_note_at_version(
            note,
            Some(&input.base),
            &input.edit,
            self.write_actor(),
        )?;
        self.read_note_fork(&NoteForkReadRequest {
            note_ref: input.note_ref.clone(),
            fork_ref: fork.to_hex(),
            reason: input.reason.clone(),
        })?
        .value
        .ok_or_else(withheld)
    }

    /// Fork output uses the same reason-logged admission and lifting as a
    /// live NOTE read. A guessed fork id cannot disclose another NOTE.
    pub fn read_note_fork(
        &self,
        input: &NoteForkReadRequest,
    ) -> MemoryResult<ScopedReadResult<Option<NoteForkView>>> {
        let fork = side_id(&input.fork_ref)?;
        self.project_note_read(
            &NoteAccessRequest {
                note_ref: input.note_ref.clone(),
                reason: input.reason.clone(),
            },
            |txn, doc| {
                NOTE_FORK
                    .get(&self.vault().store, txn, &fork)?
                    .filter(|fork| fork.note == doc.note)
                    .map(|fork| fork_view(self.vault(), txn, fork))
                    .transpose()
            },
        )
        .map(|read| ScopedReadResult {
            value: read.value.flatten(),
            receipt: read.receipt,
        })
    }

    /// Every member is admitted, not only the first file. The engine owns
    /// assignment, independent grant routing and atomic set creation.
    pub fn open_note_proposal(
        &self,
        input: &NoteProposalOpenRequest,
    ) -> MemoryResult<NoteProposalView> {
        let mut forks = Vec::new();
        for member in &input.forks {
            let read = self.read_note_fork(&NoteForkReadRequest {
                note_ref: member.note_ref.clone(),
                fork_ref: member.fork_ref.clone(),
                reason: input.reason.clone(),
            })?;
            if read.value.is_none() {
                return Err(withheld());
            }
            forks.push(side_id(&member.fork_ref)?);
        }
        let bundle =
            self.vault()
                .open_note_proposal(&forks, &input.explainer, self.write_actor())?;
        self.read_note_proposal(&NoteProposalRequest {
            proposal_ref: bundle.id.to_hex(),
            reason: input.reason.clone(),
        })
    }

    /// A set is disclosed only if the caller can read every NOTE it names.
    /// This includes settled members and the shared explainer, not a partial set.
    pub fn read_note_proposal(
        &self,
        input: &NoteProposalRequest,
    ) -> MemoryResult<NoteProposalView> {
        let bundle = self.vault().note_proposal(side_id(&input.proposal_ref)?)?;
        let notes: std::collections::BTreeSet<_> = bundle
            .waiting
            .iter()
            .map(|fork| fork.note)
            .chain(bundle.landed.iter().map(|receipt| receipt.note))
            .collect();
        for note in notes {
            if self
                .read_note(&NoteReadRequest {
                    note_ref: note.to_hex(),
                    reason: input.reason.clone(),
                    version: None,
                    spans: Vec::new(),
                })?
                .value
                .is_none()
            {
                return Err(withheld());
            }
        }
        let mut waiting = Vec::new();
        for fork in bundle.waiting {
            waiting.push(
                self.read_note_fork(&NoteForkReadRequest {
                    note_ref: fork.note.to_hex(),
                    fork_ref: fork.fork.to_hex(),
                    reason: input.reason.clone(),
                })?
                .value
                .ok_or_else(withheld)?,
            );
        }
        let view = NoteProposalView {
            proposal_ref: bundle.id.to_hex(),
            waiting,
            landed: bundle.landed.into_iter().map(Into::into).collect(),
            explainer: bundle.explainer,
        };
        let value =
            serde_json::to_value(&view).map_err(|_| invalid("NOTE proposal view encoding"))?;
        self.lifted_view(view, || {
            let txn = self.vault().store.env.read_txn()?;
            Ok(crate::batch::secret_scan::LiftedKeys::of_json_in_txn(
                &self.vault().store,
                &txn,
                &value,
            )?)
        })
    }

    /// One engine verdict settles the complete set under the caller's
    /// existing NOTE grants. No owner proof or internal fallback is invented.
    pub fn settle_note_proposal(
        &self,
        input: &NoteProposalRequest,
        verdict: NoteVerdict,
    ) -> MemoryResult<NoteProposalView> {
        self.read_note_proposal(input)?;
        self.vault().review_note_proposal(
            side_id(&input.proposal_ref)?,
            verdict,
            self.write_actor(),
        )?;
        self.read_note_proposal(input)
    }

    pub fn note_version_tree(
        &self,
        input: &NoteAccessRequest,
    ) -> MemoryResult<ScopedReadResult<Option<NoteVersionTree>>> {
        self.project_note_read(input, |txn, doc: NoteDocument| {
            let (header, core) = super::verbs::note_core(self.vault(), txn, doc.note)?;
            let forks = NOTE_FORK
                .scan(&self.vault().store, txn)?
                .into_iter()
                .map(|(_, fork)| fork)
                .filter(|fork| fork.note == doc.note)
                .map(Into::into)
                .collect();
            let receipts = NOTE_RECEIPT
                .scan(&self.vault().store, txn)?
                .into_iter()
                .map(|(_, receipt)| receipt)
                .filter(|receipt| receipt.note == doc.note)
                .map(Into::into)
                .collect();
            Ok(NoteVersionTree {
                version: doc.version(),
                // An erased birth author reads as the erased marker, no one.
                birth_author: core.author_ref.to_wire(),
                born_at: header.occurred_start,
                forks,
                receipts,
            })
        })
    }
}
