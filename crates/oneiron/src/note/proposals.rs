//! Grant-routed fork bundles, atomic verdicts and durable head-move receipts.

use super::NoteProgramEdit;
use super::documents::{NoteDocument, invalid, live_doc, load_doc, load_head, store_doc};
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::memory::MemoryResult;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteFork {
    #[serde(with = "crate::entity_id::serde_hex")]
    pub note: EntityId,
    #[serde(with = "crate::entity_id::serde_hex")]
    pub fork: EntityId,
    #[serde(with = "crate::entity_id::serde_hex")]
    pub parent: EntityId,
    pub frontier: Vec<u8>,
    /// Recovery-only value basis: (parent text at capture, exact merged text).
    /// No old CRDT operation identity is assumed after canonical reconstruction.
    pub recovery_merge: Option<(String, String)>,
    #[serde(with = "crate::entity_id::serde_hex")]
    pub actor: EntityId,
    pub rewrite: bool,
    #[serde(with = "crate::entity_id::serde_hex::optional")]
    pub proposal: Option<EntityId>,
    pub decided: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoteVerdict {
    Merge,
    Switch,
    Reject,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteLandingReceipt {
    #[serde(with = "crate::entity_id::serde_hex")]
    pub id: EntityId,
    #[serde(with = "crate::entity_id::serde_hex")]
    pub note: EntityId,
    #[serde(with = "crate::entity_id::serde_hex")]
    pub fork: EntityId,
    #[serde(with = "crate::entity_id::serde_hex")]
    pub previous_head: EntityId,
    #[serde(with = "crate::entity_id::serde_hex")]
    pub head: EntityId,
    pub verdict: NoteVerdict,
    #[serde(with = "crate::entity_id::serde_hex")]
    pub actor: EntityId,
    pub at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteReviewBundle {
    #[serde(with = "crate::entity_id::serde_hex")]
    pub id: EntityId,
    pub waiting: Vec<NoteFork>,
    pub landed: Vec<NoteLandingReceipt>,
    pub explainer: String,
}
fn fork_key(fork: EntityId) -> Vec<u8> {
    [b"note_fork:v1:".as_slice(), fork.as_bytes()].concat()
}
fn bundle_key(id: EntityId) -> Vec<u8> {
    [b"note_proposal:v1:".as_slice(), id.as_bytes()].concat()
}
fn put<T: Serialize>(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8],
    value: &T,
) -> Result<()> {
    vault.store.vault_meta.put(
        txn,
        key,
        &rmp_serde::to_vec_named(value).map_err(|_| invalid("proposal encode"))?,
    )
}
fn get<T: serde::de::DeserializeOwned>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
) -> Result<T> {
    let bytes = vault
        .store
        .vault_meta
        .get(txn, key)?
        .ok_or(invalid("missing proposal record"))?;
    rmp_serde::from_slice(&bytes).map_err(|_| invalid("proposal decode"))
}
pub(super) fn remember_fork(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    parent: &NoteDocument,
    fork: &NoteDocument,
    actor: EntityId,
    rewrite: bool,
) -> Result<()> {
    let record = NoteFork {
        note: parent.note,
        fork: fork.head,
        parent: parent.head,
        frontier: Vec::new(),
        recovery_merge: (!rewrite).then(|| (parent.text(), fork.text())),
        actor,
        rewrite,
        proposal: None,
        decided: false,
    };
    put(vault, txn, &fork_key(fork.head), &record)
}

/// One resolver for both direct edits and proposal routing. Owner authority
/// comes from the authority log, not merely from an asserted actor class.
pub(super) fn grant_allows(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    actor: WriteActor,
) -> Result<bool> {
    let (_, core) = super::verbs::note_core(vault, txn, note)?;
    if core.author_ref == actor.entity_ref()
        || (actor.actor_class() == EdgeActorClass::Human
            && crate::memory::verify_owner_actor_binding_in_txn(vault, txn, actor.entity_ref())
                .is_ok())
    {
        return Ok(true);
    }
    automatic_edit_grant(vault, txn, note, actor)
}

/// True when the policy manifest gives `actor` an automatic `note.edit` grant
/// that names `note`.
pub(super) fn automatic_edit_grant(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    actor: WriteActor,
) -> Result<bool> {
    let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    if policy.is_fail_closed() {
        return Ok(false);
    }
    Ok(policy.scoped_grants().iter().any(|g| {
        if g.effector != "note.edit"
            || g.budget.is_some()
            || g.actor_class
                .as_deref()
                .is_some_and(|c| c != actor.actor_class().gate_actor_class())
            || g.actor_ref.as_deref() != Some(actor.entity_ref().to_hex().as_str())
        {
            return false;
        }
        let Some(rmpv::Value::Map(scope)) = g.scope.as_ref() else {
            return false;
        };
        !scope.is_empty()
            && scope.iter().all(|(k, v)| {
                k.as_str() == Some("entity_refs")
                    && v.as_array().is_some_and(|refs| {
                        refs.iter()
                            .any(|v| v.as_str() == Some(note.to_hex().as_str()))
                    })
            })
    }))
}

impl Vault {
    /// Opens all listed forks under one proposal. Each is assigned exactly
    /// once, routed independently and receipted in the same transaction.
    pub fn open_note_proposal(
        &self,
        forks: &[EntityId],
        explainer: &str,
        actor: WriteActor,
    ) -> MemoryResult<NoteReviewBundle> {
        if forks.is_empty() || forks.len() > 256 || explainer.trim().is_empty() {
            return Err(invalid("proposal needs bounded forks and an explainer").into());
        }
        self.memory(actor.entity_ref(), actor.actor_class())
            .with_verified_actor_write_txn(|txn| {
                let mut bundle = NoteReviewBundle {
                    id: self.store.clock.entity_id()?,
                    waiting: Vec::new(),
                    landed: Vec::new(),
                    explainer: explainer.to_owned(),
                };
                for id in forks {
                    let mut fork: NoteFork = get(self, txn, &fork_key(*id))?;
                    if fork.proposal.is_some() || fork.decided || fork.actor != actor.entity_ref() {
                        return Err(
                            invalid("fork already assigned or belongs to another actor").into()
                        );
                    }
                    fork.proposal = Some(bundle.id);
                    put(self, txn, &fork_key(*id), &fork)?;
                    if !fork.rewrite && grant_allows(self, txn, fork.note, actor)? {
                        if let Some(receipt) =
                            land(self, txn, &mut fork, NoteVerdict::Merge, actor)?
                        {
                            bundle.landed.push(receipt);
                        } else {
                            bundle.waiting.push(fork);
                        }
                    } else {
                        bundle.waiting.push(fork);
                    }
                }
                put(self, txn, &bundle_key(bundle.id), &bundle)?;
                Ok(bundle)
            })
    }
    pub fn note_proposal(&self, id: EntityId) -> Result<NoteReviewBundle> {
        let txn = self.store.env.read_txn()?;
        get(self, &txn, &bundle_key(id))
    }
    pub fn review_note_proposal(
        &self,
        id: EntityId,
        verdict: NoteVerdict,
        actor: WriteActor,
    ) -> MemoryResult<NoteReviewBundle> {
        self.memory(actor.entity_ref(), actor.actor_class())
            .with_verified_actor_write_txn(|txn| {
                let mut bundle: NoteReviewBundle = get(self, txn, &bundle_key(id))?;
                for fork in &mut bundle.waiting {
                    if !grant_allows(self, txn, fork.note, actor)? {
                        return Err(invalid("no grant to accept this fork").into());
                    }
                    if let Some(receipt) = land(self, txn, fork, verdict, actor)? {
                        bundle.landed.push(receipt);
                    }
                }
                bundle.waiting.retain(|fork| !fork.decided);
                put(self, txn, &bundle_key(id), &bundle)?;
                Ok(bundle)
            })
    }
    /// Explicit fork at the current frontier. The live head is never edited.
    pub fn fork_note(
        &self,
        note: EntityId,
        edit: &NoteProgramEdit,
        actor: WriteActor,
    ) -> MemoryResult<EntityId> {
        self.memory(actor.entity_ref(), actor.actor_class())
            .with_verified_actor_write_txn(|txn| {
                super::verbs::note_core(self, txn, note)?;
                let parent = load_doc(self, txn, note)?.ok_or(invalid("note has no document"))?;
                let fork_doc = parent
                    .doc
                    .fork_at(&parent.doc.state_frontiers())
                    .map_err(|_| invalid("fork frontier"))?;
                let mut fork = NoteDocument {
                    note,
                    head: parent.head,
                    doc: fork_doc,
                };
                let mut rewrite = matches!(edit, NoteProgramEdit::Rewrite { .. });
                if let Some(replacement) = fork.apply(
                    &self.store.clock,
                    edit,
                    actor.entity_ref(),
                    self.store.clock.now_recorded_at(),
                )? {
                    rewrite = true;
                    fork = replacement;
                }
                fork.head = self.store.clock.entity_id()?;
                store_doc(self, txn, &fork)?;
                remember_fork(self, txn, &parent, &fork, actor.entity_ref(), rewrite)?;
                Ok(fork.head)
            })
    }
}
fn land(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    fork: &mut NoteFork,
    verdict: NoteVerdict,
    actor: WriteActor,
) -> Result<Option<NoteLandingReceipt>> {
    let mutation_recorded_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    if fork.decided {
        return Err(invalid("fork already decided"));
    }
    super::verbs::note_core(vault, txn, fork.note)?;
    let current = live_doc(vault, txn, fork.note)?;
    let proposed = load_head(vault, txn, fork.note, fork.fork)?;
    let text = match verdict {
        NoteVerdict::Merge => {
            if fork.rewrite {
                return Err(invalid("declared rewrites require explicit switch"));
            }
            if current.head != fork.parent {
                return Err(invalid("parent is not the canonical NOTE"));
            }
            if let Some((base, merged)) = &fork.recovery_merge {
                Some(recovered_merge(base, merged, &current.text())?)
            } else {
                let scratch = current.doc.fork();
                super::storage::import_complete(
                    &scratch,
                    &super::documents::snapshot(&proposed.doc)?,
                )?;
                Some(scratch.get_text("body").to_string())
            }
        }
        NoteVerdict::Switch => Some(proposed.text()),
        NoteVerdict::Reject => None,
    };
    if let Some(text) = text {
        let operation = super::NoteOperation {
            request_id: vault.store.clock.entity_id()?,
            change: super::NoteChange::Edit {
                base: current.doc.oplog_frontiers().encode(),
                edits: vec![super::documents::text_change(&current.text(), &text)],
            },
        };
        let receipt = vault
            .memory(actor.entity_ref(), actor.actor_class())
            .apply_note_operation_in_txn(txn, fork.note, &operation, None)
            .map_err(|_| invalid("canonical NOTE proposal admission failed"))?;
        if matches!(receipt.outcome, super::NoteEditOutcome::Proposed(_)) {
            return Ok(None);
        }
    }
    vault
        .store
        .sync_state
        .delete(txn, &super::documents::doc_key(fork.note, fork.fork))?;
    fork.decided = true;
    fork.recovery_merge = None;
    put(vault, txn, &fork_key(fork.fork), fork)?;
    let receipt = NoteLandingReceipt {
        id: vault.store.clock.entity_id()?,
        note: fork.note,
        fork: fork.fork,
        previous_head: current.head,
        head: current.head,
        verdict,
        actor: actor.entity_ref(),
        at: mutation_recorded_at,
    };
    put(
        vault,
        txn,
        &[b"note_receipt:v1:".as_slice(), receipt.id.as_bytes()].concat(),
        &receipt,
    )?;
    Ok(Some(receipt))
}

/// A recovery merge carries the exact pre-recovery CRDT result. Subsequent,
/// disjoint edits are retained. Ambiguous overlaps need an explicit switch,
/// never a guessed import of unrelated fresh Loro histories.
fn recovered_merge(base: &str, proposed: &str, current: &str) -> Result<String> {
    if current == base || current == proposed {
        return Ok(proposed.to_owned());
    }
    if proposed == base {
        return Ok(current.to_owned());
    }
    let base: Vec<_> = base.chars().collect();
    let proposed: Vec<_> = proposed.chars().collect();
    let current: Vec<_> = current.chars().collect();
    let span = |changed: &[char]| {
        let start = base.iter().zip(changed).take_while(|(a, b)| a == b).count();
        let suffix = base[start..]
            .iter()
            .rev()
            .zip(changed[start..].iter().rev())
            .take_while(|(a, b)| a == b)
            .count();
        (
            start,
            base.len() - suffix,
            changed[start..changed.len() - suffix].to_vec(),
        )
    };
    let mut edits = [span(&proposed), span(&current)];
    edits.sort_by_key(|(start, end, _)| (*start, *end));
    let [
        (left_start, left_end, left),
        (right_start, right_end, right),
    ] = edits;
    // Boundary insertions have no surviving cursor order after recovery.
    if left_end >= right_start {
        return Err(invalid("recovered fork overlap; explicit switch required"));
    }
    Ok(base[..left_start]
        .iter()
        .chain(&left)
        .chain(&base[left_end..right_start])
        .chain(&right)
        .chain(&base[right_end..])
        .collect())
}
