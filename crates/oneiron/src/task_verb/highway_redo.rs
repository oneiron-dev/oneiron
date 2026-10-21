//! A TASK's redo (FIX 3153): a new TASK posted from an earlier one's
//! content, through the post the highway already runs. The earlier TASK,
//! its result and its receipts are never written; the redo is a new TASK
//! with a try of its own.

use rmpv::Value;

use crate::EdgeKind;
use crate::error::Error;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::ports::{EdgeDirection, EdgeStoreRead};

use super::decision_port::TaskDecisions;
use super::highway::not_found;
use super::highway_types::{TaskCallReceipt, TaskPost, TaskRedo, TaskVia};
use super::verb_kind::TaskAssignee;
use super::wire_decode::task_verb_body_in;

/// What a redo's intent key starts with, before the redone TASK's hex.
const REDO_KEY_PREFIX: &str = "redo:";

/// The receipt lifecycle field naming the TASK a redo copied.
const REDO_OF_FIELD: &str = "redo_of";

impl Memory<'_> {
    /// Redo ([`Memory::tasks_redo`]): reads the named TASK under
    /// `describe`'s read check, before the read and again after it, and
    /// posts its content as the caller's own new TASK.
    pub(super) fn highway_redo(
        &self,
        via: &TaskVia,
        redo: TaskRedo,
        decisions: Option<&TaskDecisions<'_>>,
    ) -> MemoryResult<TaskCallReceipt> {
        if redo.intent_key.trim().is_empty() {
            return Err(MemoryError::bad_request("intent key must not be blank"));
        }
        if self.credential_withholds(redo.task_ref)? {
            return Err(not_found());
        }
        let post = self.redo_post(&redo)?;
        if self.credential_withholds(redo.task_ref)? {
            return Err(not_found());
        }
        let mut receipt = self.highway_post(via, post, decisions)?;
        if let Some(lifecycle) = receipt.lifecycle.as_mut() {
            lifecycle
                .fields
                .insert(REDO_OF_FIELD.to_owned(), redo.task_ref.to_hex());
        }
        Ok(receipt)
    }

    /// The post a redo of `redo.task_ref` makes, from one snapshot of it:
    /// its current brief, assignee, spec, label and `ChildOf` parent, under
    /// the redo's own intent key. Its TTL is left behind.
    fn redo_post(&self, redo: &TaskRedo) -> MemoryResult<TaskPost> {
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        let Some(body) = task_verb_body_in(self.vault(), &txn, redo.task_ref)? else {
            return Err(not_found());
        };
        let Some(stored) = body.brief else {
            return Err(MemoryError::bad_request_with(
                format!(
                    "task {} carries no typed brief, and a redo posts the brief it copies",
                    redo.task_ref.to_hex()
                ),
                &["Post a new task with a brief of its own."],
            ));
        };
        let parent_ref = self
            .vault()
            .store
            .port_edges(
                &txn,
                &redo.task_ref,
                EdgeDirection::Out,
                Some(EdgeKind::ChildOf),
                None,
            )?
            .next()
            .transpose()?
            .map(|edge| edge.target);
        // The caller's key enters the post's key hashed to a fixed length
        // (Rule 5), so a key `tasks.create` takes is never too long here.
        Ok(TaskPost {
            intent_key: format!(
                "{REDO_KEY_PREFIX}{}:{}",
                redo.task_ref.to_hex(),
                blake3::hash(redo.intent_key.as_bytes()).to_hex()
            ),
            brief: stored.brief,
            assignee: body.assignee.unwrap_or(TaskAssignee::Dreamer),
            spec: (!matches!(body.spec, Value::Nil)).then_some(body.spec),
            ttl: None,
            label: body.label,
            parent_ref,
        })
    }
}
