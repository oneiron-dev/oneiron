//! A TASK's redo (FIX 3153): a new TASK posted from an earlier one's
//! content, through the post the highway already runs. The earlier TASK,
//! its result and its receipts are never written; the redo is a new TASK
//! with a try of its own.
//!
//! The copy keeps what its source read (FIX 9001): a pin whose row moved
//! since is named on the receipt, never refused, and a parent that can no
//! longer take a Task is left out and named there too, so the copy is born
//! a root. Read isolation stays: a TASK the caller does not read, by its
//! credential or because a device-local world keeps it from the caller's
//! machine (FIX 9000), is not found.

use rmpv::Value;

use crate::EdgeKind;
use crate::error::Error;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::ports::{EdgeDirection, EdgeStoreRead};

use super::create_validation::task_parent_refusal_in;
use super::decision_port::TaskDecisions;
use super::highway::not_found;
use super::highway_post::PostCopy;
use super::highway_types::{TaskCallReceipt, TaskPost, TaskRedo, TaskVia};
use super::verb_kind::TaskAssignee;
use super::wire_decode::task_verb_body_in;

/// What a redo's intent key starts with, before the redone TASK's hex.
const REDO_KEY_PREFIX: &str = "redo:";

impl Memory<'_> {
    /// Redo ([`Memory::tasks_redo`]): reads the named TASK under
    /// `describe`'s read check, before the read and again after it, and
    /// posts its content as the caller's own new TASK, a copy.
    pub(super) fn highway_redo(
        &self,
        via: &TaskVia,
        redo: TaskRedo,
        decisions: Option<&TaskDecisions<'_>>,
    ) -> MemoryResult<TaskCallReceipt> {
        if redo.intent_key.trim().is_empty() {
            return Err(MemoryError::bad_request("intent key must not be blank"));
        }
        if self.task_read_withholds(redo.task_ref)? {
            return Err(not_found());
        }
        let (post, copy) = self.redo_post(&redo)?;
        if self.task_read_withholds(redo.task_ref)? {
            return Err(not_found());
        }
        self.post_as(via, post, decisions, Some(&copy))
    }

    /// The post a redo of `redo.task_ref` makes, from one snapshot of it:
    /// its current brief, assignee, spec, label and `ChildOf` parent, under
    /// the redo's own intent key, and the copy it is. Its TTL is left
    /// behind, and so is a parent that can no longer take a Task.
    fn redo_post(&self, redo: &TaskRedo) -> MemoryResult<(TaskPost, PostCopy)> {
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
        let dropped_parent = match parent_ref {
            Some(parent) if task_parent_refusal_in(self.vault(), &txn, parent)?.is_some() => {
                Some(parent)
            }
            _ => None,
        };
        // The post hashes its key to a fixed length (FIX 9002), so the
        // caller's key enters it as written, whatever its length.
        let post = TaskPost {
            intent_key: format!(
                "{REDO_KEY_PREFIX}{}:{}",
                redo.task_ref.to_hex(),
                redo.intent_key
            ),
            brief: stored.brief,
            assignee: body.assignee.unwrap_or(TaskAssignee::Dreamer),
            spec: (!matches!(body.spec, Value::Nil)).then_some(body.spec),
            ttl: None,
            label: body.label,
            parent_ref: parent_ref.filter(|_| dropped_parent.is_none()),
        };
        let copy = PostCopy {
            of: redo.task_ref,
            dropped_parent,
        };
        Ok((post, copy))
    }
}
