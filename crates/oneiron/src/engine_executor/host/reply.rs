//! A single dispatch's early result publication and deferred host adoption.

use std::cell::RefCell;

use super::*;
use crate::code_run::{ExecutorReply, ExecutorReplyPublisher, ReplyBody, unplaced_answer};

pub(super) struct CallReplyPublisher<'a, 's> {
    storage: &'s ExecutorStorage<'a>,
    share: Option<&'s crate::result_memory::ResultShare>,
    run_id: EntityId,
    seq: u64,
    name: String,
    published: RefCell<Option<ExecutorReply>>,
}

impl<'a, 's> CallReplyPublisher<'a, 's> {
    pub(super) fn new(
        storage: &'s ExecutorStorage<'a>,
        share: Option<&'s crate::result_memory::ResultShare>,
        run_id: EntityId,
        seq: u64,
        name: String,
    ) -> Self {
        Self {
            storage,
            share,
            run_id,
            seq,
            name,
            published: RefCell::new(None),
        }
    }

    pub(super) fn take(&self) -> Option<ExecutorReply> {
        self.published.borrow_mut().take()
    }
}

impl ExecutorReplyPublisher for CallReplyPublisher<'_, '_> {
    fn publish(
        &self,
        value: &mut serde_json::Value,
        commit: &mut dyn FnMut(
            &mut heed::RwTxn<'_>,
            &serde_json::Value,
            &ExecutorReply,
        ) -> Result<()>,
    ) -> Result<Option<ExecutorReply>> {
        let ExecutorStorage::Canonical(vault) = self.storage else {
            return Ok(None);
        };
        let mut size = ByteCount::default();
        serde_json::to_writer(&mut size, &*value).map_err(|error| {
            Error::InvalidConfig(format!("verb answer encoding failed: {error}"))
        })?;
        if size.0 <= RESULT_REPLY_INLINE_BYTES {
            return Ok(None);
        }
        let _copy_hold = self
            .share
            .and_then(|share| share.hold(size.0 as u64, self.storage.limit_watch()));
        let mut sink = self.storage.code_run_reply_spool()?;
        write_json(&mut sink, &*value)?;
        let output = match vault.publish_admitted_code_run_output_and(
            bridge_result_output_path(self.seq),
            sink,
            true,
            self.run_id,
            &[],
            None,
            |wtxn, output| {
                let reply = ExecutorReply {
                    owner: self.run_id,
                    name: self.name.clone(),
                    output: output.clone(),
                };
                let mut card = result_handle_json(self.run_id, output);
                card["name"] = json!(self.name);
                commit(wtxn, &card, &reply)
            },
        )? {
            ReplyBody::Published(output) => output,
            ReplyBody::Unplaceable {
                bytes,
                text,
                reason,
            } => {
                *value = unplaced_answer(bytes, text, reason);
                return Ok(None);
            }
        };
        let mut card = result_handle_json(self.run_id, &output);
        card["name"] = json!(self.name);
        *value = card;
        Ok(Some(ExecutorReply {
            owner: self.run_id,
            name: self.name.clone(),
            output,
        }))
    }

    fn adopt(&self, reply: ExecutorReply, value: &serde_json::Value) -> Result<()> {
        let mut expected = result_handle_json(self.run_id, &reply.output);
        expected["name"] = json!(reply.name);
        if reply.owner != self.run_id
            || ["handle", "bytes", "ref", "read", "name"]
                .iter()
                .any(|key| value.get(*key) != expected.get(*key))
        {
            return Err(Error::InvariantViolation(
                "kept executor reply does not match its occurrence",
            ));
        }
        *self.published.borrow_mut() = Some(reply);
        Ok(())
    }
}
