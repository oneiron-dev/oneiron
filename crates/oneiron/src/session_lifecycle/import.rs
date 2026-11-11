//! Session hooks around an atomic imported sitting. Pre-hooks observe intent:
//! the sitting does not exist until its import transaction commits.

use super::*;
use crate::runtime_hooks::verb::{VerbHookPre, VerbHookWaitStatus};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SessionImportHint {
    key: SessionKey,
    id: EntityId,
    start: SessionHintTimestamp,
    end: SessionHintTimestamp,
}

impl SessionImportHint {
    pub(crate) fn id(&self) -> EntityId {
        self.id
    }

    pub(crate) fn key(&self) -> SessionKey {
        self.key
    }
}

pub(crate) struct SessionImportPre {
    open: VerbHookPre,
    close: Option<VerbHookPre>,
    close_stop: Option<String>,
}

impl Vault {
    pub(crate) fn prepare_session_import_hint(
        &self,
        key: SessionKey,
        start: SessionHintTimestamp,
        end: SessionHintTimestamp,
    ) -> Result<SessionImportHint> {
        Ok(SessionImportHint {
            key,
            id: self.store.clock.entity_id()?,
            start,
            end,
        })
    }

    pub(crate) fn session_import_hook_wait(
        &self,
        hint: &SessionImportHint,
        ask: EntityId,
        memory: &crate::Memory<'_>,
    ) -> Result<VerbHookWaitStatus> {
        let call = session_hook_call(HOST_SESSION_OPEN, hint.id, hint.key.actor, 0);
        let status = self.verb_hook_wait_status_on_turn(
            call.invocation,
            &call.verb,
            call.actor,
            call.class,
            ask,
            memory.task_work_turn(),
        )?;
        Ok(
            if status == VerbHookWaitStatus::Waiting && !self.hooks_enabled()? {
                VerbHookWaitStatus::Ready
            } else {
                status
            },
        )
    }

    pub(crate) fn pre_session_import_hooks(
        &self,
        hint: &SessionImportHint,
        memory: &crate::Memory<'_>,
    ) -> crate::memory::MemoryResult<
        std::result::Result<SessionImportPre, crate::runtime_hooks::VerbHookStop>,
    > {
        let open_args = session_hook_args(hint.id, "app_open");
        let mut open_call = session_hook_call(HOST_SESSION_OPEN, hint.id, hint.key.actor, 0);
        open_call.reader = crate::runtime_hooks::VerbCall::reader_of(memory, HOST_SESSION_OPEN)?;
        let open_check = |rewritten: &Value| host_args_kept(&open_args, rewritten);
        let open = match self.pre_verb_hooks_resumable(
            open_call,
            open_args.clone(),
            &open_check,
            None,
            memory.task_work_turn(),
        )? {
            Ok(pre) => pre,
            Err(stop) => return Ok(Err(stop)),
        };
        let close_args = session_hook_args(hint.id, "explicit");
        let mut close_call = session_hook_call(HOST_SESSION_CLOSE, hint.id, hint.key.actor, 1);
        close_call.reader =
            match crate::runtime_hooks::VerbCall::reader_of(memory, HOST_SESSION_CLOSE) {
                Ok(reader) => reader,
                Err(error) => {
                    self.reopen_resumed_ask(&open);
                    return Err(error);
                }
            };
        let close_check = |rewritten: &Value| host_args_kept(&close_args, rewritten);
        let close = match self.pre_verb_hooks_resumable(
            close_call,
            close_args.clone(),
            &close_check,
            None,
            memory.task_work_turn(),
        ) {
            Ok(close) => close,
            Err(error) => {
                if crate::runtime_hooks::verb::error_failed_storage(&error) {
                    self.reopen_resumed_ask(&open);
                }
                return Err(error.into());
            }
        };
        let (close, close_stop) = match close {
            Ok(pre) => (Some(pre), None),
            Err(stop) => (None, Some(stop.to_string())),
        };
        Ok(Ok(SessionImportPre {
            open,
            close,
            close_stop,
        }))
    }

    pub(crate) fn rearm_session_import_hooks(&self, pre: &SessionImportPre) {
        self.reopen_resumed_ask(&pre.open);
        if let Some(close) = &pre.close {
            self.reopen_resumed_ask(close);
        }
    }

    pub(crate) fn mint_import_session_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        hint: &SessionImportHint,
    ) -> Result<SessionMintOutcome> {
        self.mint_session_with_id_in_txn(txn, hint.key, hint.start, hint.id)
    }

    pub(crate) fn close_import_session_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        hint: &SessionImportHint,
        pre: &SessionImportPre,
        wake: &SessionEndWake,
    ) -> Result<Option<EndedSession>> {
        self.end_session_in_txn(
            txn,
            &hint.id,
            SessionClosePredicate::Explicit,
            hint.end.effective_ms / 1_000,
            wake,
            Some(hint.end),
            pre.close_stop.clone(),
        )
    }

    pub(crate) fn post_session_import_hooks(
        &self,
        hint: &SessionImportHint,
        pre: SessionImportPre,
        ended: &EndedSession,
    ) {
        let opened = json!({
            "session": hint.id.to_hex(),
            "started_at": hint.start.effective_ms / 1_000,
        });
        if let Err(error) = self.post_verb_hooks(pre.open, opened) {
            tracing::warn!(
                ?error,
                "host.session.open post-hooks failed on an imported sitting"
            );
        }
        if let Some(close) = pre.close {
            let result = json!({
                "session": ended.session.to_hex(),
                "ended_at": ended.ended_at,
                "reason": end_reason_word(ended.reason),
            });
            if let Err(error) = self.post_verb_hooks(close, result) {
                tracing::warn!(
                    ?error,
                    "host.session.close post-hooks failed on an imported sitting"
                );
            }
        }
    }
}
