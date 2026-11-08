//! The immutable identity and timestamp of a caller-retained session open.

use super::*;

/// A prepared app-open hint. Retrying it keeps the original sitting id and
/// timestamp; the ordinary hook boundary still decides whether it may open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionOpenHint {
    key: SessionKey,
    timestamp: SessionHintTimestamp,
    id: EntityId,
}

impl SessionOpenHint {
    #[must_use]
    pub const fn timestamp(&self) -> SessionHintTimestamp {
        self.timestamp
    }
}

impl Vault {
    /// Prepares the identity before running the app-open hook chain. Keeping
    /// this value is not permission to skip that chain on a retry.
    pub fn prepare_session_open_hint(
        &self,
        key: SessionKey,
        timestamp: SessionHintTimestamp,
    ) -> Result<SessionOpenHint> {
        Ok(SessionOpenHint {
            key,
            timestamp,
            id: self.store.clock.entity_id()?,
        })
    }

    /// Runs or resumes the ordinary open with its original id and timestamp.
    pub fn mint_prepared_session_hint(&self, hint: &SessionOpenHint) -> Result<SessionMintOutcome> {
        let SessionOpenHint { key, timestamp, id } = *hint;
        let open = {
            let rtxn = self.store.env.read_txn()?;
            OPEN_POINTER.get(&self.store, &rtxn, &key.pointer())?
        };
        if let Some(existing) = open {
            return Ok(SessionMintOutcome::AlreadyOpen(existing));
        }
        let args = session_hook_args(id, "app_open");
        let check = |rewritten: &Value| host_args_kept(&args, rewritten);
        let call = session_hook_call(HOST_SESSION_OPEN, id, key.actor, 0);
        let pre = self
            .pre_verb_hooks(call, args.clone(), &check)?
            .map_err(Error::from)?;
        let outcome = match self.with_write_txn_grouped(|wtxn| {
            self.mint_session_with_id_in_txn(wtxn, key, timestamp, id)
        }) {
            Ok(outcome) => outcome,
            Err(error) => {
                if crate::runtime_hooks::verb::error_failed_storage(&error) {
                    self.reopen_resumed_ask(&pre);
                }
                return Err(error);
            }
        };
        if let SessionMintOutcome::Minted(session) = outcome {
            // On the Dreamer's stage target: from this line on, a TURN this
            // key witnesses joins the sitting.
            tracing::info!(
                target: "oneiron::dreamer::stages",
                session = %session.to_hex(),
                started_ms = timestamp.effective_ms,
                "dreamer sitting open"
            );
            // The sitting is open whatever a post-hook says.
            let result = json!({
                "session": session.to_hex(),
                "started_at": timestamp.effective_ms / 1_000,
            });
            if let Err(error) = self.post_verb_hooks(pre, result) {
                tracing::warn!(
                    ?error,
                    "host.session.open post-hooks failed on an opened sitting"
                );
            }
        }
        Ok(outcome)
    }
}

impl Vault {
    /// Reads this retained open's native hook status and existing ask deadline
    /// (unix milliseconds). A ready status is only a hint to retry its boundary.
    pub fn session_open_hook_wait(
        &self,
        hint: &SessionOpenHint,
        ask: EntityId,
    ) -> Result<(crate::runtime_hooks::verb::VerbHookWaitStatus, Option<u64>)> {
        let call = session_hook_call(HOST_SESSION_OPEN, hint.id, hint.key.actor, 0);
        let status =
            self.verb_hook_wait_status(call.invocation, &call.verb, call.actor, call.class, ask)?;
        let deadline = if status == crate::runtime_hooks::verb::VerbHookWaitStatus::Waiting {
            self.verb_hook_wait_deadline(call.invocation, &call.verb, call.actor, call.class, ask)?
                .map(|until| until.saturating_mul(1_000))
        } else {
            None
        };
        Ok((status, deadline))
    }
}
