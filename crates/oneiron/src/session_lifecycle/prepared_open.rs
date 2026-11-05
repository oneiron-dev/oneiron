//! A session open prepared outside a caller's write transaction.

use super::*;
use crate::runtime_hooks::verb::VerbHookPre;

/// The exact sitting selected before a caller prepares rows that name it.
/// A changed open pointer requires fresh preparation, never a different subject.
pub(crate) struct PreparedSessionOpen {
    session: EntityId,
    key: SessionKey,
    timestamp: SessionHintTimestamp,
    pre: Option<VerbHookPre>,
}

impl PreparedSessionOpen {
    pub(crate) const fn session(&self) -> EntityId {
        self.session
    }

    /// Applies the native open only while its selected pointer still holds.
    /// `None` changes nothing and asks the caller to prepare outside the writer.
    pub(crate) fn apply_in_txn(
        &self,
        vault: &Vault,
        txn: &mut RwTxn<'_>,
    ) -> Result<Option<SessionMintOutcome>> {
        let expected = self.pre.is_none().then_some(self.session);
        if OPEN_POINTER.get(&vault.store, txn, &self.key.pointer())? != expected {
            return Ok(None);
        }
        vault
            .mint_session_with_id_in_txn(txn, self.key, self.timestamp, self.session)
            .map(Some)
    }

    pub(crate) fn reopen_on_storage_error(&self, vault: &Vault, error: &Error) {
        if crate::runtime_hooks::verb::error_failed_storage(error)
            && let Some(pre) = &self.pre
        {
            vault.reopen_resumed_ask(pre);
        }
    }

    /// Runs the original open post-chain only after the caller's commit.
    pub(crate) fn finish(self, vault: &Vault, outcome: SessionMintOutcome) {
        if let (Some(pre), SessionMintOutcome::Minted(session)) = (self.pre, outcome) {
            let result = json!({
                "session": session.to_hex(),
                "started_at": self.timestamp.effective_ms / 1_000,
            });
            if let Err(error) = vault.post_verb_hooks(pre, result) {
                tracing::warn!(
                    ?error,
                    "host.session.open post-hooks failed on an opened sitting"
                );
            }
        }
    }
}

impl Vault {
    /// Selects an open sitting or reserves its real id and runs its pre-chain.
    /// No SESSION, lifecycle record or open pointer is written here.
    pub(crate) fn prepare_session_open(
        &self,
        key: SessionKey,
        now: u64,
    ) -> Result<PreparedSessionOpen> {
        let timestamp_ms = now.saturating_mul(1_000);
        let timestamp = SessionHintTimestamp {
            claimed_ms: None,
            arrival_ms: timestamp_ms,
            effective_ms: timestamp_ms,
        };
        let open = {
            let txn = self.store.env.read_txn()?;
            OPEN_POINTER.get(&self.store, &txn, &key.pointer())?
        };
        if let Some(session) = open {
            return Ok(PreparedSessionOpen {
                session,
                key,
                timestamp,
                pre: None,
            });
        }
        let session = self.store.clock.entity_id()?;
        let args = session_hook_args(session, "app_open");
        let check = |rewritten: &Value| host_args_kept(&args, rewritten);
        let call = session_hook_call(HOST_SESSION_OPEN, session, key.actor, 0);
        let pre = self
            .pre_verb_hooks(call, args.clone(), &check)?
            .map_err(Error::from)?;
        Ok(PreparedSessionOpen {
            session,
            key,
            timestamp,
            pre: Some(pre),
        })
    }
}
