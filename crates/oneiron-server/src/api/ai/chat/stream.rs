//! One reply stream capability: ordinary recorded work or its native caller session.

use super::*;
use oneiron::memory::{SessionMessageStream, SessionStreamFinished, SessionStreamOutcome};

#[derive(Clone)]
pub(crate) enum AnswerStream {
    Recorded(MessageStreamHandle),
    Session {
        token: SessionMessageStream,
        id: EntityId,
    },
}

impl AnswerStream {
    /// Work correlation only; a session stream id is not a saved MESSAGE id.
    pub(crate) fn correlation_id(&self) -> EntityId {
        match self {
            Self::Recorded(handle) => handle.message_id(),
            Self::Session { id, .. } => *id,
        }
    }

    pub(crate) fn recorded_message_id(&self) -> Option<EntityId> {
        match self {
            Self::Recorded(handle) => Some(handle.message_id()),
            Self::Session { .. } => None,
        }
    }

    pub(crate) fn is_session(&self) -> bool {
        matches!(self, Self::Session { .. })
    }

    pub(crate) fn append(
        &self,
        memory: &Memory<'_>,
        vault: &Vault,
        text: &str,
    ) -> oneiron::memory::MessageStreamResult<()> {
        match self {
            Self::Recorded(handle) => memory.append_to_stream(*handle, text),
            Self::Session { token, .. } => token.append(vault, text),
        }
    }

    pub(crate) fn partial(
        &self,
        vault: &Vault,
    ) -> oneiron::memory::MessageStreamResult<Option<String>> {
        match self {
            Self::Recorded(_) => Ok(None),
            Self::Session { token, .. } => Ok(Some(token.partial(vault)?.text)),
        }
    }

    pub(crate) fn disclosed_text(
        &self,
        vault: &Vault,
    ) -> oneiron::memory::MessageStreamResult<Option<String>> {
        match self.partial(vault) {
            Ok(text) => Ok(text),
            Err(error) => match self.finished(vault)? {
                Some(finished) => Ok(Some(finished.text)),
                None => Err(error),
            },
        }
    }

    pub(crate) fn finished(
        &self,
        vault: &Vault,
    ) -> oneiron::memory::MessageStreamResult<Option<SessionStreamFinished>> {
        match self {
            Self::Recorded(_) => Ok(None),
            Self::Session { token, .. } => token.finished(vault),
        }
    }

    pub(crate) fn revalidate(&self, vault: &Vault) -> Result<(), String> {
        let Self::Session { token, .. } = self else {
            return Ok(());
        };
        token
            .completion(vault)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub(crate) fn finalize_model(
        &self,
        vault: &Vault,
        memory: &Memory<'_>,
        terminal: &LlmResponse,
        credential: &TurnCredential,
    ) -> oneiron::memory::MessageStreamResult<Option<MessageStreamReceipt>> {
        let asserted = assertions::witness_assertions(&terminal.reply_assertions);
        match self {
            Self::Recorded(handle) => memory
                .finalize_model_stream_if(
                    *handle,
                    terminal.finish_reason.clone(),
                    &asserted,
                    |txn| credential.live_in(txn),
                )
                .map(Some),
            Self::Session { token, .. } => {
                let outcome = token.finalize_model(
                    vault,
                    terminal.finish_reason.clone(),
                    &asserted,
                    terminal.message.content.clone(),
                )?;
                Ok(match outcome {
                    SessionStreamOutcome::Retained(receipt) => Some(receipt),
                    SessionStreamOutcome::Unretained(_) => None,
                })
            }
        }
    }

    pub(crate) fn cancel(
        &self,
        vault: &Vault,
        memory: &Memory<'_>,
        reason: StreamCancelReason,
    ) -> oneiron::memory::MessageStreamResult<Option<MessageStreamReceipt>> {
        match self {
            Self::Recorded(handle) => memory.cancel_stream(*handle, reason).map(Some),
            Self::Session { token, .. } => Ok(match token.cancel(vault, reason)? {
                SessionStreamOutcome::Retained(receipt) => Some(receipt),
                SessionStreamOutcome::Unretained(_) => None,
            }),
        }
    }
}
