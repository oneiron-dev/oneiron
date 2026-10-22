//! One rung's stream handed to the caller event by event, up to its
//! terminal or its failure.
use futures_util::StreamExt;
use oneiron::{LlmError, LlmMessage, LlmResult, LlmStream, LlmStreamEvent, LlmUsage};
use tokio::sync::mpsc::Sender;

/// What one rung's stream came to.
pub(super) enum Ended {
    Done {
        message: LlmMessage,
        usage: LlmUsage,
        finish_reason: oneiron::llm::FinishReason,
        /// The terminal's own, forwarded as it came (FIX 3416).
        reply_assertions: oneiron::llm::ReplyAssertions,
    },
    Failed {
        error: LlmError,
        spoken: bool,
    },
    /// The caller stopped reading, or the stream ended with no terminal.
    Gone,
}

/// Hands one rung's events to the caller until its terminal or its failure.
pub(super) async fn forward(
    mut stream: LlmStream<'_>,
    events: &Sender<LlmResult<LlmStreamEvent>>,
) -> Ended {
    let mut spoken = false;
    loop {
        match stream.next().await {
            Some(Ok(LlmStreamEvent::Done {
                message,
                usage,
                finish_reason,
                reply_assertions,
            })) => {
                return Ended::Done {
                    message,
                    usage,
                    finish_reason,
                    reply_assertions,
                };
            }
            Some(Ok(event)) => {
                spoken = true;
                if events.send(Ok(event)).await.is_err() {
                    return Ended::Gone;
                }
            }
            Some(Err(error)) => return Ended::Failed { error, spoken },
            // An `LlmStream` that ends before its terminal yields `StreamCut`
            // first, so this is a caller that stopped reading.
            None => return Ended::Gone,
        }
    }
}
