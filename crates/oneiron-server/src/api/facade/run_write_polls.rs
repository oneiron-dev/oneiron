//! A leased run's write envelope across the polls of an async row (FIX
//! 11698).
//!
//! A run's writes are known by the thread-local envelope a verb call opens on
//! its own thread ([`with_run_write_token`]). A generated MCP memory row runs
//! its engine call on the async task, not on a blocking hop, so it opens the
//! envelope in each poll of its future and closes it before the poll
//! returns: every synchronous stretch writes for the run, and none holds the
//! envelope across an await, so a task the runtime moves to another thread
//! never writes for this run there.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use oneiron::skill_attribution::{RunWriteToken, with_run_write_token};

/// `call` with `token`'s write envelope open in each of its polls. `None`
/// runs it as it is.
pub(crate) async fn scoped<F: Future>(token: Option<RunWriteToken>, call: F) -> F::Output {
    match token {
        Some(token) => {
            RunWritePolls {
                token,
                call: Box::pin(call),
            }
            .await
        }
        None => call.await,
    }
}

/// A future each of whose polls writes for one leased run.
struct RunWritePolls<F> {
    token: RunWriteToken,
    call: Pin<Box<F>>,
}

impl<F: Future> Future for RunWritePolls<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let polls = &mut *self;
        let call = &mut polls.call;
        with_run_write_token(Some(&polls.token), || call.as_mut().poll(cx))
    }
}
