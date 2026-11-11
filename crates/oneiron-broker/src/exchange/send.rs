//! A spooled exchange's one send: no redirect and no resend, dropped when
//! the daemon hangs up, and timed out once the idle bound passes with no
//! body byte sent.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use reqwest::Client;
use tokio::net::UnixStream;

use crate::{Failure, Outcome, Refusal};

/// How the send ended.
pub(crate) enum Sent {
    /// The far end answered; its body is still to come.
    Response(reqwest::Response),
    /// It ends the exchange.
    Outcome(Outcome),
    /// The daemon hung up, or wrote past its frame: the send is dropped.
    Cancelled,
}

/// Sends the request once through `client`, until its reply's head:
/// dropped when the daemon hangs up `stream`, and timed out once `idle`
/// passes with no body byte sent (`progress`).
pub(crate) async fn send(
    client: &Client,
    request: reqwest::Request,
    stream: &UnixStream,
    progress: &AtomicU64,
    idle: Duration,
) -> Sent {
    let execute = client.execute(request);
    tokio::pin!(execute);
    loop {
        let before = progress.load(Ordering::Relaxed);
        tokio::select! {
            sent = &mut execute => {
                return match sent {
                    Ok(response) => Sent::Response(response),
                    // A connect error comes before any request byte is written.
                    Err(error) if error.is_connect() => Sent::Outcome(Outcome::Refused {
                        reason: Refusal::Connect,
                    }),
                    Err(error) => Sent::Outcome(Outcome::Failed {
                        reason: failure(&error),
                    }),
                };
            }
            ready = stream.readable() => {
                if ready.is_err() || cancelled(stream) {
                    return Sent::Cancelled;
                }
            }
            () = tokio::time::sleep(idle) => {
                if progress.load(Ordering::Relaxed) == before {
                    return Sent::Outcome(Outcome::Failed {
                        reason: Failure::Timeout,
                    });
                }
            }
        }
    }
}

/// Whether the daemon, which sends nothing after the credential segment,
/// hung up or wrote past its frame. A readiness with nothing to read is
/// neither.
fn cancelled(stream: &UnixStream) -> bool {
    let mut byte = [0; 1];
    match stream.try_read(&mut byte) {
        Ok(_) => true,
        Err(error) => error.kind() != io::ErrorKind::WouldBlock,
    }
}

/// The failure a send or a reply read broke with.
pub(crate) fn failure(error: &reqwest::Error) -> Failure {
    if error.is_timeout() {
        Failure::Timeout
    } else {
        Failure::Send
    }
}
