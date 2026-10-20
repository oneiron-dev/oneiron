//! The relay's client for its supervisor's hold-guard broker (FIX 6826).
//!
//! One JSON request line per connection on the broker's Unix socket and one
//! answer line back, both under [`MAX_CTL_LINE`], read strictly as the
//! answer to the request sent: its one wrapper, a payload that validates and
//! the request's own fields repeated. A request or answer lost on the way is
//! `transport_unavailable`; any other answer is `answer_unrecognized`.
//! Neither deletes anything. Blocking: it runs on the relay's blocking
//! threads.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use oneiron_vault_contract::relay_delete::{
    RelayDeleteRechecksRequest, RelayDeleteRechecksWire, RelayDeleteRequest, RelayDeleteState,
    RelayDeleteUnknown, decode_execute_answer, decode_rechecks_answer,
};
use oneiron_vault_contract::{CtlRequest, MAX_CTL_LINE};

/// How much longer than its own wait a call may take: the broker's hop to
/// the engine, and an admitted delete's unlink and sync.
const TRANSPORT_MARGIN: Duration = Duration::from_secs(10);

/// The broker at one socket path.
#[derive(Clone, Debug)]
pub(super) struct BrokerClient {
    socket: PathBuf,
}

impl BrokerClient {
    pub(super) fn new(socket: PathBuf) -> Self {
        Self { socket }
    }

    /// Asks the engine to run the delete `request` names, and what became
    /// of it.
    pub(super) fn execute(
        &self,
        request: &RelayDeleteRequest,
    ) -> Result<RelayDeleteState, RelayDeleteUnknown> {
        let line = self.call(
            &CtlRequest::RelayDeleteExecute {
                request: request.clone(),
            },
            TRANSPORT_MARGIN,
        )?;
        decode_execute_answer(&line, request).map_err(|_| RelayDeleteUnknown::AnswerUnrecognized)
    }

    /// The engine's recheck counter, as `request` asks for it.
    pub(super) fn rechecks(
        &self,
        request: &RelayDeleteRechecksRequest,
    ) -> Result<RelayDeleteRechecksWire, RelayDeleteUnknown> {
        let wait = Duration::from_millis(u64::from(request.wait_ms)) + TRANSPORT_MARGIN;
        let line = self.call(
            &CtlRequest::RelayDeleteRechecks {
                request: request.clone(),
            },
            wait,
        )?;
        decode_rechecks_answer(&line, request).map_err(|_| RelayDeleteUnknown::AnswerUnrecognized)
    }

    /// Sends `request` and reads its answer line, each step within
    /// `timeout`.
    fn call(&self, request: &CtlRequest, timeout: Duration) -> Result<String, RelayDeleteUnknown> {
        self.exchange(request, timeout).map_err(|error| {
            tracing::debug!(kind = ?error.kind(), "the hold-guard broker call failed");
            RelayDeleteUnknown::TransportUnavailable
        })
    }

    fn exchange(&self, request: &CtlRequest, timeout: Duration) -> io::Result<String> {
        let mut line = serde_json::to_vec(request)?;
        line.push(b'\n');
        let mut stream = UnixStream::connect(&self.socket)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.write_all(&line)?;
        stream.flush()?;
        let mut answer = Vec::new();
        // Cap + 2 leaves room for the newline of a maximal line and stops
        // short of reading an over-cap one whole.
        BufReader::new((&stream).take(MAX_CTL_LINE as u64 + 2)).read_until(b'\n', &mut answer)?;
        if answer.pop() != Some(b'\n') || answer.len() > MAX_CTL_LINE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the broker's answer is not one line under the cap",
            ));
        }
        String::from_utf8(answer).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the broker's answer is not UTF-8",
            )
        })
    }
}
