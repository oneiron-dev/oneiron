//! Host response custody beneath the engine outbound dispatch, not a second gate.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use oneiron::LinearSyncResult;
use serde_json::{Value, json};

use crate::{GraphQlCall, GraphQlExecutor, GraphQlTransportError, invalid};

/// Stores the *provider response* keyed by the engine's operation id. Engine
/// governance, budgets, the intent ledger and ordinary receipt stay senior:
/// this journal is only needed because replayed engine dispatches do not
/// preserve the provider's issue fields needed to build a mirror link.
/// A pending entry after a crash is uncertain, never blindly resent.
pub(crate) struct LinearResponseJournal<T> {
    transport: T,
    journal_dir: PathBuf,
}

impl<T> LinearResponseJournal<T> {
    pub(crate) fn new(transport: T, journal_dir: PathBuf) -> LinearSyncResult<Self> {
        if !journal_dir.is_dir() {
            return Err(invalid("Linear outbound response directory does not exist"));
        }
        Ok(Self {
            transport,
            journal_dir,
        })
    }

    pub(crate) fn into_transport(self) -> T {
        self.transport
    }

    fn path(&self, id: &[u8; 32]) -> PathBuf {
        self.journal_dir.join(blake3::Hash::from(*id).to_hex())
    }

    fn digest(call: &GraphQlCall) -> Result<String, GraphQlTransportError> {
        Ok(blake3::hash(
            &serde_json::to_vec(&call.body()).map_err(|_| GraphQlTransportError::Uncertain)?,
        )
        .to_hex()
        .to_string())
    }

    fn sync_directory(&self) -> Result<(), GraphQlTransportError> {
        File::open(&self.journal_dir)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| GraphQlTransportError::Uncertain)
    }

    pub(crate) fn read_committed(
        &self,
        id: &[u8; 32],
        call: &GraphQlCall,
    ) -> Result<Option<Value>, GraphQlTransportError> {
        let path = self.path(id);
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(GraphQlTransportError::Uncertain),
        };
        let mut bytes = Vec::new();
        file.take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(|_| GraphQlTransportError::Uncertain)?;
        if bytes.len() > 1_048_576 {
            return Err(GraphQlTransportError::Uncertain);
        }
        let record: Value =
            serde_json::from_slice(&bytes).map_err(|_| GraphQlTransportError::Uncertain)?;
        if record.get("digest").and_then(Value::as_str) != Some(Self::digest(call)?.as_str()) {
            return Err(GraphQlTransportError::Uncertain);
        }
        record
            .get("response")
            .filter(|response| !response.is_null())
            .cloned()
            .map(Some)
            .ok_or(GraphQlTransportError::Uncertain)
    }
}

impl<T: GraphQlExecutor> LinearResponseJournal<T> {
    /// Only called from an `OutboundExecutionSink` *inside* the engine door.
    pub(crate) fn dispatch(
        &mut self,
        id: [u8; 32],
        call: &GraphQlCall,
    ) -> Result<Value, GraphQlTransportError> {
        if let Some(saved) = self.read_committed(&id, call)? {
            return Ok(saved);
        }
        let path = self.path(&id);
        let digest = Self::digest(call)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut pending = options
            .open(&path)
            .map_err(|_| GraphQlTransportError::Uncertain)?;
        let bytes = serde_json::to_vec(&json!({"digest":digest,"response":null}))
            .map_err(|_| GraphQlTransportError::Uncertain)?;
        pending
            .write_all(&bytes)
            .and_then(|()| pending.sync_all())
            .map_err(|_| GraphQlTransportError::Uncertain)?;
        self.sync_directory()?;
        let response = match self.transport.execute(call) {
            Ok(response) => response,
            Err(GraphQlTransportError::NotSent) => {
                // No bytes left the host. Undo the pending marker durably so
                // the engine's definite-non-delivery replay can send again.
                fs::remove_file(&path).map_err(|_| GraphQlTransportError::Uncertain)?;
                self.sync_directory()?;
                return Err(GraphQlTransportError::NotSent);
            }
            Err(GraphQlTransportError::Uncertain) => return Err(GraphQlTransportError::Uncertain),
        };
        let mutation = if call.query.contains("issueCreate(") {
            "issueCreate"
        } else {
            "issueUpdate"
        };
        if response
            .get("errors")
            .is_some_and(|errors| errors.as_array().is_none_or(|list| !list.is_empty()))
            || response
                .get("data")
                .and_then(|data| data.get(mutation))
                .is_none_or(|result| {
                    result.get("success").and_then(Value::as_bool) != Some(true)
                        || result
                            .get("issue")
                            .and_then(|issue| issue.get("id"))
                            .and_then(Value::as_str)
                            .is_none()
                })
        {
            return Err(GraphQlTransportError::Uncertain);
        }
        let completed = serde_json::to_vec(&json!({"digest":digest,"response":response}))
            .map_err(|_| GraphQlTransportError::Uncertain)?;
        if completed.len() > 1_048_576 {
            return Err(GraphQlTransportError::Uncertain);
        }
        let temp = path.with_extension("receipt-temp");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|_| GraphQlTransportError::Uncertain)?;
        file.write_all(&completed)
            .and_then(|()| file.sync_all())
            .map_err(|_| GraphQlTransportError::Uncertain)?;
        fs::rename(&temp, &path).map_err(|_| GraphQlTransportError::Uncertain)?;
        self.sync_directory()?;
        Ok(response)
    }
}
