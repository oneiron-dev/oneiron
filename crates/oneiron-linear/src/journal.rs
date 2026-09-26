//! Host-owned durable operation-ID door. Unknown delivery stays ambiguous.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use oneiron::LinearSyncResult;
use serde_json::{Value, json};

use crate::{GraphQlCall, GraphQlExecutor, LinearOutboundDoor, invalid};

/// Host-supplied authorization for the *exact* mutation before the first
/// write. Implementations bind this to their ExternalEffect policy and grant
/// state; a read or operation ID alone is never permission to send.
pub trait LinearOutboundAuthorization {
    /// # Errors
    /// Refuses an unapproved effect before any network call or journal entry.
    fn authorize(&mut self, operation_id: [u8; 32], call: &GraphQlCall) -> LinearSyncResult<()>;
}

/// Production host outbound door: authorized transport plus fsynced receipt
/// journal. Callers supply a private, dedicated directory on durable storage.
///
/// A pending journal entry survives a crash before a response was recorded.
/// Its delivery is UNKNOWN and retries fail closed rather than double-send.
/// A successful receipt is replayed byte-for-byte without another HTTP call.
/// The host may inspect/reconcile an ambiguous operation out of band; this
/// connector never silently assumes the tracker did not accept it.
pub struct JournaledLinearOutboundDoor<T, A> {
    transport: T,
    authorization: A,
    journal_dir: PathBuf,
}

impl<T, A> JournaledLinearOutboundDoor<T, A> {
    /// # Errors
    /// Refuses a missing directory; the host owns directory permissions and
    /// storage durability, rather than silently creating it in the vault.
    pub fn new(transport: T, authorization: A, journal_dir: PathBuf) -> LinearSyncResult<Self> {
        if !journal_dir.is_dir() {
            return Err(invalid("Linear outbound receipt directory does not exist"));
        }
        Ok(Self {
            transport,
            authorization,
            journal_dir,
        })
    }

    pub fn into_parts(self) -> (T, A) {
        (self.transport, self.authorization)
    }

    fn path(&self, id: &[u8; 32]) -> PathBuf {
        self.journal_dir.join(blake3::Hash::from(*id).to_hex())
    }

    fn sync_directory(&self) -> LinearSyncResult<()> {
        File::open(&self.journal_dir)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| invalid("Linear outbound journal sync failed"))
    }
}

impl<T: GraphQlExecutor, A: LinearOutboundAuthorization> LinearOutboundDoor
    for JournaledLinearOutboundDoor<T, A>
{
    fn dispatch(&mut self, operation_id: [u8; 32], call: &GraphQlCall) -> LinearSyncResult<Value> {
        let path = self.path(&operation_id);
        let digest = blake3::hash(
            &serde_json::to_vec(&call.body())
                .map_err(|_| invalid("Linear outbound call cannot be encoded"))?,
        )
        .to_hex()
        .to_string();
        // Check the currently active grant even on a replay: a withdrawn grant
        // must not return a success to a caller as if the action were fresh.
        self.authorization.authorize(operation_id, call)?;
        if path.exists() {
            let mut bytes = Vec::new();
            File::open(&path)
                .and_then(|file| file.take(1_048_577).read_to_end(&mut bytes))
                .map_err(|_| invalid("Linear outbound receipt cannot be read"))?;
            if bytes.len() > 1_048_576 {
                return Err(invalid("Linear outbound receipt exceeds limit"));
            }
            let record: Value = serde_json::from_slice(&bytes)
                .map_err(|_| invalid("Linear outbound receipt is corrupt"))?;
            if record.get("digest").and_then(Value::as_str) != Some(digest.as_str()) {
                return Err(invalid(
                    "Linear operation ID was reused for another payload",
                ));
            }
            return record
                .get("response")
                .filter(|response| !response.is_null())
                .cloned()
                .ok_or_else(|| invalid("Linear outbound delivery is ambiguous"));
        }
        // Exclusive creation arbitrates simultaneous callers; durable pending
        // lands before the wire. If creation raced, the next attempt reads it.
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut pending = options
            .open(&path)
            .map_err(|_| invalid("Linear outbound journal is busy or unwritable"))?;
        let pending_bytes = serde_json::to_vec(&json!({"digest":digest,"response":null}))
            .map_err(|_| invalid("Linear outbound pending record cannot be encoded"))?;
        pending
            .write_all(&pending_bytes)
            .and_then(|()| pending.sync_all())
            .map_err(|_| invalid("Linear outbound pending record cannot be synced"))?;
        self.sync_directory()?;
        let response = self.transport.execute(call)?;
        // A GraphQL error is not proof of delivery. Keep pending and require
        // reconciliation rather than inventing a safe retry.
        if response
            .get("errors")
            .is_some_and(|errors| errors.as_array().is_none_or(|list| !list.is_empty()))
        {
            return Err(invalid(
                "Linear mutation returned GraphQL errors; delivery is ambiguous",
            ));
        }
        let completed = serde_json::to_vec(&json!({"digest":digest,"response":response}))
            .map_err(|_| invalid("Linear outbound receipt cannot be encoded"))?;
        if completed.len() > 1_048_576 {
            return Err(invalid("Linear outbound receipt exceeds limit"));
        }
        // A unique temporary file in the same private directory. A crash
        // before rename leaves the pending record authoritative.
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
            .map_err(|_| invalid("Linear outbound receipt cannot be staged"))?;
        file.write_all(&completed)
            .and_then(|()| file.sync_all())
            .map_err(|_| invalid("Linear outbound receipt cannot be synced"))?;
        fs::rename(&temp, &path)
            .map_err(|_| invalid("Linear outbound receipt cannot be committed"))?;
        self.sync_directory()?;
        Ok(response)
    }
}
