//! Decoding the member-source wire bytes, without granting provenance.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::sync::{SyncSelector, decode_sync_selector};
use crate::{Error, Result};

use super::{SharedReplicaManifest, SharedReplicaWindow};

fn decode(value: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(value)
        .map_err(|_| Error::InvalidConfig("shared replica source contains invalid base64".into()))
}

impl SharedReplicaManifest {
    pub fn decode_history(&self) -> Result<Vec<Vec<u8>>> {
        self.entries.iter().map(|entry| decode(entry)).collect()
    }

    pub fn decode_selector(&self) -> Result<SyncSelector> {
        decode_sync_selector(&decode(&self.selector)?)
    }
}

impl SharedReplicaWindow {
    pub fn decode_update(&self) -> Result<Vec<u8>> {
        decode(&self.update)
    }
}
