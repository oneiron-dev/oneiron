//! FIX 3677: a live row's body as the whole-vault snapshot reads it. A row
//! is read where the snapshot holds it, never copied for the serializer. A
//! file-plane ASSET's stored file that the archive attaches as it is goes
//! out as it streams, read under the snapshot and checked to its end; one a
//! probe of the snapshot needs whole is read whole, as every body was.

use std::borrow::Cow;
use std::io::{self, Read};

use heed::RoTxn;

use crate::asset_body::AssetFileManifest;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_ASSET;
use oneiron_base::registry::ENTITY_TYPE_NOTE;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;

/// A live row's body as the serializer takes it.
pub enum ExportSnapshotEntityBody<'t> {
    /// Its bytes: the row's own, borrowed from the snapshot, or projected.
    Bytes(Cow<'t, [u8]>),
    /// A file-plane ASSET's stored file, which the archive attaches as it is.
    File(ExportSnapshotFile),
}

/// A file-plane ASSET's stored file, open under the snapshot that found its
/// manifest: `bytes` long with BLAKE3 `blake3`, each checked as `reader`
/// reads its end.
pub struct ExportSnapshotFile {
    pub bytes: u64,
    pub blake3: [u8; 32],
    pub reader: Box<dyn Read>,
}

/// A reader that notes the first byte past JSON whitespace it passes on.
pub struct JsonLead<'r> {
    pub body: &'r mut dyn Read,
    pub lead: Option<u8>,
}

impl Read for JsonLead<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let read = self.body.read(out)?;
        if self.lead.is_none() {
            self.lead = out[..read]
                .iter()
                .copied()
                .find(|&byte| !matches!(byte, b' ' | b'\n' | b'\t' | b'\r'));
        }
        Ok(read)
    }
}
