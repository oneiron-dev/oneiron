//! Writes the whole-vault archive (OF-222) from the document's spools (FIX
//! 2766): the manifest first, then each JSONL member and each attached file,
//! one at a time, straight from its spool into the ZIP. Every row was cut
//! from the credential-nulled document and every file is named by a
//! descriptor in it, so nothing reaches the archive around the serializer's
//! nulling pass. A stored file's bytes go as they are.
use std::collections::BTreeMap;
use std::io::{Seek, Write};

use crate::batch::export::{
    FileSpool, RecordSpool, VAULT_ARCHIVE_MANIFEST_PATH, WholeVaultDocumentManifest,
    archive_file_path,
};
use crate::error::{Error, Result};

/// Writes the archive to `sink` and hands `sink` back: `manifest` names
/// every member and file, `groups` are the JSONL members by path, and
/// `files` the attached files by digest.
pub(super) fn write_vault_archive<W: Write + Seek>(
    sink: W,
    manifest: &WholeVaultDocumentManifest,
    groups: &mut BTreeMap<String, RecordSpool>,
    files: &mut FileSpool,
) -> Result<W> {
    let mut zip = zip::ZipWriter::new(sink);
    let options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .large_file(true);
    let manifest = serde_json::to_vec_pretty(manifest).map_err(|_| encode_failed())?;
    zip.start_file(VAULT_ARCHIVE_MANIFEST_PATH, options).map_err(|_| encode_failed())?;
    zip.write_all(&manifest)?;
    for (path, spool) in groups.iter_mut() {
        zip.start_file(path.as_str(), options).map_err(|_| encode_failed())?;
        std::io::copy(&mut spool.reader()?, &mut zip)?;
    }
    files.each(|blake3, bytes| {
        zip.start_file(archive_file_path(blake3), options).map_err(|_| encode_failed())?;
        std::io::copy(bytes, &mut zip)?;
        Ok(())
    })?;
    zip.finish().map_err(|_| encode_failed())
}

fn encode_failed() -> Error {
    Error::InvariantViolation("whole-vault archive encoding failed")
}
