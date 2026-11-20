//! The whole-vault export as a scan surface ([CANARY-SCAN-COVERAGE] step 4).
//! `vault.export` answers the archive as standard base64 inside a ZIP, so no
//! canary word is legible in the answer itself: the scan decodes the
//! archive into its typed document, without importing a row, and reads the
//! document's JSON, where every stored string is a JSON string (a
//! MessagePack body is a run of typed nodes, each string node holding its
//! text). The document leaves the custody records out, so the scan reads
//! them from the archive's own member, each less its value.

use std::io::Read as _;

use oneiron::Vault;
use oneiron::memory::ExportAnswer;
use serde_json::{Value, json};

use super::{Reader, SurfaceRead};

/// The surface the decoded archive is read as.
const EXPORT_ARCHIVE_SURFACE: &str = "vault.export (archive decoded)";
/// The surface the archive's custody records are read as.
const EXPORT_CUSTODY_SURFACE: &str = "vault.export (custody records decoded)";
/// The archive member that holds one custody record per line.
const CUSTODY_MEMBER: &str = "records/secret_custody.jsonl";
/// The custody record field that carries the secret value (its custody
/// body, standard base64), present only in an archive that carries values.
const CUSTODY_VALUE_FIELD: &str = "body";

impl Reader<'_, '_> {
    /// Asks `vault.export` for the whole-vault archive (refused to an agent:
    /// owner only), decodes it with [`Vault::read_whole_vault_archive`],
    /// which validates every member, and keeps the document's JSON; then
    /// reads the archive's custody records, which the document leaves out:
    /// each record's id, name, handle and metadata, never its value. Every
    /// ref either names is queued. An export writes its audit receipt and
    /// logs each diary read it makes. Not read: the OKF format (a lossy
    /// Markdown copy of the same rows), the archive's attached files, and a
    /// custody record's value.
    pub(super) fn read_export(&mut self, vault: &Vault) {
        let Some(answer) = self.read("vault.export", "vault.export", json!({})) else {
            return;
        };
        let export = match serde_json::from_value::<ExportAnswer>(answer) {
            Ok(ExportAnswer::Inline(export)) => export,
            Ok(ExportAnswer::Transfer(transfer)) => {
                self.scan.incomplete.push(format!(
                    "{EXPORT_ARCHIVE_SURFACE}: the export answered transfer {}, not the archive",
                    transfer.transfer_ref
                ));
                return;
            }
            Err(error) => {
                self.scan.incomplete.push(format!(
                    "{EXPORT_ARCHIVE_SURFACE}: the answer is no export: {error}"
                ));
                return;
            }
        };
        let document = match vault.read_whole_vault_archive(&export.archive) {
            Ok(document) => document,
            Err(error) => {
                self.scan.incomplete.push(format!(
                    "{EXPORT_ARCHIVE_SURFACE}: the archive does not decode: {error}"
                ));
                return;
            }
        };
        match serde_json::to_value(&document) {
            Ok(document) => self.keep_decoded(EXPORT_ARCHIVE_SURFACE, &document),
            Err(error) => self.scan.incomplete.push(format!(
                "{EXPORT_ARCHIVE_SURFACE}: the document does not serialize: {error}"
            )),
        }
        match custody_records(&export.archive) {
            Ok(records) => self.keep_decoded(EXPORT_CUSTODY_SURFACE, &Value::Array(records)),
            Err(error) => self
                .scan
                .incomplete
                .push(format!("{EXPORT_CUSTODY_SURFACE}: {error}")),
        }
    }

    /// Keeps `decoded` as what `surface` read, and queues the refs it names.
    fn keep_decoded(&mut self, surface: &str, decoded: &Value) {
        self.discover(decoded);
        self.scan.seen.push(SurfaceRead {
            surface: surface.to_owned(),
            text: decoded.to_string(),
        });
    }
}

/// Each custody record `archive` holds, less its value; none when the
/// archive has no custody member.
fn custody_records(archive: &[u8]) -> Result<Vec<Value>, String> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(archive))
        .map_err(|error| format!("the archive does not open: {error}"))?;
    let mut text = String::new();
    match zip.by_name(CUSTODY_MEMBER) {
        Ok(mut member) => {
            member
                .read_to_string(&mut text)
                .map_err(|error| format!("{CUSTODY_MEMBER} does not read: {error}"))?;
        }
        Err(zip::result::ZipError::FileNotFound) => return Ok(Vec::new()),
        Err(error) => return Err(format!("{CUSTODY_MEMBER} does not open: {error}")),
    }
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let mut record = serde_json::from_str::<Value>(line)
                .map_err(|error| format!("a {CUSTODY_MEMBER} line is no JSON: {error}"))?;
            if let Some(fields) = record.as_object_mut() {
                fields.remove(CUSTODY_VALUE_FIELD);
            }
            Ok(record)
        })
        .collect()
}
