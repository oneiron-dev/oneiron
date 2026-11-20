//! The whole-vault export as a scan surface ([CANARY-SCAN-COVERAGE] step 4).
//! `vault.export` answers the archive as standard base64 inside a ZIP, so no
//! canary word is legible in the answer itself: the scan decodes the
//! archive into its typed document, without importing a row, and reads the
//! document's JSON, where every stored string is a JSON string (a
//! MessagePack body is a run of typed nodes, each string node holding its
//! text).

use oneiron::Vault;
use oneiron::memory::ExportAnswer;
use serde_json::json;

use super::{Reader, SurfaceRead};

/// The surface the decoded archive is read as.
const EXPORT_ARCHIVE_SURFACE: &str = "vault.export (archive decoded)";

impl Reader<'_, '_> {
    /// Asks `vault.export` for the whole-vault archive (refused to an agent:
    /// owner only), decodes it with [`Vault::read_whole_vault_archive`] and
    /// keeps the document's JSON. An export writes its audit receipt and
    /// logs each diary read it makes. Not read: the OKF format (a lossy
    /// Markdown copy of the same rows), the archive's attached files, and
    /// raw binary values, which only an archive carrying secrets holds.
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
        match serde_json::to_string(&document) {
            Ok(text) => self.scan.seen.push(SurfaceRead {
                surface: EXPORT_ARCHIVE_SURFACE.to_owned(),
                text,
            }),
            Err(error) => self.scan.incomplete.push(format!(
                "{EXPORT_ARCHIVE_SURFACE}: the document does not serialize: {error}"
            )),
        }
    }
}
