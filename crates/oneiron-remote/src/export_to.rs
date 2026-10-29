//! `vault.export` written into the caller's sink (FIX 3676): over a server,
//! the export is kept there as a transfer, read into the sink as it arrives
//! and checked against its length and BLAKE3, then let go; an embedded
//! handle writes it as it is built. Neither holds the archive whole.

use std::io::{Read, Seek, Write};

use oneiron::memory::{
    ExportDelivery, ExportOptions, ExportTransfer, MemoryError, MemoryExportReceipt,
};

use crate::{Backend, OneironClient};

impl OneironClient {
    /// Exports the whole vault into `sink` (a file, typically), owner only,
    /// as `vault.export` does: `format` is `archive` (the default) or `okf`.
    /// The answer is the archive's format, length and BLAKE3. Over a server
    /// the archive streams through a kept transfer, so no ceiling on a reply
    /// applies to it; the transfer is let go once the sink holds it whole.
    ///
    /// # Errors
    ///
    /// The export's own refusals, a transport failure, or a sink that cannot
    /// be written.
    pub fn vault_export_to<W: Read + Write + Seek>(
        &self,
        format: Option<&str>,
        mut sink: W,
    ) -> Result<MemoryExportReceipt, MemoryError> {
        self.ensure_dispatch_pid()?;
        let input = ExportOptions {
            format: format.map(str::to_owned),
            ..Default::default()
        };
        match &self.backend {
            Backend::Remote(remote) => {
                let input = ExportOptions {
                    delivery: Some(ExportDelivery::Transfer),
                    ..input
                };
                let value = serde_json::to_value(&input).map_err(|_| {
                    crate::error::bad_request(
                        "SDK input encoding failed",
                        &["Send the documented typed SDK input."],
                    )
                })?;
                oneiron::task_verb::sdk::validate_input("vault.export", &value)?;
                let transfer: ExportTransfer = remote.call("vault.export", &input)?;
                // The transfer is this call's own: it is let go whether the
                // read finished or failed, and the read's error is the one
                // returned. One that cannot be let go is named in the error.
                let read = remote.read_export_transfer(&transfer, &mut sink);
                let released = remote.release_export_transfer(&transfer.transfer_ref);
                match (read, released) {
                    (Ok(()), Ok(())) => Ok(MemoryExportReceipt {
                        format: transfer.format,
                        bytes: transfer.bytes,
                        digest: transfer.digest,
                        holder_requests: transfer.holder_requests,
                    }),
                    (Err(error), Ok(())) => Err(error),
                    (Ok(()), Err(kept)) => Err(still_kept(None, &transfer.transfer_ref, kept)),
                    (Err(error), Err(kept)) => {
                        Err(still_kept(Some(error), &transfer.transfer_ref, kept))
                    }
                }
            }
            Backend::Embedded(embedded) => {
                let memory = embedded.memory();
                oneiron::task_verb::verb_hook_boundary::typed_row(
                    &memory,
                    "vault.export",
                    input,
                    |input| memory.export_to(&input, &mut sink),
                )
            }
        }
    }
}

/// The error a call returns when its transfer `transfer_ref` could not be
/// let go (`release`): the read's own error when the read failed, else
/// `release`, each naming the transfer still kept on the server.
fn still_kept(read: Option<MemoryError>, transfer_ref: &str, release: MemoryError) -> MemoryError {
    let mut error = match read {
        Some(mut read) => {
            read.message = format!(
                "{} (the export transfer {transfer_ref} is still kept on the server: letting it \
                 go failed: {})",
                read.message, release.message
            );
            read
        }
        None => {
            let mut release = release;
            release.message = format!(
                "the export is whole in the sink, but its transfer {transfer_ref} is still kept \
                 on the server: {}",
                release.message
            );
            release
        }
    };
    error.suggestions.push(format!(
        "Let the transfer go with DELETE /v1/core/export-transfers/{transfer_ref}."
    ));
    error
}
