//! A kept whole-vault export's transfer routes (FIX 3676): `GET` and
//! `DELETE /v1/core/export-transfers/{transfer_ref}`. The body is read into
//! the caller's sink a piece at a time and checked against the transfer's
//! length and BLAKE3, never held whole.

use std::io::{Read, Write};

use oneiron::memory::{ExportDigest, ExportTransfer, MemoryError};
use reqwest::{Method, Url};

use super::RemoteClient;
use super::response::read_error_envelope;
use crate::error::transport_error;

/// Path prefix the transfer routes hang off.
const EXPORT_TRANSFERS_PREFIX: &str = "v1/core/export-transfers";
/// The most bytes one read of a transfer's body takes before they are written
/// on: a pacing quantum, every byte is read.
const READ_PIECE_BYTES: usize = 64 * 1024;

impl RemoteClient {
    /// Writes the kept export `transfer` names into `sink` as it arrives,
    /// and checks it is exactly the archive the transfer names.
    pub(crate) fn read_export_transfer(
        &self,
        transfer: &ExportTransfer,
        sink: &mut dyn Write,
    ) -> Result<(), MemoryError> {
        let url = self.export_transfer_url(&transfer.transfer_ref)?;
        let headers = self.credential_headers()?;
        let reply = self.send(Method::GET, url, headers, None, true)?;
        if !reply.status.is_success() {
            return Err(read_error_envelope(reply.body, reply.status));
        }
        let mut body = reply.body;
        let mut digest = ExportDigest::default();
        let mut piece = vec![0_u8; READ_PIECE_BYTES];
        loop {
            let read = match body.read(&mut piece) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(transport_error(format!(
                        "the export transfer was cut short: {error}"
                    )));
                }
            };
            digest.update(&piece[..read]);
            sink.write_all(&piece[..read]).map_err(|error| {
                transport_error(format!("could not write the export transfer: {error}"))
            })?;
        }
        if !digest.matches(transfer) {
            return Err(transport_error(
                "the export transfer's bytes are not the archive its transfer names",
            ));
        }
        Ok(())
    }

    /// Lets the kept export `transfer_ref` names go on the server.
    pub(crate) fn release_export_transfer(&self, transfer_ref: &str) -> Result<(), MemoryError> {
        let url = self.export_transfer_url(transfer_ref)?;
        let headers = self.credential_headers()?;
        let reply = self.send(Method::DELETE, url, headers, None, false)?;
        if !reply.status.is_success() {
            return Err(read_error_envelope(reply.body, reply.status));
        }
        Ok(())
    }

    /// The transfer route for `transfer_ref`, the handle as ONE
    /// percent-encoded path segment.
    fn export_transfer_url(&self, transfer_ref: &str) -> Result<Url, MemoryError> {
        let unbuilt = || transport_error("could not build the export transfer URL");
        let mut url = self
            .base_url
            .join(EXPORT_TRANSFERS_PREFIX)
            .map_err(|_| unbuilt())?;
        url.path_segments_mut()
            .map_err(|()| unbuilt())?
            .pop_if_empty()
            .push(transfer_ref);
        Ok(url)
    }
}
