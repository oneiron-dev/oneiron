//! The tools an installed connector lists, whichever way it was installed
//! (L8-31 D6, D8): an MCP connector's `tools/list`, or an HTTP API's
//! document, read from the file or URL its section names and translated.

use std::io::Read;

use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, HeaderValue};

use super::{Discovery, ListedTool, discover, refused};
use crate::config::{ConnectorHostConfig, ConnectorTransport};
use crate::connector_translate::{self, MAX_DOCUMENT_BYTES};

/// Lists the tools of the connector installed as `installed`: an MCP
/// connector's at `pinned` once its key pinned a revision (see
/// [`discover`]), an HTTP API's from its document. The document is read
/// with no credential: it may live on another host than the API, and the
/// connector's secret goes to its endpoint alone, at a call. Its revision
/// is the document's OpenAPI version; a key pinned at another refuses until
/// a refresh takes the new one.
pub(crate) fn list_tools(
    client: &Client,
    installed: &ConnectorHostConfig,
    auth: Option<&HeaderValue>,
    pinned: Option<&str>,
) -> oneiron::Result<Discovery> {
    match installed.transport {
        ConnectorTransport::McpHttp => discover(client, &installed.endpoint, auth, pinned),
        ConnectorTransport::HttpApi => {
            let document = installed
                .document
                .as_deref()
                .ok_or_else(|| refused("the connector's section names no API document"))?;
            let bytes = read_document(client, document)?;
            let translation = connector_translate::translate(&bytes, &installed.endpoint)?;
            if let Some(pinned) = pinned
                && pinned != translation.revision
            {
                return Err(refused(&format!(
                    "the API document is now {}, and the key pinned {pinned}: refresh the \
                     connector",
                    translation.revision
                )));
            }
            Ok(Discovery {
                revision: translation.revision,
                tools: translation
                    .tools
                    .into_iter()
                    .map(ListedTool::translated)
                    .collect(),
                skipped: translation.skipped,
            })
        }
    }
}

/// The document's bytes: an absolute path is a file on this host, anything
/// else the URL the section's validation admitted, fetched with the
/// admission client (no proxy, no redirect). At most one byte past the
/// translator's bound is read, so an oversized document refuses there.
fn read_document(client: &Client, document: &str) -> oneiron::Result<Vec<u8>> {
    let bound = (MAX_DOCUMENT_BYTES + 1) as u64;
    let mut bytes = Vec::new();
    if document.starts_with('/') {
        std::fs::File::open(document)
            .and_then(|file| file.take(bound).read_to_end(&mut bytes))
            .map_err(|_| refused("the API document file could not be read"))?;
        return Ok(bytes);
    }
    let response = client
        .get(document)
        .header(
            ACCEPT,
            "application/json, application/yaml;q=0.9, */*;q=0.1",
        )
        .send()
        .map_err(|_| refused("the API document could not be fetched"))?;
    if !response.status().is_success() {
        return Err(refused(&format!(
            "fetching the API document answered HTTP {}",
            response.status().as_u16()
        )));
    }
    response
        .take(bound)
        .read_to_end(&mut bytes)
        .map_err(|_| refused("the API document could not be fetched"))?;
    Ok(bytes)
}
