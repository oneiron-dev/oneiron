//! The transport seam under [`RemoteClient`] (OF-237): what carries a
//! request this client signed, and the reply as its readers take it.
//!
//! A connected handle sends over the network through its reqwest agents. A
//! served handle ([`crate::OneironClient::connect_in_process`]) hands the
//! same request, headers, credential and holder proof included, to an
//! [`InProcessTransport`] the binding that runs the server implements. The
//! signing above this seam and the decoding below it are one code path for
//! both, so neither a refusal envelope nor a receipt ref nor a lens callback
//! reads differently in process.

use std::io::Cursor;

use reqwest::header::HeaderName;

use super::*;
use crate::{InProcessReply, InProcessRequest, InProcessTransport};

/// What carries a client's requests.
#[derive(Clone)]
pub(super) enum Wire {
    /// The network.
    Http {
        agent: Client,
        // Export is a single large document. Keep an export-specific total
        // timeout and byte ceiling, not the ordinary verbs' short timeout and
        // 64 MiB.
        export_agent: Client,
        stream_agent: reqwest::Client,
    },
    /// An `oneiron-server` this process runs.
    InProcess(Arc<dyn InProcessTransport>),
}

/// A reply before any of its body is read.
pub(super) struct Reply {
    pub(super) status: StatusCode,
    pub(super) headers: HeaderMap,
    /// What the reply announced; the readers still cap what they read.
    pub(super) content_length: Option<u64>,
    pub(super) body: Box<dyn Read>,
}

impl RemoteClient {
    /// Sends one request on this client's wire and returns its reply
    /// unread. On the network, `long` rides the export agent's total
    /// timeout.
    pub(super) fn send(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
        long: bool,
    ) -> Result<Reply, MemoryError> {
        match &self.wire {
            Wire::Http {
                agent,
                export_agent,
                ..
            } => {
                let agent = if long { export_agent } else { agent };
                let mut request = agent.request(method, url).headers(headers);
                if let Some(body) = body {
                    request = request.body(body);
                }
                let response = request
                    .send()
                    .map_err(|error| transport_error(describe_send_failure(&error)))?;
                Ok(Reply {
                    status: response.status(),
                    headers: response.headers().clone(),
                    content_length: response.content_length(),
                    body: Box::new(response),
                })
            }
            Wire::InProcess(transport) => {
                exchange_in_process(transport.as_ref(), &method, &url, &headers, body)
            }
        }
    }
}

/// One exchange through the in-process server: the URL's path and query in
/// origin form, every header as it would cross a socket.
fn exchange_in_process(
    transport: &dyn InProcessTransport,
    method: &Method,
    url: &Url,
    headers: &HeaderMap,
    body: Option<Vec<u8>>,
) -> Result<Reply, MemoryError> {
    let path = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    };
    let request = InProcessRequest {
        method: method.as_str().to_owned(),
        path,
        headers: headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect(),
        body: body.unwrap_or_default(),
    };
    let InProcessReply {
        status,
        headers: reply_headers,
        body,
    } = transport.exchange(request).map_err(|message| {
        transport_error(format!(
            "the in-process Oneiron server did not answer: {message}"
        ))
    })?;
    let status = StatusCode::from_u16(status).map_err(|_| {
        transport_error(format!(
            "the in-process Oneiron server answered an invalid status {status}"
        ))
    })?;
    let mut headers = HeaderMap::new();
    for (name, value) in reply_headers {
        // A header no socket could carry is not one a reader looks for.
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_bytes(&value),
        ) {
            headers.append(name, value);
        }
    }
    Ok(Reply {
        status,
        headers,
        content_length: u64::try_from(body.len()).ok(),
        body: Box::new(Cursor::new(body)),
    })
}
