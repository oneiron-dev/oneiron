//! Serialized facade requests, spillable before their HTTP body is read.

use std::io::{self, Read, Seek, SeekFrom};

use oneiron::memory::MemoryError;
use oneiron::sync::transport::{CODEC_MIN_FRAME_BYTES, CODEC_ZSTD_LEVEL};
use reqwest::header::{CONTENT_ENCODING, HeaderMap, HeaderValue};
use serde::Serialize;
use tempfile::{SpooledTempFile, spooled_tempfile};

use super::response::{check_request_length, encode_request};
use crate::error::{bad_request, transport_error};

pub(super) enum RequestBody {
    Bytes(Vec<u8>),
    Spool { body: SpooledTempFile, length: u64 },
}

impl From<Vec<u8>> for RequestBody {
    fn from(body: Vec<u8>) -> Self {
        Self::Bytes(body)
    }
}

impl RequestBody {
    pub(super) fn serialize<Q: Serialize>(request: &Q) -> Result<Self, MemoryError> {
        let mut body = spooled_tempfile(CODEC_MIN_FRAME_BYTES);
        serde_json::to_writer(&mut body, request).map_err(|error| {
            if error.is_io() {
                spool_failed(error)
            } else {
                bad_request(
                    format!("this request could not be serialized: {error}"),
                    &["Check the request for non-finite numbers or non-serializable values."],
                )
            }
        })?;
        let length = body.seek(SeekFrom::End(0)).map_err(spool_failed)?;
        body.rewind().map_err(spool_failed)?;
        Ok(Self::Spool { body, length })
    }

    pub(super) fn within_ceiling(self) -> Result<Self, MemoryError> {
        let length = match &self {
            Self::Bytes(body) => body.len() as u64,
            Self::Spool { length, .. } => *length,
        };
        check_request_length(length)?;
        Ok(self)
    }

    pub(super) fn encode(self, headers: &mut HeaderMap) -> Result<Self, MemoryError> {
        let (mut body, length) = match self {
            Self::Bytes(body) => return Ok(Self::Bytes(encode_request(body, headers))),
            Self::Spool { body, length } => (body, length),
        };
        if length < CODEC_MIN_FRAME_BYTES as u64 {
            return Ok(Self::Spool { body, length });
        }
        // As for the buffered codec, failure to compress keeps the raw body.
        let encoded = (|| -> io::Result<Option<Self>> {
            let mut encoder = zstd::stream::Encoder::new(
                spooled_tempfile(CODEC_MIN_FRAME_BYTES),
                CODEC_ZSTD_LEVEL,
            )?;
            io::copy(&mut body, &mut encoder)?;
            let mut encoded = encoder.finish()?;
            let encoded_length = encoded.seek(SeekFrom::End(0))?;
            if encoded_length >= length {
                return Ok(None);
            }
            encoded.rewind()?;
            Ok(Some(Self::Spool {
                body: encoded,
                length: encoded_length,
            }))
        })();
        if let Ok(Some(encoded)) = encoded {
            headers.insert(CONTENT_ENCODING, HeaderValue::from_static("zstd"));
            return Ok(encoded);
        }
        body.rewind().map_err(spool_failed)?;
        Ok(Self::Spool { body, length })
    }

    pub(super) fn into_http(self) -> reqwest::blocking::Body {
        match self {
            Self::Bytes(body) => body.into(),
            Self::Spool { body, length } => reqwest::blocking::Body::sized(body, length),
        }
    }

    pub(super) fn into_bytes(self) -> Result<Vec<u8>, MemoryError> {
        match self {
            Self::Bytes(body) => Ok(body),
            Self::Spool { mut body, .. } => {
                let mut bytes = Vec::new();
                body.read_to_end(&mut bytes).map_err(spool_failed)?;
                Ok(bytes)
            }
        }
    }
}

fn spool_failed(error: impl std::fmt::Display) -> MemoryError {
    transport_error(format!("could not spool this request's body: {error}"))
}
