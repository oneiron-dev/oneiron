//! Completed MCP replies, decoded only after their carrier finishes collection.

use axum::body::Bytes;
use serde_json::Value;

pub(super) enum ReplyBody {
    Owned(Vec<u8>),
    HttpChunks(Vec<Bytes>),
}

impl ReplyBody {
    pub(super) fn into_json(self) -> Value {
        match self {
            Self::Owned(body) => serde_json::from_slice(&body)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned())),
            Self::HttpChunks(chunks) => {
                let reader = std::io::BufReader::new(HttpChunks::new(&chunks));
                serde_json::from_reader(reader).unwrap_or_else(|_| {
                    let mut body = Vec::with_capacity(chunks.iter().map(Bytes::len).sum());
                    for chunk in chunks {
                        body.extend_from_slice(&chunk);
                    }
                    Value::String(String::from_utf8_lossy(&body).into_owned())
                })
            }
        }
    }
}

struct HttpChunks<'a> {
    chunks: std::slice::Iter<'a, Bytes>,
    current: &'a [u8],
}

impl<'a> HttpChunks<'a> {
    fn new(chunks: &'a [Bytes]) -> Self {
        Self {
            chunks: chunks.iter(),
            current: &[],
        }
    }
}

impl std::io::Read for HttpChunks<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let n = std::io::Read::read(&mut self.current, buf)?;
            if n != 0 {
                return Ok(n);
            }
            self.current = match self.chunks.next() {
                Some(chunk) => chunk,
                None => return Ok(0),
            };
        }
    }
}
