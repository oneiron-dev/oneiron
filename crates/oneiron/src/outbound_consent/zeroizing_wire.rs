//! Foreign bytes a live connector exchange holds, wiped once done with
//! (FIX 8309, L10 09:30).
//!
//! A connector may put the presented secret in anything it says, and a
//! round's answer goes back under the connector's own keys (FIX 8051), its
//! request id and request state restored. The host reads a reply stream
//! through [`ZeroizingBufReader`], whose buffer wipes each byte as it is
//! consumed and the whole buffer on drop, so a stream kept open for a round
//! holds none of what it already read. Each message the host POSTs goes as
//! [`zeroizing_json_body`], its exact JSON text in zeroizing storage, and is
//! itself wiped by [`zeroize_json`] once that body is built. What goes on
//! the wire is unchanged.

use std::io::{self, BufRead, Read, Write};

use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

/// The buffer a [`ZeroizingBufReader`] reads through: `std::io::BufReader`'s
/// default capacity.
const READ_BUFFER_BYTES: usize = 8 * 1024;

/// A buffered reader whose buffer never keeps a byte past its read: each
/// consumed byte is wiped as it is consumed, so a refill finds nothing left,
/// and the whole buffer is wiped on drop. Reads exactly as
/// `std::io::BufReader` does otherwise.
pub struct ZeroizingBufReader<R> {
    inner: R,
    buffer: Zeroizing<Vec<u8>>,
    /// The next unconsumed byte in `buffer`.
    position: usize,
    /// How many bytes of `buffer` the last refill read.
    filled: usize,
}

impl<R: Read> ZeroizingBufReader<R> {
    /// A reader of `inner` with an empty, zeroed buffer.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buffer: Zeroizing::new(vec![0; READ_BUFFER_BYTES]),
            position: 0,
            filled: 0,
        }
    }
}

impl<R: Read> Read for ZeroizingBufReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let count = available.len().min(out.len());
        out[..count].copy_from_slice(&available[..count]);
        self.consume(count);
        Ok(count)
    }
}

impl<R: Read> BufRead for ZeroizingBufReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.position >= self.filled {
            // Every byte of the last refill was consumed, and so wiped.
            self.position = 0;
            self.filled = 0;
            self.filled = self.inner.read(&mut self.buffer[..])?;
        }
        Ok(&self.buffer[self.position..self.filled])
    }

    fn consume(&mut self, amount: usize) {
        let end = self.position.saturating_add(amount).min(self.filled);
        self.buffer[self.position..end].zeroize();
        self.position = end;
    }
}

/// Wipes every string `value` owns, each member key included, as it drops:
/// a message that carried a restored key, id or request state leaves none
/// of their text behind once its body is built. Numbers, booleans and null
/// own no text.
pub fn zeroize_json(value: Value) {
    match value {
        Value::String(mut text) => text.zeroize(),
        Value::Array(items) => items.into_iter().for_each(zeroize_json),
        Value::Object(members) => {
            for (mut key, member) in members {
                key.zeroize();
                zeroize_json(member);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// `value`'s compact JSON text, as `Value`'s `Display` writes it, in
/// zeroizing storage sized to it exactly first, so no smaller buffer the
/// text outgrew is freed unwiped.
pub fn zeroizing_json_body(value: &Value) -> Zeroizing<Vec<u8>> {
    let mut length = WrittenLength(0);
    let mut body = match serde_json::to_writer(&mut length, value) {
        Ok(()) => Zeroizing::new(Vec::with_capacity(length.0)),
        Err(_) => Zeroizing::new(Vec::new()),
    };
    // A `Value` always serializes, and a `Vec` takes every byte.
    let _ = serde_json::to_writer(&mut *body, value);
    body
}

/// A writer that keeps nothing and counts the bytes written to it.
struct WrittenLength(usize);

impl Write for WrittenLength {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
