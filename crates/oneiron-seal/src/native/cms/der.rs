//! Strict-DER TLV writer/reader plus the shared sha256 helper.

use const_oid::ObjectIdentifier;
use sha2::Digest;

use crate::api::Sha256Digest;
use crate::error::SealError;

use super::cms_err;

pub(crate) fn sha256(data: &[u8]) -> Sha256Digest {
    sha2::Sha256::digest(data).into()
}

// ---------------------------------------------------------------------------
// Minimal strict-DER writer/reader
// ---------------------------------------------------------------------------

pub(crate) fn len_bytes(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let be = len.to_be_bytes();
    let start = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
    let significant = &be[start..];
    let mut out = vec![0x80 | significant.len() as u8];
    out.extend_from_slice(significant);
    out
}

pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&len_bytes(content.len()));
    out.extend_from_slice(content);
    out
}

pub(crate) fn oid_tlv(oid: &ObjectIdentifier) -> Vec<u8> {
    tlv(0x06, oid.as_bytes())
}

fn null_tlv() -> Vec<u8> {
    vec![0x05, 0x00]
}

pub(super) fn alg_id(oid: &ObjectIdentifier, with_null: bool) -> Vec<u8> {
    let mut body = oid_tlv(oid);
    if with_null {
        body.extend_from_slice(&null_tlv());
    }
    tlv(0x30, &body)
}

/// One parsed TLV: tag, content octets, and the complete TLV slice.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub full: &'a [u8],
}

pub(crate) struct DerReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Strict DER read: rejects indefinite and non-minimal lengths.
    pub(crate) fn read(&mut self) -> Result<Tlv<'a>, SealError> {
        let start = self.pos;
        if self.buf.len() < start + 2 {
            return Err(cms_err());
        }
        let tag = self.buf[start];
        let first_len = self.buf[start + 1];
        let (len, hdr) = if first_len & 0x80 == 0 {
            (usize::from(first_len), 2)
        } else {
            let n = usize::from(first_len & 0x7F);
            if n == 0 || n > 4 || self.buf.len() < start + 2 + n {
                return Err(cms_err());
            }
            if self.buf[start + 2] == 0 {
                return Err(cms_err()); // non-minimal long form
            }
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | usize::from(self.buf[start + 2 + i]);
            }
            if len < 0x80 {
                return Err(cms_err()); // should have used short form
            }
            (len, 2 + n)
        };
        let end = start
            .checked_add(hdr)
            .and_then(|p| p.checked_add(len))
            .filter(|e| *e <= self.buf.len())
            .ok_or_else(cms_err)?;
        self.pos = end;
        Ok(Tlv {
            tag,
            content: &self.buf[start + hdr..end],
            full: &self.buf[start..end],
        })
    }

    pub(crate) fn expect(&mut self, tag: u8) -> Result<Tlv<'a>, SealError> {
        let t = self.read()?;
        if t.tag != tag {
            return Err(cms_err());
        }
        Ok(t)
    }
}
