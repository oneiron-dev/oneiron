//! A Loro row's content as the shared projection frames it: the framing
//! version, the family, the slice, each hole's address and the no-one
//! history, every length a u32be.

use ::loro::IdSpan;

use super::super::corrupt;
use super::{Atom, Slice};
use crate::error::Result;

/// The content framing's version.
const FRAME_VERSION: u8 = 1;
const SNAPSHOT: u8 = 0;
const UPDATES: u8 = 1;

fn put_len(out: &mut Vec<u8>, len: usize) -> Result<()> {
    let len = u32::try_from(len).map_err(|_| corrupt())?;
    out.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    put_len(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

/// A row's content: the framing version, the family, the slice, each hole's
/// address and the no-one history, every length a u32be.
pub(super) fn write_frame(
    family: &str,
    slice: &Slice,
    atoms: &[Atom],
    history: &[u8],
) -> Result<Vec<u8>> {
    let mut out = vec![FRAME_VERSION];
    put_bytes(&mut out, family.as_bytes())?;
    match slice {
        Slice::Snapshot => out.push(SNAPSHOT),
        Slice::Updates(spans) => {
            out.push(UPDATES);
            put_len(&mut out, spans.len())?;
            for span in spans {
                out.extend_from_slice(&span.peer.to_be_bytes());
                out.extend_from_slice(&span.counter.start.to_be_bytes());
                out.extend_from_slice(&span.counter.end.to_be_bytes());
            }
        }
    }
    put_len(&mut out, atoms.len())?;
    for atom in atoms {
        put_bytes(&mut out, atom.field.as_bytes())?;
    }
    put_bytes(&mut out, history)?;
    Ok(out)
}

/// A row's content, read back.
pub(super) struct Frame {
    pub(super) slice: Slice,
    pub(super) holes: Vec<String>,
    pub(super) history: Vec<u8>,
}

pub(super) fn read_frame(family: &str, bytes: &[u8]) -> Result<Frame> {
    let mut reader = Reader(bytes);
    if reader.byte()? != FRAME_VERSION || reader.bytes()? != family.as_bytes() {
        return Err(corrupt());
    }
    let slice = match reader.byte()? {
        SNAPSHOT => Slice::Snapshot,
        UPDATES => {
            let count = reader.count()?;
            let mut spans = Vec::new();
            for _ in 0..count {
                let peer = u64::from_be_bytes(reader.array()?);
                let start = i32::from_be_bytes(reader.array()?);
                let end = i32::from_be_bytes(reader.array()?);
                if start < 0 || end <= start {
                    return Err(corrupt());
                }
                spans.push(IdSpan::new(peer, start, end));
            }
            Slice::Updates(spans)
        }
        _ => return Err(corrupt()),
    };
    let count = reader.count()?;
    let mut holes = Vec::new();
    for _ in 0..count {
        let hole = std::str::from_utf8(reader.bytes()?).map_err(|_| corrupt())?;
        holes.push(hole.to_owned());
    }
    let history = reader.bytes()?.to_vec();
    if !reader.0.is_empty() {
        return Err(corrupt());
    }
    Ok(Frame {
        slice,
        holes,
        history,
    })
}

/// Reads a content front to back, refusing a short one.
struct Reader<'b>(&'b [u8]);

impl<'b> Reader<'b> {
    fn take(&mut self, len: usize) -> Result<&'b [u8]> {
        let (head, rest) = self.0.split_at_checked(len).ok_or_else(corrupt)?;
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| corrupt())
    }

    fn byte(&mut self) -> Result<u8> {
        let [byte] = self.array::<1>()?;
        Ok(byte)
    }

    fn count(&mut self) -> Result<usize> {
        usize::try_from(u32::from_be_bytes(self.array()?)).map_err(|_| corrupt())
    }

    fn bytes(&mut self) -> Result<&'b [u8]> {
        let len = self.count()?;
        self.take(len)
    }
}
