//! Allocation hooks for owned decoding. Byte counts describe requested and actual backing.

use std::convert::Infallible;
use std::io::{self, Read};
use std::mem::size_of;

use rmp::decode::{MarkerReadError, ValueReadError};

use super::super::Error;

/// An allocation and its replacement share one caller-owned accounting context.
pub trait Allocation {
    type Error;

    /// Reserves a complete replacement while the old allocation is still live.
    fn reserve(&mut self, bytes: u64) -> Result<(), Self::Error>;

    /// The reservation became `actual` backing and the old backing was released.
    fn materialized(&mut self, reserved: u64, old: u64, actual: u64);
}

/// Native decoding failures remain distinct from the caller's allocation failure.
#[derive(Debug)]
pub enum DecodeError<E> {
    Decode(Error),
    Allocation(E),
}

impl<E> From<Error> for DecodeError<E> {
    fn from(error: Error) -> Self {
        Self::Decode(error)
    }
}

impl<E> From<MarkerReadError> for DecodeError<E> {
    fn from(error: MarkerReadError) -> Self {
        Self::Decode(error.into())
    }
}

impl<E> From<ValueReadError> for DecodeError<E> {
    fn from(error: ValueReadError) -> Self {
        Self::Decode(error.into())
    }
}

pub(super) struct Unbound;

impl Allocation for Unbound {
    type Error = Infallible;

    fn reserve(&mut self, _bytes: u64) -> Result<(), Self::Error> {
        Ok(())
    }

    fn materialized(&mut self, _reserved: u64, _old: u64, _actual: u64) {}
}

impl DecodeError<Infallible> {
    pub(super) fn into_decode_error(self) -> Error {
        match self {
            Self::Decode(error) => error,
            Self::Allocation(never) => match never {},
        }
    }
}

fn bytes<T>(capacity: usize) -> u64 {
    (capacity as u64).saturating_mul(size_of::<T>() as u64)
}

pub(super) fn ensure_capacity<T, A: Allocation>(
    values: &mut Vec<T>,
    limit: usize,
    allocation: &mut A,
) -> Result<(), DecodeError<A::Error>> {
    if values.len() < values.capacity() {
        return Ok(());
    }
    let old = values.capacity();
    let requested = old
        .saturating_add(old)
        .max(values.len().saturating_add(1))
        .min(limit);
    let reserved = bytes::<T>(requested);
    allocation
        .reserve(reserved)
        .map_err(DecodeError::Allocation)?;
    values.reserve_exact(requested - values.len());
    allocation.materialized(reserved, bytes::<T>(old), bytes::<T>(values.capacity()));
    Ok(())
}

pub(super) fn read_bin_data<R: Read, A: Allocation>(
    rd: &mut R,
    len: usize,
    allocation: &mut A,
) -> Result<Vec<u8>, DecodeError<A::Error>> {
    let requested = len.min(super::PREALLOC_MAX);
    allocation
        .reserve(requested as u64)
        .map_err(DecodeError::Allocation)?;
    let mut buf = Vec::with_capacity(requested);
    allocation.materialized(requested as u64, 0, buf.capacity() as u64);
    while buf.len() < len {
        ensure_capacity(&mut buf, len, allocation)?;
        let start = buf.len();
        let end = len.min(buf.capacity());
        buf.resize(end, 0);
        match rd.read(&mut buf[start..end]) {
            Ok(0) => {
                buf.truncate(start);
                break;
            }
            Ok(read) => buf.truncate(start + read),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => buf.truncate(start),
            Err(error) => return Err(Error::InvalidDataRead(error).into()),
        }
    }
    let bytes_read = buf.len();
    if bytes_read != len {
        return Err(Error::InvalidDataRead(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("Expected {len} bytes, read {bytes_read} bytes"),
        ))
        .into());
    }
    Ok(buf)
}
