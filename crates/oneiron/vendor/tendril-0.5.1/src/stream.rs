// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Streams of tendrils.

use crate::utf8_decode::{decode_utf8, DecodeError, REPLACEMENT_CHARACTER};
use crate::{fmt, IncompleteUtf8};
use crate::{Atomicity, NonAtomic, Tendril};

use std::borrow::Cow;
use std::fs::File;
use std::io;
use std::marker::PhantomData;
use std::path::Path;

#[cfg(feature = "encoding_rs")]
use encoding_rs::{self, DecoderResult};

/// Trait for types that can process a tendril.
///
/// This is a "push" interface, unlike the "pull" interface of
/// `Iterator<Item=Tendril<F>>`. The push interface matches
/// [html5ever][] and other incremental parsers with a similar
/// architecture.
///
/// [html5ever]: https://github.com/servo/html5ever
pub trait TendrilSink<F, A = NonAtomic>
where
    F: fmt::Format,
    A: Atomicity,
{
    /// Process this tendril.
    fn process(&mut self, t: Tendril<F, A>);

    /// Indicates that an error has occurred.
    fn error(&mut self, desc: Cow<'static, str>);

    /// What the overall result of processing is.
    type Output;

    /// Indicates the end of the stream.
    fn finish(self) -> Self::Output;

    /// Process one tendril and finish.
    fn one<T>(mut self, t: T) -> Self::Output
    where
        Self: Sized,
        T: Into<Tendril<F, A>>,
    {
        self.process(t.into());
        self.finish()
    }

    /// Consume an iterator of tendrils, processing each item, then finish.
    fn from_iter<I>(mut self, i: I) -> Self::Output
    where
        Self: Sized,
        I: IntoIterator,
        I::Item: Into<Tendril<F, A>>,
    {
        for t in i {
            self.process(t.into())
        }
        self.finish()
    }

    /// Read from the given stream of bytes until exhaustion and process incrementally,
    /// then finish. Return `Err` at the first I/O error.
    fn read_from<R>(mut self, r: &mut R) -> io::Result<Self::Output>
    where
        Self: Sized,
        R: io::Read,
        F: fmt::SliceFormat<Slice = [u8]>,
    {
        const BUFFER_SIZE: u32 = 4 * 1024;
        loop {
            let mut tendril = Tendril::<F, A>::new();
            // FIXME: this exposes uninitialized bytes to a generic R type
            // this is fine for R=File which never reads these bytes,
            // but user-defined types might.
            // The standard library pushes zeros to `Vec<u8>` for that reason.
            unsafe {
                tendril.push_uninitialized(BUFFER_SIZE);
            }
            loop {
                match r.read(&mut tendril) {
                    Ok(0) => return Ok(self.finish()),
                    Ok(n) => {
                        tendril.pop_back(BUFFER_SIZE - n as u32);
                        self.process(tendril);
                        break;
                    },
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {},
                    Err(e) => return Err(e),
                }
            }
        }
    }

    /// Read from the file at the given path and process incrementally,
    /// then finish. Return `Err` at the first I/O error.
    fn from_file<P>(self, path: P) -> io::Result<Self::Output>
    where
        Self: Sized,
        P: AsRef<Path>,
        F: fmt::SliceFormat<Slice = [u8]>,
    {
        self.read_from(&mut File::open(path)?)
    }
}

/// A `TendrilSink` adaptor that takes bytes, decodes them as UTF-8,
/// lossily replace ill-formed byte sequences with U+FFFD replacement characters,
/// and emits Unicode (`StrTendril`).
///
/// This does not allocate memory: the output is either subtendrils on the input,
/// on inline tendrils for a single code point.
pub struct Utf8LossyDecoder<Sink, A = NonAtomic>
where
    Sink: TendrilSink<fmt::UTF8, A>,
    A: Atomicity,
{
    pub inner_sink: Sink,
    incomplete: Option<IncompleteUtf8>,
    marker: PhantomData<A>,
}

impl<Sink, A> Utf8LossyDecoder<Sink, A>
where
    Sink: TendrilSink<fmt::UTF8, A>,
    A: Atomicity,
{
    /// Create a new incremental UTF-8 decoder.
    #[inline]
    pub fn new(inner_sink: Sink) -> Self {
        Utf8LossyDecoder {
            inner_sink,
            incomplete: None,
            marker: PhantomData,
        }
    }
}

impl<Sink, A> TendrilSink<fmt::Bytes, A> for Utf8LossyDecoder<Sink, A>
where
    Sink: TendrilSink<fmt::UTF8, A>,
    A: Atomicity,
{
    #[inline]
    fn process(&mut self, mut bytes: Tendril<fmt::Bytes, A>) {
        // FIXME: remove take() and map() when non-lexical borrows are stable.
        if let Some(mut incomplete) = self.incomplete.take() {
            let resume_at = incomplete
                .try_to_complete_codepoint(&bytes)
                .map(|(result, rest)| {
                    match result {
                        Ok(decoded_string) => {
                            self.inner_sink.process(Tendril::from_slice(decoded_string))
                        },
                        Err(_) => {
                            self.inner_sink.error("invalid byte sequence".into());
                            self.inner_sink
                                .process(Tendril::from_slice(REPLACEMENT_CHARACTER));
                        },
                    }
                    bytes.len() - rest.len()
                });
            match resume_at {
                None => {
                    self.incomplete = Some(incomplete);
                    return;
                },
                Some(resume_at) => bytes.pop_front(resume_at as u32),
            }
        }
        while !bytes.is_empty() {
            let unborrowed_result = match decode_utf8(&bytes) {
                Ok(s) => {
                    debug_assert!(s.as_ptr() == bytes.as_ptr());
                    debug_assert!(s.len() == bytes.len());
                    Ok(())
                },
                Err(DecodeError::Invalid {
                    valid_prefix,
                    invalid_sequence,
                    ..
                }) => {
                    debug_assert!(valid_prefix.as_ptr() == bytes.as_ptr());
                    debug_assert!(valid_prefix.len() <= bytes.len());
                    Err((
                        valid_prefix.len(),
                        Err(valid_prefix.len() + invalid_sequence.len()),
                    ))
                },
                Err(DecodeError::Incomplete {
                    valid_prefix,
                    incomplete_suffix,
                }) => {
                    debug_assert!(valid_prefix.as_ptr() == bytes.as_ptr());
                    debug_assert!(valid_prefix.len() <= bytes.len());
                    Err((valid_prefix.len(), Ok(incomplete_suffix)))
                },
            };
            match unborrowed_result {
                Ok(()) => {
                    unsafe {
                        self.inner_sink
                            .process(bytes.reinterpret_without_validating())
                    }
                    return;
                },
                Err((valid_len, and_then)) => {
                    if valid_len > 0 {
                        let subtendril = bytes.subtendril(0, valid_len as u32);
                        unsafe {
                            self.inner_sink
                                .process(subtendril.reinterpret_without_validating())
                        }
                    }
                    match and_then {
                        Ok(incomplete) => {
                            self.incomplete = Some(incomplete);
                            return;
                        },
                        Err(offset) => {
                            self.inner_sink.error("invalid byte sequence".into());
                            self.inner_sink
                                .process(Tendril::from_slice(REPLACEMENT_CHARACTER));
                            bytes.pop_front(offset as u32);
                        },
                    }
                },
            }
        }
    }

    #[inline]
    fn error(&mut self, desc: Cow<'static, str>) {
        self.inner_sink.error(desc);
    }

    type Output = Sink::Output;

    #[inline]
    fn finish(mut self) -> Sink::Output {
        if self.incomplete.is_some() {
            self.inner_sink
                .error("incomplete byte sequence at end of stream".into());
            self.inner_sink
                .process(Tendril::from_slice(REPLACEMENT_CHARACTER));
        }
        self.inner_sink.finish()
    }
}

/// A `TendrilSink` adaptor that takes bytes, decodes them as the given character encoding,
/// lossily replace ill-formed byte sequences with U+FFFD replacement characters,
/// and emits Unicode (`StrTendril`).
///
/// This allocates new tendrils for encodings other than UTF-8.
#[cfg(feature = "encoding_rs")]
pub struct LossyDecoder<Sink, A = NonAtomic>
where
    Sink: TendrilSink<fmt::UTF8, A>,
    A: Atomicity,
{
    inner: LossyDecoderInner<Sink, A>,
}

#[cfg(feature = "encoding_rs")]
enum LossyDecoderInner<Sink, A>
where
    Sink: TendrilSink<fmt::UTF8, A>,
    A: Atomicity,
{
    Utf8(Utf8LossyDecoder<Sink, A>),
    #[cfg(feature = "encoding_rs")]
    EncodingRs(encoding_rs::Decoder, Sink),
}

#[cfg(feature = "encoding_rs")]
impl<Sink, A> LossyDecoder<Sink, A>
where
    Sink: TendrilSink<fmt::UTF8, A>,
    A: Atomicity,
{
    /// Create a new incremental decoder using the encoding_rs crate.
    #[cfg(feature = "encoding_rs")]
    #[inline]
    pub fn new_encoding_rs(encoding: &'static encoding_rs::Encoding, sink: Sink) -> Self {
        if encoding == encoding_rs::UTF_8 {
            return Self::utf8(sink);
        }
        Self {
            inner: LossyDecoderInner::EncodingRs(encoding.new_decoder(), sink),
        }
    }

    /// Create a new incremental decoder using the encoding_rs crate.
    ///
    /// This is a more flexible version of [Self::new_encoding_rs], allowing the caller
    /// to configure the decoder themselves.
    #[cfg(feature = "encoding_rs")]
    #[inline]
    pub fn new_from_encoding_rs_decoder(decoder: encoding_rs::Decoder, sink: Sink) -> Self {
        Self {
            inner: LossyDecoderInner::EncodingRs(decoder, sink),
        }
    }

    /// Create a new incremental decoder for the UTF-8 encoding.
    ///
    /// This is useful for content that is known at run-time to be UTF-8
    /// (whereas `Utf8LossyDecoder` requires knowning at compile-time.)
    #[inline]
    pub fn utf8(sink: Sink) -> LossyDecoder<Sink, A> {
        LossyDecoder {
            inner: LossyDecoderInner::Utf8(Utf8LossyDecoder::new(sink)),
        }
    }

    /// Give a reference to the inner sink.
    pub fn inner_sink(&self) -> &Sink {
        match self.inner {
            LossyDecoderInner::Utf8(ref utf8) => &utf8.inner_sink,
            #[cfg(feature = "encoding_rs")]
            LossyDecoderInner::EncodingRs(_, ref inner_sink) => inner_sink,
        }
    }

    /// Give a mutable reference to the inner sink.
    pub fn inner_sink_mut(&mut self) -> &mut Sink {
        match self.inner {
            LossyDecoderInner::Utf8(ref mut utf8) => &mut utf8.inner_sink,
            #[cfg(feature = "encoding_rs")]
            LossyDecoderInner::EncodingRs(_, ref mut inner_sink) => inner_sink,
        }
    }
}

#[cfg(feature = "encoding_rs")]
impl<Sink, A> TendrilSink<fmt::Bytes, A> for LossyDecoder<Sink, A>
where
    Sink: TendrilSink<fmt::UTF8, A>,
    A: Atomicity,
{
    #[inline]
    fn process(&mut self, t: Tendril<fmt::Bytes, A>) {
        match self.inner {
            LossyDecoderInner::Utf8(ref mut utf8) => utf8.process(t),
            #[cfg(feature = "encoding_rs")]
            LossyDecoderInner::EncodingRs(ref mut decoder, ref mut sink) => {
                if t.is_empty() {
                    return;
                }
                decode_to_sink(t, decoder, sink, false);
            },
        }
    }

    #[inline]
    fn error(&mut self, desc: Cow<'static, str>) {
        match self.inner {
            LossyDecoderInner::Utf8(ref mut utf8) => utf8.error(desc),
            #[cfg(feature = "encoding_rs")]
            LossyDecoderInner::EncodingRs(_, ref mut sink) => sink.error(desc),
        }
    }

    type Output = Sink::Output;

    #[inline]
    fn finish(self) -> Sink::Output {
        match self.inner {
            LossyDecoderInner::Utf8(utf8) => utf8.finish(),
            #[cfg(feature = "encoding_rs")]
            LossyDecoderInner::EncodingRs(mut decoder, mut sink) => {
                decode_to_sink(Tendril::new(), &mut decoder, &mut sink, true);
                sink.finish()
            },
        }
    }
}

#[cfg(feature = "encoding_rs")]
fn decode_to_sink<Sink, A>(
    mut input: Tendril<fmt::Bytes, A>,
    decoder: &mut encoding_rs::Decoder,
    sink: &mut Sink,
    last: bool,
) where
    Sink: TendrilSink<fmt::UTF8, A>,
    A: Atomicity,
{
    loop {
        let mut out = <Tendril<fmt::Bytes, A>>::new();
        let max_len = decoder
            .max_utf8_buffer_length_without_replacement(input.len())
            .unwrap_or(8192);
        unsafe {
            out.push_uninitialized(max_len.min(8192) as u32);
        }
        let (result, bytes_read, bytes_written) =
            decoder.decode_to_utf8_without_replacement(&input, &mut out, last);
        if bytes_written > 0 {
            sink.process(unsafe {
                out.subtendril(0, bytes_written as u32)
                    .reinterpret_without_validating()
            });
        }
        match result {
            DecoderResult::InputEmpty => return,
            DecoderResult::OutputFull => {},
            DecoderResult::Malformed(_, _) => {
                sink.error(Cow::Borrowed("invalid sequence"));
                sink.process(Tendril::from_slice(REPLACEMENT_CHARACTER));
            },
        }
        input.pop_front(bytes_read as u32);
        if input.is_empty() {
            return;
        }
    }
}
