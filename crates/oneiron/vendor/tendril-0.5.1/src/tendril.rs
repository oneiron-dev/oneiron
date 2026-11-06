// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::borrow::Borrow;
use std::cell::{Cell, UnsafeCell};
use std::cmp::Ordering;
use std::default::Default;
use std::fmt as strfmt;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::Ordering as AtomicOrdering;
use std::sync::atomic::{self, AtomicUsize};
use std::{hash, io, mem, ptr, str};

use crate::buf32::{self, Buf32};
use crate::fmt::imp::Fixup;
use crate::fmt::{self, Slice, ASCII, UTF8};
use crate::util::{
    copy_and_advance, copy_lifetime, copy_lifetime_mut, unsafe_slice, unsafe_slice_mut,
};
use crate::{ReserveError, OFLOW};

const MAX_INLINE_LEN: usize = 8;
const MAX_INLINE_TAG: usize = 0xF;
const EMPTY_TAG: usize = 0xF;

#[inline(always)]
fn inline_tag(len: u32) -> NonZeroUsize {
    debug_assert!(len <= MAX_INLINE_LEN as u32);
    unsafe { NonZeroUsize::new_unchecked(if len == 0 { EMPTY_TAG } else { len as usize }) }
}

/// The multithreadedness of a tendril.
///
/// Exactly two types implement this trait:
///
/// - `Atomic`: use this in your tendril and you will have a `Send` tendril which works
///   across threads; this is akin to `Arc`.
///
/// - `NonAtomic`: use this in your tendril and you will have a tendril which is neither
///   `Send` nor `Sync` but should be a tad faster; this is akin to `Rc`.
///
/// The layout of this trait is also mandated to be that of a `usize`,
/// for it is used for reference counting.
pub unsafe trait Atomicity: 'static {
    #[doc(hidden)]
    fn new() -> Self;

    #[doc(hidden)]
    fn increment(&self) -> usize;

    #[doc(hidden)]
    fn decrement(&self) -> usize;

    #[doc(hidden)]
    fn fence_acquire();
}

/// A marker of a non-atomic tendril.
///
/// This is the default for the second type parameter of a `Tendril`
/// and so doesn't typically need to be written.
///
/// This is akin to using `Rc` for reference counting.
#[repr(C)]
pub struct NonAtomic(Cell<usize>);

unsafe impl Atomicity for NonAtomic {
    #[inline]
    fn new() -> Self {
        NonAtomic(Cell::new(1))
    }

    #[inline]
    fn increment(&self) -> usize {
        let value = self.0.get();
        self.0.set(value.checked_add(1).expect(OFLOW));
        value
    }

    #[inline]
    fn decrement(&self) -> usize {
        let value = self.0.get();
        self.0.set(value - 1);
        value
    }

    #[inline]
    fn fence_acquire() {}
}

/// A marker of an atomic (and hence concurrent) tendril.
///
/// This is used as the second, optional type parameter of a `Tendril`;
/// `Tendril<F, Atomic>` thus implements`Send`.
///
/// This is akin to using `Arc` for reference counting.
pub struct Atomic(AtomicUsize);

unsafe impl Atomicity for Atomic {
    #[inline]
    fn new() -> Self {
        Atomic(AtomicUsize::new(1))
    }

    #[inline]
    fn increment(&self) -> usize {
        // Relaxed is OK because we have a reference already.
        self.0.fetch_add(1, AtomicOrdering::Relaxed)
    }

    #[inline]
    fn decrement(&self) -> usize {
        self.0.fetch_sub(1, AtomicOrdering::Release)
    }

    #[inline]
    fn fence_acquire() {
        atomic::fence(AtomicOrdering::Acquire);
    }
}

#[repr(C)] // Preserve field order for cross-atomicity transmutes
struct Header<A: Atomicity> {
    refcount: A,
    cap: u32,
    reservation: Option<Box<dyn Send + Sync>>,
}

impl<A> Header<A>
where
    A: Atomicity,
{
    #[inline(always)]
    unsafe fn new() -> Header<A> {
        Header {
            refcount: A::new(),
            cap: 0,
            reservation: None,
        }
    }
}

/// Errors that can occur when slicing a `Tendril`.
#[derive(Copy, Clone, Hash, Debug, PartialEq, Eq)]
pub enum SubtendrilError {
    OutOfBounds,
    ValidationFailed,
}

/// Compact string type for zero-copy parsing.
///
/// `Tendril`s have the semantics of owned strings, but are sometimes views
/// into shared buffers. When you mutate a `Tendril`, an owned copy is made
/// if necessary. Further mutations occur in-place until the string becomes
/// shared, e.g. with `clone()` or `subtendril()`.
///
/// Buffer sharing is accomplished through thread-local (non-atomic) reference
/// counting, which has very low overhead. The Rust type system will prevent
/// you at compile time from sending a `Tendril` between threads. We plan to
/// relax this restriction in the future; see `README.md`.
///
/// Whereas `String` allocates in the heap for any non-empty string, `Tendril`
/// can store small strings (up to 8 bytes) in-line, without a heap allocation.
/// `Tendril` is also smaller than `String` on 64-bit platforms — 16 bytes
/// versus 24.
///
/// The type parameter `F` specifies the format of the tendril, for example
/// UTF-8 text or uninterpreted bytes. The parameter will be instantiated
/// with one of the marker types from `tendril::fmt`. See the `StrTendril`
/// and `ByteTendril` type aliases for two examples.
///
/// The type parameter `A` indicates the atomicity of the tendril; it is by
/// default `NonAtomic`, but can be specified as `Atomic` to get a tendril
/// which implements `Send` (viz. a thread-safe tendril).
///
/// The maximum length of a `Tendril` is 4 GB. The library will panic if
/// you attempt to go over the limit.
#[repr(C)]
pub struct Tendril<F, A = NonAtomic>
where
    F: fmt::Format,
    A: Atomicity,
{
    ptr: Cell<NonZeroUsize>,
    buf: UnsafeCell<Buffer>,
    marker: PhantomData<*mut F>,
    refcount_marker: PhantomData<A>,
}

#[repr(C)]
union Buffer {
    heap: Heap,
    inline: [u8; 8],
}

#[derive(Copy, Clone)]
#[repr(C)]
struct Heap {
    len: u32,
    aux: u32,
}

unsafe impl<F, A> Send for Tendril<F, A>
where
    F: fmt::Format,
    A: Atomicity + Sync,
{
}

/// `Tendril` for storing native Rust strings.
pub type StrTendril = Tendril<fmt::UTF8>;

/// `Tendril` for storing binary data.
pub type ByteTendril = Tendril<fmt::Bytes>;

impl<F, A> Clone for Tendril<F, A>
where
    F: fmt::Format,
    A: Atomicity,
{
    #[inline]
    fn clone(&self) -> Tendril<F, A> {
        unsafe {
            if self.ptr.get().get() > MAX_INLINE_TAG {
                self.make_buf_shared();
                self.incref();
            }

            ptr::read(self)
        }
    }
}

impl<F, A> Drop for Tendril<F, A>
where
    F: fmt::Format,
    A: Atomicity,
{
    #[inline]
    fn drop(&mut self) {
        unsafe {
            let p = self.ptr.get().get();
            if p <= MAX_INLINE_TAG {
                return;
            }

            let (buf, shared, _) = self.assume_buf();
            if shared {
                let header = self.header();
                if (*header).refcount.decrement() == 1 {
                    A::fence_acquire();
                    Self::destroy_buf(buf);
                }
            } else {
                Self::destroy_buf(buf);
            }
        }
    }
}

macro_rules! from_iter_method {
    ($ty:ty) => {
        #[inline]
        fn from_iter<I>(iterable: I) -> Self
        where
            I: IntoIterator<Item = $ty>,
        {
            let mut output = Self::new();
            output.extend(iterable);
            output
        }
    };
}

impl<A> Extend<char> for Tendril<fmt::UTF8, A>
where
    A: Atomicity,
{
    #[inline]
    fn extend<I>(&mut self, iterable: I)
    where
        I: IntoIterator<Item = char>,
    {
        let iterator = iterable.into_iter();
        self.force_reserve(iterator.size_hint().0 as u32);
        for c in iterator {
            self.push_char(c);
        }
    }
}

impl<A> FromIterator<char> for Tendril<fmt::UTF8, A>
where
    A: Atomicity,
{
    from_iter_method!(char);
}

impl<A> Extend<u8> for Tendril<fmt::Bytes, A>
where
    A: Atomicity,
{
    #[inline]
    fn extend<I>(&mut self, iterable: I)
    where
        I: IntoIterator<Item = u8>,
    {
        let iterator = iterable.into_iter();
        self.force_reserve(iterator.size_hint().0 as u32);
        for b in iterator {
            self.push_slice(&[b]);
        }
    }
}

impl<A> FromIterator<u8> for Tendril<fmt::Bytes, A>
where
    A: Atomicity,
{
    from_iter_method!(u8);
}

impl<'a, A> Extend<&'a u8> for Tendril<fmt::Bytes, A>
where
    A: Atomicity,
{
    #[inline]
    fn extend<I>(&mut self, iterable: I)
    where
        I: IntoIterator<Item = &'a u8>,
    {
        let iterator = iterable.into_iter();
        self.force_reserve(iterator.size_hint().0 as u32);
        for &b in iterator {
            self.push_slice(&[b]);
        }
    }
}

impl<'a, A> FromIterator<&'a u8> for Tendril<fmt::Bytes, A>
where
    A: Atomicity,
{
    from_iter_method!(&'a u8);
}

impl<'a, A> Extend<&'a str> for Tendril<fmt::UTF8, A>
where
    A: Atomicity,
{
    #[inline]
    fn extend<I>(&mut self, iterable: I)
    where
        I: IntoIterator<Item = &'a str>,
    {
        for s in iterable {
            self.push_slice(s);
        }
    }
}

impl<'a, A> FromIterator<&'a str> for Tendril<fmt::UTF8, A>
where
    A: Atomicity,
{
    from_iter_method!(&'a str);
}

impl<'a, A> Extend<&'a [u8]> for Tendril<fmt::Bytes, A>
where
    A: Atomicity,
{
    #[inline]
    fn extend<I>(&mut self, iterable: I)
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        for s in iterable {
            self.push_slice(s);
        }
    }
}

impl<'a, A> FromIterator<&'a [u8]> for Tendril<fmt::Bytes, A>
where
    A: Atomicity,
{
    from_iter_method!(&'a [u8]);
}

impl<'a, F, A> Extend<&'a Tendril<F, A>> for Tendril<F, A>
where
    F: fmt::Format + 'a,
    A: Atomicity,
{
    #[inline]
    fn extend<I>(&mut self, iterable: I)
    where
        I: IntoIterator<Item = &'a Tendril<F, A>>,
    {
        for t in iterable {
            self.push_tendril(t);
        }
    }
}

impl<'a, F, A> FromIterator<&'a Tendril<F, A>> for Tendril<F, A>
where
    F: fmt::Format + 'a,
    A: Atomicity,
{
    from_iter_method!(&'a Tendril<F, A>);
}

impl<F, A> Deref for Tendril<F, A>
where
    F: fmt::SliceFormat,
    A: Atomicity,
{
    type Target = F::Slice;

    #[inline]
    fn deref(&self) -> &F::Slice {
        unsafe { F::Slice::from_bytes(self.as_byte_slice()) }
    }
}

impl<F, A> DerefMut for Tendril<F, A>
where
    F: fmt::SliceFormat,
    A: Atomicity,
{
    #[inline]
    fn deref_mut(&mut self) -> &mut F::Slice {
        unsafe { F::Slice::from_mut_bytes(self.as_mut_byte_slice()) }
    }
}

impl<F, A> Borrow<[u8]> for Tendril<F, A>
where
    F: fmt::SliceFormat,
    A: Atomicity,
{
    fn borrow(&self) -> &[u8] {
        self.as_byte_slice()
    }
}

// Why not impl Borrow<str> for Tendril<fmt::UTF8>? str and [u8] hash differently,
// and so a HashMap<StrTendril, _> would silently break if we indexed by str. Ick.
// https://github.com/rust-lang/rust/issues/27108

impl<F, A> PartialEq for Tendril<F, A>
where
    F: fmt::Format,
    A: Atomicity,
{
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_byte_slice() == other.as_byte_slice()
    }
}

impl<A: Atomicity> PartialEq<str> for Tendril<ASCII, A> {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.as_byte_slice() == other.as_bytes()
    }
}

impl<A: Atomicity> PartialEq<str> for Tendril<UTF8, A> {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.as_byte_slice() == other.as_bytes()
    }
}

impl<F, A> Eq for Tendril<F, A>
where
    F: fmt::Format,
    A: Atomicity,
{
}

impl<F, A> PartialOrd for Tendril<F, A>
where
    F: fmt::SliceFormat,
    <F as fmt::SliceFormat>::Slice: PartialOrd,
    A: Atomicity,
{
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        PartialOrd::partial_cmp(&**self, &**other)
    }
}

impl<F, A> Ord for Tendril<F, A>
where
    F: fmt::SliceFormat,
    <F as fmt::SliceFormat>::Slice: Ord,
    A: Atomicity,
{
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        Ord::cmp(&**self, &**other)
    }
}

impl<F, A> Default for Tendril<F, A>
where
    F: fmt::Format,
    A: Atomicity,
{
    #[inline(always)]
    fn default() -> Tendril<F, A> {
        Tendril::new()
    }
}

impl<F, A> strfmt::Debug for Tendril<F, A>
where
    F: fmt::SliceFormat + Default + strfmt::Debug,
    <F as fmt::SliceFormat>::Slice: strfmt::Debug,
    A: Atomicity,
{
    #[inline]
    fn fmt(&self, f: &mut strfmt::Formatter) -> strfmt::Result {
        let kind = match self.ptr.get().get() {
            p if p <= MAX_INLINE_TAG => "inline",
            p if p & 1 == 1 => "shared",
            _ => "owned",
        };

        write!(f, "Tendril<{:?}>({}: ", <F as Default>::default(), kind)?;
        <<F as fmt::SliceFormat>::Slice as strfmt::Debug>::fmt(&**self, f)?;
        write!(f, ")")
    }
}

impl<F, A> hash::Hash for Tendril<F, A>
where
    F: fmt::Format,
    A: Atomicity,
{
    #[inline]
    fn hash<H: hash::Hasher>(&self, hasher: &mut H) {
        self.as_byte_slice().hash(hasher)
    }
}

impl<F, A> Tendril<F, A>
where
    F: fmt::Format,
    A: Atomicity,
{
    /// Create a new, empty `Tendril` in any format.
    #[inline(always)]
    pub fn new() -> Tendril<F, A> {
        unsafe { Tendril::inline(&[]) }
    }

    /// Create a new, empty `Tendril` with a specified capacity.
    #[inline]
    pub fn with_capacity(capacity: u32) -> Tendril<F, A> {
        let mut t: Tendril<F, A> = Tendril::new();
        if capacity > MAX_INLINE_LEN as u32 {
            unsafe {
                t.make_owned_with_capacity(capacity);
            }
        }
        t
    }

    /// Reserve additional bytes with caller admission for each new allocation.
    ///
    /// An inline value needs no allocation while it still fits inline. Existing
    /// owned capacity is reused, not retrospectively admitted. A shared value or
    /// growing owned value is copied into a freshly admitted block while the old
    /// allocation remains live. On failure the original value is unchanged.
    /// Later ordinary allocating operations remain unadmitted, as documented by
    /// `try_from_slice_with_reservation`.
    pub fn try_reserve_with_reservation<R, E>(
        &mut self,
        additional: u32,
        reserve: impl FnOnce(usize) -> Result<R, E>,
        settle: impl FnOnce(&mut R, usize) -> Result<(), E>,
    ) -> Result<(), ReserveError<E>>
    where
        R: Send + Sync + 'static,
    {
        let required = self
            .len32()
            .checked_add(additional)
            .ok_or(ReserveError::CapacityOverflow)?;
        let p = self.ptr.get().get();
        if p <= MAX_INLINE_TAG && required <= MAX_INLINE_LEN as u32 {
            return Ok(());
        }
        if p > MAX_INLINE_TAG && p & 1 == 0 && required <= unsafe { self.aux() } {
            return Ok(());
        }
        let capacity = required
            .checked_next_power_of_two()
            .ok_or(ReserveError::CapacityOverflow)?;
        let replacement = unsafe {
            Self::try_owned_copy_with_reservation(self.as_byte_slice(), capacity, reserve, settle)?
        };
        let old = mem::replace(self, replacement);
        drop(old);
        Ok(())
    }

    /// Reserve space for additional bytes.
    ///
    /// This is only a suggestion. There are cases where `Tendril` will
    /// decline to allocate until the buffer is actually modified.
    #[inline]
    pub fn reserve(&mut self, additional: u32) {
        if !self.is_shared() {
            // Don't grow a shared tendril because we'd have to copy
            // right away.
            self.force_reserve(additional);
        }
    }

    /// Reserve space for additional bytes, even for shared buffers.
    #[inline]
    fn force_reserve(&mut self, additional: u32) {
        let new_len = self.len32().checked_add(additional).expect(OFLOW);
        if new_len > MAX_INLINE_LEN as u32 {
            unsafe {
                self.make_owned_with_capacity(new_len);
            }
        }
    }

    /// Get the length of the `Tendril`.
    ///
    /// This is named not to conflict with `len()` on the underlying
    /// slice, if any.
    #[inline(always)]
    pub fn len32(&self) -> u32 {
        match self.ptr.get().get() {
            EMPTY_TAG => 0,
            n if n <= MAX_INLINE_LEN => n as u32,
            _ => unsafe { self.raw_len() },
        }
    }

    /// Is the backing buffer shared?
    #[inline]
    pub fn is_shared(&self) -> bool {
        let n = self.ptr.get().get();

        (n > MAX_INLINE_TAG) && ((n & 1) == 1)
    }

    /// Is the backing buffer shared with this other `Tendril`?
    #[inline]
    pub fn is_shared_with(&self, other: &Tendril<F, A>) -> bool {
        let n = self.ptr.get().get();

        (n > MAX_INLINE_TAG) && (n == other.ptr.get().get())
    }

    /// Truncate to length 0 without discarding any owned storage.
    #[inline]
    pub fn clear(&mut self) {
        if self.ptr.get().get() <= MAX_INLINE_TAG {
            self.ptr
                .set(unsafe { NonZeroUsize::new_unchecked(EMPTY_TAG) });
        } else {
            let (_, shared, _) = unsafe { self.assume_buf() };
            if shared {
                // No need to keep a reference alive for a 0-size slice.
                *self = Tendril::new();
            } else {
                unsafe { self.set_len(0) };
            }
        }
    }

    /// Build a `Tendril` by copying a byte slice, if it conforms to the format.
    #[inline]
    pub fn try_from_byte_slice(x: &[u8]) -> Result<Tendril<F, A>, ()> {
        match F::validate(x) {
            true => Ok(unsafe { Tendril::from_byte_slice_without_validating(x) }),
            false => Err(()),
        }
    }

    /// View as uninterpreted bytes.
    #[inline(always)]
    pub fn as_bytes(&self) -> &Tendril<fmt::Bytes, A> {
        unsafe { mem::transmute(self) }
    }

    /// Convert into uninterpreted bytes.
    #[inline(always)]
    pub fn into_bytes(self) -> Tendril<fmt::Bytes, A> {
        unsafe { mem::transmute(self) }
    }

    /// Convert `self` into a type which is `Send`.
    ///
    /// If the tendril is owned or inline, this is free,
    /// but if it's shared this will entail a copy of the contents.
    #[inline]
    pub fn into_send(mut self) -> SendTendril<F> {
        if self.is_shared() {
            self.make_owned();
        }
        SendTendril {
            // This changes the header.refcount from A to NonAtomic, but that's
            // OK because we have defined the format of A as a usize.
            tendril: unsafe { mem::transmute(self) },
        }
    }

    /// Convert into a sendable value, admitting only a required shared copy.
    /// Inline and uniquely owned buffers transfer their existing storage and guard.
    pub fn try_into_send_with_reservation<R, E>(
        mut self,
        reserve: impl FnOnce(usize) -> Result<R, E>,
        settle: impl FnOnce(&mut R, usize) -> Result<(), E>,
    ) -> Result<SendTendril<F>, ReserveError<E>>
    where
        R: Send + Sync + 'static,
    {
        if self.is_shared() {
            let replacement = unsafe {
                Self::try_owned_copy_with_reservation(
                    self.as_byte_slice(),
                    self.len32(),
                    reserve,
                    settle,
                )?
            };
            let old = mem::replace(&mut self, replacement);
            drop(old);
        }
        Ok(SendTendril {
            // As in into_send, the unique header's refcount has usize layout.
            tendril: unsafe { mem::transmute(self) },
        })
    }

    /// View as a superset format, for free.
    #[inline(always)]
    pub fn as_superset<Super>(&self) -> &Tendril<Super, A>
    where
        F: fmt::SubsetOf<Super>,
        Super: fmt::Format,
    {
        unsafe { mem::transmute(self) }
    }

    /// Convert into a superset format, for free.
    #[inline(always)]
    pub fn into_superset<Super>(self) -> Tendril<Super, A>
    where
        F: fmt::SubsetOf<Super>,
        Super: fmt::Format,
    {
        unsafe { mem::transmute(self) }
    }

    /// View as a subset format, if the `Tendril` conforms to that subset.
    #[inline]
    pub fn try_as_subset<Sub>(&self) -> Result<&Tendril<Sub, A>, ()>
    where
        Sub: fmt::SubsetOf<F>,
    {
        match Sub::revalidate_subset(self.as_byte_slice()) {
            true => Ok(unsafe { mem::transmute(self) }),
            false => Err(()),
        }
    }

    /// Convert into a subset format, if the `Tendril` conforms to that subset.
    #[inline]
    pub fn try_into_subset<Sub>(self) -> Result<Tendril<Sub, A>, Self>
    where
        Sub: fmt::SubsetOf<F>,
    {
        match Sub::revalidate_subset(self.as_byte_slice()) {
            true => Ok(unsafe { mem::transmute(self) }),
            false => Err(self),
        }
    }

    /// View as another format, if the bytes of the `Tendril` are valid for
    /// that format.
    #[inline]
    pub fn try_reinterpret_view<Other>(&self) -> Result<&Tendril<Other, A>, ()>
    where
        Other: fmt::Format,
    {
        match Other::validate(self.as_byte_slice()) {
            true => Ok(unsafe { mem::transmute(self) }),
            false => Err(()),
        }
    }

    /// Convert into another format, if the `Tendril` conforms to that format.
    ///
    /// This only re-validates the existing bytes under the new format. It
    /// will *not* change the byte content of the tendril!
    ///
    /// See the `encode` and `decode` methods for character encoding conversion.
    #[inline]
    pub fn try_reinterpret<Other>(self) -> Result<Tendril<Other, A>, Self>
    where
        Other: fmt::Format,
    {
        match Other::validate(self.as_byte_slice()) {
            true => Ok(unsafe { mem::transmute(self) }),
            false => Err(self),
        }
    }

    /// Push some bytes onto the end of the `Tendril`, if they conform to the
    /// format.
    #[inline]
    pub fn try_push_bytes(&mut self, buf: &[u8]) -> Result<(), ()> {
        match F::validate(buf) {
            true => unsafe {
                self.push_bytes_without_validating(buf);
                Ok(())
            },
            false => Err(()),
        }
    }

    /// Push another `Tendril` onto the end of this one.
    #[inline]
    pub fn push_tendril(&mut self, other: &Tendril<F, A>) {
        let new_len = self.len32().checked_add(other.len32()).expect(OFLOW);

        unsafe {
            if (self.ptr.get().get() > MAX_INLINE_TAG) && (other.ptr.get().get() > MAX_INLINE_TAG) {
                let (self_buf, self_shared, _) = self.assume_buf();
                let (other_buf, other_shared, _) = other.assume_buf();

                if self_shared
                    && other_shared
                    && (self_buf.data_ptr() == other_buf.data_ptr())
                    && other.aux() == self.aux() + self.raw_len()
                {
                    self.set_len(new_len);
                    return;
                }
            }

            self.push_bytes_without_validating(other.as_byte_slice())
        }
    }

    /// Attempt to slice this `Tendril` as a new `Tendril`.
    ///
    /// This will share the buffer when possible. Mutating a shared buffer
    /// will copy the contents.
    ///
    /// The offset and length are in bytes. The function will return
    /// `Err` if these are out of bounds, or if the resulting slice
    /// does not conform to the format.
    #[inline]
    pub fn try_subtendril(
        &self,
        offset: u32,
        length: u32,
    ) -> Result<Tendril<F, A>, SubtendrilError> {
        let self_len = self.len32();
        if offset > self_len || length > (self_len - offset) {
            return Err(SubtendrilError::OutOfBounds);
        }

        unsafe {
            let byte_slice = unsafe_slice(self.as_byte_slice(), offset as usize, length as usize);
            if !F::validate_subseq(byte_slice) {
                return Err(SubtendrilError::ValidationFailed);
            }

            Ok(self.unsafe_subtendril(offset, length))
        }
    }

    /// Slice this `Tendril` as a new `Tendril`.
    ///
    /// Panics on bounds or validity check failure.
    #[inline]
    pub fn subtendril(&self, offset: u32, length: u32) -> Tendril<F, A> {
        self.try_subtendril(offset, length).unwrap()
    }

    /// Try to drop `n` bytes from the front.
    ///
    /// Returns `Err` if the bytes are not available, or the suffix fails
    /// validation.
    #[inline]
    pub fn try_pop_front(&mut self, n: u32) -> Result<(), SubtendrilError> {
        if n == 0 {
            return Ok(());
        }
        let old_len = self.len32();
        if n > old_len {
            return Err(SubtendrilError::OutOfBounds);
        }
        let new_len = old_len - n;

        unsafe {
            if !F::validate_suffix(unsafe_slice(
                self.as_byte_slice(),
                n as usize,
                new_len as usize,
            )) {
                return Err(SubtendrilError::ValidationFailed);
            }

            self.unsafe_pop_front(n);
            Ok(())
        }
    }

    /// Drop `n` bytes from the front.
    ///
    /// Panics if the bytes are not available, or the suffix fails
    /// validation.
    #[inline]
    pub fn pop_front(&mut self, n: u32) {
        self.try_pop_front(n).unwrap()
    }

    /// Drop `n` bytes from the back.
    ///
    /// Returns `Err` if the bytes are not available, or the prefix fails
    /// validation.
    #[inline]
    pub fn try_pop_back(&mut self, n: u32) -> Result<(), SubtendrilError> {
        if n == 0 {
            return Ok(());
        }
        let old_len = self.len32();
        if n > old_len {
            return Err(SubtendrilError::OutOfBounds);
        }
        let new_len = old_len - n;

        unsafe {
            if !F::validate_prefix(unsafe_slice(self.as_byte_slice(), 0, new_len as usize)) {
                return Err(SubtendrilError::ValidationFailed);
            }

            self.unsafe_pop_back(n);
            Ok(())
        }
    }

    /// Drop `n` bytes from the back.
    ///
    /// Panics if the bytes are not available, or the prefix fails
    /// validation.
    #[inline]
    pub fn pop_back(&mut self, n: u32) {
        self.try_pop_back(n).unwrap()
    }

    /// View as another format, without validating.
    #[inline(always)]
    pub unsafe fn reinterpret_view_without_validating<Other>(&self) -> &Tendril<Other, A>
    where
        Other: fmt::Format,
    {
        mem::transmute(self)
    }

    /// Convert into another format, without validating.
    #[inline(always)]
    pub unsafe fn reinterpret_without_validating<Other>(self) -> Tendril<Other, A>
    where
        Other: fmt::Format,
    {
        mem::transmute(self)
    }

    /// Build a `Tendril` by copying a byte slice, without validating.
    #[inline]
    pub unsafe fn from_byte_slice_without_validating(x: &[u8]) -> Tendril<F, A> {
        assert!(x.len() <= buf32::MAX_LEN);
        if x.len() <= MAX_INLINE_LEN {
            Tendril::inline(x)
        } else {
            Tendril::owned_copy(x)
        }
    }

    /// Push some bytes onto the end of the `Tendril`, without validating.
    #[inline]
    pub unsafe fn push_bytes_without_validating(&mut self, buf: &[u8]) {
        assert!(buf.len() <= buf32::MAX_LEN);

        let Fixup {
            drop_left,
            drop_right,
            insert_len,
            insert_bytes,
        } = F::fixup(self.as_byte_slice(), buf);

        // FIXME: think more about overflow
        let adj_len = self.len32() + insert_len - drop_left;

        let new_len = adj_len.checked_add(buf.len() as u32).expect(OFLOW) - drop_right;

        let drop_left = drop_left as usize;
        let drop_right = drop_right as usize;

        if new_len <= MAX_INLINE_LEN as u32 {
            let mut tmp = [0_u8; MAX_INLINE_LEN];
            {
                let old = self.as_byte_slice();
                let mut dest = tmp.as_mut_ptr();
                copy_and_advance(&mut dest, unsafe_slice(old, 0, old.len() - drop_left));
                copy_and_advance(
                    &mut dest,
                    unsafe_slice(&insert_bytes, 0, insert_len as usize),
                );
                copy_and_advance(
                    &mut dest,
                    unsafe_slice(buf, drop_right, buf.len() - drop_right),
                );
            }
            *self = Tendril::inline(&tmp[..new_len as usize]);
        } else {
            self.make_owned_with_capacity(new_len);
            let (owned, _, _) = self.assume_buf();
            let mut dest = owned.data_ptr().add(owned.len as usize - drop_left);
            copy_and_advance(
                &mut dest,
                unsafe_slice(&insert_bytes, 0, insert_len as usize),
            );
            copy_and_advance(
                &mut dest,
                unsafe_slice(buf, drop_right, buf.len() - drop_right),
            );
            self.set_len(new_len);
        }
    }

    /// Slice this `Tendril` as a new `Tendril`.
    ///
    /// Does not check validity or bounds!
    #[inline]
    pub unsafe fn unsafe_subtendril(&self, offset: u32, length: u32) -> Tendril<F, A> {
        if length <= MAX_INLINE_LEN as u32 {
            Tendril::inline(unsafe_slice(
                self.as_byte_slice(),
                offset as usize,
                length as usize,
            ))
        } else {
            self.make_buf_shared();
            self.incref();
            let (buf, _, _) = self.assume_buf();
            Tendril::shared(buf, self.aux() + offset, length)
        }
    }

    /// Drop `n` bytes from the front.
    ///
    /// Does not check validity or bounds!
    #[inline]
    pub unsafe fn unsafe_pop_front(&mut self, n: u32) {
        let new_len = self.len32() - n;
        if new_len <= MAX_INLINE_LEN as u32 {
            *self = Tendril::inline(unsafe_slice(
                self.as_byte_slice(),
                n as usize,
                new_len as usize,
            ));
        } else {
            self.make_buf_shared();
            self.set_aux(self.aux() + n);
            let len = self.raw_len();
            self.set_len(len - n);
        }
    }

    /// Drop `n` bytes from the back.
    ///
    /// Does not check validity or bounds!
    #[inline]
    pub unsafe fn unsafe_pop_back(&mut self, n: u32) {
        let new_len = self.len32() - n;
        if new_len <= MAX_INLINE_LEN as u32 {
            *self = Tendril::inline(unsafe_slice(self.as_byte_slice(), 0, new_len as usize));
        } else {
            self.make_buf_shared();
            let len = self.raw_len();
            self.set_len(len - n);
        }
    }

    #[inline]
    unsafe fn incref(&self) {
        (*self.header()).refcount.increment();
    }

    #[inline]
    unsafe fn make_buf_shared(&self) {
        let p = self.ptr.get().get();
        if p & 1 == 0 {
            let header = p as *mut Header<A>;
            (*header).cap = self.aux();

            self.ptr.set(NonZeroUsize::new_unchecked(p | 1));
            self.set_aux(0);
        }
    }

    // This is not public as it is of no practical value to users.
    // By and large they shouldn't need to worry about the distinction at all,
    // and going out of your way to make it owned is pointless.
    #[inline]
    fn make_owned(&mut self) {
        unsafe {
            let ptr = self.ptr.get().get();
            if ptr <= MAX_INLINE_TAG || (ptr & 1) == 1 {
                *self = Tendril::owned_copy(self.as_byte_slice());
            }
        }
    }

    #[inline]
    unsafe fn make_owned_with_capacity(&mut self, cap: u32) {
        self.make_owned();
        let mut buf = self.assume_buf().0;
        if cap > buf.cap && (*buf.ptr).reservation.is_some() {
            // Ordinary mutation stays unadmitted. Do not realloc a charged block:
            // free that exact block before releasing its original reservation.
            let capacity = cap.checked_next_power_of_two().expect(OFLOW);
            let mut replacement = Buf32::with_capacity(capacity, Header::new());
            ptr::copy_nonoverlapping(buf.data_ptr(), replacement.data_ptr(), buf.len as usize);
            replacement.len = buf.len;
            // Publish first: a caller reservation's Drop may unwind.
            self.ptr.set(NonZeroUsize::new_unchecked(replacement.ptr as usize));
            self.set_aux(replacement.cap);
            Self::destroy_buf(buf);
            return;
        }
        buf.grow(cap);
        self.ptr.set(NonZeroUsize::new_unchecked(buf.ptr as usize));
        self.set_aux(buf.cap);
    }

    #[inline(always)]
    unsafe fn header(&self) -> *mut Header<A> {
        (self.ptr.get().get() & !1) as *mut Header<A>
    }

    #[inline]
    unsafe fn assume_buf(&self) -> (Buf32<Header<A>>, bool, u32) {
        let ptr = self.ptr.get().get();
        let header = self.header();
        let shared = (ptr & 1) == 1;
        let (cap, offset) = match shared {
            true => ((*header).cap, self.aux()),
            false => (self.aux(), 0),
        };

        (
            Buf32 {
                ptr: header,
                len: offset + self.len32(),
                cap,
            },
            shared,
            offset,
        )
    }

    #[inline]
    unsafe fn inline(x: &[u8]) -> Tendril<F, A> {
        let len = x.len();
        let t = Tendril {
            ptr: Cell::new(inline_tag(len as u32)),
            buf: UnsafeCell::new(Buffer { inline: [0; 8] }),
            marker: PhantomData,
            refcount_marker: PhantomData,
        };
        ptr::copy_nonoverlapping(x.as_ptr(), (*t.buf.get()).inline.as_mut_ptr(), len);
        t
    }

    #[inline]
    unsafe fn owned(x: Buf32<Header<A>>) -> Tendril<F, A> {
        Tendril {
            ptr: Cell::new(NonZeroUsize::new_unchecked(x.ptr as usize)),
            buf: UnsafeCell::new(Buffer {
                heap: Heap {
                    len: x.len,
                    aux: x.cap,
                },
            }),
            marker: PhantomData,
            refcount_marker: PhantomData,
        }
    }

    unsafe fn try_owned_copy_with_reservation<R, E>(
        bytes: &[u8],
        capacity: u32,
        reserve: impl FnOnce(usize) -> Result<R, E>,
        settle: impl FnOnce(&mut R, usize) -> Result<(), E>,
    ) -> Result<Tendril<F, A>, ReserveError<E>>
    where
        R: Send + Sync + 'static,
    {
        let (mut buf, reservation) =
            Buf32::try_with_capacity(capacity, Header::new(), reserve, settle)?;
        (*buf.ptr).reservation = Some(Box::new(reservation));
        ptr::copy_nonoverlapping(bytes.as_ptr(), buf.data_ptr(), bytes.len());
        buf.len = bytes.len() as u32;
        Ok(Tendril::owned(buf))
    }

    #[inline]
    unsafe fn destroy_buf(buf: Buf32<Header<A>>) {
        let reservation = (*buf.ptr).reservation.take();
        buf.destroy();
        drop(reservation);
    }

    #[inline]
    unsafe fn owned_copy(x: &[u8]) -> Tendril<F, A> {
        let len32 = x.len() as u32;
        let mut b = Buf32::with_capacity(len32, Header::new());
        ptr::copy_nonoverlapping(x.as_ptr(), b.data_ptr(), x.len());
        b.len = len32;
        Tendril::owned(b)
    }

    #[inline]
    unsafe fn shared(buf: Buf32<Header<A>>, off: u32, len: u32) -> Tendril<F, A> {
        Tendril {
            ptr: Cell::new(NonZeroUsize::new_unchecked((buf.ptr as usize) | 1)),
            buf: UnsafeCell::new(Buffer {
                heap: Heap { len, aux: off },
            }),
            marker: PhantomData,
            refcount_marker: PhantomData,
        }
    }

    #[inline]
    fn as_byte_slice(&self) -> &[u8] {
        unsafe {
            match self.ptr.get().get() {
                EMPTY_TAG => &[],
                n if n <= MAX_INLINE_LEN => (*self.buf.get()).inline.get_unchecked(..n),
                _ => {
                    let (buf, _, offset) = self.assume_buf();
                    copy_lifetime(
                        self,
                        unsafe_slice(buf.data(), offset as usize, self.len32() as usize),
                    )
                },
            }
        }
    }

    // There's no need to worry about locking on an atomic Tendril, because it makes it unique as
    // soon as you do that.
    #[inline]
    fn as_mut_byte_slice(&mut self) -> &mut [u8] {
        unsafe {
            match self.ptr.get().get() {
                EMPTY_TAG => &mut [],
                n if n <= MAX_INLINE_LEN => (*self.buf.get()).inline.get_unchecked_mut(..n),
                _ => {
                    self.make_owned();
                    let (mut buf, _, offset) = self.assume_buf();
                    let len = self.len32() as usize;
                    copy_lifetime_mut(self, unsafe_slice_mut(buf.data_mut(), offset as usize, len))
                },
            }
        }
    }

    unsafe fn raw_len(&self) -> u32 {
        (*self.buf.get()).heap.len
    }

    unsafe fn set_len(&mut self, len: u32) {
        (*self.buf.get()).heap.len = len;
    }

    unsafe fn aux(&self) -> u32 {
        (*self.buf.get()).heap.aux
    }

    unsafe fn set_aux(&self, aux: u32) {
        (*self.buf.get()).heap.aux = aux;
    }
}

impl<F, A> Tendril<F, A>
where
    F: fmt::SliceFormat,
    A: Atomicity,
{
    /// Build a `Tendril` by copying a slice.
    #[inline]
    pub fn from_slice(x: &F::Slice) -> Tendril<F, A> {
        unsafe { Tendril::from_byte_slice_without_validating(x.as_bytes()) }
    }

    /// Copy a slice with admission owned by the native allocation.
    ///
    /// Inline slices need no reservation. For heap slices, `reserve` runs before
    /// allocation and `settle` receives the reported allocation bytes, including
    /// the header and rounding. The native shared header retains the reservation
    /// until after the last owner frees that allocation. Its small boxed guard
    /// and allocator-private overhead are not included in those bytes.
    ///
    /// Ordinary copying and growing APIs remain unadmitted: an ordinary CoW copy
    /// or growth can create a new unadmitted allocation. Sharing without copying
    /// retains admission for the original block; in-place writes retain it too.
    pub fn try_from_slice_with_reservation<R, E>(
        x: &F::Slice,
        reserve: impl FnOnce(usize) -> Result<R, E>,
        settle: impl FnOnce(&mut R, usize) -> Result<(), E>,
    ) -> Result<Tendril<F, A>, ReserveError<E>>
    where
        R: Send + Sync + 'static,
    {
        let bytes = x.as_bytes();
        let len = u32::try_from(bytes.len()).map_err(|_| ReserveError::CapacityOverflow)?;
        if bytes.len() <= MAX_INLINE_LEN {
            return Ok(unsafe { Tendril::inline(bytes) });
        }
        unsafe { Self::try_owned_copy_with_reservation(bytes, len, reserve, settle) }
    }

    /// Push a slice onto the end of the `Tendril`.
    #[inline]
    pub fn push_slice(&mut self, x: &F::Slice) {
        unsafe { self.push_bytes_without_validating(x.as_bytes()) }
    }
}

/// A simple wrapper to make `Tendril` `Send`.
///
/// Although there is a certain subset of the operations on a `Tendril` that a `SendTendril` could
/// reasonably implement, in order to clearly separate concerns this type is deliberately
/// minimalist, acting as a safe encapsulation around the invariants which permit `Send`ness and
/// behaving as an opaque object.
///
/// A `SendTendril` may be produced by `Tendril.into_send()` or `SendTendril::from(tendril)`,
/// and may be returned to a `Tendril` by `Tendril::from(self)`.
#[derive(Clone)]
pub struct SendTendril<F>
where
    F: fmt::Format,
{
    tendril: Tendril<F>,
}

unsafe impl<F> Send for SendTendril<F> where F: fmt::Format {}

impl<F, A> From<Tendril<F, A>> for SendTendril<F>
where
    F: fmt::Format,
    A: Atomicity,
{
    #[inline]
    fn from(tendril: Tendril<F, A>) -> SendTendril<F> {
        tendril.into_send()
    }
}

impl<F, A> From<SendTendril<F>> for Tendril<F, A>
where
    F: fmt::Format,
    A: Atomicity,
{
    #[inline]
    fn from(send: SendTendril<F>) -> Tendril<F, A> {
        unsafe { mem::transmute(send.tendril) }
        // header.refcount may have been initialised as an Atomic or a NonAtomic, but the value
        // will be the same (1) regardless, because the layout is defined.
        // Thus we don't need to fiddle about resetting it or anything like that.
    }
}

/// `Tendril`-related methods for Rust slices.
pub trait SliceExt<F>: fmt::Slice
where
    F: fmt::SliceFormat<Slice = Self>,
{
    /// Make a `Tendril` from this slice.
    #[inline]
    fn to_tendril(&self) -> Tendril<F> {
        // It should be done thusly, but at the time of writing the defaults don't help inference:
        //fn to_tendril<A = NonAtomic>(&self) -> Tendril<Self::Format, A>
        //    where A: Atomicity,
        //{
        Tendril::from_slice(self)
    }
}

impl SliceExt<fmt::UTF8> for str {}
impl SliceExt<fmt::Bytes> for [u8] {}

impl<F, A> Tendril<F, A>
where
    F: for<'a> fmt::CharFormat<'a>,
    A: Atomicity,
{
    /// Remove and return the first character, if any.
    #[inline]
    pub fn pop_front_char(&mut self) -> Option<char> {
        unsafe {
            let next_char; // first char in iterator
            let mut skip = 0; // number of bytes to skip, or 0 to clear

            {
                // <--+
                //  |  Creating an iterator borrows self, so introduce a
                //  +- scope to contain the borrow (that way we can mutate
                //     self below, after this scope exits).

                let mut iter = F::char_indices(self.as_byte_slice());
                match iter.next() {
                    Some((_, c)) => {
                        next_char = Some(c);
                        if let Some((n, _)) = iter.next() {
                            skip = n as u32;
                        }
                    },
                    None => {
                        next_char = None;
                    },
                }
            }

            if skip != 0 {
                self.unsafe_pop_front(skip);
            } else {
                self.clear();
            }

            next_char
        }
    }

    /// Remove and return a run of characters at the front of the `Tendril`
    /// which are classified the same according to the function `classify`.
    ///
    /// Returns `None` on an empty string.
    #[inline]
    pub fn pop_front_char_run<C, R>(&mut self, mut classify: C) -> Option<(Tendril<F, A>, R)>
    where
        C: FnMut(char) -> R,
        R: PartialEq,
    {
        let (class, first_mismatch);
        {
            let mut chars = unsafe { F::char_indices(self.as_byte_slice()) };
            let (_, first) = chars.next()?;
            class = classify(first);
            first_mismatch = chars.find(|&(_, ch)| classify(ch) != class);
        }

        match first_mismatch {
            Some((idx, _)) => unsafe {
                let t = self.unsafe_subtendril(0, idx as u32);
                self.unsafe_pop_front(idx as u32);
                Some((t, class))
            },
            None => {
                let t = self.clone();
                self.clear();
                Some((t, class))
            },
        }
    }

    /// Push a character, if it can be represented in this format.
    #[inline]
    pub fn try_push_char(&mut self, c: char) -> Result<(), ()> {
        F::encode_char(c, |b| unsafe {
            self.push_bytes_without_validating(b);
        })
    }
}

/// Extension trait for `io::Read`.
pub trait ReadExt: io::Read {
    fn read_to_tendril<A>(&mut self, buf: &mut Tendril<fmt::Bytes, A>) -> io::Result<usize>
    where
        A: Atomicity;
}

impl<T> ReadExt for T
where
    T: io::Read,
{
    /// Read all bytes until EOF.
    fn read_to_tendril<A>(&mut self, buf: &mut Tendril<fmt::Bytes, A>) -> io::Result<usize>
    where
        A: Atomicity,
    {
        // Adapted from libstd/io/mod.rs.
        const DEFAULT_BUF_SIZE: u32 = 64 * 1024;

        let start_len = buf.len();
        let mut len = start_len;
        let mut new_write_size = 16;
        let ret;
        loop {
            if len == buf.len() {
                if new_write_size < DEFAULT_BUF_SIZE {
                    new_write_size *= 2;
                }
                // FIXME: this exposes uninitialized bytes to a generic R type
                // this is fine for R=File which never reads these bytes,
                // but user-defined types might.
                // The standard library pushes zeros to `Vec<u8>` for that reason.
                unsafe {
                    buf.push_uninitialized(new_write_size);
                }
            }

            match self.read(&mut buf[len..]) {
                Ok(0) => {
                    ret = Ok(len - start_len);
                    break;
                },
                Ok(n) => len += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {},
                Err(e) => {
                    ret = Err(e);
                    break;
                },
            }
        }

        let buf_len = buf.len32();
        buf.pop_back(buf_len - (len as u32));
        ret
    }
}

impl<A> io::Write for Tendril<fmt::Bytes, A>
where
    A: Atomicity,
{
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.push_slice(buf);
        Ok(buf.len())
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.push_slice(buf);
        Ok(())
    }

    #[inline(always)]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<F, A> Tendril<F, A>
where
    A: Atomicity,
    F: fmt::SliceFormat<Slice = [u8]>,
{
    /// Push "uninitialized bytes" onto the end.
    ///
    /// Really, this grows the tendril without writing anything to the new area.
    /// It's only defined for byte tendrils because it's only useful if you
    /// plan to then mutate the buffer.
    #[inline]
    pub unsafe fn push_uninitialized(&mut self, n: u32) {
        let new_len = self.len32().checked_add(n).expect(OFLOW);
        if new_len <= MAX_INLINE_LEN as u32 && self.ptr.get().get() <= MAX_INLINE_TAG {
            self.ptr.set(inline_tag(new_len))
        } else {
            self.make_owned_with_capacity(new_len);
            self.set_len(new_len);
        }
    }
}

impl<A> strfmt::Display for Tendril<fmt::UTF8, A>
where
    A: Atomicity,
{
    #[inline]
    fn fmt(&self, f: &mut strfmt::Formatter) -> strfmt::Result {
        <str as strfmt::Display>::fmt(&**self, f)
    }
}

impl<A> str::FromStr for Tendril<fmt::UTF8, A>
where
    A: Atomicity,
{
    type Err = ();

    #[inline]
    fn from_str(s: &str) -> Result<Self, ()> {
        Ok(Tendril::from_slice(s))
    }
}

impl<A> strfmt::Write for Tendril<fmt::UTF8, A>
where
    A: Atomicity,
{
    #[inline]
    fn write_str(&mut self, s: &str) -> strfmt::Result {
        self.push_slice(s);
        Ok(())
    }
}

impl<A> Tendril<fmt::UTF8, A>
where
    A: Atomicity,
{
    /// Push a character onto the end.
    #[inline]
    pub fn push_char(&mut self, c: char) {
        unsafe {
            self.push_bytes_without_validating(c.encode_utf8(&mut [0_u8; 4]).as_bytes());
        }
    }

    /// Create a `Tendril` from a single character.
    #[inline]
    pub fn from_char(c: char) -> Tendril<fmt::UTF8, A> {
        let mut t: Tendril<fmt::UTF8, A> = Tendril::new();
        t.push_char(c);
        t
    }

    /// Helper for the `format_tendril!` macro.
    #[inline]
    pub fn format(args: strfmt::Arguments) -> Tendril<fmt::UTF8, A> {
        use std::fmt::Write;
        let mut output: Tendril<fmt::UTF8, A> = Tendril::new();
        let _ = write!(&mut output, "{}", args);
        output
    }
}

/// Create a `StrTendril` through string formatting.
///
/// Works just like the standard `format!` macro.
#[macro_export]
macro_rules! format_tendril {
    ($($arg:tt)*) => ($crate::StrTendril::format(format_args!($($arg)*)))
}

impl<F, A> From<&F::Slice> for Tendril<F, A>
where
    F: fmt::SliceFormat,
    A: Atomicity,
{
    #[inline]
    fn from(input: &F::Slice) -> Tendril<F, A> {
        Tendril::from_slice(input)
    }
}

impl<A> From<String> for Tendril<fmt::UTF8, A>
where
    A: Atomicity,
{
    #[inline]
    fn from(input: String) -> Tendril<fmt::UTF8, A> {
        Tendril::from_slice(&*input)
    }
}

impl<F, A> AsRef<F::Slice> for Tendril<F, A>
where
    F: fmt::SliceFormat,
    A: Atomicity,
{
    #[inline]
    fn as_ref(&self) -> &F::Slice {
        self
    }
}

impl<A> From<Tendril<fmt::UTF8, A>> for String
where
    A: Atomicity,
{
    #[inline]
    fn from(input: Tendril<fmt::UTF8, A>) -> String {
        String::from(&*input)
    }
}

impl<'a, A> From<&'a Tendril<fmt::UTF8, A>> for String
where
    A: Atomicity,
{
    #[inline]
    fn from(input: &'a Tendril<fmt::UTF8, A>) -> String {
        String::from(&**input)
    }
}
