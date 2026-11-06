//! An agent dispatch's payload text in checkpoint images (FIX 7115, KEY
//! STORE = A): its attempt row is a row-held response of its own (KS-2B1),
//! sealed whole under a body instance its dispatch target's erase retires.
//!
//! An image carries the row as an erase of its target leaves it: the same
//! deterministic rewrite ([`erase_dispatch_payload_text`]) with every other
//! input member, the envelope's parent and every row field kept. A live
//! instance lands the exact row; a retired one leaves the text-free row,
//! which every strict reader reads. Only the dispatch target owns the text,
//! never its requester or a definition guessed from elsewhere.
//!
//! A dispatch's row is recognized by a routing probe that asks no strict
//! validator: its version, its kind and its payload's attempt type. One that
//! the strict reader then refuses, or whose text-free form does not encode,
//! is carried whole as an opaque response, and its retired form is the
//! erased marker, which the strict reader answers `ResponseErased` (FIX
//! 9390). No other row of the queue is taken for a dispatch's.

#[cfg(doc)]
use super::erase_dispatch_payload_text;

pub(crate) use crate::store::attempt_payload_response::attempt_row_opaque;
