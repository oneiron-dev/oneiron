//! Transaction-bound resident diary coreference over NOTE, edge and grant rows.
mod access;
mod commands;
mod pair;

pub(crate) use access::{edge_access_in, readable_through_link};
