//! Typed question records and shared outcome projection.

mod codec;
mod ladder;
mod policy;
pub mod questions;
mod types;

pub use ladder::*;
pub use policy::*;
pub use types::*;

#[cfg(test)]
mod tests;
