//! Shared value vocabulary of the oneiron engine: the lowest engine crate, with no
//! dependency on any implementation crate. `oneiron` re-exports every module here at
//! its old `oneiron::<module>` path; applications depend on `oneiron`, not on this crate.

pub mod limits;
pub mod temporal;
