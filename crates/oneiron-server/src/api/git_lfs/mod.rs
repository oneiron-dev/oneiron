//! Git-LFS routes (ARCH-0068 Phase A, ONE-1909).
//!
//! Stock Git-LFS `basic` transfer and nothing else: batch negotiation, exact
//! body upload, download, and verify. The routes NEST inside the ONE-1908 git
//! router — there is no second router, no new token format, and no new
//! credential on the wire. The object plane itself lives in
//! [`oneiron::origin::lfs`]; this module owns the transport and the gate.
//!
//! # The gates
//!
//! | Route | Gate |
//! |---|---|
//! | `POST /git/{repo}/info/lfs/objects/batch` (download) | `Read` |
//! | `POST /git/{repo}/info/lfs/objects/batch` (upload) | `Write` + a registered `principal_ref` |
//! | `GET  /git/{repo}/info/lfs/objects/{oid}` | `Read` |
//! | `PUT/POST /git/{repo}/info/lfs/objects/{oid}` | `Write` + a registered `principal_ref` |
//! | `POST /git/{repo}/info/lfs/objects/{oid}/verify` | `Write` + a registered `principal_ref` |
//!
//! The write rows are the receive-pack rule read again: a bearer that carries
//! no `principal_ref` is authenticated but is not a REGISTERED actor, and the
//! unauthenticated-dev hatch mints exactly such an identity. No loopback branch
//! exists to take, because the gate never reads an address.
//!
//! `verify` sits on the write row deliberately. Its href is minted only inside
//! an upload batch, so it is an upload-flow endpoint; gating it lower would
//! publish a probe of what a vault holds to any read-scoped bearer.
//!
//! Uploads and downloads stream with bounded backpressure. Object length has
//! no transport cap; control requests retain the normal bounded body limit.

mod chunks;
mod gate;
mod handlers;
mod streaming;
mod support;
mod wire;

#[cfg(test)]
mod tests;

pub(crate) use self::gate::lfs_routes;
pub(crate) use self::handlers::{lfs_batch, lfs_download, lfs_upload, lfs_verify};

// The flat git_lfs.rs module used to provide these names to the sibling test
// module through `use super::*`. After the directory split the seam
// re-imports every child so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::gate::{LfsAccess, authorize};
#[cfg(test)]
use self::support::{LFS_BATCH_NOT_FOUND, LFS_OBJECT_MEDIA_TYPE, declared_size};
