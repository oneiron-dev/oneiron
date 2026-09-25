//! Per-vault runtime-kind handles. Names are identity; bytes are local intern handles.
//!
//! ASSET snapshots are sync/export DATA. Only a local install command advances
//! the local head pin. A foreign snapshot cannot install code or grant authority.

mod doors;
mod hex_bytes;
mod persistence;
mod state;
mod types;

pub use types::{
    PackByteMapSnapshot, PackInstanceEnvelope, PackInstanceOrigin, PackKindIdentity,
    PackKindRegistration,
};

#[cfg(test)]
mod tests;
