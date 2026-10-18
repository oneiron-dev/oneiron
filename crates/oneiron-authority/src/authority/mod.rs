//! The AUTHORITY_LOG wire layer: pinned constants, key material and signature transcripts,
//! the op vocabulary and signed entry envelope, the `rmpv` codec (edited in lockstep), device
//! and confirmation types, federation pact types and capability-slip payloads.
//!
//! Everything here is a value, a codec, a shape check or a signature-transcript check. The
//! fold that derives authority from the log, and every door that applies it, stay in
//! `oneiron::authority`. Items that were private to that module are public here only so the
//! fold, checkpoint, slip and peer-authority code in `oneiron` can call them across the
//! crate line; `oneiron` re-exports them crate-internally, and its public
//! `oneiron::authority` surface is unchanged. Nothing here folds authority, mints a verified
//! witness or applies an op to fold state.

mod confirm;
mod constants;
mod crypto;
mod device;
mod federation_pact;
mod log_entry_op;
mod machine_profile;
mod owner_handover;
mod owner_root;
mod recovery_ceremony;
mod residence;
mod slip_claims;
mod slip_wire;
mod wire_decode;
mod wire_encode;
mod world_key_wraps;
mod world_privacy;

pub use confirm::*;
pub use constants::*;
pub use crypto::*;
pub use device::*;
pub use federation_pact::*;
pub use log_entry_op::*;
pub use machine_profile::*;
pub use owner_handover::*;
pub use owner_root::*;
pub use recovery_ceremony::*;
pub use residence::*;
pub use slip_claims::*;
pub use slip_wire::*;
pub use wire_decode::*;
pub use wire_encode::*;
pub use world_key_wraps::*;
pub use world_privacy::*;
