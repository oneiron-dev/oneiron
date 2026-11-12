//! Moved from `crates/oneiron/src/store/body_envelope/frames.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_crypto::Argon2Cost;
use oneiron_crypto::Envelope;
use oneiron_crypto::Kek;
use oneiron_crypto::OpenKey;
use oneiron_crypto::OpenPolicy;
use oneiron_crypto::Purpose;
use oneiron_crypto::SealKey;
use oneiron_crypto::SealParams;
use oneiron_crypto::SuiteId;
use oneiron_crypto::WrapType;
use oneiron_crypto::seal;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::sync::Arc;

/// What one envelope of a file is.
#[derive(Clone, Copy)]
pub enum Role {
    Chunk = 0,
    Last = 1,
    Terminal = 2,
}
