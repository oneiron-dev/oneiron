//! Moved from `crates/oneiron/src/code_sandbox/proposal/body.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_store::proposal_spool::ProposalSpoolClaim;
use oneiron_store::proposal_spool::ProposalSpoolFloor;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;

/// One host buffer of a spool copy or a body read; never a size bound.
pub const READ_FRAME: usize = 1024 * 1024;
