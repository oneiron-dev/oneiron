//! Moved from `crates/oneiron/src/world_keys/page_seal.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub(crate) use oneiron_store::key_material::page_seal_open_error;
pub use oneiron_store::vault_page_seal::VaultPageSeal;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use zeroize::Zeroizing;

pub const MIRROR_VERSION: u32 = 2;
pub mod creation;
