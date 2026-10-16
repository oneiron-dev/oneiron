//! Retrieval-transaction execution: channel fan-out, the outer context-pack driver, and attempt plumbing.

mod channels;
mod pack;
mod retrieval_policy;
mod types;

use super::authority;
