//! The checkpoint getter of the bm25 index source (KS7-2): the canonical
//! caller-supplied text fields each document's postings are rebuilt from,
//! whole, under the document's entity tree. The postings themselves are an
//! index, rebuilt after a restore, and are not captured here. Nothing calls
//! this until KS7-5, and only once CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::{RoTxn, RwTxn};

use crate::checkpoint_payload::rows;
use oneiron_base::error::Result;
