//! The checkpoint getter of the phonetic index source (KS7-2): the supplied
//! and generated codes each entity's phonetic postings are reconciled from,
//! whole, under the entity's tree. The postings themselves are an index,
//! rebuilt after a restore, and are not captured here. Nothing calls this
//! until KS7-5, and only once CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::{RoTxn, RwTxn};

use crate::checkpoint_payload::rows;
use oneiron_base::error::Result;
