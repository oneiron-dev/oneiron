//! A projected candidate's source, as every later seam proves it (FIX 7608
//! slice 2b-ii-A).
//!
//! A candidate from a masked copy stands only while its ingress proof and
//! its translation record both stand, exactly as written: the copy graph,
//! the receive operation and its admitted authority, the submitted COPY
//! tip, the ORIGINAL base and the canonical target its pins name. The
//! translation record is written with the candidate, once, and never
//! rebinds its source or base; an exact or rebased replacement is a new
//! candidate with its own record.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: the queue and landing seams call it in 2b-ii-B"
)]

use heed::{RoTxn, RwTxn};

use crate::git_wire::ids::GitOid;
use crate::origin::secret_projection::claims::RepoProjectionTranslation;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
