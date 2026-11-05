//! What an Arc is written from (FIX 7509 P8, SUMMARY-SOURCE = A): the
//! current summary of each closed sitting with turns in the Arc's scope, and
//! of each its lines, read in the planner's writer.
//!
//! A line whose every cited TURN stands in the Arc's scope, from a summary
//! still as it was generated and still valid, is the Arc's input as written,
//! with its refs. Any other line is replaced by the Arc's own TURNs it cites,
//! which are read again in its place: a line is never admitted whole on one
//! overlapping ref, and never dropped while a TURN it cites stands in the
//! Arc. A line citing none of the Arc's TURNs belongs to another Arc. A
//! sitting still open is not yet below the Arc; a closed sitting whose
//! summary is still owed keeps the Arc owed, never smaller.

use crate::attempt_id::AttemptId;
use crate::attempt_state::AttemptState;
use crate::conversation_record::ScopeSelector;
use crate::scope_summary::codec::invalid;
use crate::write_envelope::WriteActor;
use heed::{RoTxn, RwTxn};
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;
use std::collections::{BTreeMap, BTreeSet};

/// The purpose a sitting's summary takes (`super::session`'s).
pub const SESSION_PURPOSE: &str = "session_recap";
pub const SOURCE_SET_DOMAIN: &[u8] = b"oneiron:arc-summary-sources:v1";
