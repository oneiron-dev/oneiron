//! Owner settlement of a run review (ARCH-0040), split by whole item.
//! `Memory::settle_run_as_owner` in `owner` is its call surface.
//! `memory::run_review` defines the review, settlement and decision records.

use super::*;
use crate::claim::ClaimApprovalStatus;
use crate::identity_topology::{IdentityOpWrite, ProposalRuling, TopologySeal};
use crate::run_tree::GateConsentBundleAction;

mod owner;
