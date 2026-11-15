//! Door for `tests/fingerprint_keep_custody_policy_digest.rs` (PLAN-UC-04 stage 6.3f): the
//! custody journal's publication policy digest, which is private to `store::key_custody`.

use std::collections::{BTreeMap, BTreeSet};

use oneiron_authority::authority::WrapRecipient;
use oneiron_crypto::HybridPublicKey;

use crate::EntityId;

/// The publication policy digest of these parts: the four world sets (each group's pads
/// kept local, own then hosted, then each group's eligible credentials), each group's
/// recovery root id, each group's admitted pad recipients by world, and the carried set's
/// digest.
#[must_use]
pub fn custody_policy_digest(
    sets: &[&BTreeSet<[u8; 16]>],
    roots: [Option<[u8; 32]>; 2],
    pads: [&BTreeMap<EntityId, BTreeMap<WrapRecipient, HybridPublicKey>>; 2],
    carried: Option<[u8; 32]>,
) -> [u8; 32] {
    crate::store::custody_policy_digest_for_test(sets, roots, pads, carried)
}
