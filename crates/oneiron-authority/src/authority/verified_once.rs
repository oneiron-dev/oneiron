//! Process memory of signature checks that already succeeded on exact bytes
//! (FIX 21959).
//!
//! A signature check is a pure function of its inputs. A success recorded
//! under the BLAKE3 digest of the exact inputs answers every later run of the
//! same check kind on the same bytes. Only successes are recorded; a failure
//! is computed again every time. A changed byte gives another digest, so the
//! full check runs again. Nothing here is persisted, synced, exported or
//! restored: no peer, backup or disk write can plant a fact. Authority
//! standing (revocation, roles, bindings) is never recorded here; readers
//! evaluate it on every read.

use std::collections::HashSet;
use std::sync::{LazyLock, RwLock};

/// Digests held before the set empties itself and starts again.
const VERIFIED_FACTS_CAPACITY: usize = 1 << 16;

static VERIFIED_FACTS: LazyLock<RwLock<HashSet<[u8; 32]>>> =
    LazyLock::new(|| RwLock::new(HashSet::new()));

/// The check a recorded fact stands for. Each kind keeps its own digests, so
/// a success of one kind never answers for another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedFact {
    /// `verify_authority_signature` returned true.
    AuthoritySignature,
    /// `VerifyingKey::from_bytes` and then `verify_strict` succeeded.
    Ed25519Strict,
    /// `strong_ed25519_key` and then `verify_strict` succeeded.
    StrongEd25519Strict,
    /// A signed MACHINE claim birth's whole `verify` succeeded on its
    /// canonical encoding.
    MachineClaimBirth,
}

impl VerifiedFact {
    fn tag(self) -> u8 {
        match self {
            Self::AuthoritySignature => 1,
            Self::Ed25519Strict => 2,
            Self::StrongEd25519Strict => 3,
            Self::MachineClaimBirth => 4,
        }
    }
}

fn fact_digest(fact: VerifiedFact, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron verified signature fact v1");
    hasher.update(&[fact.tag()]);
    for part in parts {
        hasher.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// Whether `fact` already succeeded on exactly `parts`.
#[must_use]
pub fn verified_before(fact: VerifiedFact, parts: &[&[u8]]) -> bool {
    let digest = fact_digest(fact, parts);
    VERIFIED_FACTS
        .read()
        .is_ok_and(|facts| facts.contains(&digest))
}

/// Records that `fact` succeeded on exactly `parts`. Call it only after the
/// full check returned success on those parts.
pub fn remember_verified(fact: VerifiedFact, parts: &[&[u8]]) {
    let digest = fact_digest(fact, parts);
    if let Ok(mut facts) = VERIFIED_FACTS.write() {
        if facts.len() >= VERIFIED_FACTS_CAPACITY {
            facts.clear();
        }
        facts.insert(digest);
    }
}
