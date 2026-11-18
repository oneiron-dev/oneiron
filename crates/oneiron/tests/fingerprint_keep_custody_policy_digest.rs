//! K-proof (oracle) for PLAN-UC-04 stage 6.3f: the custody journal's publication policy
//! digest keeps its bytes.
//!
//! The digest starts through the fingerprint crate's K door
//! (`purposes::key_custody::PUBLICATION_POLICY`). The custody log journals it in a
//! `PublicationPolicy` frame, the `policy` record keeps it with the log position it is proven
//! through, and a head is sealed only while it is the policy in force. So it must give main's
//! bytes for every input.
//!
//! `base_policy` holds main's lines at 72fd8019a3d5, copied by range (each range is named above its
//! copy; the generator is `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and
//! differing from them only in indentation. The few lines around the copies are the imports
//! main's lines name, main's `PadRecipients` alias (`oneiron-store`
//! `key_custody::head::pad_scope`), and a wrapper for main's private fn.
//!
//! The door builds only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_custody_policy_digest`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};

use oneiron::EntityId;
use oneiron::test_doors::fingerprint_keep_custody_policy_digest as door;
use oneiron_authority::authority::{RecoveryRootId, WrapRecipient};
use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};
use oneiron_crypto::{HybridPublicKey, HybridSecretKey};

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
mod base_policy {
    use std::collections::{BTreeMap, BTreeSet};

    use oneiron::EntityId;
    use oneiron_authority::authority::WrapRecipient;
    use oneiron_crypto::HybridPublicKey;

    /// Main's `PadRecipients` (`oneiron-store` `key_custody::head::pad_scope`).
    pub(crate) type PadRecipients = BTreeMap<WrapRecipient, HybridPublicKey>;

    // main 72fd8019a3d5: crates/oneiron/src/store/key_custody/publication_policy.rs:39-39
    const POLICY_CONTEXT: &[u8] = b"oneiron/custody-publication-policy/v1";

    // main 72fd8019a3d5: crates/oneiron/src/store/key_custody/publication_policy.rs:79-139
    fn policy_digest(
        sets: &[&BTreeSet<[u8; 16]>],
        roots: [Option<[u8; 32]>; 2],
        pads: [&BTreeMap<EntityId, PadRecipients>; 2],
        carried: Option<[u8; 32]>,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(POLICY_CONTEXT);
        // Each group's recovery root by identity, not presence alone (FIX
        // 7995): a changed root moves the policy, so every head is sealed to the
        // new kit and acknowledged again. A root also decides whether a
        // credential's keys may ride at all (KS-6).
        for root in roots {
            match root {
                Some(id) => {
                    hasher.update(&[1]);
                    hasher.update(&id);
                }
                None => {
                    hasher.update(&[0]);
                }
            }
        }
        let credentials = sets.iter().skip(2).any(|set| !set.is_empty());
        let hashed = if credentials { sets.len() } else { 2 };
        for worlds in sets.iter().take(hashed).copied() {
            hasher.update(&(worlds.len() as u64).to_be_bytes());
            for world in worlds {
                hasher.update(world);
            }
        }
        // Each group's world pad recipients (FIX 6706): each world, then each
        // admitted machine's and root's id and canonical public key, counted and
        // in order, so a recipient-only change seals and acknowledges every head
        // again at a new position. Hashed once a group names a world, so the
        // policy of a vault with none stays the digest it is.
        if pads.iter().any(|group| !group.is_empty()) {
            hasher.update(b"pad-recipients");
            for group in pads {
                hasher.update(&(group.len() as u64).to_be_bytes());
                for (world, admitted) in group {
                    hasher.update(world.as_bytes());
                    hasher.update(&(admitted.len() as u64).to_be_bytes());
                    for (recipient, public) in admitted {
                        for part in [recipient.envelope_recipient(), public.to_bytes()] {
                            hasher.update(&(part.len() as u64).to_be_bytes());
                            hasher.update(&part);
                        }
                    }
                }
            }
        }
        // The carried world pad compartments, wraps included (PAD-3): a change
        // of them alone seals every head again. Hashed only while one is
        // carried, so a vault with none keeps the digest it has.
        if let Some(carried) = carried {
            hasher.update(b"carried-world-pads");
            hasher.update(&carried);
        }
        *hasher.finalize().as_bytes()
    }

    /// Main's policy tag, which is private there.
    pub(crate) const MAIN_POLICY_CONTEXT: &[u8] = POLICY_CONTEXT;

    /// Main's policy digest, which is private there.
    pub(crate) fn main_policy_digest(
        sets: &[&BTreeSet<[u8; 16]>],
        roots: [Option<[u8; 32]>; 2],
        pads: [&BTreeMap<EntityId, PadRecipients>; 2],
        carried: Option<[u8; 32]>,
    ) -> [u8; 32] {
        policy_digest(sets, roots, pads, carried)
    }
}

#[test]
fn the_policy_purpose_keeps_main_s_tag() {
    let policy = purposes::key_custody::PUBLICATION_POLICY;
    assert_eq!(policy.tag(), "oneiron/custody-publication-policy/v1");
    assert_eq!(policy.tag().as_bytes(), base_policy::MAIN_POLICY_CONTEXT);
    assert_eq!(policy.hash(), LegacyHash::Blake3);
    assert_eq!(policy.tag_mode(), TagMode::HashedFirst);
}

#[test]
fn the_policy_digest_keeps_its_bytes() {
    let none = BTreeSet::new();
    let one = BTreeSet::from([[0x11; 16]]);
    let two = BTreeSet::from([[0x11; 16], [0x22; 16]]);
    let other = BTreeSet::from([[0x33; 16]]);
    // Own and hosted pads kept local, then own and hosted eligible credentials; the
    // credentials' sets are hashed only when one is not empty.
    let set_cases: [[&BTreeSet<[u8; 16]>; 4]; 7] = [
        [&none, &none, &none, &none],
        [&one, &none, &none, &none],
        [&none, &one, &none, &none],
        [&two, &other, &none, &none],
        [&one, &one, &one, &none],
        [&one, &one, &none, &other],
        [&none, &none, &two, &two],
    ];
    let root_cases = [
        [None, None],
        [Some([0x71; 32]), None],
        [None, Some([0x71; 32])],
        [Some([0x71; 32]), Some([0x72; 32])],
    ];
    let first = public_key(1);
    let second = public_key(2);
    let empty = BTreeMap::new();
    let machine = BTreeMap::from([(
        id(0x41),
        BTreeMap::from([(WrapRecipient::Machine(id(0x51)), first.clone())]),
    )]);
    let machine_and_root = BTreeMap::from([
        (
            id(0x41),
            BTreeMap::from([
                (WrapRecipient::Machine(id(0x51)), first),
                (
                    WrapRecipient::RecoveryRoot(RecoveryRootId([0x61; 32])),
                    second.clone(),
                ),
            ]),
        ),
        // A world with no admitted recipient still counts.
        (id(0x42), BTreeMap::new()),
    ]);
    let other_machine = BTreeMap::from([(
        id(0x42),
        BTreeMap::from([(WrapRecipient::Machine(id(0x52)), second)]),
    )]);
    let pad_cases = [
        [&empty, &empty],
        [&machine, &empty],
        [&empty, &machine],
        [&machine_and_root, &other_machine],
    ];
    let carried_cases = [None, Some([0; 32]), Some([0x5a; 32])];
    let mut seen = BTreeSet::new();
    let mut cases = 0;
    for sets in &set_cases {
        for roots in root_cases {
            for pads in pad_cases {
                for carried in carried_cases {
                    let digest = door::custody_policy_digest(sets, roots, pads, carried);
                    assert_eq!(
                        digest,
                        base_policy::main_policy_digest(sets, roots, pads, carried),
                        "sets {sets:?} roots {roots:?} carried {carried:?}"
                    );
                    seen.insert(digest);
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 336);
    assert_eq!(seen.len(), 336);
}

/// A recipient's hybrid public key from fixed seeds.
fn public_key(seed: u8) -> HybridPublicKey {
    HybridSecretKey::from_seeds(&[seed; 64], &[seed; 32])
        .public_key()
        .clone()
}

fn id(n: u8) -> EntityId {
    EntityId::from_hex(&format!("{n:02x}{}", "ab".repeat(15))).expect("a valid id")
}
