//! K-proof (oracle) for PLAN-UC-04 stage 6.3d: the runtime hook digests keep their bytes.
//!
//! The input hashes of a released tick, a settled proposal and an admitted inbound event
//! (`purposes::runtime_hooks::{TICK_INPUT, SETTLEMENT_INPUT, SURFACE_INBOUND_INPUT}`), a hook
//! run's params digest (`RUN_PARAMS`) and its run key (`RUN_KEY`) start through the
//! fingerprint crate's K door. A run key starts with its fact's input hash and keys the run's
//! memo, intent, receipt and index rows, so a run is taken once per binding and fact; a run's
//! memo stores the input hash and the params digest. So each must give main's bytes for every
//! input.
//!
//! Main's rows are private to `runtime_hooks`. The `base_*` modules hold main's lines at
//! 3db42b3bc550, copied by range (each range is named above its copy; the generator is
//! `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and differing from them only
//! in indentation. The few lines around the copies are stand-in rows by main's names with the
//! fields main hashes (main's rows also hold the time each was recorded, which it does not
//! hash), the imports main's lines name, and wrappers for main's private items. Main computes
//! a memo's selector hash inside `HookRunDerivation::new_in_snapshot`: its lines 239-243 are
//! copied, and the expression of its line 292 is written after them.
//!
//! The door builds only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_hook_digests`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::EntityId;
use oneiron::runtime_hooks::{
    ClaimChangelogPosition, FactPosition, SchedulePosition, SettledOutcome, SettlementKind,
    SettlementPosition, SurfaceInboundPosition,
};
use oneiron::skill_hub::pack_catalog::PackHookBinding;
use oneiron::test_doors::fingerprint_keep_hook_digests as door;
use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};
use serde_json::{Value, json};

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
mod base_schedule {
    use oneiron::EntityId;

    /// Main's `ReleasedTick` (`runtime_hooks::source::schedule`), with the fields it hashes.
    pub(crate) struct ReleasedTick {
        pub(crate) task: EntityId,
        pub(crate) due_at: u64,
    }

    impl ReleasedTick {
    // main 3db42b3bc550: crates/oneiron/src/runtime_hooks/source/schedule.rs:97-102
        fn input_hash(&self) -> [u8; 32] {
            let mut hasher = blake3::Hasher::new_derive_key("oneiron.hook-tick.v1");
            hasher.update(self.task.as_bytes());
            hasher.update(&self.due_at.to_be_bytes());
            *hasher.finalize().as_bytes()
        }
    }

    /// Main's tick input hash, which is private there.
    pub(crate) fn main_tick_input_hash(task: EntityId, due_at: u64) -> [u8; 32] {
        ReleasedTick { task, due_at }.input_hash()
    }
}

#[rustfmt::skip]
mod base_settlement {
    use oneiron::EntityId;
    use oneiron::runtime_hooks::{SettledOutcome, SettlementKind};

    /// Main's `SettledRow` (`runtime_hooks::source::settlement`), with the fields it hashes.
    pub(crate) struct SettledRow {
        pub(crate) proposal: EntityId,
        pub(crate) outcome: SettledOutcome,
        pub(crate) settled_by: EntityId,
        pub(crate) kind: SettlementKind,
        pub(crate) body_hash: Option<[u8; 32]>,
    }

    impl SettledRow {
    // main 3db42b3bc550: crates/oneiron/src/runtime_hooks/source/settlement.rs:57-64
        fn input_hash(&self) -> [u8; 32] {
            let mut hasher = blake3::Hasher::new_derive_key("oneiron.hook-settlement.v1");
            hasher.update(self.proposal.as_bytes());
            hasher.update(&[self.outcome as u8, self.kind as u8]);
            hasher.update(self.settled_by.as_bytes());
            hasher.update(&self.body_hash.unwrap_or_default());
            *hasher.finalize().as_bytes()
        }
    }

    /// Main's settlement input hash, which is private there.
    pub(crate) fn main_settlement_input_hash(row: &SettledRow) -> [u8; 32] {
        row.input_hash()
    }
}

#[rustfmt::skip]
mod base_surface_inbound {
    use oneiron::EntityId;

    /// Main's `SurfaceInboundRow` (`runtime_hooks::source::surface_inbound`), with the fields
    /// it hashes.
    pub(crate) struct SurfaceInboundRow {
        pub(crate) attempt: [u8; 16],
        pub(crate) connector: String,
        pub(crate) channel: String,
        pub(crate) action: String,
        pub(crate) receiving_identity: EntityId,
        pub(crate) actor: EntityId,
        pub(crate) received_at: u64,
    }

    impl SurfaceInboundRow {
    // main 3db42b3bc550: crates/oneiron/src/runtime_hooks/source/surface_inbound.rs:71-82
        fn input_hash(&self) -> [u8; 32] {
            let mut hasher = blake3::Hasher::new_derive_key("oneiron.hook-surface-inbound.v1");
            hasher.update(&self.attempt);
            hasher.update(self.receiving_identity.as_bytes());
            hasher.update(self.actor.as_bytes());
            for token in [&self.connector, &self.channel, &self.action] {
                hasher.update(&(token.len() as u64).to_be_bytes());
                hasher.update(token.as_bytes());
            }
            hasher.update(&self.received_at.to_be_bytes());
            *hasher.finalize().as_bytes()
        }
    }

    /// Main's inbound input hash, which is private there.
    pub(crate) fn main_surface_inbound_input_hash(row: &SurfaceInboundRow) -> [u8; 32] {
        row.input_hash()
    }
}

#[rustfmt::skip]
mod base_store {
    use oneiron::runtime_hooks::FactPosition;
    use oneiron::skill_hub::pack_catalog::PackHookBinding;
    use oneiron::store::receipt_row::hex_lower;
    use oneiron::{EntityId, Error, Result};
    use oneiron_records::runtime_hooks::store::RunKey;
    use serde::{Deserialize, Serialize};

    /// Main's `FactEntry` (`runtime_hooks::source`), with the fields the run key reads.
    pub(crate) struct FactEntry {
        pub(crate) input_hash: [u8; 32],
        pub(crate) position: FactPosition,
    }

    // main 3db42b3bc550: crates/oneiron/src/runtime_hooks/store.rs:75-76
    /// The derivation envelope's model id for a body that calls no model.
    const HOOK_MODEL_ID: &str = "hook-js";

    // main 3db42b3bc550: crates/oneiron/src/runtime_hooks/store.rs:78-89
    /// The ARCH-0035 derivation envelope shape, for one hook run. Copied rather
    /// than shared, as `SavedQueryDerivationEnvelope` is.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct HookDerivationEnvelope {
        /// Hex of the fact's input hash.
        content_hash: String,
        model_id: String,
        /// The hook version and its body hash.
        version: String,
        /// Hex BLAKE3 of the selector JSON and the binding id.
        params_hash: String,
    }

    // main 3db42b3bc550: crates/oneiron/src/runtime_hooks/store.rs:91-115
    /// The run key for `binding` on `fact`.
    pub(super) fn run_key(
        binding_id: EntityId,
        binding: &PackHookBinding,
        fact: &FactEntry,
    ) -> Result<RunKey> {
        let selector = serde_json::to_vec(&binding.selector)
            .map_err(|_| Error::InvariantViolation("hook selector encode"))?;
        let mut params = blake3::Hasher::new();
        params.update(&selector);
        params.update(binding_id.as_bytes());
        let envelope = HookDerivationEnvelope {
            content_hash: hex_lower(&fact.input_hash),
            model_id: HOOK_MODEL_ID.to_owned(),
            version: format!("{}+{}", binding.hook_version, binding.body_hash),
            params_hash: params.finalize().to_hex().to_string(),
        };
        let envelope = serde_json::to_vec(&envelope)
            .map_err(|_| Error::InvariantViolation("hook envelope encode"))?;
        let mut key = blake3::Hasher::new_derive_key("oneiron.hook-run-key.v1");
        key.update(&envelope);
        key.update(&[fact.position.source().tag()]);
        key.update(&fact.position.bytes());
        Ok(*key.finalize().as_bytes())
    }

    /// Main's memo selector hash (`HookRunDerivation::new_in_snapshot`).
    pub(crate) fn main_selector_hash(binding_id: EntityId, binding: &PackHookBinding) -> Result<String> {
    // main 3db42b3bc550: crates/oneiron/src/runtime_hooks/store.rs:239-243
            let selector = serde_json::to_vec(&binding.selector)
                .map_err(|_| Error::InvariantViolation("hook selector encode"))?;
            let mut params = blake3::Hasher::new();
            params.update(&selector);
            params.update(binding_id.as_bytes());
        // The expression of main's line 292 (`selector_hash: ...`).
        Ok(params.finalize().to_hex().to_string())
    }
}

fn id(n: u8) -> EntityId {
    EntityId::from_hex(&format!("{n:02x}{}", "ab".repeat(15))).expect("a valid id")
}

fn small(n: usize) -> u8 {
    u8::try_from(n).expect("a small index")
}

fn ids() -> Vec<EntityId> {
    [0x00, 0x01, 0x10, 0x7f, 0x80, 0xab, 0xfe, 0xff]
        .into_iter()
        .map(id)
        .collect()
}

fn bytes<const N: usize>(seed: u8) -> [u8; N] {
    std::array::from_fn(|i| seed.wrapping_mul(31).wrapping_add(small(i)))
}

/// Selectors of each phase, with and without a scope, actors, served surfaces and the
/// generative render class.
fn selectors() -> Vec<Value> {
    vec![
        json!({"verbs": ["proposal.settled:*"], "actors": [], "scope": null, "phase": "fact",
               "priority": 0, "budget_ms": 50, "blocking": false, "outcomes": ["propose"]}),
        json!({"verbs": ["schedule.tick"], "actors": ["human", "agent"], "scope": "vault",
               "phase": "fact", "priority": -3, "budget_ms": 1000, "blocking": true,
               "outcomes": ["continue", "annotate"], "served": ["telegram"],
               "render_class": "generative"}),
        json!({"verbs": ["surface.inbound:slack*", "tasks.post"], "actors": ["system"],
               "scope": null, "phase": "pre", "priority": 7, "budget_ms": 0, "blocking": false,
               "outcomes": [], "served": [], "render_class": "deterministic_eager"}),
        json!({"verbs": [], "actors": [], "scope": "pack:\u{fc}/\u{df}", "phase": "post",
               "priority": i32::MAX, "budget_ms": u32::MAX, "blocking": true,
               "outcomes": ["nothing", "effect", "redact"]}),
    ]
}

fn binding(selector: &Value, n: u8) -> PackHookBinding {
    serde_json::from_value(json!({
        "version": 1,
        "code": id(n).to_hex(),
        "owner": id(n.wrapping_add(1)).to_hex(),
        "source": id(n.wrapping_add(2)).to_hex(),
        "pack": format!("pack-{n}"),
        "hook": "on-settle",
        "hook_version": format!("{n}.0.{}", n % 3),
        "body_hash": oneiron_hex::encode(bytes::<32>(n)),
        "selector": selector,
        "enabled": n % 2 == 0,
        "author": {"kind": "owner"},
    }))
    .expect("a valid binding")
}

#[test]
fn the_hook_purposes_keep_main_s_recipes() {
    for (purpose, context) in [
        (purposes::runtime_hooks::TICK_INPUT, "oneiron.hook-tick.v1"),
        (
            purposes::runtime_hooks::SETTLEMENT_INPUT,
            "oneiron.hook-settlement.v1",
        ),
        (
            purposes::runtime_hooks::SURFACE_INBOUND_INPUT,
            "oneiron.hook-surface-inbound.v1",
        ),
        (purposes::runtime_hooks::RUN_KEY, "oneiron.hook-run-key.v1"),
    ] {
        assert_eq!(purpose.tag(), context);
        assert_eq!(purpose.hash(), LegacyHash::Blake3);
        assert_eq!(purpose.tag_mode(), TagMode::DeriveKeyContext);
    }
    let params = purposes::runtime_hooks::RUN_PARAMS;
    assert_eq!(params.hash(), LegacyHash::Blake3);
    assert_eq!(params.tag_mode(), TagMode::NotHashed);
}

#[test]
fn the_tick_input_hash_keeps_its_bytes() {
    let due_times = [
        0,
        1,
        59,
        1_700_000_000,
        1_893_456_000,
        u64::from(u32::MAX),
        u64::MAX - 1,
        u64::MAX,
    ];
    let mut seen = BTreeSet::new();
    for task in ids() {
        for due_at in due_times {
            let hash = door::tick_input_hash(task, due_at);
            assert_eq!(hash, base_schedule::main_tick_input_hash(task, due_at));
            seen.insert(hash);
        }
    }
    assert_eq!(seen.len(), 64);
}

#[test]
fn the_settlement_input_hash_keeps_its_bytes() {
    let outcomes = [
        SettledOutcome::Approved,
        SettledOutcome::Declined,
        SettledOutcome::Retracted,
        SettledOutcome::Demoted,
    ];
    let kinds = [
        SettlementKind::GateConsentBundle,
        SettlementKind::CriticalWriteConfirm,
        SettlementKind::ClaimSettlement,
    ];
    // No body hashes as zeros, as on main.
    let bodies = [None, Some([0; 32]), Some([0xff; 32]), Some(bytes::<32>(5))];
    let pairs = [
        (id(0x01), id(0x02)),
        (id(0x02), id(0x01)),
        (id(0xff), id(0xff)),
    ];
    let mut cases = 0;
    for (proposal, settled_by) in pairs {
        for outcome in outcomes {
            for kind in kinds {
                for body_hash in bodies {
                    let row = base_settlement::SettledRow {
                        proposal,
                        outcome,
                        settled_by,
                        kind,
                        body_hash,
                    };
                    assert_eq!(
                        door::settlement_input_hash(proposal, outcome, settled_by, kind, body_hash),
                        base_settlement::main_settlement_input_hash(&row),
                    );
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 144);
}

#[test]
fn the_surface_inbound_input_hash_keeps_its_bytes() {
    let attempts = [[0; 16], [0xff; 16], bytes::<16>(9)];
    let long = "a".repeat(300);
    let tokens: [[&str; 3]; 5] = [
        ["", "", ""],
        ["slack", "C024BE91L", "message"],
        ["telegram", "-1001234567890", "reaction"],
        ["ab", "c", ""],
        ["a", "bc", long.as_str()],
    ];
    let times = [0, 1_700_000_000, u64::MAX];
    let identities = [(id(0x10), id(0x7f)), (id(0x7f), id(0x10))];
    let mut seen = BTreeSet::new();
    for attempt in attempts {
        for [connector, channel, action] in tokens {
            for (receiving_identity, actor) in identities {
                for received_at in times {
                    let row = base_surface_inbound::SurfaceInboundRow {
                        attempt,
                        connector: connector.to_owned(),
                        channel: channel.to_owned(),
                        action: action.to_owned(),
                        receiving_identity,
                        actor,
                        received_at,
                    };
                    let hash = door::surface_inbound_input_hash(
                        attempt,
                        [connector, channel, action],
                        receiving_identity,
                        actor,
                        received_at,
                    );
                    assert_eq!(
                        hash,
                        base_surface_inbound::main_surface_inbound_input_hash(&row)
                    );
                    seen.insert(hash);
                }
            }
        }
    }
    assert_eq!(seen.len(), 90);
}

#[test]
fn the_run_params_digest_keeps_its_bytes() {
    let mut seen = BTreeSet::new();
    for selector in selectors() {
        for n in [0x00, 0x2a] {
            let binding = binding(&selector, n);
            for binding_id in [id(0x00), id(0x80), id(0xff)] {
                let digest = door::selector_params_hash(binding_id, &binding).expect("a digest");
                assert_eq!(
                    digest,
                    base_store::main_selector_hash(binding_id, &binding).expect("main's digest")
                );
                assert_eq!(digest.len(), 64);
                seen.insert(digest);
            }
        }
    }
    // The selector and the binding id are hashed; the binding's other fields are not.
    assert_eq!(seen.len(), 12);
}

#[test]
fn the_run_key_keeps_its_bytes() {
    let positions = [
        FactPosition::ClaimChangelog(ClaimChangelogPosition([0; 16])),
        FactPosition::ClaimChangelog(ClaimChangelogPosition(bytes::<16>(3))),
        FactPosition::Settlement(SettlementPosition(0)),
        FactPosition::Settlement(SettlementPosition(u64::MAX)),
        FactPosition::Schedule(SchedulePosition(0)),
        FactPosition::Schedule(SchedulePosition(1 << 40)),
        FactPosition::SurfaceInbound(SurfaceInboundPosition(0)),
        FactPosition::SurfaceInbound(SurfaceInboundPosition(u64::MAX)),
    ];
    let input_hashes = [[0; 32], [0xff; 32], bytes::<32>(7)];
    let mut seen = BTreeSet::new();
    for selector in selectors() {
        for n in [0x00, 0x2a] {
            let binding = binding(&selector, n);
            let binding_id = id(n);
            for input_hash in input_hashes {
                for position in positions {
                    let key = door::run_key(binding_id, &binding, input_hash, position)
                        .expect("a run key");
                    let fact = base_store::FactEntry {
                        input_hash,
                        position,
                    };
                    assert_eq!(
                        key,
                        base_store::run_key(binding_id, &binding, &fact).expect("main's run key")
                    );
                    seen.insert(key);
                }
            }
        }
    }
    assert_eq!(seen.len(), 192);
}
