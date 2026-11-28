//! Row RSI-ARM-RESULT, stored bytes (Engine ACCEPT 28 Nov 11:49, condition 1; ANSWER
//! RSI-FIXTURE-BYTES = B, 12:03). A unit claim gains an optional result binding, and
//! `EXPERIMENT_ARM_UNIT` rows are named msgpack: `rmp_serde::to_vec_named` on write, the side
//! table's strict whole-row decode on read (`Named`). The frozen copies below are the fixture:
//! main a17a3d80's `UnitClaim` and `UnitAsk`, with its fields in its order and its serde
//! attributes (none on the fields). With fixed field values, a claim with no result encodes to
//! the frozen claim's bytes, the frozen claim's bytes decode with no result, and an ask with no
//! result frames the frozen ask's digest, so a later edit that changes either encoding fails
//! here.
#![cfg(oneiron_test_support)]

use oneiron::EntityId;
use oneiron::experiment_arm::{ARMS_UNITS_RESERVE_VERB, UnitReserveRequest};
use oneiron::federation::WalletRef;
use oneiron::gpu_job::GpuJobResultBinding;
use oneiron::gpu_line::{ClaimState, Draw, DrawSource, IntentAsk, UnitClaim, UnitPurpose};
use oneiron::llm::run_admission::AllocationRef;
use oneiron::test_doors::experiment_arm_rows::unit_ask_digest;
use oneiron::work_order::WaitRule;
use oneiron_store::side_table::codec::strict_msgpack;
use serde::{Deserialize, Serialize};

/// Main a17a3d80's `UnitClaim` (crates/oneiron/src/gpu_line/claim/mod.rs), field for field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UnitClaimOnMain {
    id: EntityId,
    arm: EntityId,
    rung: u8,
    unit_key: String,
    attempt: u16,
    line: EntityId,
    family: EntityId,
    period: u32,
    purpose: UnitPurpose,
    workload: String,
    machine: Option<EntityId>,
    code_sha: String,
    contract_sha256: String,
    reserved_secs: u64,
    draws: Vec<Draw>,
    wallet: WalletRef,
    allocation: AllocationRef,
    grant: Option<EntityId>,
    reserved_by: Option<EntityId>,
    reserved_at_ms: u64,
    ask_digest: String,
    state: ClaimState,
    revision: u64,
}

/// Main a17a3d80's `UnitAsk` (crates/oneiron/src/experiment_arm/reserve.rs), field for field: the
/// reserve's ask without its intent key and its wait.
#[derive(Serialize)]
struct UnitAskOnMain<'a> {
    line: EntityId,
    arm: EntityId,
    rung: u8,
    unit_key: &'a str,
    attempt: u16,
    purpose: UnitPurpose,
    offer: &'a str,
    workload: &'a str,
    machine: Option<EntityId>,
    code_sha: &'a str,
    contract_sha256: &'a str,
    secs: u64,
}

fn id(n: u8) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x02;
    bytes[15] = n;
    EntityId::from_bytes_unchecked(bytes)
}

/// One claim with fixed values throughout.
fn claim(result: Option<GpuJobResultBinding>) -> UnitClaim {
    UnitClaim {
        id: id(1),
        arm: id(2),
        rung: 1,
        unit_key: "inkling-check/shard-0".to_owned(),
        attempt: 1,
        line: id(3),
        family: id(4),
        period: 7,
        purpose: UnitPurpose::Work,
        workload: "ab".repeat(32),
        machine: Some(id(7)),
        code_sha: "c0de".repeat(10),
        contract_sha256: "cd".repeat(32),
        result,
        reserved_secs: 1_800,
        draws: vec![
            Draw {
                source: DrawSource::FirstAllowance,
                units: 1_000,
            },
            Draw {
                source: DrawSource::Floor,
                units: 800,
            },
        ],
        wallet: WalletRef {
            issuer: "home".to_owned(),
            id: "gpu".to_owned(),
        },
        allocation: AllocationRef {
            id: "gpu-line-7".to_owned(),
            generation: 7,
        },
        grant: Some(id(5)),
        reserved_by: Some(id(6)),
        reserved_at_ms: 1_764_000_000_000,
        ask_digest: "ad".repeat(32),
        state: ClaimState::Claimed,
        revision: 1,
    }
}

/// `claim` as main's type holds it.
fn on_main(claim: &UnitClaim) -> UnitClaimOnMain {
    UnitClaimOnMain {
        id: claim.id,
        arm: claim.arm,
        rung: claim.rung,
        unit_key: claim.unit_key.clone(),
        attempt: claim.attempt,
        line: claim.line,
        family: claim.family,
        period: claim.period,
        purpose: claim.purpose,
        workload: claim.workload.clone(),
        machine: claim.machine,
        code_sha: claim.code_sha.clone(),
        contract_sha256: claim.contract_sha256.clone(),
        reserved_secs: claim.reserved_secs,
        draws: claim.draws.clone(),
        wallet: claim.wallet.clone(),
        allocation: claim.allocation.clone(),
        grant: claim.grant,
        reserved_by: claim.reserved_by,
        reserved_at_ms: claim.reserved_at_ms,
        ask_digest: claim.ask_digest.clone(),
        state: claim.state.clone(),
        revision: claim.revision,
    }
}

/// The fixed ask `UnitAskOnMain` frames, with the claim's terms.
fn ask_on_main() -> UnitAskOnMain<'static> {
    UnitAskOnMain {
        line: id(3),
        arm: id(2),
        rung: 1,
        unit_key: "inkling-check/shard-0",
        attempt: 1,
        purpose: UnitPurpose::Work,
        offer: "fixture-gpu",
        workload: "abababababababababababababababababababababababababababababababab",
        machine: Some(id(7)),
        code_sha: "c0dec0dec0dec0dec0dec0dec0dec0dec0dec0de",
        contract_sha256: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        secs: 1_800,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn named(value: &impl Serialize) -> Vec<u8> {
    rmp_serde::to_vec_named(value).expect("the row encodes")
}

/// (a) A claim with no result encodes to the bytes main's type encodes for the same claim.
#[test]
fn a_claim_with_no_result_encodes_as_main_encodes_it() {
    let claim = claim(None);
    assert_eq!(hex(&named(&claim)), hex(&named(&on_main(&claim))));
}

/// (b) Main's bytes, with no `result` key, decode through the side table's strict whole-row
/// decode into the new type with no result.
#[test]
fn main_claim_bytes_decode_with_no_result() {
    let claim = claim(None);
    let main_bytes = named(&on_main(&claim));
    let decoded: UnitClaim = strict_msgpack(&main_bytes).expect("main's row decodes");
    assert_eq!(decoded.result, None);
    assert_eq!(decoded, claim);
}

/// A claim with a result writes it under its own key and reads it back; main's type, which
/// ignores the key, reads every other field of it.
#[test]
fn a_claim_with_a_result_keeps_it() {
    let bound = claim(Some(GpuJobResultBinding {
        artifact: id(8),
        task: id(9),
    }));
    let bytes = named(&bound);
    assert_ne!(hex(&bytes), hex(&named(&claim(None))));
    let decoded: UnitClaim = strict_msgpack(&bytes).expect("the bound row decodes");
    assert_eq!(decoded, bound);
    let on_main_type: UnitClaimOnMain =
        strict_msgpack(&bytes).expect("main's type reads the bound row");
    assert_eq!(on_main_type, on_main(&bound));
}

/// The reserve's ask with the claim's terms, `result` and `wait` as given.
fn request(result: Option<GpuJobResultBinding>, wait: WaitRule) -> UnitReserveRequest {
    UnitReserveRequest {
        intent_key: "fixture-intent".to_owned(),
        line: id(3),
        arm: id(2),
        rung: 1,
        unit_key: "inkling-check/shard-0".to_owned(),
        attempt: 1,
        purpose: UnitPurpose::Work,
        offer: "fixture-gpu".to_owned(),
        workload: "ab".repeat(32),
        machine: Some(id(7)),
        code_sha: "c0de".repeat(10),
        contract_sha256: "cd".repeat(32),
        secs: 1_800,
        result,
        wait,
    }
}

/// An ask with no result frames the frozen ask's digest, whatever its wait; a result is part of
/// the ask, so a bound ask frames another.
#[test]
fn an_ask_with_no_result_frames_main_s_digest() {
    let asker = id(6);
    let main = IntentAsk::new(
        asker,
        ARMS_UNITS_RESERVE_VERB,
        "fixture-intent",
        &ask_on_main(),
    )
    .expect("frame the frozen ask");
    for wait in [WaitRule::No, WaitRule::Open] {
        assert_eq!(
            unit_ask_digest(asker, &request(None, wait)).expect("frame the ask"),
            main.ask_digest()
        );
    }
    let bound = request(
        Some(GpuJobResultBinding {
            artifact: id(8),
            task: id(9),
        }),
        WaitRule::No,
    );
    assert_ne!(
        unit_ask_digest(asker, &bound).expect("frame the bound ask"),
        main.ask_digest()
    );
}
