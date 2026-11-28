//! Row RSI-ARM-RESULT, stored bytes (Engine ACCEPT 28 Nov 11:49, condition 1). A unit claim gains
//! an optional result binding, and `EXPERIMENT_ARM_UNIT` rows are named msgpack
//! (`rmp_serde::to_vec_named`, the side table's `Named` codec). A claim with no result encodes
//! to the bytes main encodes for the same claim, and main's bytes, which carry no `result` key,
//! decode with no result. `UnitClaimOnMain` is main's `UnitClaim` (a17a3d80): its fields, in its
//! order, with its serde attributes (none on the fields). The ask digest's half against a live
//! reserve is in tests/experiment_arm_reserve.rs
//! (`a_unit_without_a_result_keeps_its_ask_digest_and_a_result_is_part_of_the_ask`).
use oneiron::EntityId;
use oneiron::federation::WalletRef;
use oneiron::gpu_job::GpuJobResultBinding;
use oneiron::gpu_line::{ClaimState, Draw, DrawSource, IntentAsk, UnitClaim, UnitPurpose};
use oneiron::llm::run_admission::AllocationRef;
use serde::{Deserialize, Serialize};

/// Main's `UnitClaim`, field for field.
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

/// Main's reserve ask (`UnitAsk` before results), as its intent digest frames it.
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

/// (b) Main's bytes, with no `result` key, decode under the new type with no result.
#[test]
fn main_claim_bytes_decode_with_no_result() {
    let claim = claim(None);
    let main_bytes = named(&on_main(&claim));
    let decoded: UnitClaim = rmp_serde::from_slice(&main_bytes).expect("main's row decodes");
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
    let decoded: UnitClaim = rmp_serde::from_slice(&bytes).expect("the bound row decodes");
    assert_eq!(decoded, bound);
    let on_main_type: UnitClaimOnMain =
        rmp_serde::from_slice(&bytes).expect("main's type reads the bound row");
    assert_eq!(on_main_type, on_main(&bound));
}

/// Prints the fixed fixtures: the bytes of `claim(None)` and the digest of `ask_on_main()`.
#[test]
#[ignore = "prints the fixed fixtures; run with --ignored --nocapture"]
fn print_the_fixed_fixtures() {
    println!("CLAIM_ON_MAIN_HEX={}", hex(&named(&on_main(&claim(None)))));
    let ask = IntentAsk::new(
        id(6),
        "vault.arms.units.reserve",
        "fixture-intent",
        &ask_on_main(),
    )
    .expect("frame the ask");
    println!("ASK_ON_MAIN_DIGEST={}", ask.ask_digest());
}
