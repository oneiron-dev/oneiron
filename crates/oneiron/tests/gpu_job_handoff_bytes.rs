//! Row RSI-ARTIFACT-HANDOFF, stored bytes (Engine ACCEPT 28 Nov 12:58, condition 3; the pattern
//! of ANSWER RSI-FIXTURE-BYTES = B, 12:03). Three stored types gain an optional field, each left
//! out of the encoding when `None`:
//! - `JobReturn.handoff` (`JOB_RETURN`, named msgpack: `rmp_serde::to_vec_named` on write, the
//!   side table's strict whole-row decode on read);
//! - `GpuJobResultBinding.manifest`, inside a unit claim's named msgpack row and inside a
//!   chunk's quote inputs (JSON);
//! - the work order's `ResultBinding.manifest` (`WORK_ORDERS`, named msgpack; the type denies
//!   unknown fields).
//!
//! The frozen copies below are the fixture: main 6806854e's types, with its fields in its order
//! and its serde attributes. With fixed field values, a row with no new field encodes to the
//! frozen row's bytes, and the frozen row's bytes decode with `None`, so a later edit that
//! changes either encoding fails here.
#![cfg(oneiron_test_support)]

use oneiron::EntityId;
use oneiron::gpu_job::GpuJobResultBinding;
use oneiron::job_dispatch::machine_records::{HandoffReturn, JobReturn, ReturnRefusal};
use oneiron::work_order::ResultBinding;
use oneiron_store::side_table::codec::strict_msgpack;
use serde::{Deserialize, Serialize};

/// Main 6806854e's `JobReturn` (crates/oneiron/src/job_dispatch/machine_records/job_return.rs),
/// field for field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JobReturnOnMain {
    key: String,
    machine: EntityId,
    job: EntityId,
    #[serde(default)]
    landed: Vec<String>,
    #[serde(default)]
    refused: Vec<ReturnRefusal>,
    #[serde(default)]
    acknowledged_at_ms: Option<u64>,
    opened_at_ms: u64,
    updated_at_ms: u64,
}

/// Main 6806854e's `GpuJobResultBinding` (crates/oneiron/src/gpu_job/result_landing.rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct GpuJobResultBindingOnMain {
    artifact: EntityId,
    task: EntityId,
}

/// Main 6806854e's work order `ResultBinding` (crates/oneiron/src/work_order/record.rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultBindingOnMain {
    artifact: EntityId,
    task: EntityId,
}

fn id(n: u8) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x02;
    bytes[15] = n;
    EntityId::from_bytes_unchecked(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn named(value: &impl Serialize) -> Vec<u8> {
    rmp_serde::to_vec_named(value).expect("the row encodes")
}

/// One acknowledged return with fixed values throughout.
fn job_return(handoff: Option<HandoffReturn>) -> JobReturn {
    JobReturn {
        key: "gpu-chunk-key-0".to_owned(),
        machine: id(1),
        job: id(2),
        landed: vec!["verdict.json".to_owned()],
        refused: vec![ReturnRefusal {
            name: "notes.txt".to_owned(),
            why: "digest_mismatch".to_owned(),
        }],
        acknowledged_at_ms: Some(1_764_000_030_000),
        handoff,
        opened_at_ms: 1_764_000_000_000,
        updated_at_ms: 1_764_000_030_000,
    }
}

/// `row` as main's type holds it.
fn return_on_main(row: &JobReturn) -> JobReturnOnMain {
    JobReturnOnMain {
        key: row.key.clone(),
        machine: row.machine,
        job: row.job,
        landed: row.landed.clone(),
        refused: row.refused.clone(),
        acknowledged_at_ms: row.acknowledged_at_ms,
        opened_at_ms: row.opened_at_ms,
        updated_at_ms: row.updated_at_ms,
    }
}

fn binding(manifest: Option<EntityId>) -> GpuJobResultBinding {
    GpuJobResultBinding {
        artifact: id(8),
        task: id(9),
        manifest,
    }
}

fn binding_on_main() -> GpuJobResultBindingOnMain {
    GpuJobResultBindingOnMain {
        artifact: id(8),
        task: id(9),
    }
}

/// (a) A return with no handoff encodes to the bytes main's type encodes for the same row.
#[test]
fn a_return_with_no_handoff_encodes_as_main_encodes_it() {
    let row = job_return(None);
    assert_eq!(hex(&named(&row)), hex(&named(&return_on_main(&row))));
}

/// (b) Main's bytes, with no `handoff` key, decode through the strict whole-row decode into the
/// new type with no handoff.
#[test]
fn main_return_bytes_decode_with_no_handoff() {
    let row = job_return(None);
    let decoded: JobReturn =
        strict_msgpack(&named(&return_on_main(&row))).expect("main's row decodes");
    assert_eq!(decoded.handoff, None);
    assert_eq!(decoded, row);
}

/// A return with a handoff writes it under its own key and reads it back, each state; main's
/// type, which ignores the key, reads every other field of it.
#[test]
fn a_return_with_a_handoff_keeps_it() {
    for handoff in [
        HandoffReturn::Owed,
        HandoffReturn::Landed,
        HandoffReturn::Refused {
            why: "job_revoked".to_owned(),
        },
    ] {
        let row = job_return(Some(handoff));
        let bytes = named(&row);
        assert_ne!(hex(&bytes), hex(&named(&job_return(None))));
        let decoded: JobReturn = strict_msgpack(&bytes).expect("the row decodes");
        assert_eq!(decoded, row);
        let on_main_type: JobReturnOnMain =
            strict_msgpack(&bytes).expect("main's type reads the row");
        assert_eq!(on_main_type, return_on_main(&row));
    }
}

/// A result binding with no manifest encodes as main's, as named msgpack (a unit claim's
/// `result`) and as JSON (a chunk's `inputs.result`), and main's encodings decode with no
/// manifest.
#[test]
fn a_binding_with_no_manifest_encodes_as_main_encodes_it() {
    let new = binding(None);
    let main = binding_on_main();
    assert_eq!(hex(&named(&new)), hex(&named(&main)));
    assert_eq!(
        serde_json::to_string(&new).expect("the binding as JSON"),
        serde_json::to_string(&main).expect("main's binding as JSON"),
    );
    let decoded: GpuJobResultBinding =
        strict_msgpack(&named(&main)).expect("main's binding decodes");
    assert_eq!(decoded, new);
    let decoded: GpuJobResultBinding =
        serde_json::from_value(serde_json::to_value(main).expect("main's binding as JSON"))
            .expect("main's JSON binding decodes");
    assert_eq!(decoded, new);
}

/// A binding with a manifest writes it under its own key; main's type reads the rest.
#[test]
fn a_binding_with_a_manifest_keeps_it() {
    let bound = binding(Some(id(10)));
    let bytes = named(&bound);
    assert_ne!(hex(&bytes), hex(&named(&binding(None))));
    let decoded: GpuJobResultBinding = strict_msgpack(&bytes).expect("the binding decodes");
    assert_eq!(decoded, bound);
    let on_main_type: GpuJobResultBindingOnMain =
        strict_msgpack(&bytes).expect("main's type reads the binding");
    assert_eq!(on_main_type, binding_on_main());
    let json = serde_json::to_value(bound).expect("the binding as JSON");
    assert!(json.get("manifest").is_some(), "{json}");
    let decoded: GpuJobResultBinding =
        serde_json::from_value(json).expect("the JSON binding decodes");
    assert_eq!(decoded, bound);
}

/// The work order's binding with no manifest encodes as main's, and main's bytes decode with no
/// manifest; one with a manifest keeps it.
#[test]
fn an_order_binding_with_no_manifest_encodes_as_main_encodes_it() {
    let new = ResultBinding {
        artifact: id(8),
        task: id(9),
        manifest: None,
    };
    let main = ResultBindingOnMain {
        artifact: id(8),
        task: id(9),
    };
    assert_eq!(hex(&named(&new)), hex(&named(&main)));
    let decoded: ResultBinding = strict_msgpack(&named(&main)).expect("main's binding decodes");
    assert_eq!(decoded, new);
    let bound = ResultBinding {
        manifest: Some(id(10)),
        ..new
    };
    let decoded: ResultBinding = strict_msgpack(&named(&bound)).expect("the binding decodes");
    assert_eq!(decoded, bound);
}
