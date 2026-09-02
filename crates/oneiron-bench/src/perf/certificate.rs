//! ONE-1961 run certificate: the block an external verifier reads first.
//!
//! The certificate is the part of the report that is ABOUT the report. It says
//! which axes can withhold candidacy and which are advisory, where every
//! publication input came from, which artifact was spawned as the ready child,
//! how many trials each axis actually got, and — through three hashes — exactly
//! which bytes all of that was computed over.
//!
//! ## Hashes, and why RFC 8785
//!
//! ```text
//! axes_blake3        = blake3(JCS({ the eight axis objects }))
//! provenance_blake3  = blake3(JCS(provenance))
//! certificate_blake3 = blake3(JCS(certificate MINUS certificate_blake3))
//! ```
//!
//! These have to be reproducible by a Python verifier reading the emitted JSON,
//! and hashing the raw emitted bytes cannot do that: serde_json formats floats
//! with `ryu` while Python's `repr` disagrees on cases like `1e300` vs `1e+300`,
//! and key order is a property of whoever built the document. RFC 8785 (JCS)
//! removes both degrees of freedom — sorted keys, no whitespace, ES6 number
//! formatting — so `serde_json_canonicalizer` here and `rfc8785` there produce
//! the SAME bytes. The hash is then blake3 over those bytes.
//!
//! ## Fail-closed sealing
//!
//! Sealing refuses rather than emits a report whose hashes could not mean what
//! they say:
//!
//! * a non-finite float has no JSON representation, so the canonicalizer errors
//!   and the run refuses to emit — the same posture as the emit path's missing
//!   axis check;
//! * an integer beyond 2^53 cannot survive the ES6 number formatting JCS
//!   mandates, so it would hash differently on the two sides of the contract.
//!   It is refused here rather than producing a hash the verifier disagrees
//!   with;
//! * the [`trust`] tables must satisfy the ONE-1961 rule, and the axis scope
//!   partition must be exact. A certificate is a claim about how the verdict
//!   was reached; it may not be sealed over a broken claim.

use std::collections::BTreeMap;

use serde::Serialize;

use super::axes::{GatedWriteAxis, RecallLatencyAxis, ResidentMemoryAxis, SessionsAxis, WakeAxis};
use super::cache_events::CacheAxis;
use super::cells::Cell;
use super::nvme::NvmeFsyncAxis;
use super::precision::PrecisionAxis;
use super::provenance::Provenance;
use super::trust::{self, TrustInput};

/// The contract id an `oneiron-eval perf-verify` run validates before it reads
/// anything else, mirroring the BEAM `EVAL_CONTRACT_VERSION` idiom.
pub(crate) const PERF_CANDIDATE_CONTRACT_VERSION: &str = "oneiron-eval.perf_candidate.v1";

/// Axes whose failure withholds candidacy.
pub(crate) const BLOCKING_AXES: [&str; 7] = [
    "recall_latency",
    "wake",
    "sessions",
    "resident_memory",
    "gated_writes",
    "precision",
    "nvme_fsync",
];

/// Axes that are reported but cannot withhold candidacy. Exactly the axes whose
/// evidence is operator-declared (ONE-1961).
pub(crate) const ADVISORY_AXES: [&str; 1] = ["cache"];

/// Axes whose reported number comes from ONE trial in this run: they are
/// measured once, with no repeat loop and no variance estimate.
///
/// ONE-1579 round 7 EXPOSES this; it does not fix it. The external verifier
/// copies the list verbatim into its verdict caveats, and per-axis statistical
/// floors are eval-owned so they can move without an engine release.
pub(crate) const SINGLE_TRIAL_AXES: [&str; 4] =
    ["wake", "resident_memory", "precision", "recall_latency"];

/// How many times each axis was repeated. One, everywhere, today.
pub(crate) const REPEATS_PER_AXIS: usize = 1;

/// The largest integer that survives the ES6 number formatting RFC 8785
/// mandates. Beyond it, two conforming canonicalizers can disagree.
const MAX_EXACT_JSON_INTEGER: u64 = 1_u64 << 53;

const SCOPE_RULE: &str = "every emitted axis is either blocking or advisory and never both: a blocking axis can \
     withhold publication candidacy, an advisory axis is reported and carried forward as a caveat. \
     The partition is exact — an axis missing from both lists would be an axis nobody decided \
     about";

const HASH_RULE: &str = "axes_blake3 = blake3(RFC8785-JCS of the eight axis objects); provenance_blake3 = \
     blake3(RFC8785-JCS of provenance); certificate_blake3 = blake3(RFC8785-JCS of this \
     certificate with certificate_blake3 removed). JCS rather than the emitted bytes, so a Python \
     verifier using rfc8785 recomputes the same digests: raw-byte hashing would diverge on float \
     formatting and key order";

const STATISTICS_RULE: &str = "per_axis.samples is the COMPLETED count from provenance.sample_counts that defines the \
     axis population (recall_latency reports its COLD population; the warm population is \
     `warm_queries` in sample_counts). repeats is 1 for every axis: this harness runs each axis \
     exactly once and has no repeat loop, so no variance or confidence interval is reported. \
     single_trial_axes names the axes whose headline number rests on that single trial";

/// One row of the trust manifest: an input, its class, its origin, and which
/// checks rest on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct TrustInputRow {
    pub(crate) name: &'static str,
    pub(crate) class: TrustInput,
    pub(crate) source: &'static str,
    pub(crate) consumed_by: Vec<&'static str>,
}

/// The exactly-one partition of the emitted axes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PublicationScope {
    pub(crate) blocking_axes: [&'static str; 7],
    pub(crate) advisory_axes: [&'static str; 1],
    pub(crate) rule: &'static str,
}

/// Trials and sample sizes for one axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct AxisStatistics {
    pub(crate) samples: usize,
    pub(crate) repeats: usize,
}

/// The statistical exposure block (ONE-1579 §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RunStatistics {
    pub(crate) per_axis: BTreeMap<&'static str, AxisStatistics>,
    pub(crate) single_trial_axes: [&'static str; 4],
    pub(crate) repeats: usize,
    pub(crate) rule: &'static str,
}

/// Everything the certificate asserts, EXCEPT its own digest.
///
/// Split out so `certificate_blake3` can be computed over exactly these fields
/// without deleting a key from a serialized copy: the payload the hash covers
/// is a type, not a convention.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct CertificateBody {
    pub(crate) contract_version: &'static str,
    pub(crate) publication_scope: PublicationScope,
    pub(crate) trust_rule: &'static str,
    pub(crate) trust_inputs: Vec<TrustInputRow>,
    /// BLAKE3 of the program the harness resolved as its ready child, hashed
    /// BEFORE the first spawn. `not_ready` with a reason when no child program
    /// could be resolved at all.
    pub(crate) child_program_blake3: Cell<String>,
    pub(crate) statistics: RunStatistics,
    pub(crate) axes_blake3: String,
    pub(crate) provenance_blake3: String,
    pub(crate) hash_rule: &'static str,
}

/// The sealed certificate: a body plus the digest over that body.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct RunCertificate {
    #[serde(flatten)]
    pub(crate) body: CertificateBody,
    pub(crate) certificate_blake3: String,
}

/// The eight axis objects as one hashable document. The key set is asserted
/// against `report::AXES` by a unit test, so this cannot drift from the report.
#[derive(Debug, Serialize)]
pub(crate) struct AxesView<'a> {
    pub(crate) recall_latency: &'a RecallLatencyAxis,
    pub(crate) wake: &'a WakeAxis,
    pub(crate) sessions: &'a SessionsAxis,
    pub(crate) resident_memory: &'a ResidentMemoryAxis,
    pub(crate) gated_writes: &'a GatedWriteAxis,
    pub(crate) precision: &'a PrecisionAxis,
    pub(crate) cache: &'a CacheAxis,
    pub(crate) nvme_fsync: &'a NvmeFsyncAxis,
}

/// What sealing needs. Everything is already measured; nothing here re-runs.
pub(crate) struct CertificateInputs<'a> {
    pub(crate) axes: AxesView<'a>,
    pub(crate) provenance: &'a Provenance,
    pub(crate) child_program_blake3: Cell<String>,
}

/// Which `sample_counts` key defines each axis's reported population.
///
/// Public inside the crate because it is a contract between the runner (which
/// tallies the counts) and this module (which exposes them): the runner's own
/// regression asserts it produces every key named here.
pub(crate) const AXIS_SAMPLE_SOURCES: [(&str, &str); 8] = [
    ("recall_latency", "cold_queries"),
    ("wake", "wake_probes"),
    ("sessions", "session_curve_points"),
    ("resident_memory", "ready_children"),
    ("gated_writes", "gated_write_commits_ok"),
    ("precision", "precision_rows"),
    ("cache", "cache_events"),
    ("nvme_fsync", "nvme_fsync_ops_completed"),
];

/// Seals the certificate over the measured report, or refuses.
pub(crate) fn seal(inputs: CertificateInputs<'_>) -> Result<RunCertificate, String> {
    let violations = trust::blocking_evidence_violations();
    if !violations.is_empty() {
        return Err(format!(
            "refusing to seal a run certificate: blocking check(s) rest on operator-declared \
             evidence, which is the one thing this design forbids: {violations:?}"
        ));
    }
    if let Some(reason) = scope_partition_error() {
        return Err(format!("refusing to seal a run certificate: {reason}"));
    }

    let statistics = statistics(&inputs.provenance.sample_counts)?;
    let body = CertificateBody {
        contract_version: PERF_CANDIDATE_CONTRACT_VERSION,
        publication_scope: PublicationScope {
            blocking_axes: BLOCKING_AXES,
            advisory_axes: ADVISORY_AXES,
            rule: SCOPE_RULE,
        },
        trust_rule: trust::TRUST_RULE,
        trust_inputs: trust_manifest(),
        child_program_blake3: inputs.child_program_blake3,
        statistics,
        axes_blake3: canonical_blake3("the axis section", &inputs.axes)?,
        provenance_blake3: canonical_blake3("the provenance section", inputs.provenance)?,
        hash_rule: HASH_RULE,
    };
    let certificate_blake3 = canonical_blake3("the run certificate", &body)?;
    Ok(RunCertificate {
        body,
        certificate_blake3,
    })
}

/// One manifest row per declared trust input, in table order.
pub(crate) fn trust_manifest() -> Vec<TrustInputRow> {
    trust::INPUTS
        .iter()
        .map(|input| TrustInputRow {
            name: input.name,
            class: input.class,
            source: input.source,
            consumed_by: trust::consumers(input.name),
        })
        .collect()
}

/// The per-axis statistics, or an error naming the count that was missing.
/// Fail-closed: a missing sample count is never reported as zero samples.
fn statistics(sample_counts: &BTreeMap<String, usize>) -> Result<RunStatistics, String> {
    let mut per_axis = BTreeMap::new();
    for (axis, source_key) in AXIS_SAMPLE_SOURCES {
        let samples = sample_counts.get(source_key).copied().ok_or_else(|| {
            format!(
                "the `{axis}` axis reports its sample size from `sample_counts.{source_key}`, \
                 which this run did not record; a missing count is not zero samples"
            )
        })?;
        per_axis.insert(
            axis,
            AxisStatistics {
                samples,
                repeats: REPEATS_PER_AXIS,
            },
        );
    }
    Ok(RunStatistics {
        per_axis,
        single_trial_axes: SINGLE_TRIAL_AXES,
        repeats: REPEATS_PER_AXIS,
        rule: STATISTICS_RULE,
    })
}

/// Why the axis scope partition is not exact, or `None` when it is.
fn scope_partition_error() -> Option<String> {
    let axes = super::report::AXES;
    for axis in axes {
        let blocking = BLOCKING_AXES.contains(&axis);
        let advisory = ADVISORY_AXES.contains(&axis);
        if blocking == advisory {
            return Some(format!(
                "axis `{axis}` is {} of the publication scope partition",
                if blocking {
                    "in both halves"
                } else {
                    "in neither half"
                }
            ));
        }
    }
    for listed in BLOCKING_AXES.iter().chain(ADVISORY_AXES.iter()) {
        if !axes.contains(listed) {
            return Some(format!(
                "the publication scope lists `{listed}`, which is not an emitted axis"
            ));
        }
    }
    None
}

/// blake3 over the RFC 8785 canonical form of `value`.
///
/// This is THE hash definition; a verifier reproduces it with `rfc8785` plus
/// `blake3` over the same logical document.
pub(crate) fn canonical_blake3<T: Serialize>(label: &str, value: &T) -> Result<String, String> {
    Ok(blake3::hash(&canonical_bytes(label, value)?)
        .to_hex()
        .to_string())
}

/// The exact canonical bytes a hash is taken over.
pub(crate) fn canonical_bytes<T: Serialize>(label: &str, value: &T) -> Result<Vec<u8>, String> {
    refuse_non_finite_floats(label, value)?;
    let inspected = serde_json::to_value(value)
        .map_err(|error| format!("{label} could not be inspected before hashing: {error}"))?;
    refuse_unrepresentable_integers(label, &inspected, "")?;
    serde_json_canonicalizer::to_vec(value).map_err(|error| {
        format!("{label} has no RFC 8785 canonical form, so it cannot be hashed: {error}")
    })
}

/// `serde_json` 1.0.151 and the JCS crate both emit JSON `null` for NaN/Inf
/// (the inner `Serializer` writes null; `JcsSerializer::serialize_f64` is not
/// used for struct fields). Walk the value ourselves and refuse.
fn refuse_non_finite_floats<T: Serialize>(label: &str, value: &T) -> Result<(), String> {
    value.serialize(FiniteSink).map_err(|error| {
        format!("{label} has no RFC 8785 canonical form, so it cannot be hashed: {error}")
    })
}

#[derive(Copy, Clone)]
struct FiniteSink;

#[derive(Debug)]
struct FiniteError(String);

impl std::fmt::Display for FiniteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for FiniteError {}

impl serde::ser::Error for FiniteError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Self(msg.to_string())
    }
}

impl serde::ser::Serializer for FiniteSink {
    type Ok = ();
    type Error = FiniteError;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, _: bool) -> Result<(), FiniteError> {
        Ok(())
    }
    fn serialize_i8(self, _: i8) -> Result<(), FiniteError> {
        Ok(())
    }
    fn serialize_i16(self, _: i16) -> Result<(), FiniteError> {
        Ok(())
    }
    fn serialize_i32(self, _: i32) -> Result<(), FiniteError> {
        Ok(())
    }
    fn serialize_i64(self, _: i64) -> Result<(), FiniteError> {
        Ok(())
    }
    fn serialize_u8(self, _: u8) -> Result<(), FiniteError> {
        Ok(())
    }
    fn serialize_u16(self, _: u16) -> Result<(), FiniteError> {
        Ok(())
    }
    fn serialize_u32(self, _: u32) -> Result<(), FiniteError> {
        Ok(())
    }
    fn serialize_u64(self, _: u64) -> Result<(), FiniteError> {
        Ok(())
    }
    fn serialize_f32(self, value: f32) -> Result<(), FiniteError> {
        self.serialize_f64(f64::from(value))
    }
    fn serialize_f64(self, value: f64) -> Result<(), FiniteError> {
        if value.is_finite() {
            Ok(())
        } else {
            Err(FiniteError(
                "NaN and +/-Infinity are not permitted in JSON".to_owned(),
            ))
        }
    }
    fn serialize_char(self, _: char) -> Result<(), FiniteError> {
        Ok(())
    }
    fn serialize_str(self, _: &str) -> Result<(), FiniteError> {
        Ok(())
    }
    fn serialize_bytes(self, _: &[u8]) -> Result<(), FiniteError> {
        Ok(())
    }
    fn serialize_none(self) -> Result<(), FiniteError> {
        Ok(())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), FiniteError> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), FiniteError> {
        Ok(())
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), FiniteError> {
        Ok(())
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
    ) -> Result<(), FiniteError> {
        Ok(())
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<(), FiniteError> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        value: &T,
    ) -> Result<(), FiniteError> {
        value.serialize(self)
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<Self, FiniteError> {
        Ok(self)
    }
    fn serialize_tuple(self, _: usize) -> Result<Self, FiniteError> {
        Ok(self)
    }
    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self, FiniteError> {
        Ok(self)
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self, FiniteError> {
        Ok(self)
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self, FiniteError> {
        Ok(self)
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self, FiniteError> {
        Ok(self)
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self, FiniteError> {
        Ok(self)
    }
}

impl serde::ser::SerializeSeq for FiniteSink {
    type Ok = ();
    type Error = FiniteError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), FiniteError> {
        value.serialize(FiniteSink)
    }
    fn end(self) -> Result<(), FiniteError> {
        Ok(())
    }
}
impl serde::ser::SerializeTuple for FiniteSink {
    type Ok = ();
    type Error = FiniteError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), FiniteError> {
        value.serialize(FiniteSink)
    }
    fn end(self) -> Result<(), FiniteError> {
        Ok(())
    }
}
impl serde::ser::SerializeTupleStruct for FiniteSink {
    type Ok = ();
    type Error = FiniteError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), FiniteError> {
        value.serialize(FiniteSink)
    }
    fn end(self) -> Result<(), FiniteError> {
        Ok(())
    }
}
impl serde::ser::SerializeTupleVariant for FiniteSink {
    type Ok = ();
    type Error = FiniteError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), FiniteError> {
        value.serialize(FiniteSink)
    }
    fn end(self) -> Result<(), FiniteError> {
        Ok(())
    }
}
impl serde::ser::SerializeMap for FiniteSink {
    type Ok = ();
    type Error = FiniteError;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), FiniteError> {
        key.serialize(FiniteSink)
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), FiniteError> {
        value.serialize(FiniteSink)
    }
    fn end(self) -> Result<(), FiniteError> {
        Ok(())
    }
}
impl serde::ser::SerializeStruct for FiniteSink {
    type Ok = ();
    type Error = FiniteError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _: &'static str,
        value: &T,
    ) -> Result<(), FiniteError> {
        value.serialize(FiniteSink)
    }
    fn end(self) -> Result<(), FiniteError> {
        Ok(())
    }
}
impl serde::ser::SerializeStructVariant for FiniteSink {
    type Ok = ();
    type Error = FiniteError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _: &'static str,
        value: &T,
    ) -> Result<(), FiniteError> {
        value.serialize(FiniteSink)
    }
    fn end(self) -> Result<(), FiniteError> {
        Ok(())
    }
}

/// Refuses integers that ES6 number formatting cannot carry exactly.
///
/// JCS mandates ES6 formatting, which is IEEE-754 double formatting: past 2^53
/// two conforming implementations legitimately disagree, so a hash taken over
/// such a value would not reproduce. Refusing is the only honest option.
fn refuse_unrepresentable_integers(
    label: &str,
    value: &serde_json::Value,
    path: &str,
) -> Result<(), String> {
    match value {
        serde_json::Value::Number(number) => {
            let magnitude = number
                .as_u64()
                .or_else(|| number.as_i64().map(i64::unsigned_abs));
            match magnitude {
                Some(magnitude) if magnitude > MAX_EXACT_JSON_INTEGER => Err(format!(
                    "{label} carries the integer {number} at `{path}`, which is past 2^53 and \
                     therefore not exactly representable under the ES6 number formatting RFC 8785 \
                     mandates; its hash would not reproduce on the verifying side"
                )),
                _ => Ok(()),
            }
        }
        serde_json::Value::Array(items) => {
            items.iter().enumerate().try_for_each(|(index, item)| {
                refuse_unrepresentable_integers(label, item, &format!("{path}[{index}]"))
            })
        }
        serde_json::Value::Object(fields) => fields.iter().try_for_each(|(key, field)| {
            refuse_unrepresentable_integers(label, field, &format!("{path}.{key}"))
        }),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::String(_) => {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
