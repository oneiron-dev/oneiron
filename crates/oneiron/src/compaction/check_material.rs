//! A conversation summary's check material (FIX 5040, the remainder of FIX
//! 4819). The accepted try's gate input is kept, so the Dreamer's check can
//! run the six checks again: the exact sealed request, the backend's whole
//! reply and why it stopped, and the gate policy the pass used. Nothing here
//! rebuilds that input from the conversation's HEAD, its pins, the profile or
//! the gate defaults of today.
//!
//! The material is one row-held body under body custody. Its row is keyed by
//! the SUMMARY and owned by the SUMMARY and by every record its window was
//! read from. A checkpoint carries the row as a row-held response (the
//! `CompactionCheckMaterial` response family). The material's ref (its
//! occurrence, and the BLAKE3 digest and byte length of its encoding) is in
//! the conversation evidence. Thus the landing receipt, the receipt's digest
//! and the check's declaration all bind it. The row lands in the mint's own
//! write, with the summary, the receipt and the check's declaration.
//!
//! The reply is a model's words, so the side-row wall admits the material
//! first in that write, before its ref is taken: each secret the wall places
//! reads as its handle, and the ref names the bytes the row keeps. A
//! material the wall refuses is not kept, and the check reads it missing.
//!
//! The erase of the SUMMARY or of any source, and the withdrawal of the
//! summary's words, take the material out of the live row. The erase's
//! obligations retire the copy in each image. The erased row keeps its refs
//! and its digest only. A row that does not decode keeps the opaque erased
//! marker. Nothing here refuses an erase. No clock expires the row: it stays
//! while its summary stands, and ordinary retention retires its instances
//! when no row names them.

use std::time::Duration;

use heed::{RoTxn, RwTxn};
use oneiron_store::body_envelope::opaque_response::OPAQUE_ERASED;
use serde::{Deserialize, Serialize};

use super::driver::StoredCompactionRequest;
use super::{
    CompactionGateFailure, CompactionGatePolicy, CompactionProduct, CompactionRequest,
    gate_compaction,
};
use crate::error::GateError;
use crate::side_table::{self, ErasedForm, Named, SideKey, SideTable};
use crate::store::body_descriptor::{BodyLocation, BodyRef, BodyState, OwnedBody};
use crate::store::{
    ResponseCarriage, ResponseFamily, ResponseRead, ResponseScan, Store, is_opaque_erased,
    stamp_opaque_erased,
};
use crate::{EntityId, Error, Result, Vault};
use oneiron_model::llm::FinishReason;

/// Check material rows. Key: id16(summary).
const MATERIALS: SideTable<EntityId, CheckMaterialRow, Named> =
    SideTable::new(&side_table::COMPACTION_CHECK_MATERIAL);

/// Whether a masked copy of a `COMPACTION_CHECK_MATERIAL` row still decodes
/// as its typed value, for the historical lift sweep (FIX 2680, 5040).
pub(crate) fn compaction_check_material_accepts_masked(bytes: &[u8]) -> bool {
    side_table::decodes::<CheckMaterialRow, Named>(bytes)
}

/// Where a conversation summary's check material is, and what it is (FIX
/// 5040): its occurrence, which is the sealed request's job id, and its
/// body, which is the BLAKE3 digest and byte length of its encoding, held
/// inline in its row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionCheckMaterialRef {
    pub occurrence: EntityId,
    pub body: BodyRef,
}

/// The gate policy a pass used, as its material keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredGatePolicy {
    tries: u32,
    floor_tokens: u64,
    max_repeated_line_share: f64,
    max_consecutive_repeats: usize,
    min_distinct_token_share: f64,
    distinct_min_tokens: usize,
}

impl StoredGatePolicy {
    fn of(policy: &CompactionGatePolicy) -> Self {
        Self {
            tries: policy.tries,
            floor_tokens: policy.floor_tokens,
            max_repeated_line_share: policy.max_repeated_line_share,
            max_consecutive_repeats: policy.max_consecutive_repeats,
            min_distinct_token_share: policy.min_distinct_token_share,
            distinct_min_tokens: policy.distinct_min_tokens,
        }
    }

    fn policy(self) -> CompactionGatePolicy {
        CompactionGatePolicy {
            tries: self.tries,
            floor_tokens: self.floor_tokens,
            max_repeated_line_share: self.max_repeated_line_share,
            max_consecutive_repeats: self.max_consecutive_repeats,
            min_distinct_token_share: self.min_distinct_token_share,
            distinct_min_tokens: self.distinct_min_tokens,
        }
    }
}

/// The gate input of one accepted try (FIX 5040): the sealed request, the
/// backend's whole reply before the gate parsed it, why the reply stopped,
/// the call's wall time, and the gate policy the pass used.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompactionCheckMaterial {
    request: StoredCompactionRequest,
    reply: String,
    finish: FinishReason,
    latency: Duration,
    policy: StoredGatePolicy,
}

impl CompactionCheckMaterial {
    /// The material of the accepted try, taken before its whole reply is
    /// discarded. `None` for a window that no conversation binds. The reply
    /// is as the backend gave it: only [`admit_check_material_in_txn`] makes
    /// it a copy that a row may keep.
    pub(crate) fn capture(
        request: &CompactionRequest,
        product: &CompactionProduct,
        policy: &CompactionGatePolicy,
    ) -> Option<Self> {
        Some(Self {
            request: StoredCompactionRequest::capture(request)?,
            reply: product.summary_text.clone(),
            finish: product.finish.clone(),
            latency: product.latency,
            policy: StoredGatePolicy::of(policy),
        })
    }

    /// The material's ref: its occurrence, and the digest and length of its
    /// encoding.
    ///
    /// # Errors
    ///
    /// A material that does not encode.
    pub(crate) fn reference(&self) -> Result<CompactionCheckMaterialRef> {
        let bytes = rmp_serde::to_vec_named(self)
            .map_err(|_| Error::InvariantViolation("a compaction check material did not encode"))?;
        Ok(CompactionCheckMaterialRef {
            occurrence: self.request.request_id(),
            body: BodyRef {
                blake3: *blake3::hash(&bytes).as_bytes(),
                bytes: bytes.len() as u64,
                location: BodyLocation::Inline,
            },
        })
    }

    /// The request the gate judged, field for field.
    pub(crate) fn sealed_request(&self) -> CompactionRequest {
        self.request.sealed_request()
    }

    /// Runs the six checks again on the kept request, reply and policy. The
    /// result is the accepted summary prose, or the first check that fails.
    pub(crate) fn rerun_gate(&self) -> std::result::Result<String, CompactionGateFailure> {
        let product = CompactionProduct {
            summary_text: self.reply.clone(),
            finish: self.finish.clone(),
            latency: self.latency,
        };
        gate_compaction(&self.sealed_request(), &product, &self.policy.policy())
            .map(|gated| gated.summary_text().to_owned())
    }
}

/// The row of one material: its occurrence, owned by the SUMMARY it landed
/// with; every record its window was read from; and the material while it
/// stands.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckMaterialRow {
    body: OwnedBody,
    sources: Vec<EntityId>,
    /// `None` after an erase took it. The row keeps its refs and digest.
    material: Option<CompactionCheckMaterial>,
}

impl CheckMaterialRow {
    /// The standing row of `material`, landed with `summary` and bound to
    /// `reference`.
    fn of(
        summary: EntityId,
        reference: &CompactionCheckMaterialRef,
        material: CompactionCheckMaterial,
    ) -> Self {
        Self {
            body: bound_body(summary, reference),
            sources: material.request.sources().to_vec(),
            material: Some(material),
        }
    }

    /// The records whose words the material copies: the SUMMARY (its reply)
    /// and the sources (its window). The erase of any one takes it.
    fn owners(&self) -> Vec<EntityId> {
        let mut owners = vec![self.body.owner];
        for source in &self.sources {
            if !owners.contains(source) {
                owners.push(*source);
            }
        }
        owners
    }
}

/// An erase takes the material and keeps the refs and digest (FIX 5040).
impl ErasedForm for CheckMaterialRow {
    fn into_erased(mut self) -> Result<Self> {
        self.material = None;
        Ok(self)
    }
}

/// The body that `reference` names, owned by `summary`.
fn bound_body(summary: EntityId, reference: &CompactionCheckMaterialRef) -> OwnedBody {
    OwnedBody {
        owner: summary,
        occurrence: reference.occurrence,
        mark_occurrence: reference.occurrence,
        state: BodyState::Complete {
            body: reference.body.clone(),
        },
        result: None,
        // A compaction's check material is no code run's output.
        code_run_output: None,
    }
}

/// Admits `material`, the material of the landing `summary`, through the
/// side-row wall into its row, in the mint's own write, before its ref is
/// taken (FIX 5040). Each secret the wall places reads as its handle, so
/// the ref names the bytes the row keeps. When the wall refuses, the
/// material is not kept: the ref names the material as given, no row holds
/// it, and the check answers `check_material_missing`. The summary still
/// lands.
///
/// # Errors
///
/// Storage errors, and a material that does not encode.
pub(crate) fn admit_check_material_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    summary: EntityId,
    material: CompactionCheckMaterial,
) -> Result<(CompactionCheckMaterialRef, Option<CompactionCheckMaterial>)> {
    let given = material.reference()?;
    let mut row = CheckMaterialRow::of(summary, &given, material);
    // The wall refuses before it mints a custody record.
    if let Err(error) = MATERIALS.admit(vault, txn, &summary, &mut row) {
        if !matches!(error, Error::Gate(GateError::GateWriteRejected { .. })) {
            return Err(error);
        }
        tracing::warn!(
            "a conversation summary's check material holds a secret the side-row wall cannot \
             place; it is not kept"
        );
        return Ok((given, None));
    }
    let material = row.material.ok_or(Error::InvariantViolation(
        "an admitted compaction check material is gone",
    ))?;
    Ok((material.reference()?, Some(material)))
}

/// Puts `material`, the admitted material of the landing `summary`, in the
/// mint's own write, bound to `reference`, the ref that its receipt names.
/// When an owner is already gone, the row is kept in its erased form.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put_check_material_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    summary: EntityId,
    material: CompactionCheckMaterial,
    reference: &CompactionCheckMaterialRef,
) -> Result<()> {
    let row = CheckMaterialRow::of(summary, reference, material);
    if crate::llm::owner_gone_in_txn(vault, &*txn, &row.owners())? {
        return MATERIALS.put_erased(vault, txn, &summary, side_table::Erased::of(row)?);
    }
    MATERIALS.put(vault, txn, &summary, &row)
}

/// Why a check found no material to judge again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckMaterialFault {
    /// No row holds it.
    Missing,
    /// An erase took it. Its row keeps its refs and digest only.
    Erased,
    /// Its row does not decode.
    Unreadable,
    /// Its row holds a material other than the one the receipt binds.
    Changed,
}

impl CheckMaterialFault {
    /// The stable name that the reason of a finding carries.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "check_material_missing",
            Self::Erased => "check_material_erased",
            Self::Unreadable => "check_material_unreadable",
            Self::Changed => "check_material_changed",
        }
    }
}

/// The material that `reference` binds for `summary`, read in the caller's
/// snapshot. Its row must name that occurrence and body, owned by
/// `summary`, and its encoding must have that digest and length.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn check_material_in(
    store: &Store,
    txn: &RoTxn<'_>,
    summary: &EntityId,
    reference: &CompactionCheckMaterialRef,
) -> Result<std::result::Result<CompactionCheckMaterial, CheckMaterialFault>> {
    use CheckMaterialFault::{Changed, Erased, Missing, Unreadable};
    let Some(raw) = MATERIALS.get_bytes(store, txn, summary)? else {
        return Ok(Err(Missing));
    };
    // A retired copy that never decoded keeps the erased marker.
    let key = MATERIALS.key_bytes(summary);
    let ResponseRead::Present(bytes) =
        ResponseRead::of(ResponseFamily::CompactionCheckMaterial, &key, &raw)
    else {
        return Ok(Err(Erased));
    };
    let Ok(row) = MATERIALS.decode_value(bytes) else {
        return Ok(Err(Unreadable));
    };
    if row.body != bound_body(*summary, reference) {
        return Ok(Err(Changed));
    }
    let Some(material) = row.material else {
        return Ok(Err(Erased));
    };
    match material.reference() {
        Ok(found) if found == *reference => Ok(Ok(material)),
        Ok(_) => Ok(Err(Changed)),
        Err(_) => Ok(Err(Unreadable)),
    }
}

/// What a checkpoint carries of the material row `value`: the whole row.
/// The stub is the row's erased form, which a retired instance keeps. A row
/// that is already erased holds no response. A row that does not decode, or
/// whose stub does not encode, is carried whole as an opaque response.
pub(crate) fn check_material_carriage(value: &[u8]) -> ResponseScan {
    let Ok(mut row) = MATERIALS.decode_value(value) else {
        return ResponseScan::opaque_row();
    };
    if row.material.take().is_none() {
        return ResponseScan::NotResponse;
    }
    let Ok(stub) = MATERIALS.encode_value(&row) else {
        return ResponseScan::opaque_row();
    };
    ResponseScan::Decoded(ResponseCarriage::whole(stub))
}

/// The owners of the copies of the material row `key`, whose bytes are
/// `value`: its SUMMARY and every source it names. For a row that does not
/// decode, the SUMMARY that its key names.
pub(crate) fn check_material_owners(key: &[u8], value: &[u8]) -> Vec<EntityId> {
    if let Ok(row) = MATERIALS.decode_value(value) {
        return row.owners();
    }
    key.strip_prefix(side_table::COMPACTION_CHECK_MATERIAL.prefix)
        .and_then(<EntityId as SideKey>::decode_key)
        .into_iter()
        .collect()
}

/// The erase of `owner` takes the material out of every row that it owns,
/// in the erase's own transaction, at both delete doors. The row keyed by
/// `owner` as its SUMMARY is taken whatever its bytes decode to (FIX 5040).
/// A row that decodes stays in its erased form, with its refs and digest.
/// A row that does not decode, keyed by `owner` or naming its id, keeps the
/// opaque erased marker that its response family reads as erased. The
/// copies in images retire through the obligations of the rows.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_check_material_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    owner: &EntityId,
) -> Result<()> {
    let needle = owner.to_hex();
    let mut erased = Vec::new();
    let mut opaque = Vec::new();
    for row in MATERIALS.iter_raw_from(store, wtxn, &[])? {
        let (key, bytes) = row?;
        let Some(summary) = <EntityId as SideKey>::decode_key(&key) else {
            continue;
        };
        let keyed = summary == *owner;
        // An owner's id is in its row as hex text: a row without that text,
        // and not keyed by the owner, is not decoded.
        let named = keyed
            || bytes
                .windows(needle.len())
                .any(|window| window == needle.as_bytes());
        if !named || is_opaque_erased(&bytes) {
            continue;
        }
        match MATERIALS.decode_value(&bytes) {
            Ok(row) if row.material.is_some() && (keyed || row.owners().contains(owner)) => {
                erased.push((summary, row));
            }
            Ok(_) => {}
            Err(_) => opaque.push(summary),
        }
    }
    for (summary, row) in erased {
        MATERIALS.put_erased(store, wtxn, &summary, side_table::Erased::of(row)?)?;
    }
    let marker = stamp_opaque_erased(OPAQUE_ERASED);
    for summary in opaque {
        store
            .vault_meta
            .put(wtxn, &MATERIALS.key_bytes(&summary), &marker)?;
    }
    Ok(())
}
