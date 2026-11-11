//! Port of generate.py:2622-2926 (main `e79eb76df3e`): the UniFFI verb surface (`facade_generated.rs`, one
//! `export_facade!` arm per facade row) and its generated types (`facade_types_generated.rs`, uniffi_types.py).
//!
//! A row with a `uniffi` signature projects by it. A row without one projects by type: an engine type with a
//! hand-written UniFFI record (`dto.rs`) crosses as that record, a typed binding argument as its foreign value, and
//! any other input or output as the generated record of its type, converted through the shared wire shape; an input
//! record with no fields is no argument at all, and a type the inventory could not read crosses as `WireJson`. A
//! definition row gets no export: the generator refuses one until the table gives it a call. Codecs are selected by
//! type, never by verb name.

use std::path::Path;

use indexmap::{IndexMap, IndexSet};

use super::common::{argument_kind, rust_type, str_format};
use super::row_access::{concat, item, json_item, shown, text};
use super::{Generator, HEADER, RowId};
use crate::error::GenerateError;
use crate::py::value::{Dict, Value};
use crate::uniffi_types::UniffiTypes;

/// Port of generate.py:2622-2630 (UNIFFI_INPUTS): engine input types with a hand-written UniFFI record.
pub(crate) const UNIFFI_INPUTS: &[(&str, &str)] = &[
    ("crate::memory::WitnessTurn", "WitnessTurn"),
    ("crate::memory::ClaimInput", "ClaimInput"),
    ("crate::memory::ClaimListFilter", "ClaimListFilter"),
    ("crate::memory::StructuralPutInput", "StructuralPutInput"),
    ("crate::memory::HabitCheckinInput", "HabitCheckinInput"),
    (
        "crate::memory::AdmitImportedClaimInput",
        "AdmitImportedClaimInput",
    ),
    ("crate::memory::BlobArtifactInput", "BlobArtifactInput"),
];

/// Port of generate.py:2631-2647 (UNIFFI_RESULTS): engine result types with a hand-written UniFFI record.
pub(crate) const UNIFFI_RESULTS: &[(&str, &str)] = &[
    ("crate::memory::WitnessReceipt", "WitnessReceipt"),
    ("crate::memory::CommitReceipt", "CommitReceipt"),
    ("crate::memory::MemoryPack", "MemoryPack"),
    ("crate::memory::MemoryReceipt", "FacadeReceipt"),
    ("crate::memory::DeleteReceipt", "DeleteReceipt"),
    ("crate::memory::PendingWrite", "PendingWrite"),
    ("crate::memory::EntityRefReceipt", "EntityRefReceipt"),
    ("crate::memory::BlobVersionView", "BlobVersionView"),
    (
        "crate::memory::OutboundIntentReceipt",
        "OutboundIntentReceipt",
    ),
    ("crate::task_verb::sdk::BlobContent", "Vec<u8>"),
    (
        "crate::claim::ScopedReadResult<Vec<crate::memory::ClaimView>>",
        "ClaimViews",
    ),
    (
        "crate::claim::ScopedReadResult<Vec<crate::memory::EntityView>>",
        "EntityViews",
    ),
    (
        "crate::claim::ScopedReadResult<Option<crate::memory::EntityView>>",
        "EntityRead",
    ),
    (
        "crate::claim::ScopedReadResult<Vec<crate::memory::LexicalHit>>",
        "LexicalHits",
    ),
    (
        "crate::claim::ScopedReadResult<Vec<crate::memory::NeighborHit>>",
        "NeighborHits",
    ),
];

/// Port of generate.py:2648-2711 (UNIFFI_GENERATED_RESULT_LIFTS): generated records with an owned codec for a nested
/// opaque JSON result; `types.root()` still emits their public records before this codec is selected.
pub(crate) const UNIFFI_GENERATED_RESULT_LIFTS: &[(&str, &str)] = &[
    ("crate::lens::InspectionResolved", "InspectionResolved"),
    (
        "crate::lens::LensSelectionResolved",
        "LensSelectionResolved",
    ),
    ("crate::claim::WeaveReportView", "WeaveReportView"),
    ("crate::lens::LensFrameCard", "LensFrameCard"),
    (
        "crate::claim::ScopedReadResult<crate::lens::LensFrameCard>",
        "ScopedReadResultLensFrameCard",
    ),
    ("crate::claim::WeaveDigestView", "WeaveDigestView"),
    ("crate::lens::LensListPage", "LensListPage"),
    ("crate::agent_inbox_lens::InboxItemView", "InboxItemView"),
    ("crate::inbox::NotificationPage", "NotificationPage"),
    ("crate::inbox::NotificationRow", "NotificationRow"),
    (
        "crate::task_verb::sdk::OffRecordResultCards",
        "OffRecordResultCards",
    ),
    (
        "crate::memory::result_doors::ResultReadView",
        "ResultReadView",
    ),
    ("crate::vault_shape::ShapeRead", "ShapeRead"),
    ("crate::vault_shape::ShapePlan", "ShapePlan"),
    ("crate::vault_shape::ShapeApplyReceipt", "ShapeApplyReceipt"),
    ("crate::memory::ShapeItemReceipt", "ShapeItemReceipt"),
    (
        "crate::inbox::UnifiedInboxGroupPage",
        "UnifiedInboxGroupPage",
    ),
    ("crate::inbox::InboxGroupResolution", "InboxGroupResolution"),
    (
        "crate::task_verb::sdk::FeedbackSubjectPreview",
        "FeedbackSubjectPreview",
    ),
    (
        "crate::task_verb::sdk::OffRecordResultRead",
        "OffRecordResultRead",
    ),
    ("crate::memory::ShapePlanCardView", "ShapePlanCardView"),
    (
        "crate::dreamer_runner::maintenance::identity::IdentityActNow",
        "IdentityActNow",
    ),
    (
        "crate::task_verb::sdk::BrowserObservationPage",
        "BrowserAnswerObservationPage",
    ),
    (
        "crate::task_verb::sdk::BrowserImageOutput",
        "BrowserAnswerImageOutput",
    ),
    (
        "crate::task_verb::sdk::BrowserFindOutput",
        "BrowserAnswerFindOutput",
    ),
    (
        "crate::task_verb::sdk::BrowserWaitForOutput",
        "BrowserAnswerWaitForOutput",
    ),
    (
        "crate::task_verb::sdk::BrowserExpectOutput",
        "BrowserAnswerExpectOutput",
    ),
    (
        "crate::task_verb::sdk::BrowserScreenshotOutput",
        "BrowserAnswerScreenshotOutput",
    ),
    (
        "crate::task_verb::sdk::BrowserLibraryFindOutput",
        "BrowserAnswerLibraryFindOutput",
    ),
    (
        "crate::task_verb::sdk::BrowserLibraryDraftOutput",
        "BrowserAnswerDraftOutput",
    ),
    (
        "crate::task_verb::sdk::BrowserDemonstrationStartOutput",
        "BrowserAnswerDemonstrationStarted",
    ),
    (
        "crate::task_verb::sdk::BrowserDemonstrationStopOutput",
        "BrowserAnswerDemonstrationOutput",
    ),
    (
        "crate::task_verb::sdk::BrowserLibraryRetireOutput",
        "BrowserAnswerLibraryRetireOutput",
    ),
    (
        "crate::task_verb::sdk::BrowserLibraryRetiredOutput",
        "BrowserAnswerLibraryRetiredOutput",
    ),
    (
        "crate::task_verb::sdk::BrowserHandoverOutput",
        "BrowserAnswerHandoverOutput",
    ),
    (
        "crate::task_verb::sdk::BrowserSwitchEngineOutput",
        "BrowserAnswerSwitchEngineOutput",
    ),
    (
        "crate::task_verb::sdk::BrowserLibraryProposeOutput",
        "BrowserAnswerProposeOutput",
    ),
    (
        "crate::task_verb::sdk::BrowserLibraryRunOutput",
        "BrowserAnswerLibraryRunOutput",
    ),
    (
        "crate::task_verb::sdk::BrowserBatchOutput",
        "BrowserAnswerBatchOutput",
    ),
    (
        "crate::edit_settle::PendingProposalView",
        "PendingProposalView",
    ),
    ("crate::memory::ClaimProposalReview", "ClaimProposalReview"),
    ("crate::memory::KeyValueItem", "KeyValueItem"),
    ("crate::memory::KeyValuePutReceipt", "KeyValuePutReceipt"),
    ("crate::skill::helper::CallableCardView", "CallableCardView"),
    ("crate::task_verb::sdk::AiOptions", "AiOptions"),
    (
        "crate::core_write::CoreEntityWriteReceipt",
        "CoreEntityWriteReceipt",
    ),
    (
        "crate::engine_executor::checkpoint_read::CheckpointView",
        "CheckpointView",
    ),
    (
        "crate::policy_setting_doors::PolicyActionOutcome",
        "PolicyActionOutcome",
    ),
    (
        "crate::lens::LensResultSetActionResult",
        "LensResultSetActionResult",
    ),
    (
        "crate::claim::ScopedReadResult<Vec<crate::memory::DiagnosticEventView>>",
        "ScopedReadResultDiagnosticEventViewList",
    ),
    (
        "crate::claim::ScopedReadResult<Option<crate::memory::DiagnosticEventView>>",
        "ScopedReadResultOptionalDiagnosticEventView",
    ),
    (
        "crate::claim::ScopedReadResult<crate::memory::CoachInspectionView>",
        "ScopedReadResultCoachInspectionView",
    ),
    (
        "crate::blob_artifact::DeckProposeOutcome",
        "DeckProposeOutcome",
    ),
    ("crate::office_body::DeckExportView", "DeckExportView"),
    (
        "crate::blob_artifact::ArtifactAskOutcome",
        "ArtifactAskOutcome",
    ),
    (
        "crate::task_verb::sdk::ConnectorCallReply",
        "ConnectorCallReply",
    ),
    (
        "crate::task_verb::sdk::ConnectorCallStatus",
        "ConnectorCallStatus",
    ),
    (
        "crate::task_verb::sdk::ConnectorSchemaReply",
        "ConnectorSchemaReply",
    ),
    (
        "crate::task_verb::sdk::ActAnswer<crate::blob_artifact::SlideReviewOutcome>",
        "ActAnswerSlideReviewOutcome",
    ),
    (
        "crate::task_verb::sdk::ActAnswer<crate::blob_artifact::ArtifactAskOutcome>",
        "ActAnswerArtifactAskOutcome",
    ),
];

/// Port of generate.py:2713-2723 (UNIFFI_ARGUMENTS): a typed binding argument the client takes as is, by kind: its
/// foreign type and how it is passed (a `str.format` template). Any other binding argument is lowered into its
/// `ARGUMENTS` type.
pub(crate) const UNIFFI_ARGUMENTS: &[(&str, (&str, &str))] = &[
    ("text", ("String", "&{name}")),
    ("ref", ("Option<String>", "{name}.as_deref()")),
    ("format", ("Option<String>", "{name}.as_deref()")),
    ("as_of", ("Option<u64>", "{name}")),
    ("deadline_ms", ("Option<u64>", "{name}")),
    ("token_budget", ("Option<u64>", "{name}")),
    (
        "kinds",
        (
            "Option<Vec<String>>",
            "{name}.as_deref().unwrap_or_default()",
        ),
    ),
];

/// Port of generate.py:2725-2733 (UNIFFI_LENS_ROOTS): FIX 3297, the hand-written lens-frame calls cross the generated
/// records of the client crate's bodies, under these names.
pub(crate) const UNIFFI_LENS_ROOTS: &[(&str, &str)] = &[
    (
        "oneiron_remote::LensFrameEventRequest",
        "LensFrameEventRequest",
    ),
    ("oneiron_remote::LensFrameEventReply", "LensFrameEventReply"),
    ("oneiron_remote::CloseLensFrameReply", "CloseLensFrameReply"),
];

/// Port of generate.py:2735-2738 (UNIFFI_STREAM_ROOTS): FIX 7968, 9891, roots that reach no row.
pub(crate) const UNIFFI_STREAM_ROOTS: &[&str] = &[
    "crate::lens::GeneratedUiSegment",
    "crate::lens::GeneratedUiCatalogDescriptor",
];

/// Port of generate.py:2748-2750 (UNIFFI_HAND_WRITTEN): the files whose public types a generated type may not be named.
pub(crate) const UNIFFI_HAND_WRITTEN: &[&str] = &[
    "crates/oneiron-uniffi/src/dto.rs",
    "crates/oneiron-uniffi/src/lib.rs",
    "crates/oneiron-uniffi/src/error.rs",
];

/// Port of generate.py:2751 (UNIFFI_ROOT_NAMES): what the crate root already binds.
pub(crate) const UNIFFI_ROOT_NAMES: &[&str] = &["Arc", "Lift", "Lower", "UniFfiTag"];

/// `{table}.get(text)` of a `UNIFFI_*` table.
fn lookup(table: &[(&str, &'static str)], text: &str) -> Option<&'static str> {
    table
        .iter()
        .find(|(key, _)| *key == text)
        .map(|&(_, value)| value)
}

/// `UNIFFI_ARGUMENTS[kind]` if `kind in UNIFFI_ARGUMENTS`: a list or dict kind is the membership test's unhashable
/// `TypeError`; any other value that is no known string is not in it.
fn uniffi_argument(kind: &Value) -> Result<Option<(&'static str, &'static str)>, GenerateError> {
    kind.check_hashable("a dict key")?;
    Ok(kind.as_str().and_then(|kind| {
        UNIFFI_ARGUMENTS
            .iter()
            .find(|(name, _)| *name == kind)
            .map(|&(_, argument)| argument)
    }))
}

/// Port of generate.py:2740-2746 (uniffi_record): the UniFFI type an engine type crosses as, or `None` when it has no
/// record (through `Option<...>` and `Vec<...>`).
pub(crate) fn uniffi_record(value: &str, records: &[(&str, &'static str)]) -> Option<String> {
    for container in ["Option", "Vec"] {
        if let Some(inner) = value
            .strip_prefix(container)
            .and_then(|rest| rest.strip_prefix('<'))
            .and_then(|rest| rest.strip_suffix('>'))
        {
            // `inner and f'{container}<{inner}>'`: no record value is empty, so a falsy inner is `None`.
            return uniffi_record(inner, records).map(|inner| format!("{container}<{inner}>"));
        }
    }
    lookup(records, value).map(str::to_owned)
}

/// Port of generate.py:2753-2757 (uniffi_taken): the crate's hand-written public struct and enum names, and what the
/// crate root binds (a set; `UniffiTypes` reads it for membership).
pub(crate) fn uniffi_taken(root: &Path) -> Result<IndexSet<String>, GenerateError> {
    let mut names: IndexSet<String> = UNIFFI_ROOT_NAMES
        .iter()
        .map(|&name| name.to_owned())
        .collect();
    // re.findall(r'(?m)^pub (?:struct|enum) (\w+)', text): the one group; Rust `(?m)^pub (?:struct|enum)
    // ([\p{L}\p{N}_]+)` (`translate`; `(?m)^` matches at the start and after each `\n`, as Python's does).
    let pattern = crate::py::re::compile(r"(?m)^pub (?:struct|enum) (\w+)");
    for path in UNIFFI_HAND_WRITTEN {
        let text = crate::py::read_text(&root.join(path))?;
        for found in pattern.captures_iter(&text) {
            if let Some(name) = found.get(1) {
                names.insert(name.as_str().to_owned());
            }
        }
    }
    Ok(names)
}

/// The census of uniffi_facade: each row's name, by its `(input, result)` sides (`typed`, `generated` or `wire`), a
/// dict in first-filled order.
pub(crate) type Census = IndexMap<Vec<&'static str>, Vec<Value>>;

/// A Python `dict` with keys that are any hashable value (`dict(signature['args'])`, a comprehension keyed by a
/// binding argument's name): insertion order; an equal key (`1 == 1.0 == True`) keeps its first place and takes the
/// last value.
type PyDict = Vec<(Value, Value)>;

/// Python's `==` between two values decoded from the verb files, as a dict key lookup, a list comparison or a dict
/// comparison makes it: identity first, then equality. Python's `json.loads` returns its one `NaN` object for every
/// `NaN` token, so any two NaNs from the rows are the same object and compare equal there, while `Value::py_eq` (the
/// scalar `==`) keeps `NaN != NaN`. Every other value compares by `py_eq`, element by element.
pub(crate) fn json_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Float(x), Value::Float(y)) if x.is_nan() && y.is_nan() => true,
        (Value::List(a), Value::List(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| json_eq(x, y))
        }
        (Value::Dict(a), Value::Dict(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, x)| b.get(key).is_some_and(|y| json_eq(x, y)))
        }
        _ => a.py_eq(b),
    }
}

fn dict_insert(dict: &mut PyDict, key: Value, value: Value) -> Result<(), GenerateError> {
    key.check_hashable("a dict key")?;
    match dict.iter_mut().find(|(seen, _)| json_eq(seen, &key)) {
        Some(entry) => entry.1 = value,
        None => dict.push((key, value)),
    }
    Ok(())
}

/// `dict(value)`: a dict's entries, or each item of an iterable as a key and value pair, with Python 3.14's errors.
fn dict_of(value: &Value) -> Result<PyDict, GenerateError> {
    let mut out = PyDict::new();
    let items = match value {
        Value::Dict(entries) => {
            for (key, value) in entries {
                out.push((Value::Str(key.clone()), value.clone()));
            }
            return Ok(out);
        }
        Value::List(items) => items.clone(),
        Value::Str(_) => value.iterate()?,
        other => {
            return Err(GenerateError::type_error(format!(
                "'{}' object is not iterable",
                other.type_name()
            )));
        }
    };
    for (at, element) in items.iter().enumerate() {
        let pair = match element {
            Value::List(_) | Value::Str(_) | Value::Dict(_) => element.iterate()?,
            _ => return Err(GenerateError::type_error("object is not iterable")),
        };
        let [key, value] = pair.as_slice() else {
            return Err(GenerateError::value(format!(
                "dictionary update sequence element #{at} has length {}; 2 is required",
                pair.len()
            )));
        };
        dict_insert(&mut out, key.clone(), value.clone())?;
    }
    Ok(out)
}

/// `', '.join(keys)`: each must be a `str`.
fn join_keys(dict: &PyDict) -> Result<String, GenerateError> {
    let mut parts = Vec::with_capacity(dict.len());
    for (at, (key, _)) in dict.iter().enumerate() {
        let Value::Str(key) = key else {
            return Err(GenerateError::type_error(format!(
                "sequence item {at}: expected str instance, {} found",
                key.type_name()
            )));
        };
        parts.push(key.as_str());
    }
    Ok(parts.join(", "))
}

/// `', '.join(arg + ': ' + typ for arg, typ in params.items())`.
fn declaration(params: &PyDict) -> Result<String, GenerateError> {
    let mut parts = Vec::with_capacity(params.len());
    for (arg, typ) in params {
        let Value::Str(arg) = arg else {
            return Err(GenerateError::type_error(format!(
                "unsupported operand type(s) for +: '{}' and 'str'",
                arg.type_name()
            )));
        };
        parts.push(format!("{arg}: {}", concat(typ)?));
    }
    Ok(parts.join(", "))
}

/// Port of generate.py:2759-2900 (uniffi_export): one `export_facade!` arm: lower the arguments, call the typed
/// client method, lift. Appends the row's name to `census` under its sides.
pub(crate) fn uniffi_export(
    row: &Dict,
    types: &mut UniffiTypes<'_>,
    census: &mut Census,
) -> Result<String, GenerateError> {
    let name = json_item(row, "name")?;
    let method = text(row, "name", "replace")?.replace('.', "_");
    let signature = row.get("uniffi");
    if !row.contains_key("call") {
        // Every UniFFI row is callable (the last definition rows took calls in #2049), so the binding keeps no
        // fail-closed stub for one.
        return Err(GenerateError::value(format!(
            "{}: a definition row has no UniFFI export until it takes a call",
            shown(row, "name")?
        )));
    }
    // binding = row.get('binding') or {}
    let no_binding = Value::Dict(Dict::new());
    let binding = row
        .get("binding")
        .filter(|binding| binding.truthy())
        .unwrap_or(&no_binding);
    // typed_args = binding['args'] if binding.get('args') and binding.get('wire') != 'json' else None
    let typed_args = if binding.dict_get("args")?.is_some_and(Value::truthy)
        && !binding
            .dict_get("wire")?
            .is_some_and(|wire| wire.is_str("json"))
    {
        Some(binding.getitem("args")?)
    } else {
        None
    };
    let engine_input = rust_type(item(row, "input")?)?;
    let mut setup: Vec<String> = Vec::new();
    let mut values: Vec<String> = Vec::new();
    let params: PyDict;
    let output: String;
    let result: String;
    if let Some(signature) = signature.filter(|signature| signature.truthy()) {
        params = dict_of(signature.getitem("args")?)?;
        output = signature.getitem("output")?.str();
        result = "Lift::lift(output)".to_owned();
        if let Some(typed_args) = typed_args {
            let args = typed_args.iterate()?;
            let mut names = Vec::with_capacity(args.len());
            for a in &args {
                names.push(a.getitem("name")?);
            }
            // list(params) != [a['name'] for a in typed_args]
            if params.len() != names.len()
                || !params
                    .iter()
                    .zip(&names)
                    .all(|((key, _), name)| json_eq(key, name))
            {
                return Err(GenerateError::value(format!(
                    "{}: its uniffi arguments are its binding arguments, in order",
                    shown(row, "name")?
                )));
            }
            for a in &args {
                if let Some((_, pass)) = uniffi_argument(a.getitem("kind")?)? {
                    values.push(str_format(pass, &[("name", &a.getitem("name")?.str())])?);
                    continue;
                }
                let target = argument_kind(a.getitem("kind")?)?.text("rust")?;
                let arg = a.getitem("name")?.str();
                setup.push(format!(
                    "let {arg}: {} = {arg}.lower()?;",
                    target.trim_start_matches('&')
                ));
                let borrow = if target.starts_with('&') { "&" } else { "" };
                values.push(format!("{borrow}{}", concat(a.getitem("name")?)?));
            }
        } else {
            let lowered = if params.len() == 1 {
                params[0].0.str()
            } else {
                format!("({})", join_keys(&params)?)
            };
            setup.push(format!("let input: {engine_input} = {lowered}.lower()?;"));
            values.push("&input".to_owned());
        }
        census
            .entry(vec!["typed", "typed"])
            .or_default()
            .push(item(row, "name")?.clone());
    } else {
        let mut sides: Vec<&'static str>;
        let mut unnamed = PyDict::new();
        if let Some(typed_args) = typed_args {
            let args = typed_args.iterate()?;
            let mut unknown = Vec::new();
            for a in &args {
                let kind = a.getitem("kind")?;
                if uniffi_argument(kind)?.is_none() {
                    unknown.push(kind.clone());
                }
            }
            if !unknown.is_empty() {
                return Err(GenerateError::value(format!(
                    "{}: no UniFFI projection for binding argument kinds {}",
                    shown(row, "name")?,
                    Value::List(unknown).repr()
                )));
            }
            for a in &args {
                let key = a.getitem("name")?.clone();
                let foreign =
                    uniffi_argument(a.getitem("kind")?)?.map_or("", |(foreign, _)| foreign);
                dict_insert(&mut unnamed, key, Value::Str(foreign.to_owned()))?;
            }
            for a in &args {
                let pass = uniffi_argument(a.getitem("kind")?)?.map_or("", |(_, pass)| pass);
                values.push(str_format(pass, &[("name", &a.getitem("name")?.str())])?);
            }
            sides = vec!["typed"];
        } else {
            let input = text(row, "input", "startswith")?;
            let single = |typ: String| vec![(Value::Str("input".to_owned()), Value::Str(typ))];
            if let Some(record) = uniffi_record(input, UNIFFI_INPUTS) {
                unnamed = single(record);
                setup.push(format!("let input: {engine_input} = input.lower()?;"));
                sides = vec!["typed"];
            } else if types.root_is_empty(input)? {
                setup.push(format!(
                    "let input: {engine_input} = crate::codec::lower_empty({name})?;"
                ));
                sides = vec!["generated"];
            } else if let Some(mirror) = types.root(input)? {
                unnamed = single(mirror);
                setup.push(format!(
                    "let input: {engine_input} = crate::codec::lower_record({name}, input)?;"
                ));
                sides = vec!["generated"];
            } else {
                unnamed = single("WireJson".to_owned());
                setup.push(format!(
                    "let input: {engine_input} = crate::codec::decode({name}, &input)?;"
                ));
                sides = vec!["wire"];
            }
            values.push("&input".to_owned());
        }
        params = unnamed;
        let row_output = text(row, "output", "startswith")?;
        if let Some(record) = uniffi_record(row_output, UNIFFI_RESULTS) {
            output = record;
            result = "Lift::lift(output)".to_owned();
            sides.push("typed");
        } else if let Some(mirror) = types.root(row_output)? {
            let owned = uniffi_record(row_output, UNIFFI_GENERATED_RESULT_LIFTS);
            if owned.as_ref().is_some_and(|owned| *owned != mirror) {
                return Err(GenerateError::value(format!(
                    "{}: its owned result codec must keep the generated record {mirror}",
                    shown(row, "name")?
                )));
            }
            result = generated_result(row_output, &mirror, &name, owned.is_some());
            output = mirror;
            sides.push("generated");
        } else {
            output = "WireJson".to_owned();
            result = if row_output == "serde_json::Value" {
                "Lift::lift(output)".to_owned()
            } else {
                format!("crate::codec::encode({name}, &output)")
            };
            sides.push("wire");
        }
        census
            .entry(sides)
            .or_default()
            .push(item(row, "name")?.clone());
    }
    let declaration = declaration(&params)?;
    let mut body = String::new();
    for line in setup {
        body.push_str(&format!("    {line}\n"));
    }
    body.push_str(&format!(
        "    let output = client.{method}({})?;\n",
        values.join(", ")
    ));
    body.push_str(&format!("    {result}\n"));
    let receiver = if declaration.is_empty() {
        "&self".to_owned()
    } else {
        format!("&self, {declaration}")
    };
    Ok(format!(
        "{name} => fn {method}({receiver}) -> {output} = |client| {{\n{body}}};\n"
    ))
}

/// generate.py:2823-2890: how a generated result is lifted: a named codec for the rows whose result keeps a nested
/// opaque JSON value, the owned codec, the `ActAnswer` match, or the whole-record conversion.
fn generated_result(row_output: &str, mirror: &str, name: &str, owned: bool) -> String {
    let codec = |function: &str| format!("crate::codec::{function}({name}, output)");
    match row_output {
        "Vec<crate::vault_shape::ShapeInboxGroup>" => {
            "crate::codec::lift_shape_groups(output)".to_owned()
        }
        "crate::task_verb::sdk::AiAnswer" => codec("lift_ai_answer"),
        "crate::task_verb::sdk::AiVideoJob" => codec("lift_ai_video_job"),
        "crate::task_verb::sdk::AskImageAnswer" => codec("lift_ask_image"),
        "crate::llm::manifest::doors::ModelRoleInvocation" => codec("lift_model_role_invocation"),
        "crate::llm::model_step::ModelStepReceipt" => codec("lift_model_step_receipt"),
        "crate::llm::model_stream::ModelStreamEvents" => codec("lift_model_stream_events"),
        "crate::llm::model_stream::ModelStreamTerminal" => codec("lift_model_stream_terminal"),
        "Option<crate::llm::model_step::SettledStepView>" => codec("lift_settled_step"),
        "Option<crate::dreamer_runner::SettledProgramStepView>" => {
            codec("lift_settled_program_step")
        }
        "crate::llm::catalog_doors::ModelTrialView" => codec("lift_model_trial"),
        "crate::llm::catalog_doors::ModelBindingProposal" => codec("lift_model_binding_proposal"),
        "crate::campaign::surface::SavedQueryRecordView" => codec("lift_saved_query_record"),
        "crate::campaign::surface::SavedQueryReadResult" => codec("lift_saved_query_read"),
        "crate::campaign::surface::SavedQueryEvaluationReceipt" => {
            codec("lift_saved_query_evaluation")
        }
        _ if owned => "Lift::lift(output)".to_owned(),
        _ if row_output.starts_with("crate::task_verb::sdk::ActAnswer<")
            && row_output.ends_with('>') =>
        {
            act_answer_result(row_output, mirror, name)
        }
        _ => format!("crate::codec::lift_record({name}, &output)"),
    }
}

/// generate.py:2856-2888: an `ActAnswer<...>` result: its `QuestionsNarrowed` variant lifts the hand-written record,
/// the live-voice and connector-call results lift their nested replies, and the other variants keep the whole-record
/// conversion.
fn act_answer_result(row_output: &str, mirror: &str, name: &str) -> String {
    const LIVE_VOICE: &str =
        "crate::task_verb::sdk::ActAnswer<crate::task_verb::sdk::LiveVoiceToolReply>";
    const CONNECTOR_CALL: &str =
        "crate::task_verb::sdk::ActAnswer<crate::task_verb::sdk::ConnectorCallReply>";
    let nested_voice = if row_output == LIVE_VOICE {
        format!(
            "oneiron::task_verb::sdk::ActAnswer::Done(oneiron::task_verb::sdk::LiveVoiceToolReply {{ \
             processed: oneiron::task_verb::sdk::LiveVoiceProcessed {{ session_ref, cursor, ended }}, \
             reply: oneiron::task_verb::sdk::LiveVoiceToolCallReply::QuestionsNarrowed(q) }}) => \
             Ok({mirror}::Done(crate::LiveVoiceToolReply {{ \
             processed: crate::LiveVoiceProcessed {{ session_ref, cursor, ended }}, \
             reply: crate::LiveVoiceToolCallReply::QuestionsNarrowed(crate::NarrowedQuestions::lift(q)?) }})), "
        )
    } else {
        String::new()
    };
    let owned_done = if row_output == CONNECTOR_CALL {
        format!(
            "oneiron::task_verb::sdk::ActAnswer::Done(reply) => \
             Ok({mirror}::Done(crate::ConnectorCallReply::lift(reply)?)), "
        )
    } else if row_output == LIVE_VOICE {
        format!(
            "oneiron::task_verb::sdk::ActAnswer::Done(oneiron::task_verb::sdk::LiveVoiceToolReply {{ \
             processed: oneiron::task_verb::sdk::LiveVoiceProcessed {{ session_ref, cursor, ended }}, \
             reply: oneiron::task_verb::sdk::LiveVoiceToolCallReply::Done(reply) }}) => \
             Ok({mirror}::Done(crate::LiveVoiceToolReply {{ \
             processed: crate::LiveVoiceProcessed {{ session_ref, cursor, ended }}, \
             reply: crate::LiveVoiceToolCallReply::Done(crate::ConnectorCallReply::lift(reply)?) }})), "
        )
    } else {
        String::new()
    };
    format!(
        "match output {{ oneiron::task_verb::sdk::ActAnswer::QuestionsNarrowed(q) => \
         Ok({mirror}::QuestionsNarrowed(crate::NarrowedQuestions::lift(q)?)), \
         {nested_voice}{owned_done}\
         other => crate::codec::lift_record({name}, &other) }}"
    )
}

/// `row in rows` for a list of rows: by identity, then by Python's `==` on the dicts.
fn holds_row(generator: &Generator, rows: &[RowId], id: RowId) -> bool {
    if rows.contains(&id) {
        return true;
    }
    let row = &generator.rows[id];
    rows.iter().any(|&other| {
        let other = &generator.rows[other];
        other.len() == row.len()
            && row
                .iter()
                .all(|(key, value)| other.get(key).is_some_and(|seen| json_eq(seen, value)))
    })
}

/// Port of generate.py:2902-2926 (uniffi_facade): the UniFFI verb surface (every facade row; a definition row is
/// refused) and its generated types: `(facade_generated.rs, facade_types_generated.rs)`. `facade_rows` is
/// outputs()'s local of that name (generate.py:2242).
pub(crate) fn uniffi_facade(
    generator: &mut Generator,
    facade_rows: &[RowId],
) -> Result<(String, String), GenerateError> {
    // rows = facade_rows + [row for row in DEFINITIONS if 'uniffi' in row]
    let mut rows: Vec<RowId> = facade_rows.to_vec();
    rows.extend(
        generator
            .definitions
            .iter()
            .copied()
            .filter(|&id| generator.rows[id].contains_key("uniffi")),
    );
    // any('uniffi' in row for row in ROWS if row not in facade_rows): neither test can raise, so their order is
    // free.
    if generator.callable_rows.iter().any(|&id| {
        generator.rows[id].contains_key("uniffi") && !holds_row(generator, facade_rows, id)
    }) {
        return Err(GenerateError::value(
            "only a facade row carries a uniffi signature",
        ));
    }
    // UniffiTypes(INVENTORY, uniffi_taken()): the files are read before the cycles are found.
    let taken = uniffi_taken(&generator.root)?;
    let inventory = generator.inventory.as_mut().ok_or_else(|| {
        GenerateError::exception(
            "RuntimeError",
            "INVENTORY is not built (Generator::rows_only)",
        )
    })?;
    let mut types = UniffiTypes::new(inventory, &taken)?;
    let mut census = Census::new();
    let mut arms = String::new();
    for &id in &rows {
        arms.push_str(&uniffi_export(
            &generator.rows[id],
            &mut types,
            &mut census,
        )?);
    }
    for &(text, name) in UNIFFI_LENS_ROOTS {
        if types.root(text)?.as_deref() != Some(name) {
            return Err(GenerateError::value(format!(
                "{text}: lib.rs crosses it as the generated record {name}, which it does not read as"
            )));
        }
    }
    for &text in UNIFFI_STREAM_ROOTS {
        if types.root(text)?.is_none() {
            return Err(GenerateError::value(format!(
                "{text}: no generated UniFFI record reads it"
            )));
        }
    }
    let count = |sides: &[&str]| census.get(sides).map_or(0, Vec::len);
    let mut wire_rows = Vec::new();
    let mut sorted: Vec<(&Vec<&'static str>, &Vec<Value>)> = census.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (sides, names) in sorted {
        if !sides.contains(&"wire") {
            continue;
        }
        let input = if sides.first() == Some(&"wire") {
            "input"
        } else {
            ""
        };
        let and = if sides.as_slice() == ["wire", "wire"] {
            " and "
        } else {
            ""
        };
        let result = if sides.get(1) == Some(&"wire") {
            "result"
        } else {
            ""
        };
        for name in names {
            wire_rows.push(format!("{} ({input}{and}{result})", name.str()));
        }
    }
    let mut leaves: Vec<(&String, &String)> = types.leaves.iter().collect();
    leaves.sort_by(|a, b| a.0.cmp(b.0));
    let leaves: Vec<String> = leaves
        .into_iter()
        .map(|(at, why)| format!("{at} ({why})"))
        .collect();
    let none_or = |parts: Vec<String>| {
        if parts.is_empty() {
            "none".to_owned()
        } else {
            parts.join(", ")
        }
    };
    let lines = vec![
        format!(
            "UniFFI census: {} facade rows, {} generated types.",
            facade_rows.len(),
            types.items.len()
        ),
        format!(
            "Hand-written records in and out: {}; typed arguments or a hand-written input with a generated result: {}; \
             a generated input with a hand-written result: {}; generated in and out: {}.",
            count(&["typed", "typed"]),
            count(&["typed", "generated"]),
            count(&["generated", "typed"]),
            count(&["generated", "generated"])
        ),
        format!("WireJson rows: {}.", none_or(wire_rows)),
        format!(
            "WireJson leaves inside the generated types, past each serde_json::Value: {}.",
            none_or(leaves)
        ),
    ];
    Ok((
        format!("{HEADER}export_facade! {{\n{arms}}}\n"),
        types.render(HEADER, &lines),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // print(repr(v), err(dict, v)) of <workspace>/.claude/jobs/51b185fd/tmp/g3/probe_uniffi.py on nelly (3.14.7).
    #[test]
    fn dict_of_is_pythons_dict() {
        let parse = |text: &str| crate::py::json::loads(text).expect("json");
        let shown = |dict: &PyDict| {
            let parts: Vec<String> = dict
                .iter()
                .map(|(k, v)| format!("{}: {}", k.repr(), v.repr()))
                .collect();
            format!("{{{}}}", parts.join(", "))
        };
        let cases: &[(&str, &str)] = &[
            (r#"{"a": "T"}"#, "{'a': 'T'}"),
            (r#"[["a", "T"], ["b", "U"]]"#, "{'a': 'T', 'b': 'U'}"),
            (r#"[["a", "T"], ["a", "V"]]"#, "{'a': 'V'}"),
            (r#"["ab"]"#, "{'a': 'b'}"),
            (
                r#"["abc"]"#,
                "ValueError: dictionary update sequence element #0 has length 3; 2 is required",
            ),
            ("[1]", "TypeError: object is not iterable"),
            (
                "[[[1], 2]]",
                "TypeError: cannot use 'list' as a dict key (unhashable type: 'list')",
            ),
            (
                r#""ab""#,
                "ValueError: dictionary update sequence element #0 has length 1; 2 is required",
            ),
            (r#""""#, "{}"),
            ("5", "TypeError: 'int' object is not iterable"),
            ("null", "TypeError: 'NoneType' object is not iterable"),
            ("true", "TypeError: 'bool' object is not iterable"),
            (r#"[{"x": 1, "y": 2}]"#, "{'x': 'y'}"),
            (
                r#"[["a"]]"#,
                "ValueError: dictionary update sequence element #0 has length 1; 2 is required",
            ),
            ("[]", "{}"),
            (r#"[[1, "T"], [1.0, "U"], [true, "V"]]"#, "{1: 'V'}"),
        ];
        for &(input, expected) in cases {
            let got =
                dict_of(&parse(input)).map_or_else(|error| error.to_string(), |dict| shown(&dict));
            assert_eq!(got, expected, "{input}");
        }
    }

    // On nelly (Python 3.14.7): sig = json.loads('{"args": [[NaN, "bool"], [NaN, "bool"]], ...}'); dict(sig['args'])
    // has one key; json.loads('[NaN]') == json.loads('[NaN]') is True (one decoder object); the declaration of that
    // one key is `TypeError: unsupported operand type(s) for +: 'float' and 'str'`; the pairs [[1, "a"], [NaN, "b"],
    // [1.0, "c"], [NaN, "d"], [true, "e"]] give {1: 'e', nan: 'd'}.
    #[test]
    fn decoded_nans_are_one_object() {
        let parse = |text: &str| crate::py::json::loads(text).expect("json");
        let one = dict_of(&parse("[[NaN, \"bool\"], [NaN, \"bool\"]]")).expect("a dict");
        assert_eq!(one.len(), 1);
        assert_eq!(
            declaration(&one).map_err(|error| error.to_string()),
            Err("TypeError: unsupported operand type(s) for +: 'float' and 'str'".to_owned())
        );
        let mixed = dict_of(&parse(
            "[[1, \"a\"], [NaN, \"b\"], [1.0, \"c\"], [NaN, \"d\"], [true, \"e\"]]",
        ))
        .expect("a dict");
        let shown: Vec<String> = mixed
            .iter()
            .map(|(k, v)| format!("{}: {}", k.repr(), v.repr()))
            .collect();
        assert_eq!(shown, ["1: 'e'", "nan: 'd'"]);
        assert!(json_eq(&parse("[NaN]"), &parse("[NaN]")));
        assert!(json_eq(
            &parse("{\"a\": NaN, \"b\": [NaN, 1]}"),
            &parse("{\"b\": [NaN, 1], \"a\": NaN}")
        ));
        assert!(!json_eq(&parse("[NaN]"), &parse("[1.0]")));
    }

    // print(repr(a), repr(b), err(lambda a, b: a + b, a, b)) and the join cases of probe_uniffi.py.
    #[test]
    fn declarations_and_joins_refuse_as_python() {
        let text = |s: &str| Value::Str(s.to_owned());
        assert_eq!(
            declaration(&vec![(text("a"), text("T")), (text("b"), text("U"))]).as_deref(),
            Ok("a: T, b: U")
        );
        assert_eq!(
            declaration(&vec![(Value::Int(5), text("T"))]).map_err(|error| error.to_string()),
            Err("TypeError: unsupported operand type(s) for +: 'int' and 'str'".to_owned())
        );
        assert_eq!(
            declaration(&vec![(text("a"), Value::None)]).map_err(|error| error.to_string()),
            Err("TypeError: can only concatenate str (not \"NoneType\") to str".to_owned())
        );
        assert_eq!(
            join_keys(&vec![
                (text("a"), Value::None),
                (Value::Int(5), Value::None)
            ])
            .map_err(|error| error.to_string()),
            Err("TypeError: sequence item 1: expected str instance, int found".to_owned())
        );
    }

    #[test]
    fn uniffi_record_reads_through_option_and_vec() {
        assert_eq!(
            uniffi_record("Option<Vec<crate::memory::ClaimInput>>", UNIFFI_INPUTS).as_deref(),
            Some("Option<Vec<ClaimInput>>")
        );
        assert_eq!(
            uniffi_record("Vec<crate::memory::Nope>", UNIFFI_INPUTS),
            None
        );
        assert_eq!(
            uniffi_record("crate::task_verb::sdk::BlobContent", UNIFFI_RESULTS).as_deref(),
            Some("Vec<u8>")
        );
        assert_eq!(uniffi_record("Option<>", UNIFFI_RESULTS), None);
    }
}
