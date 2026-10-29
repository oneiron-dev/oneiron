//! The compiled model's functions on Core ML (FIX 6755 slice 2c, contract
//! rev 3 B2), built on macOS aarch64 only.
//!
//! The row's extraction is loaded once per turn function, each with its
//! own configuration: compute units CPU and Neural Engine, and the
//! function's name. The first load on a path compiles the function for the
//! Neural Engine, tens of seconds each; the OS caches that compile by path,
//! so the path is the stable extraction, never a copy. Each function's
//! description must be the row's: the same feature names, each a
//! multi-array of the row's type and of its shape in that function, or a
//! flexible shape consistent with it.
//!
//! Every model, configuration, array and provider is this thread's, held
//! as a `Retained` and never sent: the worker that owns this set stays on
//! the thread that loaded it. Each load and prediction runs in its own
//! autorelease pool ([`arrays`]), and only copied Rust values leave a
//! prediction.

use std::path::Path;

use objc2::rc::{Retained, autoreleasepool};
use objc2_core_ml::{
    MLComputeUnits, MLFeatureDescription, MLFeatureType, MLModel, MLModelConfiguration,
    MLMultiArrayDataType,
};
use objc2_foundation::{NSDictionary, NSError, NSString, NSURL};

use super::super::bundle::TensorSpec;
use super::super::dispatcher::Fault;
use super::decode::Outputs;
use super::{LOAD_FAILED, MASK, Models, X, arrays, down};

/// Down, `coreml_io_mismatch:<feature>`: a function's description differs
/// from the row's tensor of that name, or names one the row does not.
const IO_MISMATCH: &str = "coreml_io_mismatch";

/// The model's loaded functions, in the row's turn order.
pub(super) struct ModelSet {
    /// The extraction's directory URL.
    url: Retained<NSURL>,
    functions: Vec<Function>,
}

/// One loaded function, with its inputs' shapes.
struct Function {
    model: Retained<MLModel>,
    x: Vec<usize>,
    mask: Vec<usize>,
}

impl ModelSet {
    /// The compiled model at `model`, the row's verified `.mlmodelc`
    /// extraction, no function loaded yet.
    pub(super) fn open(model: &Path) -> Result<Self, Fault> {
        let Some(url) = NSURL::from_directory_path(model) else {
            return Err(down(&format!("{LOAD_FAILED}:model")));
        };
        Ok(Self {
            url,
            functions: Vec::new(),
        })
    }
}

impl Models for ModelSet {
    fn load(
        &mut self,
        name: &str,
        tokens: usize,
        inputs: &[TensorSpec],
        outputs: &[TensorSpec],
    ) -> Result<(), Fault> {
        let model = autoreleasepool(|_| compile(&self.url, name));
        let model = model.map_err(|error| {
            tracing::warn!(
                function = name,
                code = error.code(),
                error = %error.localizedDescription(),
                "oneironer coreml function did not load"
            );
            down(&format!("{LOAD_FAILED}:{name}"))
        })?;
        // SAFETY: the description of a model this thread loaded, read only.
        let description = unsafe { model.modelDescription() };
        // SAFETY: reads of that description.
        let held = unsafe { description.inputDescriptionsByName() };
        described(&held, inputs, tokens)?;
        // SAFETY: as for the inputs.
        let held = unsafe { description.outputDescriptionsByName() };
        described(&held, outputs, tokens)?;
        let x = input_shape(inputs, X, tokens)?;
        let mask = input_shape(inputs, MASK, tokens)?;
        self.functions.push(Function { model, x, mask });
        Ok(())
    }

    fn predict(
        &self,
        function: usize,
        x: &[f32],
        mask: &[i32],
        outputs: &mut Outputs,
    ) -> anyhow::Result<()> {
        let Some(function) = self.functions.get(function) else {
            anyhow::bail!("no such core ml function");
        };
        let Function {
            model,
            x: x_shape,
            mask: mask_shape,
        } = function;
        arrays::predict(model, x_shape, x, mask_shape, mask, outputs)
    }
}

/// Loads function `name` of the model at `url` for the CPU and the Neural
/// Engine, blocking this thread until it is compiled and loaded.
fn compile(url: &NSURL, name: &str) -> Result<Retained<MLModel>, Retained<NSError>> {
    let function: &NSString = &NSString::from_str(name);
    // SAFETY: a fresh configuration this thread alone holds, set before any
    // load reads it. `functionName` exists from macOS 15.0, the row's
    // `min_os`, which admission checked.
    let configuration = unsafe {
        let configuration = MLModelConfiguration::new();
        configuration.setComputeUnits(MLComputeUnits::CPUAndNeuralEngine);
        configuration.setFunctionName(Some(function));
        configuration
    };
    // SAFETY: `url` names the verified extraction and the configuration is
    // complete; the call returns the model or the error that refused it.
    unsafe { MLModel::modelWithContentsOfURL_configuration_error(url, &configuration) }
}

/// Checks Core ML's description of a function's features, `held`, against
/// the row's `specs` in a function of `tokens`. A down fault names the
/// first feature that differs or that the row does not declare.
fn described(
    held: &NSDictionary<NSString, MLFeatureDescription>,
    specs: &[TensorSpec],
    tokens: usize,
) -> Result<(), Fault> {
    let differs = |name: &str| down(&format!("{IO_MISMATCH}:{name}"));
    for spec in specs {
        let feature = held.objectForKey(&NSString::from_str(spec.name()));
        if !feature.is_some_and(|feature| same(&feature, spec, tokens)) {
            return Err(differs(spec.name()));
        }
    }
    for key in held.allKeys().to_vec() {
        let name = key.to_string();
        if specs.iter().all(|spec| spec.name() != name) {
            return Err(differs(&name));
        }
    }
    Ok(())
}

/// Input `name`'s shape in a function of `tokens`.
fn input_shape(inputs: &[TensorSpec], name: &str, tokens: usize) -> Result<Vec<usize>, Fault> {
    match inputs.iter().find(|spec| spec.name() == name) {
        Some(spec) => Ok(resolved(spec, tokens)),
        None => Err(down(&format!("{IO_MISMATCH}:{name}"))),
    }
}

/// Whether `feature` is a multi-array of `spec`'s type, of its shape in a
/// function of `tokens`. An empty reported shape declares nothing and
/// matches; a flexible dimension matches any size. Only an explicit,
/// different shape mismatches.
fn same(feature: &MLFeatureDescription, spec: &TensorSpec, tokens: usize) -> bool {
    // SAFETY: reads of a description the loaded model owns.
    let (kind, constraint) = unsafe { (feature.r#type(), feature.multiArrayConstraint()) };
    let Some(constraint) = constraint else {
        return false;
    };
    // SAFETY: reads of that constraint.
    let (dtype, shape) = unsafe { (constraint.dataType(), constraint.shape()) };
    if kind != MLFeatureType::MultiArray || data_type(spec.dtype()) != Some(dtype) {
        return false;
    }
    let expected = resolved(spec, tokens);
    let reported: Vec<isize> = shape
        .to_vec()
        .iter()
        .map(|number| number.as_isize())
        .collect();
    reported.is_empty()
        || reported.len() == expected.len()
            && reported
                .iter()
                .zip(&expected)
                .all(|(&got, &want)| got < 0 || got as usize == want)
}

/// `spec`'s shape in a function of `tokens`: `L` is its tokens.
fn resolved(spec: &TensorSpec, tokens: usize) -> Vec<usize> {
    spec.dims()
        .into_iter()
        .map(|size| size.unwrap_or(tokens))
        .collect()
}

/// Core ML's array type for a row's dtype.
fn data_type(dtype: &str) -> Option<MLMultiArrayDataType> {
    match dtype {
        "float16" => Some(MLMultiArrayDataType::Float16),
        "float32" => Some(MLMultiArrayDataType::Float32),
        "int32" => Some(MLMultiArrayDataType::Int32),
        _ => None,
    }
}
