//! One Core ML prediction's arrays (FIX 6755 slice 2c, contract rev 3 B2),
//! built on macOS aarch64 only.
//!
//! Every array is Core ML's own: allocated by Core ML in a shape, then
//! checked for its type, its shape, first-major strides and an aligned
//! buffer before one copy goes in or out of it. An input is filled from
//! the call's first-major values. An output must be float16; it is moved
//! by Core ML's own transfer into a heap array of its shape, so whatever
//! backs it (a pixel buffer, a Neural Engine surface) is read through Core
//! ML, and that copy's bits leave with their shape and strides. The arrays
//! and the provider holding them live through the synchronous prediction,
//! inside its autorelease pool.

use std::ptr::NonNull;

use objc2::AnyThread;
use objc2::rc::{Retained, autoreleasepool};
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2_core_ml::{
    MLDictionaryFeatureProvider, MLFeatureProvider, MLFeatureValue, MLModel, MLMultiArray,
    MLMultiArrayDataType,
};
use objc2_foundation::{NSArray, NSDictionary, NSError, NSNumber, NSString};

use super::decode::{HalfArray, Outputs};
use super::{LOGITS, MASK, PROJ, X};

/// An element type a Core ML array holds, by Core ML's name for it.
trait Scalar: Copy {
    const TYPE: MLMultiArrayDataType;
}

impl Scalar for f32 {
    const TYPE: MLMultiArrayDataType = MLMultiArrayDataType::Float32;
}

impl Scalar for i32 {
    const TYPE: MLMultiArrayDataType = MLMultiArrayDataType::Int32;
}

/// A float16, by its bits.
impl Scalar for u16 {
    const TYPE: MLMultiArrayDataType = MLMultiArrayDataType::Float16;
}

/// Where a checked array's elements start, how many it holds, and its
/// strides.
struct Layout<T> {
    data: NonNull<T>,
    count: usize,
    strides: Vec<usize>,
}

/// One prediction of `model` on `x` and `mask`, first-major in
/// `x_shape` and `mask_shape`, its logits and projection copied into
/// `outputs`.
pub(super) fn predict(
    model: &MLModel,
    x_shape: &[usize],
    x: &[f32],
    mask_shape: &[usize],
    mask: &[i32],
    outputs: &mut Outputs,
) -> anyhow::Result<()> {
    autoreleasepool(|_| {
        let x = filled(x_shape, x)?;
        let mask = filled(mask_shape, mask)?;
        let provider = provider(&x, &mask)?;
        let input: &ProtocolObject<dyn MLFeatureProvider> = ProtocolObject::from_ref(&*provider);
        // SAFETY: the provider holds both arrays until the synchronous call
        // returns; the answer is Core ML's own.
        let answer = unsafe { model.predictionFromFeatures_error(input) };
        let answer = answer.map_err(|error| failed("prediction", &error))?;
        read(&answer, LOGITS, &mut outputs.logits)?;
        read(&answer, PROJ, &mut outputs.proj)
    })
}

/// A Core ML array of `shape` holding `values`, first-major, of `T`'s type.
fn filled<T: Scalar>(shape: &[usize], values: &[T]) -> anyhow::Result<Retained<MLMultiArray>> {
    let array = allocated(shape, T::TYPE)?;
    let layout = layout::<T>(&array, shape)?;
    anyhow::ensure!(
        values.len() == layout.count,
        "a core ml input is not its shape's length"
    );
    // SAFETY: `layout` checked that `count` aligned elements of `T` start at
    // `data` in the array's own buffer, first-major as `values` are; the
    // array outlives this copy, and nothing else touches its buffer.
    unsafe { std::ptr::copy_nonoverlapping(values.as_ptr(), layout.data.as_ptr(), values.len()) };
    Ok(array)
}

/// The prediction's input provider: `x` and `attention_mask` by name.
fn provider(
    x: &MLMultiArray,
    mask: &MLMultiArray,
) -> anyhow::Result<Retained<MLDictionaryFeatureProvider>> {
    let (x_name, mask_name) = (NSString::from_str(X), NSString::from_str(MASK));
    // SAFETY: wraps an array this thread holds; the value retains it.
    let x = unsafe { MLFeatureValue::featureValueWithMultiArray(x) };
    // SAFETY: as for `x`.
    let mask = unsafe { MLFeatureValue::featureValueWithMultiArray(mask) };
    let keys: [&NSString; 2] = [&x_name, &mask_name];
    let values: [Retained<AnyObject>; 2] = [x.into(), mask.into()];
    let features: Retained<NSDictionary<NSString, AnyObject>> =
        NSDictionary::from_retained_objects(&keys, &values);
    let fresh = MLDictionaryFeatureProvider::alloc();
    // SAFETY: a fresh provider over feature values keyed by their names, as
    // Core ML reads them.
    let made = unsafe { MLDictionaryFeatureProvider::initWithDictionary_error(fresh, &features) };
    made.map_err(|error| failed("input", &error))
}

/// Copies output `name` of `answer` into `into`, as the module says.
fn read(
    answer: &ProtocolObject<dyn MLFeatureProvider>,
    name: &str,
    into: &mut HalfArray,
) -> anyhow::Result<()> {
    let key: &NSString = &NSString::from_str(name);
    // SAFETY: a lookup on the prediction's own outputs.
    let value = unsafe { answer.featureValueForName(key) };
    let value = value.ok_or_else(|| anyhow::anyhow!("core ml gave no {name} output"))?;
    // SAFETY: a read of that value.
    let source = unsafe { value.multiArrayValue() };
    let source = source.ok_or_else(|| anyhow::anyhow!("core ml output {name} is no array"))?;
    // SAFETY: reads of the output array.
    let (kind, shape) = unsafe { (source.dataType(), source.shape()) };
    anyhow::ensure!(
        kind == MLMultiArrayDataType::Float16,
        "core ml output {name} is not float16"
    );
    let shape = sizes(&shape);
    let shape = shape.ok_or_else(|| anyhow::anyhow!("core ml output {name} has a negative size"))?;
    let copy = allocated(&shape, MLMultiArrayDataType::Float16)?;
    // SAFETY: both arrays are this thread's, the copy of the source's shape
    // and type; Core ML's transfer, from macOS 15.0, the row's `min_os`,
    // writes every element of it by both arrays' strides.
    unsafe { source.transferToMultiArray(&copy) };
    let layout = layout::<u16>(&copy, &shape)?;
    // SAFETY: `layout` checked that `count` aligned float16 elements start
    // at `data` in the copy's own buffer, which the transfer filled; they
    // are only read, while `copy` lives.
    let bits = unsafe { std::slice::from_raw_parts(layout.data.as_ptr(), layout.count) };
    into.bits.clear();
    into.bits.extend_from_slice(bits);
    into.shape = shape;
    into.strides = layout.strides;
    Ok(())
}

/// A fresh Core ML array of `shape` and `kind`, its contents unset.
fn allocated(
    shape: &[usize],
    kind: MLMultiArrayDataType,
) -> anyhow::Result<Retained<MLMultiArray>> {
    let sizes: Vec<_> = shape.iter().copied().map(NSNumber::new_usize).collect();
    let shape = NSArray::from_retained_slice(&sizes);
    let fresh = MLMultiArray::alloc();
    // SAFETY: a fresh allocation, initialized once with sizes and a type
    // Core ML defines; Core ML lays it out first-major.
    let array = unsafe { MLMultiArray::initWithShape_dataType_error(fresh, &shape, kind) };
    array.map_err(|error| failed("array", &error))
}

/// `array`'s elements as `T`, once its type is `T`'s, its shape `shape`, its
/// strides first-major and its buffer aligned for `T`: then `count` elements
/// of `T` from `data` are the array's own, in first-major order.
#[allow(
    deprecated,
    reason = "an array this thread allocated on the heap: its pointer needs no access handler"
)]
fn layout<T: Scalar>(array: &MLMultiArray, shape: &[usize]) -> anyhow::Result<Layout<T>> {
    // SAFETY: reads of an array this thread holds.
    let (kind, held, strides) = unsafe { (array.dataType(), array.shape(), array.strides()) };
    // SAFETY: as above.
    let count = usize::try_from(unsafe { array.count() })?;
    let held = sizes(&held);
    let strides = sizes(&strides).unwrap_or_default();
    anyhow::ensure!(
        kind == T::TYPE
            && held.as_deref() == Some(shape)
            && strides == first_major(shape)
            && count == shape.iter().product::<usize>(),
        "a core ml array is not laid out as its shape"
    );
    // SAFETY: the address of the array's buffer, used only while `array`
    // lives.
    let data = unsafe { array.dataPointer() }.cast::<T>();
    anyhow::ensure!(
        data.as_ptr().is_aligned(),
        "a core ml array is not aligned for its type"
    );
    Ok(Layout {
        data,
        count,
        strides,
    })
}

/// The first-major strides of `shape`, in elements.
fn first_major(shape: &[usize]) -> Vec<usize> {
    let mut strides = Vec::with_capacity(shape.len());
    let mut stride = 1;
    for size in shape.iter().rev() {
        strides.push(stride);
        stride *= size;
    }
    strides.reverse();
    strides
}

/// Core ML's sizes or strides as `usize`s; `None` when one is negative.
pub(super) fn sizes(numbers: &NSArray<NSNumber>) -> Option<Vec<usize>> {
    numbers
        .to_vec()
        .iter()
        .map(|number| usize::try_from(number.as_isize()).ok())
        .collect()
}

/// A Core ML call that refused, by its error code alone.
fn failed(what: &str, error: &NSError) -> anyhow::Error {
    anyhow::anyhow!("core ml {what} failed: code {}", error.code())
}
