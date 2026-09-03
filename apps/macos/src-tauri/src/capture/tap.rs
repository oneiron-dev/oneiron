//! The far-end leg: a Core Audio process tap (macOS 14.2+).
//!
//! `AudioHardwareCreateProcessTap` hands back a tap object that is not itself
//! readable; audio only flows once the tap is a member of an aggregate device
//! with an IOProc on it. That three-step shape — describe, tap, aggregate — is
//! the whole module, and every object it creates is torn down by [`Drop`], so
//! a failure halfway through leaves nothing behind in the HAL.
//!
//! The tap is created **unmuted**: the recorder listens to what the machine is
//! playing, it never changes what the operator hears.
//!
//! `coreaudio-rs` 0.14 exposes none of this — `CATapDescription` is an
//! Objective-C class, so the description can only be built through the ObjC
//! runtime. These are the direct `objc2` bindings.

use std::ffi::c_void;
use std::ptr::{self, NonNull};

use objc2::AnyThread;
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2_core_audio::{
    AudioDeviceCreateIOProcID, AudioDeviceDestroyIOProcID, AudioDeviceIOProcID, AudioDeviceStart,
    AudioDeviceStop, AudioHardwareCreateAggregateDevice, AudioHardwareCreateProcessTap,
    AudioHardwareDestroyAggregateDevice, AudioHardwareDestroyProcessTap, AudioObjectID,
    CATapDescription, kAudioAggregateDeviceIsPrivateKey, kAudioAggregateDeviceIsStackedKey,
    kAudioAggregateDeviceNameKey, kAudioAggregateDeviceTapAutoStartKey,
    kAudioAggregateDeviceTapListKey, kAudioAggregateDeviceUIDKey, kAudioObjectPropertyScopeGlobal,
    kAudioSubTapDriftCompensationKey, kAudioSubTapUIDKey, kAudioTapPropertyFormat,
};
use objc2_core_audio_types::{AudioBufferList, AudioStreamBasicDescription, AudioTimeStamp};
use objc2_core_foundation::CFDictionary;
use objc2_foundation::{NSArray, NSDictionary, NSNumber, NSString, NSUUID};

use super::hal::{address, read_property};
use super::{CaptureError, PcmQueue, Result};

/// What the tap is called in Audio MIDI Setup while it exists.
const TAP_NAME: &str = "Oneiron Recorder";

/// `kAudioFormatFlagIsFloat`. The binding crate does not export the format
/// flags; this is bit 0 of `mFormatFlags` in the Core Audio headers.
const FORMAT_FLAG_IS_FLOAT: u32 = 1;

/// What the IOProc needs, kept alive for exactly as long as the IOProc is
/// registered.
struct TapContext {
    queue: PcmQueue,
}

/// A running system-audio tap feeding a [`PcmQueue`].
pub struct SystemAudioTap {
    tap: AudioObjectID,
    aggregate: AudioObjectID,
    proc_id: AudioDeviceIOProcID,
    context: *mut TapContext,
    sample_rate: u32,
}

impl SystemAudioTap {
    /// Taps everything the machine is playing and starts feeding `queue`.
    ///
    /// # Errors
    ///
    /// [`CaptureError::CoreAudio`] with the failing call when the HAL refuses
    /// — most often because the operator has not granted audio-recording
    /// permission. The microphone leg keeps running either way.
    pub fn start(queue: PcmQueue) -> Result<Self> {
        // Built incrementally so that an early `?` drops a partially created
        // tap and `Drop` unwinds exactly the objects that exist.
        let mut tap = Self {
            tap: 0,
            aggregate: 0,
            proc_id: None,
            context: ptr::null_mut(),
            sample_rate: 0,
        };

        let uuid = NSUUID::new();
        tap.tap = create_process_tap(&uuid)?;
        tap.sample_rate = tap_sample_rate(tap.tap)?;
        tap.aggregate = create_aggregate_device(&uuid)?;
        tap.context = Box::into_raw(Box::new(TapContext { queue }));

        let mut proc_id: AudioDeviceIOProcID = None;
        // SAFETY: `tap.aggregate` is a live aggregate device, `tap.context` is
        // the box just leaked above (freed only in `Drop`, after the IOProc is
        // destroyed), and `proc_id` is a live local for the call.
        let status = unsafe {
            AudioDeviceCreateIOProcID(
                tap.aggregate,
                Some(far_end_io_proc),
                tap.context.cast::<c_void>(),
                NonNull::from(&mut proc_id),
            )
        };
        core_audio_ok("AudioDeviceCreateIOProcID", status)?;
        tap.proc_id = proc_id;

        // SAFETY: the IOProc was just registered on this device.
        let status = unsafe { AudioDeviceStart(tap.aggregate, tap.proc_id) };
        core_audio_ok("AudioDeviceStart", status)?;
        Ok(tap)
    }

    /// Frame rate the tap delivers, as the HAL reported it.
    #[must_use]
    pub const fn sample_rate(&self) -> u32 {
        self.sample_rate
    }
}

impl Drop for SystemAudioTap {
    fn drop(&mut self) {
        // SAFETY: each object is destroyed at most once, in the order the HAL
        // requires (stop the IO before unregistering it, unregister before
        // destroying the device that carries it), and the context box outlives
        // the IOProc that reads it.
        unsafe {
            if self.proc_id.is_some() {
                AudioDeviceStop(self.aggregate, self.proc_id);
                AudioDeviceDestroyIOProcID(self.aggregate, self.proc_id);
            }
            if self.aggregate != 0 {
                AudioHardwareDestroyAggregateDevice(self.aggregate);
            }
            if self.tap != 0 {
                AudioHardwareDestroyProcessTap(self.tap);
            }
            if !self.context.is_null() {
                drop(Box::from_raw(self.context));
            }
        }
    }
}

/// A global tap: every process's output, mixed to stereo, minus nothing. The
/// UUID is set by us so the aggregate device below can name this tap without
/// reading it back out of the HAL.
fn create_process_tap(uuid: &NSUUID) -> Result<AudioObjectID> {
    // SAFETY: `CATapDescription`'s initializers are the documented way to
    // build one, and the array of excluded processes is empty by design.
    let description = unsafe {
        let description = CATapDescription::initStereoGlobalTapButExcludeProcesses(
            CATapDescription::alloc(),
            &NSArray::new(),
        );
        description.setName(&NSString::from_str(TAP_NAME));
        description.setUUID(uuid);
        description
    };

    let mut tap: AudioObjectID = 0;
    // SAFETY: the description is live for the call and `tap` is a live local.
    let status = unsafe { AudioHardwareCreateProcessTap(Some(&description), &raw mut tap) };
    core_audio_ok("AudioHardwareCreateProcessTap", status)?;
    Ok(tap)
}

/// The tap's own stream format, which is also the rate the far end arrives at.
fn tap_sample_rate(tap: AudioObjectID) -> Result<u32> {
    let format: AudioStreamBasicDescription = read_property(
        tap,
        address(kAudioTapPropertyFormat, kAudioObjectPropertyScopeGlobal),
        "kAudioTapPropertyFormat",
    )?;
    if format.mBitsPerChannel != 32 || format.mFormatFlags & FORMAT_FLAG_IS_FLOAT == 0 {
        return Err(CaptureError::Audio(format!(
            "process tap delivers {} bit samples, not 32-bit float",
            format.mBitsPerChannel
        )));
    }
    let rate = format.mSampleRate;
    if !rate.is_finite() || rate <= 0.0 {
        return Err(CaptureError::Audio(
            "process tap reports no rate".to_owned(),
        ));
    }
    Ok(rate as u32)
}

/// A private aggregate device whose only member is the tap. Private keeps it
/// out of every other app's device list; auto-start means the tap runs as soon
/// as the IOProc does.
fn create_aggregate_device(tap_uuid: &NSUUID) -> Result<AudioObjectID> {
    let sub_tap = NSDictionary::from_slices::<NSString>(
        &[
            &*key(kAudioSubTapUIDKey),
            &*key(kAudioSubTapDriftCompensationKey),
        ],
        &[
            &*retain_object(tap_uuid.UUIDString()),
            &*retain_object(NSNumber::new_bool(true)),
        ],
    );
    let tap_list = NSArray::from_retained_slice(&[sub_tap]);

    let description = NSDictionary::from_slices::<NSString>(
        &[
            &*key(kAudioAggregateDeviceNameKey),
            &*key(kAudioAggregateDeviceUIDKey),
            &*key(kAudioAggregateDeviceIsPrivateKey),
            &*key(kAudioAggregateDeviceIsStackedKey),
            &*key(kAudioAggregateDeviceTapAutoStartKey),
            &*key(kAudioAggregateDeviceTapListKey),
        ],
        &[
            &*retain_object(NSString::from_str(TAP_NAME)),
            &*retain_object(NSUUID::new().UUIDString()),
            &*retain_object(NSNumber::new_bool(true)),
            &*retain_object(NSNumber::new_bool(false)),
            &*retain_object(NSNumber::new_bool(true)),
            &*retain_object(tap_list),
        ],
    );

    let mut device: AudioObjectID = 0;
    // SAFETY: `NSDictionary` is toll-free bridged to `CFDictionary`, the
    // dictionary outlives the call, and `device` is a live local.
    let status = unsafe {
        let cf = &*Retained::as_ptr(&description).cast::<CFDictionary>();
        AudioHardwareCreateAggregateDevice(cf, NonNull::from(&mut device))
    };
    core_audio_ok("AudioHardwareCreateAggregateDevice", status)?;
    Ok(device)
}

/// The aggregate-device description keys are C strings in the SDK; the
/// dictionary wants `NSString`s.
fn key(name: &std::ffi::CStr) -> Retained<NSString> {
    NSString::from_str(&name.to_string_lossy())
}

/// Erases a concrete Foundation type to the dictionary's heterogeneous value
/// type.
fn retain_object<T: objc2::Message>(value: Retained<T>) -> Retained<AnyObject> {
    // SAFETY: every Foundation object is an `AnyObject`; this is an upcast,
    // and the retain count is carried across unchanged.
    unsafe { Retained::cast_unchecked::<AnyObject>(value) }
}

/// Called by the HAL on its own realtime thread, once per IO cycle.
///
/// The far end is downmixed to its first channel: the recorder needs one
/// reference of what was playing, not a stereo copy of it.
unsafe extern "C-unwind" fn far_end_io_proc(
    _device: AudioObjectID,
    _now: NonNull<AudioTimeStamp>,
    input: NonNull<AudioBufferList>,
    _input_time: NonNull<AudioTimeStamp>,
    _output: NonNull<AudioBufferList>,
    _output_time: NonNull<AudioTimeStamp>,
    client: *mut c_void,
) -> i32 {
    if client.is_null() {
        return 0;
    }
    // SAFETY: `client` is the `TapContext` leaked in `start`, which lives
    // until `Drop` has unregistered this IOProc.
    let context = unsafe { &*client.cast::<TapContext>() };
    // SAFETY: the HAL hands over a buffer list valid for this cycle.
    let list = unsafe { input.as_ref() };
    if list.mNumberBuffers == 0 {
        return 0;
    }

    let buffer = list.mBuffers[0];
    let channels = (buffer.mNumberChannels as usize).max(1);
    let count = buffer.mDataByteSize as usize / std::mem::size_of::<f32>();
    if buffer.mData.is_null() || count == 0 {
        return 0;
    }
    // SAFETY: the buffer reports `mDataByteSize` bytes of the tap's 32-bit
    // float format at `mData`, valid for the duration of this callback, and
    // the samples are copied out before returning.
    let samples = unsafe { std::slice::from_raw_parts(buffer.mData.cast::<f32>(), count) };
    context
        .queue
        .extend(samples.iter().step_by(channels).copied().map(pcm_from_f32));
    0
}

fn pcm_from_f32(sample: f32) -> i16 {
    let scaled = sample.clamp(-1.0, 1.0) * f32::from(i16::MAX);
    scaled as i16
}

fn core_audio_ok(call: &'static str, status: i32) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(CaptureError::CoreAudio { call, status })
    }
}
