//! The Core Audio HAL border.
//!
//! Every property read the recorder does goes through one function, so the
//! raw-pointer surface of `AudioObjectGetPropertyData` is written once and
//! reviewed once instead of being open-coded at each call site.

use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::ptr::{self, NonNull};

use objc2_core_audio::{
    AudioObjectGetPropertyData, AudioObjectID, AudioObjectPropertyAddress,
    kAudioObjectPropertyElementMain,
};

use super::{CaptureError, Result};

/// A property address on the main element.
pub(crate) const fn address(selector: u32, scope: u32) -> AudioObjectPropertyAddress {
    AudioObjectPropertyAddress {
        mSelector: selector,
        mScope: scope,
        mElement: kAudioObjectPropertyElementMain,
    }
}

/// Reads one fixed-size property value from `object`.
///
/// `T` must be a plain-data type whose layout matches what the HAL writes for
/// `address` — the caller states that by choosing the type, and the size
/// check below refuses the read when the HAL disagrees, so a mismatched
/// property never leaves a half-initialized value behind.
pub(crate) fn read_property<T: Copy>(
    object: AudioObjectID,
    mut address: AudioObjectPropertyAddress,
    call: &'static str,
) -> Result<T> {
    let mut value = MaybeUninit::<T>::uninit();
    let wanted = std::mem::size_of::<T>();
    let mut size =
        u32::try_from(wanted).map_err(|_| CaptureError::CoreAudio { call, status: 0 })?;

    // SAFETY: `address` and `size` are live locals for the whole call, the
    // qualifier is the documented null/zero pair for unqualified properties,
    // and `value` is a `MaybeUninit<T>` of exactly `size` bytes — the only
    // buffer the HAL is told about.
    let status = unsafe {
        AudioObjectGetPropertyData(
            object,
            NonNull::from(&mut address),
            0,
            ptr::null(),
            NonNull::from(&mut size),
            NonNull::from(&mut value).cast::<c_void>(),
        )
    };

    if status != 0 {
        return Err(CaptureError::CoreAudio { call, status });
    }
    if size as usize != wanted {
        return Err(CaptureError::CoreAudio { call, status: 0 });
    }
    // SAFETY: the HAL returned success and reported writing exactly the
    // requested number of bytes into the buffer.
    Ok(unsafe { value.assume_init() })
}
