//! What an act answers its caller (FIX 3414). The act runs as its caller's
//! authority asked, from whatever surface it asked; only the answer is judged
//! for where it goes. A caller off this device whose act's record, or a row
//! its reply would carry, stays on this device (DEC-0005) hears that the act
//! ran, and nothing of those rows.
use serde::{Deserialize, Serialize};

/// An act's answer: its own reply, or the content-free word that it ran and
/// its details stay on this device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ActAnswer<T> {
    /// The act ran; its details stay on the device that holds them.
    DetailsOnDevice(DetailsOnDevice),
    /// The act's own reply.
    Done(T),
}

impl<T> ActAnswer<T> {
    /// The act ran, and its details stay on this device.
    #[must_use]
    pub const fn details_on_device() -> Self {
        Self::DetailsOnDevice(DetailsOnDevice {
            details_on_device: true,
        })
    }
}

/// The act ran; its details stay on this device. It carries nothing else:
/// no id, count or text of what it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetailsOnDevice {
    /// Always `true`.
    pub details_on_device: bool,
}
