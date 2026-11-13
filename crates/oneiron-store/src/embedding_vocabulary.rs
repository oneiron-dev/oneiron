//! Embedding vocabulary the store layer writes: the input modality of a kind
//! slot, the text-hash length, and the device and runtime that computed a
//! vector. `oneiron::store::embedding` re-exports every item here.

use serde::{Deserialize, Serialize};

/// One input modality a kind slot names.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    Text,
    Image,
    Audio,
}

impl InputKind {
    /// Every kind slot, in slot order.
    pub const ALL: [Self; 3] = [Self::Text, Self::Image, Self::Audio];

    /// The media kind a stored media type carries: `image/*` or `audio/*`.
    #[must_use]
    pub fn for_media_type(media_type: &str) -> Option<Self> {
        let media_type = media_type.trim().to_ascii_lowercase();
        if media_type.starts_with("image/") {
            Some(Self::Image)
        } else if media_type.starts_with("audio/") {
            Some(Self::Audio)
        } else {
            None
        }
    }

    pub const fn byte(self) -> u8 {
        match self {
            Self::Text => 0,
            Self::Image => 1,
            Self::Audio => 2,
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Text),
            1 => Some(Self::Image),
            2 => Some(Self::Audio),
            _ => None,
        }
    }
}

/// A media query's kind is the engine's input kind of the same name.
impl From<oneiron_contracts::code_run::vault_read::MediaQueryKind> for InputKind {
    fn from(kind: oneiron_contracts::code_run::vault_read::MediaQueryKind) -> Self {
        use oneiron_contracts::code_run::vault_read::MediaQueryKind;
        match kind {
            MediaQueryKind::Text => Self::Text,
            MediaQueryKind::Image => Self::Image,
            MediaQueryKind::Audio => Self::Audio,
        }
    }
}

pub const TEXT_HASH_LEN: usize = 32;

/// The family of device an embedding vector was computed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum EmbeddingDevice {
    Cpu,
    Cuda,
    Metal,
    /// Computed behind an endpoint the vault called; its device is not known
    /// to the vault.
    Remote,
    /// Not recorded: a vector written before provenance was, or one a caller
    /// supplied. A family a later build adds reads as this one.
    #[serde(other)]
    Unknown,
}

impl EmbeddingDevice {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Cuda => "cuda",
            Self::Metal => "metal",
            Self::Remote => "remote",
            Self::Unknown => "unknown",
        }
    }
}

impl std::str::FromStr for EmbeddingDevice {
    type Err = String;

    fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
        [
            Self::Cpu,
            Self::Cuda,
            Self::Metal,
            Self::Remote,
            Self::Unknown,
        ]
        .into_iter()
        .find(|device| device.as_str() == name)
        .ok_or_else(|| format!("{name:?} is not cpu, cuda, metal, remote or unknown"))
    }
}

/// The longest runtime a vector's mark may name, in bytes.
pub const MAX_EMBEDDING_RUNTIME_BYTES: usize = 128;

/// The device family and runtime that computed a vector: provenance only,
/// never part of the embedding space.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EmbeddingProvenance {
    pub device: EmbeddingDevice,
    /// The runtime's name and version (a local build), or the id of the
    /// endpoint that answered.
    pub runtime: String,
}

impl EmbeddingProvenance {
    #[must_use]
    pub fn new(device: EmbeddingDevice, runtime: impl Into<String>) -> Self {
        Self {
            device,
            runtime: runtime.into(),
        }
    }

    /// What a vector with no record reads as.
    #[must_use]
    pub fn unknown() -> Self {
        Self::new(EmbeddingDevice::Unknown, "unknown")
    }

    pub fn is_unknown(&self) -> bool {
        self.device == EmbeddingDevice::Unknown
    }

    /// Whether the runtime is fit to store: not empty, at most
    /// [`MAX_EMBEDDING_RUNTIME_BYTES`] bytes, and free of control characters.
    #[must_use]
    pub fn runtime_is_storable(&self) -> bool {
        !self.runtime.is_empty()
            && self.runtime.len() <= MAX_EMBEDDING_RUNTIME_BYTES
            && !self.runtime.chars().any(char::is_control)
    }

    /// The mark a host that embeds on its own hands in with a vector
    /// (ARCH-0036 device mark): the device family it names and its runtime.
    ///
    /// # Errors
    ///
    /// When `device` names no family [`EmbeddingDevice`] knows, or the runtime
    /// is not [storable](Self::runtime_is_storable).
    pub fn from_host(device: &str, runtime: &str) -> Result<Self, String> {
        let provenance = Self::new(device.parse()?, runtime);
        if !provenance.runtime_is_storable() {
            return Err(format!(
                "runtime must be 1 to {MAX_EMBEDDING_RUNTIME_BYTES} bytes with no control characters"
            ));
        }
        Ok(provenance)
    }
}
