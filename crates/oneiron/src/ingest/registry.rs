//! Ingest source registry: source ids, configs, harness, registry map, and the ingest source trait.

use super::image;
use super::{
    IngestError, IngestResult, JsonlTranscriptSource, MeetingTranscriptSource,
    NormalizedIngestBatch,
};
use crate::claim::{ClaimApprovalStatus, ClaimSource};

pub const JSONL_TRANSCRIPT_SOURCE_ID: &str = "jsonl-transcript";

pub const FILE_DROP_TRANSCRIPT_SOURCE_ID: &str = "file-drop-transcript";

pub const MEETING_TRANSCRIPT_SOURCE_ID: &str = "meeting-transcript";

/// CAL-02's ICS feed source, canonical registry entry #3.
pub const ICS_FEED_SOURCE_ID: &str = "ics-feed";

/// Schema version this build of `MeetingTranscriptSource` accepts.
pub const MEETING_TRANSCRIPT_SCHEMA_V1: &str = "oneiron.meeting_transcript.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IngestSourceFormat {
    JsonlTranscript,
    FileDropTranscript,
    MeetingTranscriptV1,
    // CAL-08 owns FileDropTranscript, canonical registry entry #2.
    IcsFeed,
    ImageAsset,
}

/// The ARCH-0027 adapter skill a source's records came from.
///
/// A built-in source is compiled-in code, not a runtime SKILL entity: this
/// descriptor is the parity authority for what produced the input, and it
/// never participates in SKILL lifecycle or hub machinery. Sources with no
/// adapter (records handed straight to the engine) carry `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestAdapterSkillRef {
    pub skill_id: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestTrustCeiling {
    pub claim_source: ClaimSource,
    pub max_auto_sensitivity: Option<u8>,
    pub receipted: bool,
    pub warned: bool,
}

impl IngestTrustCeiling {
    #[must_use]
    pub fn permits_auto(self, sensitivity: Option<u8>) -> bool {
        let Some(sensitivity) = sensitivity else {
            return false;
        };
        let Some(max_auto_sensitivity) = self.max_auto_sensitivity else {
            return false;
        };
        if sensitivity > max_auto_sensitivity {
            return false;
        }
        if self.claim_source.requires_explicit_auto_permit() && (!self.receipted || !self.warned) {
            return false;
        }
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestSourceConfig {
    pub source_id: &'static str,
    pub label: &'static str,
    pub format: IngestSourceFormat,
    pub adapter_skill: Option<IngestAdapterSkillRef>,
    pub writes_claims: bool,
    pub trust_ceiling: IngestTrustCeiling,
    pub default_admission: ClaimApprovalStatus,
}

#[derive(Debug, Clone, Copy)]
pub struct IngestHarnessConfig {
    registry: &'static IngestSourceRegistry,
}

impl IngestHarnessConfig {
    pub const fn from_registry(registry: &'static IngestSourceRegistry) -> Self {
        Self { registry }
    }

    #[must_use]
    pub const fn registry(&self) -> &'static IngestSourceRegistry {
        self.registry
    }

    pub fn source_configs(&self) -> impl Iterator<Item = IngestSourceConfig> + '_ {
        self.registry.source_configs()
    }

    pub fn source_ids(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.registry.source_ids()
    }

    #[must_use]
    pub fn get_config(&self, source_id: &str) -> Option<IngestSourceConfig> {
        self.registry.get_config(source_id)
    }
}

pub trait IngestSource: Send + Sync {
    fn normalize(&self, input: &str) -> IngestResult<NormalizedIngestBatch>;

    fn normalize_binary(&self, _bytes: &[u8]) -> IngestResult<NormalizedIngestBatch> {
        Err(IngestError::UnsupportedInput)
    }
}

#[derive(Clone, Copy)]
pub struct IngestSourceRegistration {
    config: IngestSourceConfig,
    source: &'static dyn IngestSource,
}

impl IngestSourceRegistration {
    pub const fn new(config: IngestSourceConfig, source: &'static dyn IngestSource) -> Self {
        Self { config, source }
    }

    #[must_use]
    pub const fn config(&self) -> IngestSourceConfig {
        self.config
    }

    #[must_use]
    pub fn source(&self) -> &'static dyn IngestSource {
        self.source
    }
}

impl std::fmt::Debug for IngestSourceRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IngestSourceRegistration")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IngestSourceRegistry {
    entries: &'static [IngestSourceRegistration],
}

impl IngestSourceRegistry {
    pub const fn new(entries: &'static [IngestSourceRegistration]) -> Self {
        Self { entries }
    }

    pub fn entries(&self) -> &'static [IngestSourceRegistration] {
        self.entries
    }

    pub fn sources(&self) -> impl Iterator<Item = &'static dyn IngestSource> + '_ {
        self.entries.iter().map(IngestSourceRegistration::source)
    }

    pub fn source_configs(&self) -> impl Iterator<Item = IngestSourceConfig> + '_ {
        self.entries.iter().map(IngestSourceRegistration::config)
    }

    pub fn source_ids(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.source_configs().map(|config| config.source_id)
    }

    #[must_use]
    pub fn get_config(&self, source_id: &str) -> Option<IngestSourceConfig> {
        self.entries
            .iter()
            .find(|entry| entry.config.source_id == source_id)
            .map(IngestSourceRegistration::config)
    }

    pub fn get(&self, source_id: &str) -> Option<&'static dyn IngestSource> {
        self.entries
            .iter()
            .find(|entry| entry.config.source_id == source_id)
            .map(IngestSourceRegistration::source)
    }

    pub fn normalize(&self, source_id: &str, input: &str) -> IngestResult<NormalizedIngestBatch> {
        let source = self
            .get(source_id)
            .ok_or_else(|| IngestError::UnknownSource {
                source_id: source_id.to_owned(),
            })?;
        source.normalize(input)
    }

    pub fn normalize_binary(
        &self,
        source_id: &str,
        bytes: &[u8],
    ) -> IngestResult<NormalizedIngestBatch> {
        let source = self
            .get(source_id)
            .ok_or_else(|| IngestError::UnknownSource {
                source_id: source_id.to_owned(),
            })?;
        source.normalize_binary(bytes)
    }
}

static JSONL_TRANSCRIPT_SOURCE: JsonlTranscriptSource = JsonlTranscriptSource;

static FILE_DROP_TRANSCRIPT_SOURCE: crate::calendar::transcript::FileDropTranscriptSource =
    crate::calendar::transcript::FileDropTranscriptSource;

static MEETING_TRANSCRIPT_SOURCE: MeetingTranscriptSource = MeetingTranscriptSource;

static ICS_FEED_SOURCE: crate::calendar::ingest::IcsFeedSource =
    crate::calendar::ingest::IcsFeedSource;

static IMAGE_SOURCE: image::ImageIngestSource = image::ImageIngestSource::new();

static INGEST_SOURCE_ENTRIES: [IngestSourceRegistration; 5] = [
    IngestSourceRegistration::new(
        IngestSourceConfig {
            source_id: image::IMAGE_SOURCE_ID,
            label: "Image asset",
            format: IngestSourceFormat::ImageAsset,
            adapter_skill: Some(IngestAdapterSkillRef {
                skill_id: "builtin.ingest.image-asset",
                version: "1",
            }),
            writes_claims: false,
            trust_ceiling: IngestTrustCeiling {
                claim_source: ClaimSource::Imported,
                max_auto_sensitivity: None,
                receipted: false,
                warned: false,
            },
            default_admission: ClaimApprovalStatus::Proposed,
        },
        &IMAGE_SOURCE,
    ),
    IngestSourceRegistration::new(
        IngestSourceConfig {
            source_id: JSONL_TRANSCRIPT_SOURCE_ID,
            label: "JSONL transcript",
            format: IngestSourceFormat::JsonlTranscript,
            adapter_skill: None,
            writes_claims: false,
            trust_ceiling: IngestTrustCeiling {
                claim_source: ClaimSource::Imported,
                max_auto_sensitivity: None,
                receipted: false,
                warned: false,
            },
            default_admission: ClaimApprovalStatus::Proposed,
        },
        &JSONL_TRANSCRIPT_SOURCE,
    ),
    IngestSourceRegistration::new(
        IngestSourceConfig {
            source_id: FILE_DROP_TRANSCRIPT_SOURCE_ID,
            label: "File-drop transcript",
            format: IngestSourceFormat::FileDropTranscript,
            adapter_skill: None,
            writes_claims: false,
            trust_ceiling: IngestTrustCeiling {
                claim_source: ClaimSource::Imported,
                max_auto_sensitivity: None,
                receipted: false,
                warned: false,
            },
            default_admission: ClaimApprovalStatus::Proposed,
        },
        &FILE_DROP_TRANSCRIPT_SOURCE,
    ),
    IngestSourceRegistration::new(
        IngestSourceConfig {
            source_id: MEETING_TRANSCRIPT_SOURCE_ID,
            label: "Meeting transcript",
            format: IngestSourceFormat::MeetingTranscriptV1,
            adapter_skill: Some(IngestAdapterSkillRef {
                skill_id: "builtin.ingest.meeting-transcript",
                version: "1",
            }),
            writes_claims: false,
            trust_ceiling: IngestTrustCeiling {
                claim_source: ClaimSource::Imported,
                max_auto_sensitivity: None,
                receipted: false,
                warned: false,
            },
            default_admission: ClaimApprovalStatus::Proposed,
        },
        &MEETING_TRANSCRIPT_SOURCE,
    ),
    // CAL-02's ICS feed adapter-SKILL, registry entry #3. Imported trust
    // ceiling with the auto path closed (max_auto_sensitivity None), proposed
    // default admission — the same fail-closed posture as the transcript
    // sources. CAL-08 inserts its own entry later; parity is set-based,
    // never ordinal.
    IngestSourceRegistration::new(
        IngestSourceConfig {
            source_id: ICS_FEED_SOURCE_ID,
            label: "ICS feed",
            format: IngestSourceFormat::IcsFeed,
            adapter_skill: Some(IngestAdapterSkillRef {
                skill_id: "builtin.ingest.ics-feed",
                version: "1",
            }),
            writes_claims: false,
            trust_ceiling: IngestTrustCeiling {
                claim_source: ClaimSource::Imported,
                max_auto_sensitivity: None,
                receipted: false,
                warned: false,
            },
            default_admission: ClaimApprovalStatus::Proposed,
        },
        &ICS_FEED_SOURCE,
    ),
];

pub static INGEST_SOURCE_REGISTRY: IngestSourceRegistry =
    IngestSourceRegistry::new(&INGEST_SOURCE_ENTRIES);

pub static KNOWN_INGEST_HARNESS_CONFIG: IngestHarnessConfig =
    IngestHarnessConfig::from_registry(&INGEST_SOURCE_REGISTRY);
