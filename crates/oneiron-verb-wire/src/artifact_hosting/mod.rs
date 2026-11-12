//! Moved from `crates/oneiron/src/artifact_hosting/mod.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::artifact_hosting::vocabulary::ArtifactPointerChannel;
use heed::RwTxn;
use oneiron_base::error::CodeError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::error::SecretError;
use oneiron_base::registry::ArtifactFamilyKindId;
use oneiron_base::registry::artifact_family_kind_of;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::artifact_hosting::preview;
pub use oneiron_store::artifact_hosting::vocabulary::ARTIFACT_POINTER_CHANNELS;
pub use oneiron_store::artifact_hosting::vocabulary::ArtifactExportRef;
pub use oneiron_store::artifact_hosting::vocabulary::ArtifactPublishVerbStatus;
pub use oneiron_store::artifact_hosting::vocabulary::ArtifactSnapshotRef;
use oneiron_store::code_artifact_body::CodeArtifactClass;
use oneiron_store::code_artifact_body::decode_code_artifact_body;
use oneiron_store::code_snapshot::snapshot::CODEBASE_FILE_PATH_MAX_BYTES;
use oneiron_store::code_snapshot::snapshot::CODEBASE_FORK_HASH_LEN;
use oneiron_store::code_snapshot::snapshot::CODEBASE_PROJECT_ID_MAX_BYTES;
use oneiron_store::code_snapshot::snapshot::CodebaseFileEntry;
use oneiron_store::code_snapshot::snapshot::CodebaseForkHash;
use oneiron_store::code_snapshot::snapshot::CodebaseSnapshot;
use oneiron_store::gate_decision::types::GateDecisionId;
use oneiron_store::gate_reason::GateOutcome;
use oneiron_store::policy_record::ExternalEffectPolicyRisk;
use oneiron_store::policy_record::GateActor;
use oneiron_store::receipt_row::ReceiptKind;
use oneiron_store::side_table::codec::CodecError;
use oneiron_store::side_table::codec::RawValue;
use oneiron_store::side_table::key::SideKey;
use oneiron_store::write_envelope::WriteActor;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

pub const ARTIFACT_CHANNEL_PUBLISHED: u8 = 0;

pub const ARTIFACT_CHANNEL_PREVIEW: u8 = 1;

impl ArtifactPointerChannel {
    #[must_use]
    const fn from_key_byte(byte: u8) -> Option<Self> {
        match byte {
            ARTIFACT_CHANNEL_PUBLISHED => Some(Self::Published),
            ARTIFACT_CHANNEL_PREVIEW => Some(Self::Preview),
            _ => None,
        }
    }
}
pub mod access;
pub mod door_types;
pub mod vocabulary;
