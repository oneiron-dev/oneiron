//! The whole-vault archive (OF-222): one ZIP holding `manifest.json`, one
//! JSONL file per record kind under `records/`, and each attached file once
//! under `files/<blake3>`. Plaintext by design and re-importable; it is the
//! owner's exit path, never a backup (backups stay the encrypted snapshot).
use serde::{Deserialize, Serialize};

/// The manifest's `format`: the one whole-vault export shape.
pub const VAULT_ARCHIVE_FORMAT: &str = "oneiron-vault-archive";
/// The format of the "Export to OKF" bundle: lossy, never re-imported as a
/// vault, and labelled as not a full copy.
pub const VAULT_OKF_FORMAT: &str = "okf-0.1";

/// What a snapshot is cut into: the full archive, or the lossy OKF bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExportCut {
    Archive,
    Okf,
}
/// The archive member holding the [`super::WholeVaultDocumentManifest`].
pub const VAULT_ARCHIVE_MANIFEST_PATH: &str = "manifest.json";
pub(crate) const VAULT_ARCHIVE_RECORDS_DIR: &str = "records/";
pub(crate) const VAULT_ARCHIVE_FILES_DIR: &str = "files/";

/// One JSONL file: which record kind its rows are, how many there are, and
/// its length and BLAKE3, so an import refuses a file that changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveRecordFile {
    pub path: String,
    pub kind: ArchiveRecordKind,
    pub rows: u64,
    pub bytes: u64,
    pub blake3: String,
}

/// The record kinds. Each entity type of the evidence ledger has its own
/// file (`records/entity/<kind>.jsonl`, named from the type registry);
/// claims and skills keep theirs, and the rows beside them are typed too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveRecordKind {
    /// One evidence-ledger entity type; each row names its `entity_type`.
    Entity,
    Claim,
    /// A SKILL entity with its source package; file bodies are in `files/`.
    Skill,
    Edge,
    Pack,
    AgentPack,
    DerivationEnvelope,
    /// One code run's result manifests.
    Run,
    /// One result body's digest and length, or why the export withheld it.
    /// A body not withheld is the file `files/<blake3>`.
    ResultBody,
    /// One secret-custody record, only in the owner's own archive (owner
    /// ruling 2026-10-17: an export carries its keys, so a re-import keeps
    /// them). Exports to contacts and shares never carry one.
    SecretCustody,
    /// One declared embedding space's descriptor (OF-370), only in a
    /// whole-vault archive.
    EmbeddingSpace,
    /// One kind slot's binding, `{kind, space}` with a null `space` for an
    /// unbound slot: a row per kind, only in a whole-vault archive.
    SlotBinding,
    /// One session's epoch floor (OF-013), `{session, epoch, turn_end}`,
    /// only in a whole-vault archive.
    EpochFloor,
    /// One row of an allowlisted side table (FIX 2768) beside the record it
    /// indexes, only in a whole-vault archive.
    SideTable,
}

impl ArchiveRecordKind {
    /// The fixed path of a non-entity kind.
    pub(crate) fn fixed_path(self) -> Option<&'static str> {
        Some(match self {
            Self::Entity => return None,
            Self::Claim => "records/entity/claim.jsonl",
            Self::Skill => "records/entity/skill.jsonl",
            Self::Edge => "records/edge.jsonl",
            Self::Pack => "records/pack.jsonl",
            Self::AgentPack => "records/agent_pack.jsonl",
            Self::DerivationEnvelope => "records/derivation_envelope.jsonl",
            Self::Run => "records/run.jsonl",
            Self::ResultBody => "records/result_body.jsonl",
            Self::SecretCustody => "records/secret_custody.jsonl",
            Self::EmbeddingSpace => "records/embedding_space.jsonl",
            Self::SlotBinding => "records/slot_binding.jsonl",
            Self::EpochFloor => "records/epoch_floor.jsonl",
            Self::SideTable => "records/side_table.jsonl",
        })
    }

    /// The file of one evidence-ledger entity type, by its registry name.
    /// A type the registry does not name (a pack instance handle) goes by
    /// its byte.
    pub(crate) fn entity_path(entity_type: u8) -> String {
        match crate::registry::entity_type_registry_entry(entity_type) {
            Some(entry)
                if !matches!(entity_type, crate::registry::ENTITY_TYPE_CLAIM)
                    && !matches!(entity_type, crate::registry::ENTITY_TYPE_SKILL) =>
            {
                format!("records/entity/{}.jsonl", entry.kind.to_ascii_lowercase())
            }
            _ => format!("records/entity/type_{entity_type:03}.jsonl"),
        }
    }
}

/// One custody record: its id, its handle (the short id a model reads), its
/// value-less metadata, and, when the archive carries values, its body in the
/// custody codec (the record's one serialization), standard base64. The body
/// holds the secret value; it never passes through the document's nulling,
/// because carrying it is the point. Without a body the record is a handle
/// only, and a re-import lists it as a missing secret to re-enter.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArchiveSecretCustody {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) handle: Option<String>,
    pub(crate) metadata: crate::secret_custody::SecretCustodyMetadata,
    pub(crate) body: Option<String>,
}

impl std::fmt::Debug for ArchiveSecretCustody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveSecretCustody")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("handle", &self.handle)
            .field("metadata", &self.metadata)
            .field(
                "body",
                &format_args!(
                    "<redacted {} chars>",
                    self.body.as_ref().map_or(0, String::len)
                ),
            )
            .finish()
    }
}

/// One attached file, stored once under `files/<blake3>` whatever cites it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveFile {
    pub blake3: String,
    pub bytes: u64,
}

/// OF-490: an agent whose diaries this export holds out, and why. A held
/// diary is not in the archive; the owner exports again once the agent has
/// answered its review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportDiaryHold {
    pub agent: String,
    pub diaries: u64,
    pub reason: ExportDiaryHoldReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportDiaryHoldReason {
    /// The agent reviews each read of its diary first, and has not yet.
    AgentReviewPending,
    /// The reader's `diary.read` Grant does not cover this entry.
    NotCoveredByGrant,
    /// The agent said no to this reader's reason.
    Declined,
    /// The read log could not be written, so the entry was not read.
    ReadLogUnavailable,
}

/// OF-490: one agent's diaries an export read, and the reason the read
/// states. The vault keeps it on the export's receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportDiaryRead {
    pub agent: String,
    pub diaries: u64,
    pub reason: String,
}

pub(crate) fn archive_file_path(blake3: &str) -> String {
    format!("{VAULT_ARCHIVE_FILES_DIR}{blake3}")
}

pub(crate) fn blake3_hex(bytes: &[u8]) -> String {
    crate::entity_id::bytes_to_hex_lower(blake3::hash(bytes).as_bytes())
}
