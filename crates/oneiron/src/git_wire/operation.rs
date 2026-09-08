//! Operation enum, effect classes, and the stable wire-name mapping.

use super::failure::invalid;
use crate::error::Result;

/// The complete, positive classification of what an operation may change.
///
/// The classification is total: every [`GitWireOperation`] names exactly one
/// class, so a new operation cannot silently inherit "harmless".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitWireEffectClass {
    /// Changes no object, ref, index, or working tree.
    Read,
    /// May add objects to the object store; moves no ref.
    ObjectWrite,
    /// May move refs; writes no object.
    RefWrite,
    /// May both add objects and move a ref in one invocation.
    ObjectAndRefWrite,
    /// May change working-tree or index state on disk.
    WorktreeWrite,
}

impl GitWireEffectClass {
    /// Whether the class changes nothing.
    pub const fn is_read(self) -> bool {
        matches!(self, Self::Read)
    }

    /// Whether the class may add objects.
    pub const fn writes_objects(self) -> bool {
        matches!(self, Self::ObjectWrite | Self::ObjectAndRefWrite)
    }

    /// Whether the class may move a ref.
    pub const fn moves_refs(self) -> bool {
        matches!(self, Self::RefWrite | Self::ObjectAndRefWrite)
    }
}

/// Typed name of a git effect. The wire name is what durable rows and derived
/// keys carry, so it is stable across releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitWireOperation {
    ReadRefs,
    ObjectInfo,
    ReachableObjects,
    ReadTree,
    ReadObject,
    RevParse,
    MergeBase,
    WorktreeList,
    StatusPorcelain,
    NotesShow,
    GitPath,
    WriteBlob,
    WriteTree,
    WriteCommit,
    /// The mixed writer class: `notes add` writes objects *and* moves the notes
    /// ref in one invocation. GitWire classifies it so both phases can refuse
    /// it, and deliberately exposes no constructor for it.
    NotesAdd,
    PublishRefs,
    WorktreeAdd,
    WorktreeRemove,
    WorktreePrune,
}

pub(super) const GIT_WIRE_ALL_OPERATIONS: [GitWireOperation; 19] = [
    GitWireOperation::ReadRefs,
    GitWireOperation::ObjectInfo,
    GitWireOperation::ReachableObjects,
    GitWireOperation::ReadTree,
    GitWireOperation::ReadObject,
    GitWireOperation::RevParse,
    GitWireOperation::MergeBase,
    GitWireOperation::WorktreeList,
    GitWireOperation::StatusPorcelain,
    GitWireOperation::NotesShow,
    GitWireOperation::GitPath,
    GitWireOperation::WriteBlob,
    GitWireOperation::WriteTree,
    GitWireOperation::WriteCommit,
    GitWireOperation::NotesAdd,
    GitWireOperation::PublishRefs,
    GitWireOperation::WorktreeAdd,
    GitWireOperation::WorktreeRemove,
    GitWireOperation::WorktreePrune,
];

impl GitWireOperation {
    /// Stable wire name recorded on durable rows and hashed into keys.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadRefs => "read_refs",
            Self::ObjectInfo => "object_info",
            Self::ReachableObjects => "reachable_objects",
            Self::ReadTree => "read_tree",
            Self::ReadObject => "read_object",
            Self::RevParse => "rev_parse",
            Self::MergeBase => "merge_base",
            Self::WorktreeList => "worktree_list",
            Self::StatusPorcelain => "status_porcelain",
            Self::NotesShow => "notes_show",
            Self::GitPath => "git_path",
            Self::WriteBlob => "write_blob",
            Self::WriteTree => "write_tree",
            Self::WriteCommit => "write_commit",
            Self::NotesAdd => "notes_add",
            Self::PublishRefs => "publish_refs",
            Self::WorktreeAdd => "worktree_add",
            Self::WorktreeRemove => "worktree_remove",
            Self::WorktreePrune => "worktree_prune",
        }
    }

    /// The single effect class of this operation.
    pub const fn effect_class(self) -> GitWireEffectClass {
        match self {
            Self::ReadRefs
            | Self::ObjectInfo
            | Self::ReachableObjects
            | Self::ReadTree
            | Self::ReadObject
            | Self::RevParse
            | Self::MergeBase
            | Self::WorktreeList
            | Self::StatusPorcelain
            | Self::NotesShow
            | Self::GitPath => GitWireEffectClass::Read,
            Self::WriteBlob | Self::WriteTree | Self::WriteCommit => {
                GitWireEffectClass::ObjectWrite
            }
            Self::NotesAdd => GitWireEffectClass::ObjectAndRefWrite,
            Self::PublishRefs => GitWireEffectClass::RefWrite,
            Self::WorktreeAdd | Self::WorktreeRemove | Self::WorktreePrune => {
                GitWireEffectClass::WorktreeWrite
            }
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self> {
        GIT_WIRE_ALL_OPERATIONS
            .into_iter()
            .find(|operation| operation.as_str() == value)
            .ok_or_else(|| invalid("unknown git wire operation"))
    }
}
