pub use crate::note::files::metadata::FileFacts;
pub use crate::note::files::metadata::FileMeta;
pub use crate::note::files::source::FilesPlacement;
pub use crate::note::files::source::FilesWorld;
pub(in crate::note) use crate::note::files::source::namespace;
pub use oneiron_verb_wire::note::files::metadata::FileReadiness;
pub use oneiron_verb_wire::note::files::metadata::NameOnlyReason;
pub use oneiron_verb_wire::note::files::source::FileHandle;

pub mod metadata;
pub mod source;
