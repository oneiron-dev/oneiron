//! Portable, pure shape rules shared by the host and the isolated guest.
//! Descriptor-relative I/O, secret custody and execution stay in their owners.
mod budget;
mod path;
mod workspace;

pub use budget::ProgramBudget;
pub use path::{
    MAX_PATH_COMPONENT_BYTES, MAX_PATH_COMPONENTS, MAX_WORKSPACE_PATH_BYTES, WORKSPACE_ROOT,
    WorkspacePath,
};
pub use workspace::{OutputReservation, WorkspaceShape};

pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_COMPONENT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_REQUESTS: usize = 16_384;
pub const MAX_FILE_BYTES: usize = 1024 * 1024;
pub const MAX_WORKSPACE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_WORKSPACE_FILES: usize = 8192;
pub const MAX_WORKSPACE_DIRECTORIES: usize = 8192;
pub const MAX_PROGRAM_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShapeError(&'static str);
impl ShapeError {
    #[must_use]
    pub const fn reason(self) -> &'static str {
        self.0
    }
}
impl std::fmt::Display for ShapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ShapeError {}
pub type Result<T> = std::result::Result<T, ShapeError>;
fn refused(reason: &'static str) -> ShapeError {
    ShapeError(reason)
}
