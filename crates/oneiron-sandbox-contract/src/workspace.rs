//! Checked file and directory shape; reservations compose before execution.
use super::{
    MAX_FILE_BYTES, MAX_WORKSPACE_BYTES, MAX_WORKSPACE_DIRECTORIES, MAX_WORKSPACE_FILES, Result,
    WorkspacePath, refused,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkspaceShape {
    files: BTreeMap<String, usize>,
    directories: BTreeSet<String>,
    total_bytes: usize,
}
impl WorkspaceShape {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
    #[must_use]
    pub fn directory_count(&self) -> usize {
        self.directories.len()
    }
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Includes the ancestors of `path`, even when an empty directory is
    /// observed by the host snapshot walker.
    pub fn add_directory(&mut self, path: &WorkspacePath) -> Result<()> {
        let mut additions = self.parents(path);
        additions.insert(path.as_str().to_owned());
        self.insert_directories(additions)
    }
    pub fn add_file(&mut self, path: &WorkspacePath, bytes: usize) -> Result<()> {
        if bytes > MAX_FILE_BYTES || self.files.len() >= MAX_WORKSPACE_FILES {
            return Err(refused("workspace file limit"));
        }
        if self.files.contains_key(path.as_str()) || self.directories.contains(path.as_str()) {
            return Err(refused("workspace path collision"));
        }
        let total = self
            .total_bytes
            .checked_add(bytes)
            .ok_or_else(|| refused("workspace byte overflow"))?;
        if total > MAX_WORKSPACE_BYTES {
            return Err(refused("workspace byte limit"));
        }
        self.insert_directories(self.parents(path))?;
        self.files.insert(path.as_str().to_owned(), bytes);
        self.total_bytes = total;
        Ok(())
    }
    /// A proposal that overwrites an existing source file changes its length
    /// without allocating a second file slot. New outputs use `add_file`.
    pub fn replace_file(&mut self, path: &WorkspacePath, bytes: usize) -> Result<()> {
        let Some(old) = self.files.get(path.as_str()).copied() else {
            return self.add_file(path, bytes);
        };
        if bytes > MAX_FILE_BYTES {
            return Err(refused("workspace file limit"));
        }
        let total = self.total_bytes - old;
        let total = total
            .checked_add(bytes)
            .ok_or_else(|| refused("workspace byte overflow"))?;
        if total > MAX_WORKSPACE_BYTES {
            return Err(refused("workspace byte limit"));
        }
        self.files.insert(path.as_str().to_owned(), bytes);
        self.total_bytes = total;
        Ok(())
    }
    /// A deletion or rename origin frees its file slot and bytes; its parent
    /// directories stay, as they do when a file is unlinked.
    pub fn remove_file(&mut self, path: &WorkspacePath) -> Result<usize> {
        let bytes = self
            .files
            .remove(path.as_str())
            .ok_or_else(|| refused("workspace file missing"))?;
        self.total_bytes -= bytes;
        Ok(bytes)
    }
    /// Moves one file. The destination must fit the tree the move leaves: not
    /// an existing file or directory, not below a file, and not below its own
    /// origin. A refused move leaves the shape unchanged.
    pub fn rename_file(&mut self, from: &WorkspacePath, to: &WorkspacePath) -> Result<()> {
        if from == to
            || to
                .as_str()
                .strip_prefix(from.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
        {
            return Err(refused("workspace rename onto its own origin"));
        }
        let bytes = self.remove_file(from)?;
        if let Err(error) = self.add_file(to, bytes) {
            self.files.insert(from.as_str().to_owned(), bytes);
            self.total_bytes += bytes;
            return Err(error);
        }
        Ok(())
    }
    fn parents(&self, path: &WorkspacePath) -> BTreeSet<String> {
        let mut parents = BTreeSet::new();
        let mut prefix = String::from("/mnt/workspace");
        let mut parts = path.relative().split('/').peekable();
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                break;
            }
            prefix.push('/');
            prefix.push_str(part);
            parents.insert(prefix.clone());
        }
        parents
    }
    fn insert_directories(&mut self, additions: BTreeSet<String>) -> Result<()> {
        if additions.iter().any(|dir| self.files.contains_key(dir)) {
            return Err(refused("workspace file/directory collision"));
        }
        let new_count = additions
            .iter()
            .filter(|dir| !self.directories.contains(*dir))
            .count();
        if self.directories.len() + new_count > MAX_WORKSPACE_DIRECTORIES {
            return Err(refused("workspace directory limit"));
        }
        self.directories.extend(additions);
        Ok(())
    }
    /// Consume the same file/dir rules used by the host and guest; a promised
    /// output must fit even when every promised byte is written.
    pub fn with_output(&self, reservation: &OutputReservation) -> Result<Self> {
        let mut merged = self.clone();
        merged.add_file(&reservation.path, reservation.max_bytes)?;
        Ok(merged)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputReservation {
    path: WorkspacePath,
    max_bytes: usize,
}
impl OutputReservation {
    pub fn new(path: WorkspacePath, max_bytes: usize) -> Result<Self> {
        if max_bytes == 0 || max_bytes > MAX_FILE_BYTES {
            return Err(refused("output reservation byte limit"));
        }
        Ok(Self { path, max_bytes })
    }
    #[must_use]
    pub fn path(&self) -> &WorkspacePath {
        &self.path
    }
    #[must_use]
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_full_input_has_no_room_for_mandatory_output() {
        let mut shape = WorkspaceShape::new();
        for i in 0..16 {
            shape
                .add_file(
                    &WorkspacePath::from_relative(&format!("knowledge/{i}")).unwrap(),
                    MAX_FILE_BYTES,
                )
                .unwrap();
        }
        let output = OutputReservation::new(
            WorkspacePath::from_relative("adapter-output.json").unwrap(),
            64 * 1024,
        )
        .unwrap();
        assert!(shape.with_output(&output).is_err());
        let mut qualified = WorkspaceShape::new();
        for i in 0..15 {
            qualified
                .add_file(
                    &WorkspacePath::from_relative(&format!("knowledge/{i}")).unwrap(),
                    MAX_FILE_BYTES,
                )
                .unwrap();
        }
        qualified
            .add_file(
                &WorkspacePath::from_relative("knowledge/last").unwrap(),
                MAX_FILE_BYTES - output.max_bytes(),
            )
            .unwrap();
        assert_eq!(
            qualified.with_output(&output).unwrap().total_bytes(),
            MAX_WORKSPACE_BYTES
        );
    }
    #[test]
    fn file_and_directory_counts_are_separate() {
        let mut files = WorkspaceShape::new();
        for n in 0..MAX_WORKSPACE_FILES {
            files
                .add_file(&WorkspacePath::from_relative(&format!("f{n}")).unwrap(), 0)
                .unwrap();
        }
        assert!(
            files
                .add_file(&WorkspacePath::from_relative("extra").unwrap(), 0)
                .is_err()
        );
        let mut directories = WorkspaceShape::new();
        for n in 0..MAX_WORKSPACE_DIRECTORIES {
            directories
                .add_directory(&WorkspacePath::from_relative(&format!("d{n}")).unwrap())
                .unwrap();
        }
        assert!(
            directories
                .add_directory(&WorkspacePath::from_relative("extra").unwrap())
                .is_err()
        );
    }
    #[test]
    fn rejects_file_directory_collisions() {
        let mut shape = WorkspaceShape::new();
        shape
            .add_file(&WorkspacePath::from_relative("a").unwrap(), 1)
            .unwrap();
        assert!(
            shape
                .add_file(&WorkspacePath::from_relative("a/b").unwrap(), 1)
                .is_err()
        );
        assert!(
            shape
                .add_directory(&WorkspacePath::from_relative("a").unwrap())
                .is_err()
        );
    }
    #[test]
    fn removed_file_frees_its_path_and_bytes_but_keeps_parents() {
        let mut shape = WorkspaceShape::new();
        let nested = WorkspacePath::from_relative("d/a").unwrap();
        shape.add_file(&nested, 3).unwrap();
        assert_eq!(shape.remove_file(&nested).unwrap(), 3);
        assert_eq!((shape.file_count(), shape.total_bytes()), (0, 0));
        assert!(shape.remove_file(&nested).is_err());
        assert!(
            shape
                .add_file(&WorkspacePath::from_relative("d").unwrap(), 1)
                .is_err()
        );
        shape.add_file(&nested, 1).unwrap();
    }
    #[test]
    fn rename_refuses_impossible_destinations_and_keeps_shape() {
        let path = |relative: &str| WorkspacePath::from_relative(relative).unwrap();
        let mut shape = WorkspaceShape::new();
        for file in ["a", "b", "d/child"] {
            shape.add_file(&path(file), 2).unwrap();
        }
        shape.add_directory(&path("empty")).unwrap();
        let before = shape.clone();
        for to in ["a", "a/child", "b", "b/child", "d", "empty", "d/child/new"] {
            assert!(shape.rename_file(&path("a"), &path(to)).is_err(), "{to}");
            assert_eq!(shape, before, "{to}");
        }
        assert!(shape.rename_file(&path("missing"), &path("new")).is_err());
        shape.rename_file(&path("a"), &path("d/moved")).unwrap();
        assert!(shape.remove_file(&path("a")).is_err());
        assert_eq!(shape.remove_file(&path("d/moved")).unwrap(), 2);
    }
}
