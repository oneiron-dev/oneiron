//! Where the workbook one recalculation reads was opened from: the folder and
//! file name CELL("filename") prints, and the file name CELL("address") gives
//! a cell on another sheet.

/// The place a workbook was opened from, as Excel for Windows names it: the
/// folder before the bracketed file name, with its trailing separator
/// (`C:\Reports\`), and the file's name (`Budget.xlsx`). Like the clock, it
/// belongs to the host: CELL("filename",A1) on Sheet1 of a workbook opened
/// from `C:\Reports\Budget.xlsx` is `C:\Reports\[Budget.xlsx]Sheet1`, and
/// CELL("address",Other!B2) is `[Budget.xlsx]Other!$B$2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentLocation {
    directory: String,
    file_name: String,
}

impl DocumentLocation {
    /// `file_name` in `directory`, the folder as Excel prints it with its
    /// trailing separator (`C:\Reports\`, `\\server\share\`, or a web
    /// folder's `https://host/Shared Documents/`). `None` for a folder
    /// without that separator, or for a file name that is empty or holds a
    /// separator, a bracket (Excel's delimiter around it) or a control
    /// character.
    #[must_use]
    pub fn new(directory: impl Into<String>, file_name: impl Into<String>) -> Option<Self> {
        let (directory, file_name) = (directory.into(), file_name.into());
        let valid = directory.ends_with(['\\', '/'])
            && !directory.contains(char::is_control)
            && !file_name.is_empty()
            && !file_name.contains(['\\', '/', '[', ']'])
            && !file_name.contains(char::is_control);
        valid.then_some(Self {
            directory,
            file_name,
        })
    }

    /// The file at `path` (`C:\Reports\Budget.xlsx`), split after its last
    /// separator; `None` as for [`DocumentLocation::new`].
    #[must_use]
    pub fn from_path(path: &str) -> Option<Self> {
        let split = path.rfind(['\\', '/'])? + 1;
        Self::new(&path[..split], &path[split..])
    }

    /// The folder, with its trailing separator.
    #[must_use]
    pub fn directory(&self) -> &str {
        &self.directory
    }

    /// The file's name.
    #[must_use]
    pub fn file_name(&self) -> &str {
        &self.file_name
    }
}
