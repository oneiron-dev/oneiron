//! Credential-nulled, exact source files. No raw byte/base64 escape hatch: a
//! file that is no UTF-8 text goes beside the document as an archive file, its
//! exact bytes read by the same credential scan first (FIX 10101).
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::{Cursor, Read};

use super::ExportBodyFile;
use super::credential_nulling::{credential_key, null_credentials};
use crate::batch::export::{
    ArchiveFiles, ExportFileTree, ExportSourceContent, ExportSourceFile, FileSpool,
};
use crate::batch::secret_scan::scan_file_content;
use crate::error::{Error, Result};
use crate::skill::{SkillContentHash, canonical_skill_tree_hash};
use crate::skill_hub::HubFile;
use sha2::{Digest, Sha256};

/// Whether a source file's exact bytes and its path are clean. Bytes that are
/// no UTF-8 text are read by the text rules through their lossy text too.
fn source_file_is_safe(path: &str, content: &[u8]) -> bool {
    if scan_file_content(path, content).is_some()
        || scan_file_content("", path.as_bytes()).is_some()
        || path.split('/').any(|part| {
            credential_key(part.split('.').next().unwrap_or(part))
                || [".pem", ".key", ".sig"]
                    .iter()
                    .any(|ext| part.to_ascii_lowercase().ends_with(ext))
        })
    {
        return false;
    }
    let text = String::from_utf8_lossy(content);
    if let Ok(value @ (serde_json::Value::Object(_) | serde_json::Value::Array(_))) =
        serde_json::from_str(&text)
    {
        return safe_json(&value, 0);
    }
    // Closed, conservative inspection of YAML/frontmatter, environment and code
    // assignments. An unfamiliar credential value is still secret by field name.
    !text.lines().any(|line| {
        line.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(credential_key)
            && (line.contains(':') || line.contains('='))
    })
}

fn safe_json(value: &serde_json::Value, depth: usize) -> bool {
    if depth >= 24 || null_credentials("", value) != *value {
        return false;
    }
    match value {
        serde_json::Value::String(text) => {
            if let Ok(nested @ (serde_json::Value::Object(_) | serde_json::Value::Array(_))) =
                serde_json::from_str(text)
            {
                safe_json(&nested, depth + 1)
            } else {
                true
            }
        }
        serde_json::Value::Array(values) => values.iter().all(|v| safe_json(v, depth + 1)),
        serde_json::Value::Object(values) => values.values().all(|v| safe_json(v, depth + 1)),
        _ => true,
    }
}

fn source_digest(bytes: &[u8]) -> String {
    SkillContentHash::from_bytes(Sha256::digest(bytes).into()).to_hex()
}

/// A tree's members: a clean UTF-8 file as its text, any other clean file as
/// the archive file its bytes are, by BLAKE3 and length, and a file the scan
/// reads a credential in as redacted.
pub(crate) fn export_source_tree(files: &[HubFile]) -> Result<ExportFileTree> {
    let original_hash = canonical_skill_tree_hash(
        files
            .iter()
            .map(|f| (f.path.as_str(), f.content.as_slice())),
    )?;
    if files
        .iter()
        .any(|file| scan_file_content("", file.path.as_bytes()).is_some())
    {
        // Path names are source bytes too. Hide the whole tree's names rather
        // than leak a credential or mint aliases when replacing just one path.
        let tree = ExportFileTree {
            content_hash: None,
            files: (0..files.len())
                .map(|index| ExportSourceFile {
                    path: format!("_redacted_path/{index:08}"),
                    content: ExportSourceContent::Redacted,
                    sha256: None,
                })
                .collect(),
        };
        tree.validate()?;
        return Ok(tree);
    }
    let mut sorted: Vec<_> = files.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let mut complete = true;
    let members = sorted
        .into_iter()
        .map(|f| {
            let safe = source_file_is_safe(&f.path, &f.content);
            complete &= safe;
            ExportSourceFile {
                path: f.path.clone(),
                content: match (safe, std::str::from_utf8(&f.content)) {
                    (false, _) => ExportSourceContent::Redacted,
                    (true, Ok(text)) => ExportSourceContent::Text(text.to_owned()),
                    (true, Err(_)) => ExportSourceContent::File(ExportBodyFile::of(&f.content)),
                },
                sha256: safe.then(|| source_digest(&f.content)),
            }
        })
        .collect();
    let tree = ExportFileTree {
        content_hash: complete.then(|| original_hash.to_hex()),
        files: members,
    };
    tree.validate_in(&HeldFiles::of(files, &tree)?)?;
    Ok(tree)
}

/// [`export_source_tree`] for an archive row: each member it names as a file
/// is spooled once, as the bytes the credential scan read. A tainted row's
/// tree carries no content and claims no identity, and spools nothing.
pub(crate) fn export_source_tree_with_files(
    files: &[HubFile],
    spool: &mut FileSpool,
    tainted: bool,
) -> Result<ExportFileTree> {
    let mut tree = export_source_tree(files)?;
    if tainted {
        tree.strip();
    } else {
        attach_source_files(files, &tree, spool)?;
    }
    Ok(tree)
}

/// Spools the bytes of each member of `tree` stored as a file, from the
/// `files` the tree was exported from, checked against the member's BLAKE3
/// and length.
pub(super) fn attach_source_files(
    files: &[HubFile],
    tree: &ExportFileTree,
    spool: &mut FileSpool,
) -> Result<()> {
    for (blake3, bytes) in HeldFiles::of(files, tree)?.0 {
        if spool.attach(bytes)? != blake3 {
            return Err(invalid("source file member names other bytes"));
        }
    }
    Ok(())
}

/// Source bytes held in memory by BLAKE3 and read as an archive's files are:
/// the members a tree was exported from, or none at all.
#[derive(Default)]
pub(super) struct HeldFiles<'a>(BTreeMap<String, &'a [u8]>);

impl<'a> HeldFiles<'a> {
    /// The bytes in `files` of each member of `tree` stored as a file.
    fn of(files: &'a [HubFile], tree: &ExportFileTree) -> Result<Self> {
        let by_path: BTreeMap<&str, &'a [u8]> = files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice()))
            .collect();
        let mut held = BTreeMap::new();
        for member in &tree.files {
            let ExportSourceContent::File(body) = &member.content else {
                continue;
            };
            let bytes = by_path
                .get(member.path.as_str())
                .copied()
                .filter(|bytes| ExportBodyFile::of(bytes) == *body)
                .ok_or_else(|| invalid("source file member names other bytes"))?;
            held.insert(body.blake3().to_owned(), bytes);
        }
        Ok(Self(held))
    }
}

impl ArchiveFiles for HeldFiles<'_> {
    fn file_len(&self, blake3: &str) -> Option<u64> {
        self.0.get(blake3).map(|bytes| bytes.len() as u64)
    }

    fn with_file_reader(
        &self,
        blake3: &str,
        read: &mut dyn FnMut(&mut dyn Read) -> Result<()>,
    ) -> Result<()> {
        let bytes = self
            .0
            .get(blake3)
            .ok_or_else(|| invalid("source file member names no file"))?;
        read(&mut Cursor::new(*bytes))
    }
}

impl ExportFileTree {
    /// [`Self::validate_in`] with no archive files: a member stored as a
    /// file names none.
    pub(crate) fn validate(&self) -> Result<()> {
        self.validate_in(&HeldFiles::default())
    }

    /// Every member's proof: sorted credential-free paths, each clean
    /// member's exact bytes (a file member's read from `files`) scanned again
    /// and matching its SHA-256, the package byte bounds, and the tree hash
    /// exactly when no member is redacted.
    pub(crate) fn validate_in(&self, files: &dyn ArchiveFiles) -> Result<()> {
        self.members_in(files).map(drop)
    }

    /// [`Self::import_files_in`] with no archive files.
    pub(crate) fn import_files(&self) -> Result<Vec<HubFile>> {
        self.import_files_in(&HeldFiles::default())
    }

    /// The tree's files as their exact bytes, a file member's read from
    /// `files` and checked as [`Self::validate_in`] checks it.
    pub(crate) fn import_files_in(&self, files: &dyn ArchiveFiles) -> Result<Vec<HubFile>> {
        let members = self.members_in(files)?;
        if self.content_hash.is_none() {
            return Err(invalid("redacted source tree is not importable"));
        }
        Ok(members
            .into_iter()
            .map(|(path, content)| HubFile::new(path, content.into_owned()))
            .collect())
    }

    /// A tainted row's tree: no content, no identity claim.
    pub(crate) fn strip(&mut self) {
        self.content_hash = None;
        for file in &mut self.files {
            file.content = ExportSourceContent::Redacted;
            file.sha256 = None;
        }
    }

    /// Each member's path and exact bytes, its proof checked; a redacted
    /// member holds none.
    fn members_in<'t>(&'t self, files: &dyn ArchiveFiles) -> Result<Vec<(&'t str, Cow<'t, [u8]>)>> {
        let mut total = 0usize;
        let mut prior: Option<&str> = None;
        let mut complete = true;
        let mut members = Vec::new();
        for file in &self.files {
            if scan_file_content("", file.path.as_bytes()).is_some() {
                return Err(invalid("source path contains credential material"));
            }
            if prior.is_some_and(|p| p >= file.path.as_str()) {
                return Err(invalid("source paths not sorted"));
            }
            prior = Some(&file.path);
            let content = match (&file.content, &file.sha256) {
                (ExportSourceContent::Text(text), Some(_)) => Cow::Borrowed(text.as_bytes()),
                (ExportSourceContent::File(body), Some(_)) => {
                    // Bounded before a byte of it is read.
                    let len = usize::try_from(body.bytes()).unwrap_or(usize::MAX);
                    if len > crate::skill_hub::MAX_HUB_FILE_BYTES
                        || total.saturating_add(len) > crate::skill_hub::MAX_HUB_PACKAGE_TOTAL_BYTES
                    {
                        return Err(invalid("source files exceed package bounds"));
                    }
                    let bytes = body.read(files)?;
                    // Text is carried inline: one shape for one file.
                    if std::str::from_utf8(&bytes).is_ok() {
                        return Err(invalid("text source file is carried as a file"));
                    }
                    Cow::Owned(bytes)
                }
                (ExportSourceContent::Redacted, None) => {
                    complete = false;
                    Cow::Borrowed(&[][..])
                }
                _ => return Err(invalid("source file proof is invalid")),
            };
            if let Some(hash) = &file.sha256
                && (!source_file_is_safe(&file.path, &content) || source_digest(&content) != *hash)
            {
                return Err(invalid("source file proof is invalid"));
            }
            total = total
                .checked_add(content.len())
                .ok_or_else(|| invalid("source size overflow"))?;
            if content.len() > crate::skill_hub::MAX_HUB_FILE_BYTES
                || total > crate::skill_hub::MAX_HUB_PACKAGE_TOTAL_BYTES
            {
                return Err(invalid("source files exceed package bounds"));
            }
            members.push((file.path.as_str(), content));
        }
        // Also rejects traversal, absolute paths and case-fold aliases for redacted trees.
        let hash = canonical_skill_tree_hash(
            members
                .iter()
                .map(|(path, content)| (*path, content.as_ref())),
        )?;
        if self.content_hash != complete.then(|| hash.to_hex()) {
            return Err(invalid("source tree proof is invalid"));
        }
        Ok(members)
    }
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("whole-vault source bundle: {reason}"))
}
