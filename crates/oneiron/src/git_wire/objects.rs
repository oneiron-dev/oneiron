//! Commit and tree object model: tree entries, commit headers, commit-request bytes, tree parsers.

use super::config::{
    GIT_WIRE_MAX_ARG_BYTES, GIT_WIRE_MAX_REF_BYTES, GIT_WIRE_RESERVED_COMMIT_HEADERS,
};
use super::failure::invalid;
use super::{GitOid, GitWireResult};
use crate::error::Result;

/// One entry of a git tree object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitTreeEntry {
    pub mode: u32,
    pub name: Vec<u8>,
    pub oid: GitOid,
}

/// A validated extra commit-object header. Names are restricted to
/// `[a-z0-9-]+(:[a-z0-9-]+)*` and may never shadow a standard header; values
/// are single-line with no NUL/CR/LF. Headers ride the object body, never argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCommitHeader {
    name: String,
    value: Vec<u8>,
}

impl GitCommitHeader {
    /// Parses an extra commit header.
    pub fn parse(name: impl Into<String>, value: impl Into<Vec<u8>>) -> GitWireResult<Self> {
        let name = name.into();
        let value = value.into();
        validate_commit_header_name(&name)?;
        if value.is_empty() || value.len() > GIT_WIRE_MAX_ARG_BYTES {
            return Err(invalid("commit header value must be non-empty and bounded"));
        }
        if value.iter().any(|byte| matches!(byte, 0 | b'\n' | b'\r')) {
            return Err(invalid("commit header value must be a single line"));
        }
        Ok(Self { name, value })
    }

    /// The validated header name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The validated header value.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

fn validate_commit_header_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > GIT_WIRE_MAX_REF_BYTES {
        return Err(invalid("commit header name must be non-empty and bounded"));
    }
    if GIT_WIRE_RESERVED_COMMIT_HEADERS.contains(&name) {
        return Err(invalid(
            "commit header name must not shadow a standard header",
        ));
    }
    for segment in name.split(':') {
        let shaped = !segment.is_empty()
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !shaped {
            return Err(invalid(
                "commit header name must match [a-z0-9-]+(:[a-z0-9-]+)*",
            ));
        }
    }
    Ok(())
}

/// A commit object GitWire serializes and writes through `hash-object`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCommitRequest {
    pub tree: GitOid,
    pub parents: Vec<GitOid>,
    pub author_name: String,
    pub author_email: String,
    pub authored_at: i64,
    pub message: Vec<u8>,
    /// Extra object headers after the standard set. Empty for ordinary commits.
    pub extra_headers: Vec<GitCommitHeader>,
}

impl GitCommitRequest {
    /// Serializes the loose commit object body byte-exactly.
    pub(super) fn to_object_bytes(&self) -> Result<Vec<u8>> {
        validate_commit_identity(&self.author_name)?;
        validate_commit_identity(&self.author_email)?;
        if self.message.contains(&0) {
            return Err(invalid("commit message must not contain NUL"));
        }
        let mut object = Vec::with_capacity(256 + self.message.len());
        object.extend_from_slice(format!("tree {}\n", self.tree.as_str()).as_bytes());
        for parent in &self.parents {
            object.extend_from_slice(format!("parent {}\n", parent.as_str()).as_bytes());
        }
        let identity = format!(
            "{} <{}> {} +0000",
            self.author_name, self.author_email, self.authored_at
        );
        object.extend_from_slice(format!("author {identity}\n").as_bytes());
        object.extend_from_slice(format!("committer {identity}\n").as_bytes());
        for header in &self.extra_headers {
            object.extend_from_slice(header.name().as_bytes());
            object.push(b' ');
            object.extend_from_slice(header.value());
            object.push(b'\n');
        }
        object.push(b'\n');
        object.extend_from_slice(&self.message);
        Ok(object)
    }
}

fn validate_commit_identity(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > GIT_WIRE_MAX_REF_BYTES {
        return Err(invalid("commit identity must be non-empty and bounded"));
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || matches!(byte, b'<' | b'>'))
    {
        return Err(invalid(
            "commit identity must not contain angle or control bytes",
        ));
    }
    Ok(())
}

pub(super) fn encode_mktree_entries(entries: &[GitTreeEntry]) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    for entry in entries {
        if entry.name.is_empty() || entry.name.contains(&0) {
            return Err(invalid("tree entry name must be non-empty and NUL-free"));
        }
        let kind = match entry.mode {
            0o040_000 => "tree",
            0o160_000 => "commit",
            _ => "blob",
        };
        let record = format!("{:06o} {kind} {}\t", entry.mode, entry.oid.as_str());
        payload.extend_from_slice(record.as_bytes());
        payload.extend_from_slice(&entry.name);
        payload.push(0);
    }
    Ok(payload)
}

pub(super) fn parse_tree_entries(stdout: &[u8]) -> Result<Vec<GitTreeEntry>> {
    let mut entries = Vec::new();
    for record in stdout.split(|byte| *byte == 0) {
        if record.is_empty() {
            continue;
        }
        entries.push(parse_tree_entry(record)?);
    }
    Ok(entries)
}

fn parse_tree_entry(record: &[u8]) -> Result<GitTreeEntry> {
    let split = record
        .iter()
        .position(|byte| *byte == b'\t')
        .ok_or_else(|| invalid("git tree record is missing its name separator"))?;
    let header = std::str::from_utf8(&record[..split])
        .map_err(|_| invalid("git tree record header must be UTF-8"))?;
    let mut fields = header.split(' ');
    let mode = fields
        .next()
        .ok_or_else(|| invalid("git tree record is missing its mode"))?;
    let _kind = fields
        .next()
        .ok_or_else(|| invalid("git tree record is missing its type"))?;
    let oid = fields
        .next()
        .ok_or_else(|| invalid("git tree record is missing its oid"))?;
    Ok(GitTreeEntry {
        mode: u32::from_str_radix(mode, 8)
            .map_err(|_| invalid("git tree record mode must be octal"))?,
        name: record[split + 1..].to_vec(),
        oid: GitOid::parse_hex(oid)?,
    })
}
