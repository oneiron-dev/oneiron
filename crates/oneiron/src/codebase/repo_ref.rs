//! RepoRef identity: local-folder and GitHub-at-commit references with parsing and commit-hash normalization.

use super::snapshot::{CODEBASE_FILE_PATH_MAX_BYTES, validate_bounded_text};
use crate::error::{Error, Result};

pub const CODEBASE_REPO_REF_MAX_BYTES: usize = 1024;

pub const CODEBASE_COMMIT_HASH_HEX_LEN: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RepoRef {
    LocalFolder {
        path: String,
        commit: String,
    },
    GitHubAtCommit {
        owner: String,
        repo: String,
        commit: String,
    },
}

impl RepoRef {
    pub fn parse(input: &str) -> Result<Self> {
        validate_bounded_text(
            input,
            CODEBASE_REPO_REF_MAX_BYTES,
            "repo_ref must be non-empty and at most 1024 bytes",
        )?;
        if input.trim() != input {
            return Err(Error::InvalidCodebaseSnapshotBody(
                "repo_ref must not have leading or trailing whitespace",
            ));
        }

        if let Some(path) = input.strip_prefix("local:") {
            return parse_local_repo_ref(path);
        }
        if let Some(path) = input.strip_prefix("file://") {
            return parse_local_repo_ref(path);
        }

        if let Some(rest) = input.strip_prefix("github:") {
            return parse_github_repo_ref(rest);
        }
        if let Some(rest) = input.strip_prefix("git:") {
            return parse_github_repo_ref(rest);
        }
        parse_github_repo_ref(input)
    }

    pub fn from_task_list_repo_url(repo_url: &str, commit_ref: &str) -> Result<Self> {
        validate_bounded_text(
            repo_url,
            CODEBASE_REPO_REF_MAX_BYTES,
            "TASK_LIST repoUrl must be non-empty and at most 1024 bytes",
        )?;
        if repo_url.trim() != repo_url {
            return Err(Error::InvalidCodebaseSnapshotBody(
                "TASK_LIST repoUrl must not have leading or trailing whitespace",
            ));
        }
        if repo_url.contains('#') {
            return Err(Error::InvalidCodebaseSnapshotBody(
                "TASK_LIST repoUrl migration requires commit_ref separately",
            ));
        }
        let commit = normalize_commit_hash(commit_ref)?;
        Self::parse(&format!("{repo_url}#{commit}"))
    }

    #[must_use]
    pub fn canonical(&self) -> String {
        match self {
            Self::LocalFolder { path, commit } => format!("local:{path}#{commit}"),
            Self::GitHubAtCommit {
                owner,
                repo,
                commit,
            } => {
                format!("github:{owner}/{repo}#{commit}")
            }
        }
    }

    #[must_use]
    pub fn commit_hash(&self) -> Option<&str> {
        match self {
            Self::LocalFolder { commit, .. } => Some(commit.as_str()),
            Self::GitHubAtCommit { commit, .. } => Some(commit.as_str()),
        }
    }
}

fn parse_local_repo_ref(input: &str) -> Result<RepoRef> {
    let (path, commit) = input
        .split_once('#')
        .ok_or(Error::InvalidCodebaseSnapshotBody(
            "local repo_ref must include #<40-hex-commit>",
        ))?;
    let commit = normalize_commit_hash(commit)?;
    validate_bounded_text(
        path,
        CODEBASE_FILE_PATH_MAX_BYTES,
        "local repo_ref path must be non-empty and at most 4096 bytes",
    )?;
    if path.trim() != path {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "local repo_ref path must not have leading or trailing whitespace",
        ));
    }
    Ok(RepoRef::LocalFolder {
        path: path.to_owned(),
        commit,
    })
}

fn parse_github_repo_ref(input: &str) -> Result<RepoRef> {
    let rest = input
        .strip_prefix("https://github.com/")
        .or_else(|| input.strip_prefix("http://github.com/"))
        .or_else(|| input.strip_prefix("git@github.com:"))
        .unwrap_or(input);
    let (repo_path, commit) = rest
        .split_once('#')
        .ok_or(Error::InvalidCodebaseSnapshotBody(
            "GitHub repo_ref must include #<40-hex-commit>",
        ))?;
    let commit = normalize_commit_hash(commit)?;

    let repo_path = repo_path.trim_end_matches(".git");
    let mut parts = repo_path.split('/');
    let owner = parts.next().unwrap_or_default();
    let repo = parts.next().unwrap_or_default();
    if parts.next().is_some() || owner.is_empty() || repo.is_empty() {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "GitHub repo_ref must identify owner/repo",
        ));
    }
    validate_github_segment(owner, "GitHub owner")?;
    validate_github_segment(repo, "GitHub repo")?;
    Ok(RepoRef::GitHubAtCommit {
        owner: owner.to_owned(),
        repo: repo.to_owned(),
        commit,
    })
}

fn validate_github_segment(segment: &str, context: &'static str) -> Result<()> {
    if segment.len() > 100
        || !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(Error::InvalidCodebaseSnapshotBody(context));
    }
    Ok(())
}

pub(super) fn normalize_commit_hash(input: impl AsRef<str>) -> Result<String> {
    let input = input.as_ref();
    if input.len() != CODEBASE_COMMIT_HASH_HEX_LEN || !input.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "commit hash must be 40 hexadecimal characters",
        ));
    }
    Ok(input.to_ascii_lowercase())
}

pub(super) fn validate_normalized_commit_hash(input: &str) -> Result<()> {
    if normalize_commit_hash(input)? != input {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "commit hash must use lowercase hexadecimal",
        ));
    }
    Ok(())
}
