//! Generic pinned Git subtree reads. Files are read as blobs, never checked out or executed.
//! A repository is a hub (ARCH-0053 §7): `owner/repo` names a GitHub repository,
//! and discovery lists its skill folders the way `npx skills add` does.
use super::git_process::GitScratch;
use super::package::{MAX_HUB_FILE_BYTES, MAX_HUB_PACKAGE_FILES, MAX_HUB_PACKAGE_TOTAL_BYTES};
use super::package_codec::invalid;
use super::{HubFile, HubIndexEntry, HubPackage, HubPin, HubRef, SkillHubAdapter, SkillHubKind};
use crate::{entity_id::EntityId, error::Result};

/// A configured repository plus an immutable expected commit. A tag is checked
/// against that commit every fetch; a moved tag cannot silently update content.
/// `HubRef.ref_string` is the repository-relative skill folder (`.` for the root).
/// Local absolute paths are explicit host configuration, not index-provided URLs;
/// the `owner/repo` shorthand is `https://github.com/owner/repo.git`.
pub struct GitEndpointSkillHubAdapter {
    hub_id: EntityId,
    endpoint: String,
    commit: String,
}
impl GitEndpointSkillHubAdapter {
    pub fn new(hub_id: EntityId, endpoint: &str, expected_commit: &str) -> Result<Self> {
        if !is_oid(expected_commit) {
            return Err(invalid("Git transport requires a full commit pin"));
        }
        Ok(Self {
            hub_id,
            endpoint: normalize_endpoint(endpoint)?,
            commit: expected_commit.to_ascii_lowercase(),
        })
    }
    /// Follows a tag to the commit it names now (a pinned-ref sync). The commit
    /// only pins this transport: the fetched bytes earn nothing until their
    /// content hash passes the scan and install doors.
    pub fn at_tag(hub_id: EntityId, endpoint: &str, tag: &str) -> Result<Self> {
        if !valid_tag(tag) {
            return Err(invalid("invalid Git tag"));
        }
        let endpoint = normalize_endpoint(endpoint)?;
        let (_, commit) = fetch_revision(&endpoint, &format!("refs/tags/{tag}"))?;
        Ok(Self {
            hub_id,
            endpoint,
            commit,
        })
    }
    /// Immutable resolved revision to attach to host tracking/provenance.
    #[must_use]
    pub fn resolved_commit(&self) -> &str {
        &self.commit
    }
    fn fetch_tree(&self, reference: &HubRef) -> Result<Vec<HubFile>> {
        if reference.hub_id != self.hub_id {
            return Err(invalid("cross-hub fetch refused"));
        }
        let revision = match &reference.pin {
            HubPin::Commit(commit) if commit.eq_ignore_ascii_case(&self.commit) => {
                self.commit.clone()
            }
            HubPin::ContentHash(_) => self.commit.clone(),
            HubPin::Tag(tag) | HubPin::Semver(tag) if valid_tag(tag) => format!("refs/tags/{tag}"),
            _ => {
                return Err(invalid(
                    "Git reference is unpinned or differs from configured pin",
                ));
            }
        };
        let subtree = &reference.ref_string;
        if subtree != "." {
            crate::skill::canonical_skill_tree_hash([(subtree.as_str(), &[][..])])?;
        }
        let (repo, resolved) = fetch_revision(&self.endpoint, &revision)?;
        if resolved != self.commit {
            return Err(invalid("Git tag or commit drift"));
        }
        let object = if subtree == "." {
            format!("{}^{{tree}}", self.commit)
        } else {
            format!("{}:{subtree}", self.commit)
        };
        let listing = repo.run(
            &[
                "--git-dir=repo",
                "ls-tree",
                "-r",
                "-z",
                "--full-tree",
                &object,
            ],
            2 * 1024 * 1024,
        )?;
        let files = read_blobs(&repo, &listing)?;
        let actual = crate::skill::canonical_skill_tree_hash(
            files
                .iter()
                .map(|f| (f.path.as_str(), f.content.as_slice())),
        )?;
        if let HubPin::ContentHash(hash) = &reference.pin
            && actual != crate::skill::SkillContentHash::parse_hex(hash)?
        {
            return Err(invalid("Git subtree content hash drift"));
        }
        Ok(files)
    }
}
impl super::pack_catalog::PackSourceAdapter for GitEndpointSkillHubAdapter {
    fn fetch_pack_source(&self, reference: &HubRef) -> Result<super::pack_catalog::PackSource> {
        Ok(super::pack_catalog::PackSourceAdapter::fetch_pack_tree(self, reference)?.source)
    }
    fn fetch_pack_tree(&self, reference: &HubRef) -> Result<super::pack_catalog::PackTree> {
        super::pack_catalog::PackSource::from_tree(self.fetch_tree(reference)?)
    }
}
impl SkillHubAdapter for GitEndpointSkillHubAdapter {
    fn endpoint(&self) -> Option<&str> {
        Some(&self.endpoint)
    }
    fn hub_id(&self) -> EntityId {
        self.hub_id
    }
    fn kind(&self) -> SkillHubKind {
        SkillHubKind::Git
    }
    fn fetch_package(&self, reference: &HubRef) -> Result<HubPackage> {
        super::folder::package_from_files(self.fetch_tree(reference)?)
    }
    /// The skill folders at the pinned commit: each folder holding a `SKILL.md`
    /// that no enclosing skill folder holds, read as blobs under a fetch's
    /// bounds, never checked out. A collection (anthropics/skills, a Claude
    /// plugin marketplace's `plugins/*/skills/*`, Codex and openskills layouts)
    /// lists every skill; a folder whose tree or frontmatter does not import is
    /// left out, and an import of it refuses with the reason.
    fn discover(&self) -> Result<Vec<HubIndexEntry>> {
        let (repo, resolved) = fetch_revision(&self.endpoint, &self.commit)?;
        if resolved != self.commit {
            return Err(invalid("Git tag or commit drift"));
        }
        let root = format!("{}^{{tree}}", self.commit);
        let listing = repo.run(
            &[
                "--git-dir=repo",
                "ls-tree",
                "-r",
                "-z",
                "--full-tree",
                &root,
            ],
            16 * 1024 * 1024,
        )?;
        let mut entries = Vec::new();
        for folder in skill_folders(&listing)? {
            let object = if folder == "." {
                root.clone()
            } else {
                format!("{}:{folder}", self.commit)
            };
            let Ok(files) = repo
                .run(
                    &[
                        "--git-dir=repo",
                        "ls-tree",
                        "-r",
                        "-z",
                        "--full-tree",
                        &object,
                    ],
                    2 * 1024 * 1024,
                )
                .and_then(|listing| read_blobs(&repo, &listing))
            else {
                continue;
            };
            let Ok(package) = super::folder::package_from_files(files) else {
                continue;
            };
            entries.push(HubIndexEntry {
                name: package.record.skill_id.clone(),
                description: package.record.desc.clone(),
                version: package.record.version.clone(),
                content_hash: package.content_hash()?,
                ref_string: folder,
            });
        }
        Ok(entries)
    }
}
/// The most skill folders one discovery reads.
const MAX_DISCOVERED_SKILLS: usize = 256;
/// Folders holding a `SKILL.md`, in path order; a folder inside another skill's
/// folder is part of that skill. Repository metadata folders are skipped.
fn skill_folders(listing: &[u8]) -> Result<Vec<String>> {
    let mut folders = Vec::new();
    for row in listing
        .split(|byte| *byte == 0)
        .filter(|row| !row.is_empty())
    {
        let row = std::str::from_utf8(row).map_err(|_| invalid("Git path is not UTF-8"))?;
        let (_, path) = row
            .split_once('\t')
            .ok_or_else(|| invalid("invalid Git tree entry"))?;
        let folder = match path.rsplit_once('/') {
            Some((folder, "SKILL.md")) => folder,
            None if path == "SKILL.md" => ".",
            _ => continue,
        };
        if folder
            .split('/')
            .any(|part| part.eq_ignore_ascii_case(".git"))
        {
            continue;
        }
        folders.push(folder.to_owned());
    }
    folders.sort();
    let mut kept: Vec<String> = Vec::new();
    for folder in folders {
        if kept
            .iter()
            .any(|outer| outer == "." || folder.starts_with(&format!("{outer}/")))
        {
            continue;
        }
        if kept.len() == MAX_DISCOVERED_SKILLS {
            return Err(invalid(
                "the repository holds more skill folders than one discovery reads; name a subtree",
            ));
        }
        kept.push(folder);
    }
    Ok(kept)
}
/// `owner/repo`, the shorthand skills.sh and `npx skills add` use for GitHub.
fn github_shorthand(endpoint: &str) -> Option<String> {
    let (owner, repo) = endpoint.split_once('/')?;
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    let valid = |part: &str| {
        !part.is_empty()
            && part.len() <= 100
            && !part.starts_with('.')
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    };
    (valid(owner) && valid(repo)).then(|| format!("https://github.com/{owner}/{repo}.git"))
}
fn normalize_endpoint(endpoint: &str) -> Result<String> {
    if let Some(url) = github_shorthand(endpoint) {
        return Ok(url);
    }
    if std::path::Path::new(endpoint).is_absolute() {
        let path = std::fs::canonicalize(endpoint)?;
        return Ok(path
            .to_str()
            .ok_or_else(|| invalid("Git path is not UTF-8"))?
            .to_owned());
    }
    let url = reqwest::Url::parse(endpoint).map_err(|_| invalid("invalid Git endpoint"))?;
    if !matches!(url.scheme(), "https" | "http")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid("Git endpoint scheme or credentials refused"));
    }
    Ok(url.to_string())
}
/// One shallow, blob-less fetch into a fresh scratch store. Returns the store
/// and the commit the revision resolved to.
fn fetch_revision(endpoint: &str, revision: &str) -> Result<(GitScratch, String)> {
    let repo = GitScratch::new()?;
    repo.run(
        &["--git-dir=repo", "config", "remote.origin.url", endpoint],
        4096,
    )?;
    repo.run(
        &["--git-dir=repo", "config", "remote.origin.promisor", "true"],
        4096,
    )?;
    repo.run(
        &[
            "--git-dir=repo",
            "config",
            "remote.origin.partialclonefilter",
            "blob:none",
        ],
        4096,
    )?;
    repo.run(
        &[
            "--git-dir=repo",
            "fetch",
            "--quiet",
            "--no-tags",
            "--no-recurse-submodules",
            "--depth=1",
            "--filter=blob:none",
            "--",
            "origin",
            revision,
        ],
        4096,
    )?;
    let resolved = repo.run(
        &[
            "--git-dir=repo",
            "rev-parse",
            "--verify",
            "FETCH_HEAD^{commit}",
        ],
        128,
    )?;
    let resolved = std::str::from_utf8(&resolved)
        .ok()
        .map(str::trim)
        .filter(|commit| is_oid(commit))
        .ok_or_else(|| invalid("Git revision did not resolve to a commit"))?
        .to_ascii_lowercase();
    Ok((repo, resolved))
}
fn is_oid(text: &str) -> bool {
    matches!(text.len(), 40 | 64) && text.bytes().all(|b| b.is_ascii_hexdigit())
}
fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 256
        && !tag.starts_with('-')
        && !tag.contains("..")
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
}
fn read_blobs(repo: &GitScratch, listing: &[u8]) -> Result<Vec<HubFile>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut files = Vec::new();
    let mut remaining = MAX_HUB_PACKAGE_TOTAL_BYTES;
    for row in listing
        .split(|byte| *byte == 0)
        .filter(|row| !row.is_empty())
    {
        if files.len() >= MAX_HUB_PACKAGE_FILES || std::time::Instant::now() >= deadline {
            return Err(invalid("Git subtree resource budget exceeded"));
        }
        let row = std::str::from_utf8(row).map_err(|_| invalid("Git path is not UTF-8"))?;
        let (header, path) = row
            .split_once('\t')
            .ok_or_else(|| invalid("invalid Git tree entry"))?;
        let mut fields = header.split(' ');
        let mode = fields.next();
        let kind = fields.next();
        let oid = fields.next();
        if !matches!(mode, Some("100644" | "100755"))
            || kind != Some("blob")
            || fields.next().is_some()
            || !oid.is_some_and(is_oid)
        {
            return Err(invalid(
                "Git symlinks, submodules and non-file entries refused",
            ));
        }
        let oid = oid.ok_or_else(|| invalid("Git blob id missing"))?;
        let size = repo.run(&["--git-dir=repo", "cat-file", "-s", oid], 64)?;
        let size: usize = std::str::from_utf8(&size)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .ok_or_else(|| invalid("invalid Git blob size"))?;
        if size > MAX_HUB_FILE_BYTES.min(remaining) {
            return Err(invalid("Git blob exceeds bound"));
        }
        let content = repo.run(&["--git-dir=repo", "cat-file", "blob", oid], size)?;
        if content.len() != size {
            return Err(invalid("Git blob size drift"));
        }
        remaining -= size;
        files.push(HubFile::new(path, content));
    }
    Ok(files)
}
