//! Admission of immutable Git layout and worktree semantics before an attribute-consuming effect.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use super::failure::invalid;
use super::process::spawn_git_inner;
use super::{GIT_WIRE_CONFIG_POLICY, GitWireProcessEnv};
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RefBackend {
    Files,
    Reftable,
}

#[derive(Debug)]
pub(super) struct RepoLayout {
    pub(super) common: PathBuf,
    pub(super) git_dir: PathBuf,
    pub(super) format_version: u8,
    pub(super) refs: RefBackend,
    pub(super) bare: bool,
}

/// No raw repository config is copied into a Git child. These are the only
/// worktree-semantic values the current frozen verbs consume and can preserve.
#[derive(Debug)]
pub(super) struct WorktreeSemantics {
    filemode: bool,
    symlinks: bool,
    ignorecase: Option<bool>,
    precompose_unicode: Option<bool>,
    trust_ctime: Option<bool>,
    ignore_stat: Option<bool>,
    log_all_ref_updates: Option<bool>,
    eol: Option<&'static str>,
    safe_crlf: Option<&'static str>,
    check_stat: Option<&'static str>,
}

impl Default for WorktreeSemantics {
    fn default() -> Self {
        Self {
            filemode: true,
            symlinks: true,
            ignorecase: None,
            precompose_unicode: None,
            trust_ctime: None,
            ignore_stat: None,
            log_all_ref_updates: None,
            eol: None,
            safe_crlf: None,
            check_stat: None,
        }
    }
}

impl WorktreeSemantics {
    pub(super) fn render(&self, layout: &RepoLayout) -> String {
        let mut config = format!(
            "[core]\n repositoryformatversion = {}\n bare = {}\n filemode = {}\n symlinks = {}\n",
            layout.format_version, layout.bare, self.filemode, self.symlinks,
        );
        for (key, value) in [
            ("ignorecase", self.ignorecase),
            ("precomposeunicode", self.precompose_unicode),
            ("trustctime", self.trust_ctime),
            ("ignorestat", self.ignore_stat),
            ("logallrefupdates", self.log_all_ref_updates),
        ] {
            if let Some(value) = value {
                config.push_str(&format!(" {key} = {value}\n"));
            }
        }
        for (key, value) in [
            ("eol", self.eol),
            ("safecrlf", self.safe_crlf),
            ("checkstat", self.check_stat),
        ] {
            if let Some(value) = value {
                config.push_str(&format!(" {key} = {value}\n"));
            }
        }
        if layout.refs == RefBackend::Reftable {
            config.push_str("[extensions]\n refStorage = reftable\n");
        }
        config
    }
}

#[derive(Debug)]
struct SourceFile {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
}

impl SourceFile {
    fn observe(path: PathBuf) -> Result<Self> {
        let bytes = read_optional(&path)?;
        Ok(Self { path, bytes })
    }

    fn changed(&self) -> Result<bool> {
        Ok(read_optional(&self.path)? != self.bytes)
    }
}

#[derive(Debug)]
pub(super) struct AdmittedRepoProfile {
    pub(super) layout: RepoLayout,
    pub(super) semantics: WorktreeSemantics,
    sources: [SourceFile; 4],
}

impl AdmittedRepoProfile {
    pub(super) fn admit(
        process_env: &GitWireProcessEnv,
        repo_root: &Path,
        prefix: &[OsString],
        allow_bare_worktree_add: bool,
    ) -> Result<Self> {
        let common = git_path(process_env, repo_root, prefix, "--git-common-dir")?;
        let git_dir = git_path(process_env, repo_root, prefix, "--git-dir")?;
        let sources = [
            SourceFile::observe(common.join("config"))?,
            SourceFile::observe(git_dir.join("config.worktree"))?,
            SourceFile::observe(common.join("info/attributes"))?,
            SourceFile::observe(common.join("info/exclude"))?,
        ];
        if sources[2]
            .bytes
            .as_ref()
            .is_some_and(|bytes| !bytes.is_empty())
        {
            return Err(invalid("unmodeled repository info attributes"));
        }
        let args = prefixed(prefix, &["config", "--null", "--list", "--includes"]);
        let observed = spawn_git_inner(process_env, repo_root, &args, None, None)?;
        if !observed.success {
            return Err(invalid("git configuration snapshot could not be read"));
        }
        let (layout, semantics) = parse_effective_config(&observed.stdout, common, git_dir)?;
        if layout.bare && !allow_bare_worktree_add {
            return Err(invalid("bare repository requires a worktree-add operation"));
        }
        let profile = Self {
            layout,
            semantics,
            sources,
        };
        if profile.source_changed()? {
            return Err(invalid("repository profile changed during admission"));
        }
        // The object format is a repository fact, never guessed from a path.
        let args = prefixed(prefix, &["rev-parse", "--show-object-format=storage"]);
        let object_format = spawn_git_inner(process_env, repo_root, &args, None, None)?;
        if !object_format.success || object_format.stdout != b"sha1\n" {
            return Err(invalid("unsupported Git object format"));
        }
        if profile.source_changed()? {
            return Err(invalid("repository profile changed during admission"));
        }
        match profile.layout.refs {
            RefBackend::Files if !profile.layout.common.join("refs").is_dir() => {
                return Err(invalid("files ref store is missing"));
            }
            RefBackend::Reftable if !profile.layout.common.join("reftable").is_dir() => {
                return Err(invalid("reftable ref store is missing"));
            }
            _ => {}
        }
        if !profile.layout.common.join("objects").is_dir() {
            return Err(invalid("Git object store is missing"));
        }
        Ok(profile)
    }

    pub(super) fn exclude_bytes(&self) -> Option<&[u8]> {
        self.sources[3].bytes.as_deref()
    }

    pub(super) fn source_changed(&self) -> Result<bool> {
        for source in &self.sources {
            if source.changed()? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn git_path(
    process_env: &GitWireProcessEnv,
    repo_root: &Path,
    prefix: &[OsString],
    flag: &str,
) -> Result<PathBuf> {
    let args = prefixed(prefix, &["rev-parse", "--path-format=absolute", flag]);
    let observed = spawn_git_inner(process_env, repo_root, &args, None, None)?;
    if !observed.success {
        return Err(invalid("Git directory cannot be verified"));
    }
    let text = std::str::from_utf8(&observed.stdout)
        .map_err(|_| invalid("Git directory must be UTF-8"))?;
    let path = Path::new(text.trim_end_matches(['\r', '\n']));
    if path.as_os_str().is_empty() {
        return Err(invalid("Git directory is empty"));
    }
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_root.join(path)
    };
    path.canonicalize().map_err(Into::into)
}

pub(super) fn prefixed(prefix: &[OsString], command: &[&str]) -> Vec<OsString> {
    prefix
        .iter()
        .cloned()
        .chain(command.iter().map(|part| OsString::from(*part)))
        .collect()
}

fn parse_effective_config(
    bytes: &[u8],
    common: PathBuf,
    git_dir: PathBuf,
) -> Result<(RepoLayout, WorktreeSemantics)> {
    let mut version: Option<u8> = None;
    let mut backend: Option<RefBackend> = None;
    let mut bare = false;
    let mut semantics = WorktreeSemantics::default();
    for record in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let separator = record
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(|| invalid("malformed Git config record"))?;
        let (key, value) = record.split_at(separator);
        let value = &value[1..];
        let key = std::str::from_utf8(key).map_err(|_| invalid("Git config key is not UTF-8"))?;
        let name = key.to_ascii_lowercase();
        if GIT_WIRE_CONFIG_POLICY
            .iter()
            .any(|(pinned, _)| pinned.eq_ignore_ascii_case(&name))
        {
            continue; // command-line-precedence engine security override
        }
        match name.as_str() {
            "core.repositoryformatversion" => {
                version = Some(match value {
                    b"0" => 0,
                    b"1" => 1,
                    _ => return Err(invalid("unsupported repository format version")),
                });
            }
            "core.bare" => bare = parse_bool(value)?,
            "core.filemode" => semantics.filemode = parse_bool(value)?,
            "core.symlinks" => semantics.symlinks = parse_bool(value)?,
            "core.ignorecase" => semantics.ignorecase = Some(parse_bool(value)?),
            "core.precomposeunicode" => semantics.precompose_unicode = Some(parse_bool(value)?),
            "core.trustctime" => semantics.trust_ctime = Some(parse_bool(value)?),
            "core.ignorestat" => semantics.ignore_stat = Some(parse_bool(value)?),
            "core.logallrefupdates" => semantics.log_all_ref_updates = Some(parse_bool(value)?),
            "core.eol" => {
                semantics.eol = Some(match value {
                    b"lf" => "lf",
                    b"crlf" => "crlf",
                    b"native" => "native",
                    _ => return Err(invalid("unsupported core.eol")),
                });
            }
            "core.safecrlf" => {
                semantics.safe_crlf = Some(match value {
                    b"true" => "true",
                    b"false" => "false",
                    b"warn" => "warn",
                    _ => return Err(invalid("unsupported core.safecrlf")),
                });
            }
            "core.checkstat" => {
                semantics.check_stat = Some(match value {
                    b"default" => "default",
                    b"minimal" => "minimal",
                    _ => return Err(invalid("unsupported core.checkstat")),
                });
            }
            "extensions.objectformat" if value == b"sha1" => {}
            "extensions.objectformat" => return Err(invalid("unsupported Git object format")),
            "extensions.refstorage" => {
                backend = Some(match value {
                    b"files" => RefBackend::Files,
                    b"reftable" => RefBackend::Reftable,
                    _ => return Err(invalid("unsupported Git ref backend")),
                });
            }
            "extensions.worktreeconfig" => {
                parse_bool(value)?;
            } // flattened; child never reads mutable worktree config
            "core.sparsecheckout" | "core.sparsecheckoutcone" | "index.sparse"
                if value == b"false" => {}
            "core.sparsecheckout" | "core.sparsecheckoutcone" | "index.sparse" => {
                return Err(invalid("sparse Git worktree is unsupported"));
            }
            "core.quotepath" | "core.abbrev" | "core.compression" | "core.untrackedcache" => {}
            _ if name.starts_with("filter.")
                || name.starts_with("include.")
                || name.starts_with("includeif.")
                || name.starts_with("alias.")
                || (name.starts_with("diff.") && name.ends_with(".textconv"))
                || (name.starts_with("merge.") && name.ends_with(".driver")) =>
            {
                return Err(invalid("executable Git configuration is forbidden"));
            }
            _ if name.starts_with("core.")
                || name.starts_with("extensions.")
                || name.starts_with("index.")
                || name.starts_with("sparse.")
                || name.starts_with("submodule.") =>
            {
                return Err(invalid("unmodeled Git worktree configuration"));
            }
            _ if irrelevant_to_local_effect(&name) => {}
            _ => return Err(invalid("unmodeled Git configuration namespace")),
        }
    }
    let version = version.ok_or_else(|| invalid("Git repository format is missing"))?;
    let refs = match (version, backend) {
        (0, None | Some(RefBackend::Files)) | (1, None | Some(RefBackend::Files)) => {
            RefBackend::Files
        }
        (1, Some(RefBackend::Reftable)) => RefBackend::Reftable,
        _ => return Err(invalid("Git ref backend contradicts format version")),
    };
    Ok((
        RepoLayout {
            common,
            git_dir,
            format_version: version,
            refs,
            bare,
        },
        semantics,
    ))
}

fn parse_bool(value: &[u8]) -> Result<bool> {
    match value {
        b"true" | b"yes" | b"on" | b"1" | b"" => Ok(true),
        b"false" | b"no" | b"off" | b"0" => Ok(false),
        _ => Err(invalid("Git worktree setting must be boolean")),
    }
}

fn irrelevant_to_local_effect(name: &str) -> bool {
    [
        "user.",
        "remote.",
        "branch.",
        "color.",
        "advice.",
        "http.",
        "credential.",
        "push.",
        "fetch.",
        "pack.",
        "gc.",
        "maintenance.",
        "protocol.",
        "uploadpack.",
        "init.",
        "rerere.",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}
