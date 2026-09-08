//! The stable /mnt guest namespace: mounts, virtual paths and host-path resolution.

use std::{
    fmt,
    path::{Path, PathBuf},
};

use crate::{Error, Result};

pub const SANDBOX_MNT_ROOT: &str = "/mnt";

pub const SANDBOX_WORKSPACE_ROOT: &str = "/mnt/workspace";

pub const SANDBOX_UPLOADS_ROOT: &str = "/mnt/uploads";

pub const SANDBOX_OUTPUTS_ROOT: &str = "/mnt/outputs";

pub const SANDBOX_SKILLS_ROOT: &str = "/mnt/skills";

/// Stable `/mnt` mount classes visible to guest code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SandboxMount {
    Workspace,
    Uploads,
    Outputs,
    Skills,
}

impl SandboxMount {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Uploads => "uploads",
            Self::Outputs => "outputs",
            Self::Skills => "skills",
        }
    }

    #[must_use]
    pub const fn root(self) -> &'static str {
        match self {
            Self::Workspace => SANDBOX_WORKSPACE_ROOT,
            Self::Uploads => SANDBOX_UPLOADS_ROOT,
            Self::Outputs => SANDBOX_OUTPUTS_ROOT,
            Self::Skills => SANDBOX_SKILLS_ROOT,
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "workspace" => Some(Self::Workspace),
            "uploads" => Some(Self::Uploads),
            "outputs" => Some(Self::Outputs),
            "skills" => Some(Self::Skills),
            _ => None,
        }
    }
}

/// Canonical virtual path in the guest-visible `/mnt` ABI.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SandboxVirtualPath {
    path: String,
    mount: SandboxMount,
    relative: String,
}

impl SandboxVirtualPath {
    /// Creates a canonical virtual path under `/mnt/{workspace,uploads,outputs,skills}`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidClaimBody`] when the path is not absolute under
    /// `/mnt`, targets an unknown mount, or contains empty / `.` / `..`
    /// components.
    pub fn try_new(path: impl AsRef<str>) -> Result<Self> {
        let path = path.as_ref();
        if !path.starts_with('/') {
            return Err(Error::InvalidClaimBody(
                "sandbox virtual path must be absolute",
            ));
        }

        let without_root = path
            .strip_prefix('/')
            .ok_or(Error::InvalidClaimBody("sandbox virtual path missing root"))?;
        let components = without_root.split('/').collect::<Vec<_>>();
        if components.len() < 2 || components[0] != "mnt" {
            return Err(Error::InvalidClaimBody(
                "sandbox virtual path must start with /mnt",
            ));
        }

        if components
            .iter()
            .any(|component| component.is_empty() || *component == "." || *component == "..")
        {
            return Err(Error::InvalidClaimBody(
                "sandbox virtual path must be canonical",
            ));
        }

        if components
            .iter()
            .any(|component| component.as_bytes().contains(&0))
        {
            return Err(Error::InvalidClaimBody(
                "sandbox virtual path contains nul byte",
            ));
        }
        if components.iter().any(|component| component.contains('\\')) {
            return Err(Error::InvalidClaimBody(
                "sandbox virtual path contains host path separator",
            ));
        }

        let mount = SandboxMount::parse(components[1]).ok_or(Error::InvalidClaimBody(
            "sandbox virtual path targets unknown /mnt mount",
        ))?;
        let relative = components[2..].join("/");
        Ok(Self {
            path: format!("/{}", components.join("/")),
            mount,
            relative,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn mount(&self) -> SandboxMount {
        self.mount
    }

    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative
    }
}

impl fmt::Debug for SandboxVirtualPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SandboxVirtualPath")
            .field(&self.path)
            .finish()
    }
}

/// Host-owned mapping from virtual `/mnt` roots to real filesystem roots.
pub struct SandboxMountTable {
    workspace: PathBuf,
    uploads: PathBuf,
    outputs: PathBuf,
    skills: PathBuf,
}

impl SandboxMountTable {
    /// Creates a host mount table. The paths are host-only and are never
    /// returned by guest-facing adapter calls.
    #[must_use]
    pub fn new(
        workspace: impl Into<PathBuf>,
        uploads: impl Into<PathBuf>,
        outputs: impl Into<PathBuf>,
        skills: impl Into<PathBuf>,
    ) -> Self {
        Self {
            workspace: workspace.into(),
            uploads: uploads.into(),
            outputs: outputs.into(),
            skills: skills.into(),
        }
    }

    #[must_use]
    pub const fn guest_mount_roots(&self) -> [&'static str; 4] {
        [
            SANDBOX_WORKSPACE_ROOT,
            SANDBOX_UPLOADS_ROOT,
            SANDBOX_OUTPUTS_ROOT,
            SANDBOX_SKILLS_ROOT,
        ]
    }

    /// Resolves a validated virtual path to its host path for host-side IO.
    #[must_use]
    pub fn resolve_host_path(&self, path: &SandboxVirtualPath) -> PathBuf {
        let root = match path.mount() {
            SandboxMount::Workspace => &self.workspace,
            SandboxMount::Uploads => &self.uploads,
            SandboxMount::Outputs => &self.outputs,
            SandboxMount::Skills => &self.skills,
        };
        if path.relative_path().is_empty() {
            return root.clone();
        }
        root.join(Path::new(path.relative_path()))
    }
}

impl fmt::Debug for SandboxMountTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SandboxMountTable")
            .field("guest_mount_roots", &self.guest_mount_roots())
            .field("host_roots", &"<host-only>")
            .finish()
    }
}
