//! Reference deployment scaffolding and explicit encryption provisioning.

use crate::cli::HostInitArgs;
use std::{fs, io::Write, path::Path};

const TEMPLATES: &[(&str, &[u8])] = &[
    (
        "systemd/oneiron.service",
        include_bytes!("../../../../deploy/systemd/oneiron.service"),
    ),
    (
        "launchd/com.oneiron.server.plist",
        include_bytes!("../../../../deploy/launchd/com.oneiron.server.plist"),
    ),
    (
        "install-oneiron-server.sh",
        include_bytes!("../../../../deploy/install-oneiron-server.sh"),
    ),
];

pub fn host_init(args: HostInitArgs) -> anyhow::Result<()> {
    // create_dir, not create_dir_all: a pre-existing directory or symlink is a
    // refusal. Thus the hook never runs against an existing node by accident.
    fs::create_dir(&args.path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&args.path, fs::Permissions::from_mode(0o700))?;
    }
    if let Some(hook) = args.encryption_hook {
        let status = std::process::Command::new(hook).arg(&args.path).status()?;
        anyhow::ensure!(status.success(), "encryption hook failed");
    }
    for (name, bytes) in TEMPLATES {
        let path = args.path.join(name);
        if let Some(parent) = path.parent().filter(|p| *p != args.path) {
            // A hook-created directory is not trusted for file traversal.
            fs::create_dir(parent)?;
        }
        write_template(&path, bytes)?;
    }
    Ok(())
}

fn write_template(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if path.extension().is_some_and(|ext| ext == "sh") {
            0o700
        } else {
            0o600
        };
        file.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn init_matches_reference_and_refuses_overwrite() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("node");
        let args = HostInitArgs {
            path: path.clone(),
            encryption_hook: None,
        };
        host_init(args.clone())?;
        for (name, bytes) in TEMPLATES {
            assert_eq!(fs::read(path.join(name))?, *bytes);
        }
        assert!(host_init(args).is_err());
        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn encryption_hook_runs_and_failure_refuses_templates() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let hook = dir.path().join("provision");
        fs::write(
            &hook,
            b"#!/bin/sh\nprintf sealed > \"$1/encryption-receipt\"\n",
        )?;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o700))?;
        let path = dir.path().join("node");
        host_init(HostInitArgs {
            path: path.clone(),
            encryption_hook: Some(hook.clone()),
        })?;
        assert_eq!(fs::read(path.join("encryption-receipt"))?, b"sealed");
        fs::write(&hook, b"#!/bin/sh\nexit 1\n")?;
        let path = dir.path().join("failed");
        assert!(
            host_init(HostInitArgs {
                path: path.clone(),
                encryption_hook: Some(hook)
            })
            .is_err()
        );
        assert!(!path.join(TEMPLATES[0].0).exists());
        Ok(())
    }
}
