use std::fs;
use std::io;

use oneiron::prompt::resolve_prompt;

const HOST_PROMPT_PATH: &str = "session.md";

#[test]
fn prompt_resolver_rejects_includes_outside_package_root() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = tempfile::tempdir()?;
    let package_root = temp.path().join("packages/prompts");
    fs::create_dir_all(&package_root)?;
    fs::create_dir_all(temp.path().join("packages"))?;
    fs::write(temp.path().join("packages/outside.md"), "outside\n")?;
    fs::write(
        package_root.join(HOST_PROMPT_PATH),
        "@include ../outside.md\n",
    )?;

    let err = resolve_prompt(package_root.join(HOST_PROMPT_PATH), &package_root)
        .expect_err("include traversal outside package root must fail");
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

    Ok(())
}
