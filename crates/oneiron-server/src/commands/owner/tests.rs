use super::*;

#[test]
fn a_failed_export_write_leaves_no_file_and_the_same_out_retries() {
    let root = tempfile::tempdir().unwrap();
    let out = root.path().join("vault.md");
    let error = write_new_file(&out, |file| {
        file.write_all(b"half an exp")?;
        Err(io::Error::other("disk full"))
    })
    .unwrap_err();
    assert!(error.to_string().contains("disk full"), "{error}");
    assert!(!out.exists(), "the partial export is removed");

    write_new_file(&out, |file| file.write_all(b"the whole export")).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), b"the whole export");
    assert!(
        write_new_file(&out, |_| Ok(())).is_err(),
        "an existing export is never overwritten"
    );
    assert_eq!(std::fs::read(&out).unwrap(), b"the whole export");
}
