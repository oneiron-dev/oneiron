//! Small falsification fixtures; smoke is never accepted as a fleet baseline.
use super::*;

#[test]
fn fleet_digest_prints_the_blake3_of_a_file() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("receipt.json");
    // Longer than one 64 KiB read, so the digest spans several buffer fills.
    let bytes = (0..=u8::MAX).cycle().take(200_000).collect::<Vec<_>>();
    std::fs::write(&path, &bytes)?;
    let args = [
        "digest",
        "--file",
        path.to_str().ok_or("temp path is not UTF-8")?,
    ]
    .map(String::from);
    let mut stdout = Vec::new();
    dispatch(&args, &mut stdout)?;
    assert_eq!(
        String::from_utf8(stdout)?,
        format!("{}\n", blake3::hash(&bytes).to_hex())
    );
    Ok(())
}
