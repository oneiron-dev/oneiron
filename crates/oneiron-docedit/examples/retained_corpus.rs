//! Check retained OPC identity against a hash-pinned external corpus directory.
use oneiron_docedit::opc::{Limits, Package};
use std::io::Write;
use std::path::Path;

fn check(path: &Path) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let mut package = Package::open(&bytes, Limits::default())?;
    if package.write()? != bytes {
        return Err("no-op archive identity failed".into());
    }
    let part = package
        .names()
        .find(|p| p.ends_with(".xml") && *p != "[Content_Types].xml")
        .ok_or("no editable XML part")?
        .to_owned();
    let original = package.part(&part).ok_or("missing part")?.to_vec();
    let position = original
        .windows(2)
        .rposition(|pair| pair == b"</")
        .ok_or("no closing XML tag")?;
    package.splice(&part, position..position, b"", b"<!--retained OPC probe-->")?;
    let edited = package.write()?;
    let reopened = Package::open(&edited, Limits::default())?;
    for name in package.names() {
        if package.part(name) != reopened.part(name) {
            return Err("edited archive payload differs".into());
        }
    }
    let mut expected = original;
    expected.splice(
        position..position,
        b"<!--retained OPC probe-->".iter().copied(),
    );
    if reopened.part(&part) != Some(expected.as_slice()) {
        return Err("unknown XML was moved".into());
    }
    Ok(
        serde_json::json!({"file": path.file_name().and_then(|n| n.to_str()), "input_blake3": blake3::hash(&bytes).to_hex().as_str(),
        "bytes": bytes.len(), "parts": package.names().count(), "no_op_archive_exact": true,
        "edit_unknown_xml_in_place": true, "untouched_part_payloads_exact": true}),
    )
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let directory = args
        .next()
        .ok_or("usage: retained_corpus INPUT_DIRECTORY REPORT_JSON")?;
    let report = args.next().ok_or("missing report path")?;
    let mut paths = std::fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.retain(|path| {
        path.extension()
            .is_some_and(|ext| matches!(ext.to_str(), Some("pptx" | "xlsx" | "docx")))
    });
    paths.sort();
    if paths.is_empty() {
        return Err("empty OPC corpus".into());
    }
    let mut results = Vec::new();
    for path in paths {
        results.push(check(&path)?);
    }
    std::fs::write(report, serde_json::to_vec_pretty(&results)?)?;
    writeln!(
        std::io::stderr(),
        "retained OPC corpus: {} passed",
        results.len()
    )?;
    Ok(())
}
