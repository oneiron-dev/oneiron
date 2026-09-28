//! Resolve a DOCX revision in the pinned fork for an application oracle case.
use oneiron_docedit::{Document, ExportOptions};
use stemma::Resolution;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mode = args
        .next()
        .ok_or("usage: resolve_docx <accept|reject> <input.docx> <output.docx>")?;
    let input_path = args.next().ok_or("missing input DOCX path")?;
    let output_path = args.next().ok_or("missing output DOCX path")?;
    let resolution = match mode.as_str() {
        "accept" => Resolution::AcceptAll,
        "reject" => Resolution::RejectAll,
        _ => return Err("resolution must be accept or reject".into()),
    };
    let input = std::fs::read(input_path)?;
    let output = Document::parse(&input)?
        .project(resolution)?
        .serialize(&ExportOptions::default())?;
    std::fs::write(output_path, output)?;
    Ok(())
}
