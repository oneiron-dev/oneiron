//! The `deck-create-v1` oracle case set: six new decks the emitter writes, the run that pins them, and the rows PowerPoint owes each one (ARCH-0077 slides lane).
//!
//! Creation status: "Text, tables and charts return FitUnverified. Nothing certifies fit." The oracle runs once per case set to create golden outputs; CI uses the stored ones, so no always-on machine is required. This module is the engine half of that pass: evidence tooling run by the `deck-create-cases` binary and read back by the receipt pin test. It replays [`emit`](super::emit) once per case and pins what came out; it never changes what `emit` returns.

use super::{Candidate, Content, Destination, EmitInputs, FitTrace, Names, StoredAsset, emit};
use crate::design_plan::{AssetBinding, KeptBrief, Outcome};
use crate::graphic::GraphicLimits;
use crate::ooxml::XmlTree;
use crate::resource::Resources;
use crate::retained_opc::{Limits, Package};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The case manifest, relative to the repository root.
pub const CASE_MANIFEST: &str = "scripts/office/deck-create-v1.json";
/// The committed Office results, relative to the repository root.
pub const STORED_RESULTS: &str = "scripts/office/results/deck-create-v1";
/// The run manifest's schema; `deck_create_gate.py` reads no other.
pub const RUN_SCHEMA: &str = "oneiron.deck-create-run/1";

const USAGE: &str = "usage: --out <new dir> [--repo <dir>] [--source <commit>]";
const PML: &str = "http://schemas.openxmlformats.org/presentationml/2006/main";

/// The `deck-create-v1` case manifest: the template, the names emission uses, the cases and the Office half's pins.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSet {
    /// The case set's name.
    pub case_set: String,
    /// The manifest format; only 1 reads.
    pub version: u32,
    /// The template, relative to the repository root.
    pub template: String,
    /// The kept brief version every case compiles under.
    pub brief_version: String,
    /// The names emission stamps on what it creates.
    pub names: CaseNames,
    /// The cases, in run order.
    pub cases: Vec<CaseSpec>,
    /// The Office half's budget, observer and scripts.
    pub office: OfficeSpec,
}

/// The names emission stamps on created shapes and workbook sheets.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseNames {
    /// Ordinary text shapes.
    pub text: String,
    /// Tables.
    pub table: String,
    /// Charts.
    pub chart: String,
    /// Pictures.
    pub picture: String,
    /// Native figure groups.
    pub figure: String,
    /// The embedded workbooks' one sheet.
    pub sheet: String,
}

/// One case: its id and its brief.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSpec {
    /// Lower-case ASCII words joined by `-`.
    pub id: String,
    /// The brief, relative to the repository root.
    pub brief: String,
}

/// The Office half's budget, observer and scripts.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfficeSpec {
    /// Seconds PowerPoint gets per candidate before the case is inconclusive.
    pub timeout_seconds: u64,
    /// The observer that watches PowerPoint while it measures.
    pub observer: String,
    /// File names in `scripts/office/`, copied into the run.
    pub scripts: Vec<String>,
}

/// A case set with the bytes its run pins: the manifest and the template.
#[derive(Debug, Clone)]
pub struct LoadedCaseSet {
    /// The parsed manifest.
    pub set: CaseSet,
    /// The manifest's bytes, unchanged.
    pub manifest_bytes: Vec<u8>,
    /// The template's bytes.
    pub template_bytes: Vec<u8>,
}

/// Read the case manifest and the template it names from `repo`.
pub fn load(repo: &Path) -> Result<LoadedCaseSet, String> {
    let path = repo.join(CASE_MANIFEST);
    let manifest_bytes =
        std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let text = std::str::from_utf8(&manifest_bytes)
        .map_err(|_| format!("{} is not UTF-8", path.display()))?;
    let set: CaseSet =
        serde_json::from_str(text).map_err(|error| format!("{}: {error}", path.display()))?;
    let version = set.version;
    if version != 1 {
        return Err(format!(
            "{}: case manifest version {version} is not 1",
            path.display()
        ));
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for case in &set.cases {
        let id = case.id.as_str();
        if !valid_id(id) {
            return Err(format!(
                "{}: case id {id:?} is not lower-case words joined by '-'",
                path.display()
            ));
        }
        if !seen.insert(id) {
            return Err(format!("{}: duplicate case id {id:?}", path.display()));
        }
    }
    let template = repo.join(&set.template);
    let template_bytes =
        std::fs::read(&template).map_err(|error| format!("{}: {error}", template.display()))?;
    Ok(LoadedCaseSet {
        set,
        manifest_bytes,
        template_bytes,
    })
}

/// A case id: lower-case ASCII words joined by single `-`.
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
        && !id.starts_with('-')
        && !id.ends_with('-')
        && !id.contains("--")
}

/// The byte ceilings a case opens packages under.
fn case_limits() -> Limits {
    Limits {
        archive_bytes: 32 * 1024 * 1024,
        part_bytes: 16 * 1024 * 1024,
        expanded_bytes: 64 * 1024 * 1024,
    }
}

/// One case's candidate with the fit-unverified units PowerPoint owes it.
#[derive(Debug, Clone)]
pub struct CaseCandidate {
    /// The case id.
    pub id: String,
    /// The emitted candidate.
    pub candidate: Candidate,
    /// Its fit-unverified units, in slide then shape order.
    pub units: Vec<FitUnit>,
}

/// What a fit-unverified unit carries: laid-out text, a table, or a chart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnitKind {
    /// `Content::Title` or `Content::Text`.
    Text,
    /// `Content::Table`.
    Table,
    /// `Content::Chart` or `Content::Share`.
    Chart,
}

/// One fit-unverified unit as the run manifest and the Office pass name it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FitUnit {
    /// The slide, 1-based in presentation order.
    pub slide: u32,
    /// The slide part.
    pub part: String,
    /// The 1-based position of the unit's top-level shape among the slide's `p:spTree` element children.
    pub shape_index: u32,
    /// The shape's `p:cNvPr` id.
    pub shape_id: u32,
    /// The shape's `p:cNvPr` name.
    pub name: String,
    /// The source block.
    pub block: String,
    /// What the unit carries.
    pub kind: UnitKind,
    /// `[x, y, cx, cy]` of the unit's `Destination` bounds, in EMU.
    pub planned_emu: [i64; 4],
}

/// Emit one case's candidate: compile its brief against the case set's template, emit with the case set's names, and read every fit-unverified unit back from the candidate's own slide XML.
pub fn case_candidate(
    repo: &Path,
    loaded: &LoadedCaseSet,
    case: &CaseSpec,
) -> Result<CaseCandidate, String> {
    let id = case.id.as_str();
    let brief = repo.join(&case.brief);
    let bytes = std::fs::read(&brief).map_err(|error| format!("{}: {error}", brief.display()))?;
    let kept = KeptBrief {
        version: loaded.set.brief_version.as_str(),
        content_hash: *blake3::hash(&bytes).as_bytes(),
        bytes: &bytes,
    };
    let resources = Resources::measuring();
    let template = Package::open(&loaded.template_bytes, case_limits(), &resources)
        .map_err(|error| format!("{id}: {error}"))?;
    let bindings: BTreeMap<String, AssetBinding> = BTreeMap::new();
    let plan = match crate::design_plan::compile(&kept, &template, &bindings)
        .map_err(|error| format!("{id}: {error}"))?
    {
        Outcome::Plan(plan) => plan,
        Outcome::Ask(decisions) => {
            let pages = decisions
                .iter()
                .map(|decision| decision.page.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "{id}: the brief asks for decisions on pages {pages}"
            ));
        }
    };
    let assets: BTreeMap<String, StoredAsset<'_>> = BTreeMap::new();
    let names = Names {
        text: loaded.set.names.text.as_str(),
        table: loaded.set.names.table.as_str(),
        chart: loaded.set.names.chart.as_str(),
        picture: loaded.set.names.picture.as_str(),
        figure: loaded.set.names.figure.as_str(),
        sheet: loaded.set.names.sheet.as_str(),
    };
    let inputs = EmitInputs {
        kept,
        template: &template,
        assets: &assets,
        names,
        limits: GraphicLimits::default(),
    };
    let candidate = emit(&plan, &inputs).map_err(|error| format!("{id}: {error}"))?;
    let units = fit_units(id, &candidate)?;
    Ok(CaseCandidate {
        id: case.id.clone(),
        candidate,
        units,
    })
}

/// The candidate's fit-unverified units, read back from its slide parts and cross-checked against its fit report.
fn fit_units(id: &str, candidate: &Candidate) -> Result<Vec<FitUnit>, String> {
    let resources = Resources::measuring();
    let package = Package::open(&candidate.bytes, case_limits(), &resources)
        .map_err(|error| format!("{id}: {error}"))?;
    let mut units = Vec::new();
    for (index, slide) in candidate.report.slides.iter().enumerate() {
        let number = u32::try_from(index + 1).map_err(|_| format!("{id}: too many slides"))?;
        let part = slide.part.as_str();
        if !slide
            .units
            .iter()
            .any(|unit| matches!(unit.fit, FitTrace::Unverified { .. }))
        {
            continue;
        }
        let shapes = shape_refs(id, &package, part)?;
        for unit in &slide.units {
            if !matches!(unit.fit, FitTrace::Unverified { .. }) {
                continue;
            }
            let block = unit.block.as_str();
            let shape = unit.shape;
            let kind = match &unit.content {
                Content::Title(_) | Content::Text(_) => UnitKind::Text,
                Content::Table(_) => UnitKind::Table,
                Content::Chart(_) | Content::Share(_) => UnitKind::Chart,
                Content::Picture(_) | Content::Figure(_) => {
                    return Err(format!(
                        "{id}: block {block} is not text, a table or a chart"
                    ));
                }
            };
            let bounds = match &unit.destination {
                Destination::Placeholder { bounds, .. } | Destination::Shape { bounds } => *bounds,
            };
            let found = shapes
                .iter()
                .find(|shape_ref| shape_ref.shape_id == shape)
                .ok_or_else(|| format!("{id}: block {block}: {part} has no shape {shape}"))?;
            let name = found.name.clone().ok_or_else(|| {
                format!("{id}: block {block}: shape {shape} in {part} has no name")
            })?;
            units.push(FitUnit {
                slide: number,
                part: slide.part.clone(),
                shape_index: found.index,
                shape_id: found.shape_id,
                name,
                block: unit.block.clone(),
                kind,
                planned_emu: [bounds.x, bounds.y, bounds.cx, bounds.cy],
            });
        }
    }
    units.sort_by_key(|unit| (unit.slide, unit.shape_index));
    let mut walked: BTreeSet<(String, String, u32)> = BTreeSet::new();
    for unit in &units {
        walked.insert((unit.part.clone(), unit.block.clone(), unit.shape_id));
    }
    let mut reported: BTreeSet<(String, String, u32)> = BTreeSet::new();
    if let Err(unverified) = &candidate.fit {
        for unit in &unverified.units {
            reported.insert((unit.slide.clone(), unit.block.clone(), unit.shape));
        }
    }
    if walked != reported {
        return Err(format!(
            "{id}: the shape walk disagrees with the fit report"
        ));
    }
    Ok(units)
}

/// One top-level shape of a slide part: its PowerPoint position, its `p:cNvPr` id and its name.
struct ShapeRef {
    index: u32,
    shape_id: u32,
    name: Option<String>,
}

/// Every top-level shape of the slide part, in tree order, past the shape tree's own group.
fn shape_refs(id: &str, package: &Package, part: &str) -> Result<Vec<ShapeRef>, String> {
    let bytes = package
        .part(part)
        .map_err(|error| format!("{id}: {error}"))?
        .ok_or_else(|| format!("{id}: {part} is missing from the candidate"))?;
    let tree =
        XmlTree::parse(&bytes, package.resources()).map_err(|error| format!("{id}: {error}"))?;
    let sp_tree = child(&tree, 0, "cSld")
        .and_then(|at| child(&tree, at, "spTree"))
        .ok_or_else(|| format!("{id}: {part} has no shape tree"))?;
    let mut shapes = Vec::new();
    let mut index = 0u32;
    for &at in &tree.nodes[sp_tree].children {
        let node = &tree.nodes[at];
        if node.namespace == PML && matches!(node.name.as_str(), "nvGrpSpPr" | "grpSpPr" | "extLst")
        {
            continue;
        }
        index = index
            .checked_add(1)
            .ok_or_else(|| format!("{id}: {part} holds too many shapes"))?;
        let Some((shape_id, name)) = shape_identity(&tree, at) else {
            continue;
        };
        shapes.push(ShapeRef {
            index,
            shape_id,
            name,
        });
    }
    Ok(shapes)
}

/// The first direct child with this PresentationML name.
fn child(tree: &XmlTree, at: usize, name: &str) -> Option<usize> {
    tree.nodes
        .get(at)?
        .children
        .iter()
        .copied()
        .find(|&index| tree.nodes[index].is(PML, name))
}

/// A top-level shape's `p:cNvPr` id and name, read from its non-visual block; `None` when it has none.
fn shape_identity(tree: &XmlTree, at: usize) -> Option<(u32, Option<String>)> {
    let nv = tree.nodes[at].children.iter().copied().find(|&index| {
        let node = &tree.nodes[index];
        node.namespace == PML
            && matches!(
                node.name.as_str(),
                "nvSpPr" | "nvGraphicFramePr" | "nvPicPr" | "nvGrpSpPr"
            )
    })?;
    let cnv = tree.nodes[nv]
        .children
        .iter()
        .copied()
        .find(|&index| tree.nodes[index].is(PML, "cNvPr"))?;
    let node = &tree.nodes[cnv];
    let shape_id = node.attr("id")?.parse::<u32>().ok()?;
    Some((shape_id, node.attr("name").map(str::to_owned)))
}

/// The SHA-256 of `bytes` as lower-case hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = sha2::Sha256::digest(bytes).into();
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// What `write_run` wrote: the manifest, and which cases have candidates.
#[derive(Debug, Clone)]
pub struct RunWritten {
    /// The run manifest.
    pub manifest: PathBuf,
    /// The cases with a candidate.
    pub candidates: usize,
    /// The cases without one, each with its reason.
    pub refused: Vec<(String, String)>,
}

/// Write the run to the new directory `out`: the manifest bytes, the Office scripts, each case's candidate and, last, the run manifest. A case that does not compile becomes a `refused` row; the run goes on.
pub fn write_run(repo: &Path, out: &Path, source: Option<&str>) -> Result<RunWritten, String> {
    execute(repo, out, source).map(|(written, _)| written)
}

/// Write the run, with the printed lines beside it, in case order.
fn execute(
    repo: &Path,
    out: &Path,
    source: Option<&str>,
) -> Result<(RunWritten, Vec<String>), String> {
    if let Some(parent) = out.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    std::fs::create_dir(out).map_err(|error| {
        format!(
            "{}: {error} (the output directory must be new)",
            out.display()
        )
    })?;
    for dir in ["candidates", "office"] {
        let path = out.join(dir);
        std::fs::create_dir(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    }
    let loaded = load(repo)?;
    write_file(&out.join("case-manifest.json"), &loaded.manifest_bytes)?;
    let mut scripts = Vec::new();
    for name in &loaded.set.office.scripts {
        let name = name.as_str();
        let from = repo.join("scripts/office").join(name);
        let bytes = std::fs::read(&from).map_err(|error| format!("{}: {error}", from.display()))?;
        let relative = format!("office/{name}");
        write_file(&out.join(&relative), &bytes)?;
        scripts.push(FileRef {
            path: relative,
            sha256: sha256_hex(&bytes),
            bytes: bytes.len(),
        });
    }
    let mut candidates = Vec::new();
    let mut refused = Vec::new();
    let mut lines = Vec::new();
    for case in &loaded.set.cases {
        let id = case.id.as_str();
        match case_candidate(repo, &loaded, case) {
            Ok(built) => {
                let relative = format!("candidates/{id}.pptx");
                write_file(&out.join(&relative), &built.candidate.bytes)?;
                let slides = built.candidate.report.slides.len();
                let count = built.units.len();
                let sha = sha256_hex(&built.candidate.bytes);
                lines.push(format!("{id} {sha} slides={slides} units={count}"));
                candidates.push(CandidateRow {
                    id: built.id,
                    file: relative,
                    sha256: sha,
                    blake3: blake3::Hash::from(built.candidate.hash)
                        .to_hex()
                        .to_string(),
                    bytes: built.candidate.bytes.len(),
                    slides,
                    units: built.units,
                });
            }
            Err(reason) => {
                lines.push(format!("{id} refused: {reason}"));
                refused.push((case.id.clone(), reason));
            }
        }
    }
    let count = candidates.len();
    let rows: Vec<RefusedRow> = refused
        .iter()
        .map(|(id, reason)| RefusedRow {
            id: id.clone(),
            reason: reason.clone(),
        })
        .collect();
    let manifest = Manifest {
        schema: RUN_SCHEMA,
        case_set: loaded.set.case_set.clone(),
        source: source.unwrap_or_default().to_owned(),
        case_manifest: FileRef {
            path: "case-manifest.json".to_owned(),
            sha256: sha256_hex(&loaded.manifest_bytes),
            bytes: loaded.manifest_bytes.len(),
        },
        template: FileRef {
            path: loaded.set.template.clone(),
            sha256: sha256_hex(&loaded.template_bytes),
            bytes: loaded.template_bytes.len(),
        },
        office: OfficeRef {
            scripts,
            timeout_seconds: loaded.set.office.timeout_seconds,
            observer: loaded.set.office.observer.clone(),
        },
        candidates,
        refused: rows,
    };
    let mut text = serde_json::to_string_pretty(&manifest)
        .map_err(|error| format!("manifest.json: {error}"))?;
    text.push('\n');
    let path = out.join("manifest.json");
    write_file(&path, text.as_bytes())?;
    Ok((
        RunWritten {
            manifest: path,
            candidates: count,
            refused,
        },
        lines,
    ))
}

/// One pinned file of the run manifest.
#[derive(Serialize)]
struct FileRef {
    path: String,
    sha256: String,
    bytes: usize,
}

/// The Office half's pins in the run manifest.
#[derive(Serialize)]
struct OfficeRef {
    scripts: Vec<FileRef>,
    timeout_seconds: u64,
    observer: String,
}

/// One candidate row of the run manifest.
#[derive(Serialize)]
struct CandidateRow {
    id: String,
    file: String,
    sha256: String,
    blake3: String,
    bytes: usize,
    slides: usize,
    units: Vec<FitUnit>,
}

/// One refused case of the run manifest.
#[derive(Serialize)]
struct RefusedRow {
    id: String,
    reason: String,
}

/// The run manifest `deck_create_gate.py` reads.
#[derive(Serialize)]
struct Manifest {
    schema: &'static str,
    case_set: String,
    source: String,
    case_manifest: FileRef,
    template: FileRef,
    office: OfficeRef,
    candidates: Vec<CandidateRow>,
    refused: Vec<RefusedRow>,
}

/// Write `bytes` at `path`, whole or not at all: aside, then renamed into place.
fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut name = path
        .file_name()
        .ok_or_else(|| format!("{} names no file", path.display()))?
        .to_owned();
    name.push(".partial");
    let aside = path.with_file_name(name);
    std::fs::write(&aside, bytes).map_err(|error| format!("{}: {error}", aside.display()))?;
    std::fs::rename(&aside, path).map_err(|error| format!("{}: {error}", path.display()))
}

/// The parsed command line: the repository root, the new run directory and the recorded source revision.
struct Options {
    repo: PathBuf,
    out: PathBuf,
    source: Option<String>,
}

fn options(mut args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut repo = PathBuf::from(".");
    let (mut out, mut source) = (None, None);
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--repo" => repo = PathBuf::from(value()?),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--source" => source = Some(value()?),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(Options {
        repo,
        out: out.ok_or("--out is required")?,
        source,
    })
}

/// A recorded source revision: 40 hex digits.
fn is_source(given: &str) -> bool {
    given.len() == 40 && given.bytes().all(u8::is_ascii_hexdigit)
}

/// Run the engine half from `args` (the program name skipped) as `name`. Exit status: 0 when every case has a candidate, 1 when some case was refused, 2 when no manifest was written.
pub fn main_with(name: &str, args: impl Iterator<Item = String>) -> std::process::ExitCode {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let options = match options(args) {
        Ok(options) => options,
        Err(why) => {
            let _ = writeln!(stderr, "{name}: {why}\n{name} {USAGE}");
            return ExitCode::from(2);
        }
    };
    if let Some(given) = options.source.as_deref()
        && !is_source(given)
    {
        let _ = writeln!(
            stderr,
            "{name}: --source {given:?} is not 40 hex digits; recorded as given"
        );
    }
    match execute(&options.repo, &options.out, options.source.as_deref()) {
        Ok((written, lines)) => {
            for line in &lines {
                let _ = writeln!(stdout, "{line}");
            }
            let _ = writeln!(stdout, "manifest: {}", written.manifest.display());
            if written.refused.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(why) => {
            let _ = writeln!(stderr, "{name}: {why}");
            ExitCode::from(2)
        }
    }
}
