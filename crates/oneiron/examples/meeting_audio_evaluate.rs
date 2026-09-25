//! Offline recorded-output evaluator. No model loading, downloads, consent or default changes.
//!
//! Usage: cargo run -p oneiron --example meeting_audio_evaluate -- input.json
//! Input contains cohort, references, arms, and audio_files (file id -> path).
//! Paths are relative to input.json. The audio bytes and exact reference JSON
//! are hashed before scoring. Output is evidence only, not native qualification.
use oneiron::ingest::meeting_audio::{
    CohortManifest, RecordedArm, ReferenceDocument, evaluate_recorded_audio,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::PathBuf,
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    cohort: CohortManifest,
    references: Vec<ReferenceDocument>,
    arms: Vec<RecordedArm>,
    audio_files: BTreeMap<String, PathBuf>,
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 1 {
        return Err("expected one recorded evaluation JSON input path".into());
    }
    let input_path = PathBuf::from(&args[0]);
    let input_file = std::fs::File::open(&input_path)?;
    if !input_file.metadata()?.is_file() {
        return Err("evaluation input must be a regular file".into());
    }
    let mut bytes = Vec::new();
    input_file
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err("evaluation input too large".into());
    }
    let input: Input = serde_json::from_slice(&bytes)?;
    let cohort = CohortManifest::parse(&serde_json::to_string(&input.cohort)?)?;
    if input.audio_files.len() != cohort.files.len() {
        return Err("audio file set differs from cohort".into());
    }
    let directory = input_path.parent().ok_or("input directory unavailable")?;
    for source in &cohort.files {
        let path = input
            .audio_files
            .get(&source.file_id)
            .ok_or("cohort audio path missing")?;
        let mut audio = std::fs::File::open(directory.join(path))?;
        if !audio.metadata()?.is_file() {
            return Err("audio must be a regular file".into());
        }
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let n = audio.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        if format!("{:x}", hash.finalize()) != source.audio_sha256 {
            return Err("cohort audio digest mismatch".into());
        }
    }
    let report = evaluate_recorded_audio(&cohort, &input.references, &input.arms)?;
    let bytes = serde_json::to_vec_pretty(&report)?;
    let mut output = std::io::stdout().lock();
    output.write_all(&bytes)?;
    output.write_all(b"\n")?;
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    run()
}
