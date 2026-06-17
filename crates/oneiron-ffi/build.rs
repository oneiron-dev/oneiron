use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    let crate_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set by cargo"),
    );
    let config_path = crate_dir.join("cbindgen.toml");
    let header_path = crate_dir.join("include").join("oneiron_ffi.h");

    if let Err(err) = generate_header(&crate_dir, &config_path, &header_path) {
        println!("cargo:warning=oneiron-ffi header generation skipped: {err}");
    }
}

fn generate_header(
    crate_dir: &PathBuf,
    config_path: &PathBuf,
    header_path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = cbindgen::Config::from_file(config_path)?;
    std::fs::create_dir_all(
        header_path
            .parent()
            .expect("generated header path must have a parent"),
    )?;
    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()?
        .write_to_file(header_path);
    Ok(())
}
