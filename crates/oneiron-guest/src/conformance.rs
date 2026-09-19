//! Typed Component Model fixture. This is neither QuickJS nor a native boot proof.

use crate::{Error, Result};

/// WAT fixture using the canonical credential-input and step-result records.
/// After the metadata receipt, it proposes source bytes at result.txt, or a
/// fixed marker when source is empty. It does not evaluate JavaScript.
pub(super) const WAT: &str = include_str!("conformance.wat");

/// Encodes the conformance WAT as an ordinary WebAssembly component binary.
/// Artifact generation alone is not runtime or boot evidence.
pub fn component() -> Result<Vec<u8>> {
    let bytes = wat::parse_str(WAT).map_err(|_| Error::Runtime("conformance fixture encoding"))?;
    let mut config = wasmtime::Config::new();
    config.wasm_component_model(true).consume_fuel(true);
    let engine =
        wasmtime::Engine::new(&config).map_err(|_| Error::Runtime("conformance engine setup"))?;
    let validated = wasmtime::component::Component::new(&engine, &bytes);
    #[cfg(test)]
    assert!(
        validated.is_ok(),
        "invalid conformance component: {:?}",
        validated.as_ref().err()
    );
    validated.map_err(|_| Error::Runtime("conformance component validation"))?;
    Ok(bytes)
}
