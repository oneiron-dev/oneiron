# Pinned JSON Schema validator guest

`validator.wasm` is the same `jsonschema =0.33.0` implementation the step
shim and `self.json.validate` use. It is a core Wasm module with **zero
imports**, built for `wasm32-unknown-unknown` from `src/lib.rs` and the locked
manifest. An explicit custom entropy backend supplies a deterministic aHash seed instead
of importing a clock, random source or WASI. Compilation, validation and
bounded error formatting all run inside a fresh Wasmtime Store with fuel,
linear-memory and stack limits; no host resolver is linked.

Build with Rust 1.96 plus `wasm32-unknown-unknown`, `wasm-tools 1.239.0`, an
owned `CARGO_TARGET_DIR`, and `python3 build.py`. No tool is installed by the
script. `python3 build.py --check` verifies source and binary pins, the host's
literal digest, required exports and **absence of imports** without building.
Both generated artifact and manifest are committed together; the host also
verifies the digest and import inventory before instantiating.

ABI: `alloc(length) -> ptr`, `run(ptr,length) -> (output_length<<32)|ptr`,
`memory` export. Each call has its own Store; allocations die with it. Request
and reply are bounded JSON. Failed validation returns a bounded diagnostic;
a fuel, memory or stack trap refuses only this call. A new ordinary call must
still work. No compiled schema escapes the compartment.
