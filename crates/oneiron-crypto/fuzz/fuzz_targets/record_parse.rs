#![no_main]

use libfuzzer_sys::fuzz_target;

// Anything that parses must re-encode to exactly its input (one canonical encoding).
fuzz_target!(|data: &[u8]| {
    if let Ok(record) = oneiron_crypto::SignatureRecord::parse(data) {
        assert_eq!(record.to_bytes(), data);
    }
});
