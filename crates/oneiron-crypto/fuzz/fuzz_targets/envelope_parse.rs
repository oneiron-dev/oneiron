#![no_main]

use libfuzzer_sys::fuzz_target;

// Anything that parses must re-encode to exactly its input (one canonical encoding).
fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = oneiron_crypto::Envelope::parse(data) {
        assert_eq!(envelope.to_bytes(), data);
    }
});
