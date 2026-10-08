//! Direct calls into the items `oneiron-retrieval` made `pub` so `oneiron` can reach them
//! across the crate split. Called from outside the engine, the checks still refuse bad
//! input exactly as they did when they were crate-private.

use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_retrieval::distance::{PreparedCosine, cosine_distance, cosine_similarity};
use oneiron_retrieval::fusion::decode_msgpack_float;

#[test]
fn msgpack_float_reader_refuses_short_rows_and_out_of_range_values() {
    let header = [0_u8; ENTITY_METADATA_HEADER_LEN];
    assert_eq!(decode_msgpack_float(&header, "sal"), None);

    let row = |body: &[u8]| [&header[..], body].concat();
    // {"sal": NaN}, {"sal": "x"}, {"sal": 7}, {"sal": -1.5}
    let nan = row(&[0x81, 0xA3, b's', b'a', b'l', 0xCA, 0x7F, 0xC0, 0x00, 0x00]);
    let text = row(&[0x81, 0xA3, b's', b'a', b'l', 0xA1, b'x']);
    let big = row(&[0x81, 0xA3, b's', b'a', b'l', 0x07]);
    let negative = row(&[
        0x81, 0xA3, b's', b'a', b'l', 0xCB, 0xBF, 0xF8, 0, 0, 0, 0, 0, 0,
    ]);
    assert_eq!(decode_msgpack_float(&nan, "sal"), None);
    assert_eq!(decode_msgpack_float(&text, "sal"), None);
    assert_eq!(decode_msgpack_float(&big, "sal"), Some(1.0));
    assert_eq!(decode_msgpack_float(&negative, "sal"), Some(0.0));
    assert_eq!(decode_msgpack_float(&big, "conf"), None);
}

#[test]
fn cosine_kernels_refuse_mismatched_lengths_before_any_vector_read() {
    // Nine lanes reach past one SIMD block, so a missing length check would read out of bounds.
    let query = [1.0_f32; 9];
    let short = [1.0_f32; 8];
    assert_eq!(cosine_similarity(&query, &short), 0.0);
    assert_eq!(cosine_distance(&query, &short), 1.0);
    let prepared = PreparedCosine::new(&query);
    assert_eq!(prepared.distance(&short), 1.0);
    assert_eq!(prepared.distance(&[]), 1.0);
    assert!(prepared.distance(&query).abs() < 1e-6);
}
