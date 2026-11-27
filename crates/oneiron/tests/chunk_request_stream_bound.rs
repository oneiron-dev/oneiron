// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FIX CHUNK-STREAM-DECODE-UNBOUNDED-MEMORY (ruling CHUNK-STREAM-MEMORY-BOUND = A)
//! and CHUNK-STREAM-SELECTOR-AND-WHY-UNBOUNDED (a byte cap on each field): the
//! chunk request stream decode holds no field past its byte cap and no more of
//! HAVE and WANT than the object's manifest names. Each hash is checked
//! against the stored manifest's chunk hashes as it arrives; after the first
//! bad hash none is held, and the request is refused once its stream is read
//! whole, so a manifest's contents never change how much of a body is read
//! (REVIEW-10608 P1 1). The first byte past a field's cap refuses the request
//! at the cap. No count refuses an exchange (FIX 8183): one that names every
//! chunk of any manifest decodes whole. The manifest is indexed where its row
//! lies, one entry per distinct hash (REVIEW-10608 P1 2).
//!
//! - `a_have_hash_the_manifest_does_not_name_is_refused_once_the_stream_is_read`:
//!   red is decoding Ok with the per-hash checks undone, and, at the round-0
//!   head c3ef06b4, a refusal before the rest of the stream is read.
//! - `a_want_naming_one_hash_twice_is_refused_once_the_stream_is_read`: red is
//!   the same.
//! - `a_body_cut_before_its_end_is_read_alike_whatever_the_manifest_holds`:
//!   red at c3ef06b4 is the decode stopping early for an object with no
//!   manifest and for a hash its manifest lacks, while it reads a named one
//!   to the cut.
//! - `a_manifest_naming_one_chunk_many_times_is_indexed_once_where_it_lies` and
//!   `a_manifest_that_is_not_its_assets_is_refused_where_it_lies`: guards of
//!   the in-place index (`manifest_distinct_chunks_in_place`) against the
//!   strict decode.
//! - `a_want_hash_the_have_names_is_refused`: red is Ok.
//! - `a_have_naming_one_hash_twice_holds_it_once`: red is a HAVE of every
//!   copy sent.
//! - `a_selector_past_its_byte_cap_is_refused_at_the_cap`: red is Ok, with the
//!   caps undone.
//! - `a_read_why_past_its_byte_cap_is_refused_at_the_cap`: red is Ok, the same.
//! - `an_oid_sent_as_a_long_string_is_refused_at_its_cap`: red is the whole
//!   string read before the refusal, the same.
//! - `an_exchange_of_every_manifest_chunk_still_decodes_whole`: guard, green
//!   both ways.
//! - `a_request_for_an_object_with_no_manifest_is_refused`: red is Ok.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test chunk_request_stream_bound`.
#![cfg(feature = "sync")]

use std::cell::Cell;
use std::collections::BTreeSet;
use std::io::Read;

use oneiron::origin::lfs::{LfsChunkRef, LfsManifest};
use oneiron::sync::chunks::{
    CHUNK_STREAM_FRAME_BYTES, CHUNK_SYNC_VERSION, ChunkPageCursor, ChunkRead, ChunkSyncRequest,
    MAX_CHUNK_REQUEST_READ_BYTES, MAX_CHUNK_REQUEST_SELECTOR_BYTES,
    manifest_distinct_chunks_in_place, read_chunk_request_stream, write_chunk_request_stream,
};

/// A chunk hash naming `index`: its big-endian bytes, then zeros.
fn hash(index: u16) -> [u8; 32] {
    let mut hash = [0; 32];
    hash[..2].copy_from_slice(&index.to_be_bytes());
    hash
}

/// The chunk hashes of a manifest holding `count` chunks.
fn manifest(count: u16) -> BTreeSet<[u8; 32]> {
    (0..count).map(hash).collect()
}

/// The object the requests name.
const OID: [u8; 32] = [9; 32];

/// A request naming `have` and `want` of [`OID`], first page, no marked read.
fn request(have: Vec<[u8; 32]>, want: Option<Vec<[u8; 32]>>) -> ChunkSyncRequest {
    ChunkSyncRequest {
        request: 7,
        oid: OID,
        selector: vec![1, 2, 3],
        have,
        want,
        cursor: None,
        read: None,
    }
}

/// `request` as the bytes of one stream.
fn stream_of(request: &ChunkSyncRequest) -> Vec<u8> {
    let mut stream = Vec::new();
    write_chunk_request_stream(request, &mut stream).unwrap();
    stream
}

/// `payload` sent as a stream: the version and `payload` in frames of
/// [`CHUNK_STREAM_FRAME_BYTES`], then the end frame.
fn framed(payload: &[u8]) -> Vec<u8> {
    let mut body = vec![CHUNK_SYNC_VERSION];
    body.extend_from_slice(payload);
    let mut stream = Vec::new();
    for frame in body.chunks(CHUNK_STREAM_FRAME_BYTES) {
        stream.extend_from_slice(&u32::try_from(frame.len()).unwrap().to_be_bytes());
        stream.extend_from_slice(frame);
    }
    stream.extend_from_slice(&[0; 4]);
    stream
}

/// A stream that counts the bytes the decode takes from it.
struct CountedSource<'a> {
    bytes: &'a [u8],
    read: usize,
}

impl Read for CountedSource<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let left = self.bytes.len() - self.read;
        let count = output.len().min(left);
        output[..count].copy_from_slice(&self.bytes[self.read..self.read + count]);
        self.read += count;
        Ok(count)
    }
}

#[test]
fn a_have_hash_the_manifest_does_not_name_is_refused_once_the_stream_is_read() {
    let held = manifest(4);
    let mut have = vec![hash(1)];
    have.resize(200_001, [0x55; 32]);
    let stream = stream_of(&request(have, None));
    assert!(
        stream.len() > 16 * CHUNK_STREAM_FRAME_BYTES,
        "fixture: the bad HAVE's stream spans more than sixteen frames"
    );
    let mut source = CountedSource {
        bytes: &stream,
        read: 0,
    };
    let decoded = read_chunk_request_stream(&mut source, |_oid| Ok(held.clone()));
    assert!(
        decoded.is_err(),
        "a HAVE hash the manifest does not name is refused"
    );
    assert_eq!(
        source.read,
        stream.len(),
        "the decode read the whole stream before it refused the request"
    );
}

#[test]
fn a_want_naming_one_hash_twice_is_refused_once_the_stream_is_read() {
    let held = manifest(4);
    let mut want = vec![hash(1)];
    want.resize(200_001, hash(1));
    let stream = stream_of(&request(Vec::new(), Some(want)));
    assert!(
        stream.len() > 16 * CHUNK_STREAM_FRAME_BYTES,
        "fixture: the doubled WANT's stream spans more than sixteen frames"
    );
    let mut source = CountedSource {
        bytes: &stream,
        read: 0,
    };
    let decoded = read_chunk_request_stream(&mut source, |_oid| Ok(held.clone()));
    assert!(decoded.is_err(), "a WANT naming one hash twice is refused");
    assert_eq!(
        source.read,
        stream.len(),
        "the decode read the whole stream before it refused the request"
    );
}

#[test]
fn a_body_cut_before_its_end_is_read_alike_whatever_the_manifest_holds() {
    let mut have = vec![hash(1)];
    have.resize(200_001, hash(1));
    let stream = stream_of(&request(have, None));
    assert!(
        stream.len() > 16 * CHUNK_STREAM_FRAME_BYTES,
        "fixture: the HAVE's stream spans more than sixteen frames"
    );
    // A body that stops short of its end frame, as one the idle limit ends.
    let cut = &stream[..stream.len() - 8];
    let cases: [(&str, Option<BTreeSet<[u8; 32]>>); 3] = [
        ("a manifest naming the HAVE", Some(manifest(4))),
        ("a manifest lacking the HAVE's hash", Some(manifest(1))),
        ("no manifest", None),
    ];
    for (case, held) in cases {
        let mut source = CountedSource {
            bytes: cut,
            read: 0,
        };
        let decoded = read_chunk_request_stream(&mut source, |_oid| {
            held.ok_or(oneiron::Error::CorruptedIndex("no manifest"))
        });
        assert!(decoded.is_err(), "{case}: a body cut short is no request");
        assert_eq!(
            source.read,
            cut.len(),
            "{case}: the decode read the body to its cut, as it does for any object"
        );
    }
}

/// The stored bytes, ASSET id and size of a manifest of `chunks`, each a
/// chunk hash index and its size.
fn stored_manifest(chunks: &[(u16, u32)]) -> (Vec<u8>, oneiron::EntityId, u64) {
    let manifest = LfsManifest {
        size_bytes: chunks.iter().map(|(_, size)| u64::from(*size)).sum(),
        chunks: chunks
            .iter()
            .map(|(index, size)| LfsChunkRef {
                hash: hash(*index),
                size: *size,
            })
            .collect(),
    };
    (
        manifest.encode().unwrap(),
        manifest.asset_id().unwrap(),
        manifest.size_bytes,
    )
}

#[test]
fn a_manifest_naming_one_chunk_many_times_is_indexed_once_where_it_lies() {
    let mut chunks = vec![(1, 4096); 100_000];
    chunks.push((2, 17));
    let (bytes, asset, size) = stored_manifest(&chunks);
    let distinct = manifest_distinct_chunks_in_place(&bytes, &asset, size)
        .expect("an authentic manifest is indexed");
    assert_eq!(
        distinct,
        BTreeSet::from([hash(1), hash(2)]),
        "a chunk named a hundred thousand times is one entry"
    );
    let decoded: BTreeSet<[u8; 32]> = LfsManifest::decode(&bytes)
        .unwrap()
        .chunks
        .iter()
        .map(|chunk| chunk.hash)
        .collect();
    assert_eq!(
        distinct, decoded,
        "the index holds the strict decode's distinct hashes"
    );
}

#[test]
fn a_manifest_that_is_not_its_assets_is_refused_where_it_lies() {
    let (bytes, asset, size) = stored_manifest(&[(1, 4096), (2, 17)]);
    let mut changed = bytes.clone();
    changed[20] ^= 1;
    assert!(
        manifest_distinct_chunks_in_place(&changed, &asset, size).is_err(),
        "a changed chunk hash no longer matches the ASSET id"
    );
    assert!(
        manifest_distinct_chunks_in_place(&bytes, &asset, size + 1).is_err(),
        "a size other than the object's is refused"
    );
    assert!(
        manifest_distinct_chunks_in_place(&bytes[..bytes.len() - 1], &asset, size).is_err(),
        "a manifest cut short is refused"
    );
}

#[test]
fn a_want_hash_the_have_names_is_refused() {
    let held = manifest(4);
    let stream = stream_of(&request(vec![hash(1)], Some(vec![hash(1)])));
    let decoded = read_chunk_request_stream(stream.as_slice(), |_oid| Ok(held.clone()));
    assert!(decoded.is_err(), "a WANT hash the HAVE names is refused");
}

#[test]
fn a_have_naming_one_hash_twice_holds_it_once() {
    let held = manifest(4);
    let mut have = vec![hash(1)];
    have.resize(200_001, hash(1));
    let stream = stream_of(&request(have, None));
    let decoded = read_chunk_request_stream(stream.as_slice(), |_oid| Ok(held.clone()))
        .expect("an answer reads the HAVE as a set, so a repeated hash is no refusal");
    assert_eq!(
        decoded.have,
        vec![hash(1)],
        "a HAVE hash named again is held once, however often it is sent"
    );
}

#[test]
fn a_selector_past_its_byte_cap_is_refused_at_the_cap() {
    let held = manifest(4);
    let mut long = request(Vec::new(), None);
    long.selector = vec![1; 2 * MAX_CHUNK_REQUEST_SELECTOR_BYTES];
    let stream = stream_of(&long);
    assert!(
        stream.len() > MAX_CHUNK_REQUEST_SELECTOR_BYTES + 4 * CHUNK_STREAM_FRAME_BYTES,
        "fixture: the selector runs four frames past its cap"
    );
    let mut source = CountedSource {
        bytes: &stream,
        read: 0,
    };
    let decoded = read_chunk_request_stream(&mut source, |_oid| Ok(held.clone()));
    assert!(decoded.is_err(), "a selector past its byte cap is refused");
    assert!(
        source.read < MAX_CHUNK_REQUEST_SELECTOR_BYTES + 2 * CHUNK_STREAM_FRAME_BYTES,
        "the decode stopped at the selector's cap"
    );
}

#[test]
fn a_read_why_past_its_byte_cap_is_refused_at_the_cap() {
    let held = manifest(4);
    let mut long = request(Vec::new(), None);
    long.read = Some(ChunkRead::Ask {
        why: "w".repeat(MAX_CHUNK_REQUEST_READ_BYTES + 4 * CHUNK_STREAM_FRAME_BYTES),
    });
    let stream = stream_of(&long);
    let mut source = CountedSource {
        bytes: &stream,
        read: 0,
    };
    let decoded = read_chunk_request_stream(&mut source, |_oid| Ok(held.clone()));
    assert!(
        decoded.is_err(),
        "a read whose why is past its byte cap is refused"
    );
    assert!(
        source.read < MAX_CHUNK_REQUEST_READ_BYTES + 2 * CHUNK_STREAM_FRAME_BYTES,
        "the decode stopped at the read's cap"
    );
}

#[test]
fn an_oid_sent_as_a_long_string_is_refused_at_its_cap() {
    // A seven-field array, request 7, then an oid sent as a 32-bit-length
    // string of sixteen frames.
    let length = 16 * CHUNK_STREAM_FRAME_BYTES;
    let mut payload = vec![0x97, 0x07, 0xdb];
    payload.extend_from_slice(&u32::try_from(length).unwrap().to_be_bytes());
    payload.resize(payload.len() + length, b'o');
    let stream = framed(&payload);
    let mut source = CountedSource {
        bytes: &stream,
        read: 0,
    };
    let decoded = read_chunk_request_stream(&mut source, |_oid| Ok(manifest(4)));
    assert!(decoded.is_err(), "an oid sent as a string is refused");
    assert!(
        source.read < 2 * CHUNK_STREAM_FRAME_BYTES,
        "the decode stopped at the oid's cap, not at the length its marker declared"
    );
}

#[test]
fn an_exchange_of_every_manifest_chunk_still_decodes_whole() {
    let held = manifest(2000);
    let have: Vec<[u8; 32]> = (0..1000).map(hash).collect();
    let want: Vec<[u8; 32]> = (1000..2000).map(hash).collect();
    let mut expected = request(have, Some(want));
    expected.selector = vec![0xff; 4096];
    expected.cursor = Some(ChunkPageCursor {
        manifest: [3; 32],
        offset: 32,
    });
    expected.read = Some(ChunkRead::Ask {
        why: "the build reads these weights".to_owned(),
    });
    let stream = stream_of(&expected);
    let asked = Cell::new(None);
    let decoded = read_chunk_request_stream(stream.as_slice(), |oid| {
        asked.set(Some(*oid));
        Ok(held.clone())
    })
    .expect("an exchange of every manifest chunk decodes whole");
    assert_eq!(asked.get(), Some(OID));
    assert_eq!(decoded.request, expected.request);
    assert_eq!(decoded.oid, expected.oid);
    assert_eq!(decoded.selector, expected.selector);
    assert_eq!(decoded.have, expected.have);
    assert_eq!(decoded.want, expected.want);
    assert_eq!(decoded.cursor, expected.cursor);
    assert_eq!(decoded.read, expected.read);
}

#[test]
fn a_request_for_an_object_with_no_manifest_is_refused() {
    let stream = stream_of(&request(vec![hash(0)], None));
    let decoded = read_chunk_request_stream(stream.as_slice(), |_oid| {
        Err(oneiron::Error::CorruptedIndex("no manifest"))
    });
    assert!(
        decoded.is_err(),
        "a request for an object with no manifest is refused"
    );
}
