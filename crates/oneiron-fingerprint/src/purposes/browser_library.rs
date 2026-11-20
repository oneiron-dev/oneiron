//! Purposes of the browser library (`oneiron-records`' and the core's
//! `browser_library`).

purposes! {}

legacy_purposes! {
    /// A candidate browser program's input fingerprint, the key of the Coach's seen marker
    /// (CUA E8, CALLS row "candidate dedup";
    /// `dreamer_runner::maintenance::browser_programs::induction::digest`, which the
    /// diagnostic pass calls too): plain BLAKE3, the tag's bytes, then each part as its u64
    /// big-endian length and its bytes. Parts: the induction version (u32 big-endian), the
    /// solved group's digest (32 bytes), and the candidate's JSON body.
    PROGRAM_CANDIDATE = (Blake3, HashedFirst, "oneiron:browser-program-induction:v1");
}
