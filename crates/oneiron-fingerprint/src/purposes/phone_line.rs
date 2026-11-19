//! Purposes of the phone line (`crates/oneiron/src/phone_line`).

purposes! {}

legacy_purposes! {
    /// An arrival's input digest (`phone_line::input_digest`): plain BLAKE3 of the
    /// arrival's JSON (`serde_json::to_vec` of the `PhoneLineArrival`), with no tag written;
    /// the tag is the registry name only. The live arrival row stores it, and a replay of
    /// the call with another digest is refused.
    ARRIVAL_INPUT = (Blake3, NotHashed, "oneiron.phone_line.arrival_input.v1");
}
