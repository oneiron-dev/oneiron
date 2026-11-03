/// Board-projected consult outcome: canonical short refs, never result bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsultResultPresence {
    Answer {
        result_ref: String,
        evidence_ref_count: usize,
    },
    Abstained {
        result_ref: String,
        reason_ref: String,
    },
}
