//! [RECEIPT-ROW-FIELD-CONSTS-PUBLIC]: the engine-only receipt keys (the
//! proposal-outcome, amendment, escalation, skill-edit and pre-extraction
//! families) are crate-private in core again. Another crate names none of
//! them, through core or through the store.

fn main() {
    let _ = oneiron::store::receipt_row::FIELD_ESCALATION_SCOPE;
    let _ = oneiron_store::receipt_row::FIELD_ESCALATION_SCOPE;
}
