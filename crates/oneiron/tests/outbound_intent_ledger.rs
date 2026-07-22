use std::collections::BTreeSet;

use oneiron::{INTENT_LEDGER_SCHEMA_VERSION, INTENT_LEDGER_VALUE_KEYS, OUTBOUND_BINDING_VERSION};

// The former direct-ledger send/recovery assertions are folded into the
// crate-internal chokepoint interface tests, where the sole effectful entry is
// accessible. This integration pin keeps the public greenfield format honest.
#[test]
fn outbound_intent_ledger_exposes_one_complete_greenfield_format() {
    assert_eq!(INTENT_LEDGER_SCHEMA_VERSION, 2);
    assert_eq!(OUTBOUND_BINDING_VERSION, 2);
    assert_eq!(INTENT_LEDGER_VALUE_KEYS.len(), 19);
    assert_eq!(
        INTENT_LEDGER_VALUE_KEYS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len(),
        INTENT_LEDGER_VALUE_KEYS.len(),
        "the canonical row has no duplicate fields"
    );
    for required in [
        "binding_version",
        "resolved_endpoint",
        "budget_accounting",
        "recorded_outcome",
    ] {
        assert!(INTENT_LEDGER_VALUE_KEYS.contains(&required));
    }
}
