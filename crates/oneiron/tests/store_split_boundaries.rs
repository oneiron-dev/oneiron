//! Store-split boundaries (FIX STORE-SPLIT-PUB-SCAN): items the store split
//! (#5778) made `pub` whose docs promised the engine alone could reach them.
//! Each is either engine-only again (moved back into core, crate-private) or
//! stays `pub` in the store with the boundary held elsewhere; the fixtures in
//! `tests/store_split_compilefail/` pin both kinds from outside the engine.
//! The vault's own store handle, which core split slice 0 (#6862) made `pub`,
//! is crate-private again too (FIX VAULT-STORE-FIELD-PUBLIC).

use std::marker::PhantomData;

#[test]
fn store_split_boundaries_compilefail() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/store_split_compilefail/*.rs");
}

/// Autoref probe: `decodes()` resolves to the `Deserialize` arm only when the
/// probed type implements `DeserializeOwned`, and to the fallback otherwise.
struct Probe<T>(PhantomData<T>);

trait Decodes {
    fn decodes(&self) -> bool {
        true
    }
}

impl<T: serde::de::DeserializeOwned> Decodes for Probe<T> {}

trait DoesNotDecode {
    fn decodes(&self) -> bool {
        false
    }
}

impl<T> DoesNotDecode for &Probe<T> {}

/// [WRITE-ENVELOPE-WITH-LINEAGE-PUBLIC]: `WriteEnvelope::with_lineage` is
/// `pub`, because its callers are in core and the envelope stays in the store.
/// Its guard is the wire: no guest payload or API body decodes into a lineage
/// or an envelope, so only host code can stamp one.
#[test]
fn no_wire_payload_decodes_into_a_lineage_or_an_envelope() {
    assert!(
        (&Probe::<String>(PhantomData)).decodes(),
        "the probe must see a type that does decode"
    );
    assert!(
        !(&Probe::<oneiron::write_envelope::SourceLineage>(PhantomData)).decodes(),
        "SourceLineage must not implement Deserialize"
    );
    assert!(
        !(&Probe::<oneiron::write_envelope::WriteEnvelope>(PhantomData)).decodes(),
        "WriteEnvelope must not implement Deserialize"
    );
}
