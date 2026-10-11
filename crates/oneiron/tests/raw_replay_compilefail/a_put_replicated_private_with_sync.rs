// `BatchBuilder::put_replicated` writes a row as replay would, bypassing the
// write doors. It is `pub(crate)`: with `sync` on, an external crate still
// cannot call it.
fn attempt(vault: &oneiron::Vault, id: &oneiron::EntityId) {
    let _ = vault.batch().put_replicated(
        id,
        oneiron::registry::ENTITY_TYPE_PERSON,
        oneiron::TimeRange { start: 1, end: 1 },
        1,
        b"external replay",
    );
}

fn main() {
    let _ = attempt;
}
