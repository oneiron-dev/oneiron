//! [VAULT-STORE-FIELD-PUBLIC]: core split slice 0 (#6862) made `Vault::store`
//! `pub` so the lifted mail pack could scan its sources. Any crate then held
//! the raw store and read every stored row with no door. The field is
//! crate-private again; the lifted pack reads its Active sources through
//! `oneiron::mail_pack::source::active_sources`.

fn reach_store(vault: &oneiron::Vault) {
    let _ = &vault.store;
}

fn main() {
    let _ = reach_store;
}
