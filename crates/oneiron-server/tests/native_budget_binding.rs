//! L9-19 (ARCH-0036 #system-one-codec): the System One binding's
//! `native_budget` row is the codec row that says whether its server takes a
//! native budget (Engine ruling L9-19-WIRE = A). Set, the seat sends each
//! call's time left as `budget_ms`; unset, the server gets the body as before.
//! The wire itself is proved in `crates/oneiron-llm-systemone/tests/native_budget_wire.rs`.
//!
//! Fleet: `cargo test --locked -p oneiron-server --all-features --test native_budget_binding`

use oneiron_server::config::models::ModelsConfig;

/// A `[models]` body binding the System One seat, with `row` added.
fn binding(row: &str) -> String {
    format!(
        "[decisions.system_one]\nendpoint = \"https://seat.example/v1/systemone\"\nkey_env = \"SYSTEM_ONE_KEY\"\nmodel = \"jev\"\nversion = \"1.13.0\"\n{row}"
    )
}

#[test]
fn a_binding_whose_server_takes_a_native_budget_says_so() {
    let config =
        ModelsConfig::from_toml(&binding("native_budget = true\n"), None).expect("binding loads");
    let seat = config.decisions.system_one.expect("the System One binding");
    assert!(seat.native_budget, "the row reaches the seat's settings");
}

#[test]
fn a_binding_without_the_row_takes_no_native_budget() {
    let config = ModelsConfig::from_toml(&binding(""), None).expect("binding loads");
    let seat = config.decisions.system_one.expect("the System One binding");
    assert!(!seat.native_budget, "off unless the binding says so");
}
