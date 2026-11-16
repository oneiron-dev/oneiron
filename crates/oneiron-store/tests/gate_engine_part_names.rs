//! `GateEnginePart`'s names, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only crates/oneiron-store/src/gate_decision/types.rs`
//! on main before `GateEnginePart` became a Register (Fable pass 25, R2b): the `actor_class` tokens
//! its hand `as_str` table wrote. Green on main (the hand table) and on the adoption (the derive),
//! so no Gate receipt changes the `actor_class` it carries (M-1 keep).

use oneiron_contracts::register::Register;
use oneiron_store::gate_decision::types::GateEnginePart;

#[test]
fn every_engine_part_keeps_its_actor_class_token() {
    assert_eq!(GateEnginePart::PolicyModel.as_str(), "policy_model");
    assert_eq!(GateEnginePart::Sandbox.as_str(), "sandbox");
    assert_eq!(
        GateEnginePart::BookingHttpGuard.as_str(),
        "booking.http_guard"
    );
    assert_eq!(GateEnginePart::ConnectorCaller.as_str(), "connector_caller");
    assert_eq!(GateEnginePart::FirstParty.as_str(), "first_party");
    assert_eq!(GateEnginePart::Owner.as_str(), "owner");
    assert_eq!(GateEnginePart::Engine.as_str(), "engine");
}

/// `as_str` is a `const fn` on the hand table and on the derive alike: a token can name a `const`.
#[test]
fn the_token_is_a_const() {
    const SANDBOX: &str = GateEnginePart::Sandbox.as_str();
    assert_eq!(SANDBOX, "sandbox");
}

/// The Register (R2b): its name, the 7 parts in declaration order, and each token read back. The
/// variant's own name wins over the enum's snake_case rule: `booking.http_guard`, never
/// `booking_http_guard`.
#[test]
fn the_register_reads_every_token_back() {
    assert_eq!(GateEnginePart::NAME, "gate.engine_part");
    assert_eq!(
        GateEnginePart::ROWS,
        &[
            GateEnginePart::PolicyModel,
            GateEnginePart::Sandbox,
            GateEnginePart::BookingHttpGuard,
            GateEnginePart::ConnectorCaller,
            GateEnginePart::FirstParty,
            GateEnginePart::Owner,
            GateEnginePart::Engine,
        ]
    );
    for part in GateEnginePart::ROWS.iter().copied() {
        assert_eq!(GateEnginePart::named(part.as_str()), Some(part), "{part:?}");
    }
    assert_eq!(GateEnginePart::named("booking_http_guard"), None);
}
