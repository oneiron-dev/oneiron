//! The kit-only hold's wire on the supervisor socket (Fable pass 27 R7;
//! Engine RULING WAYBACK-BOX-HOLD-RELAY = A, 16 Nov 01:02): the request's
//! exact line and its shape checks, and the ack a vault may read. A
//! supervisor built before the op answers a ledger ack, which is not one.

use oneiron_vault_contract::{
    RECOVERY_BOX_KIT_ONLY_OP, RECOVERY_BOX_REFUSAL_MAX, RecoveryBoxKitOnly, RecoveryBoxKitOnlyAck,
    TOKEN_LEN, TokenHex, valid_recovery_box_refusal_code,
};

fn request(kit_only: bool) -> RecoveryBoxKitOnly {
    RecoveryBoxKitOnly {
        op: RECOVERY_BOX_KIT_ONLY_OP.to_owned(),
        vault: "vault-7".to_owned(),
        token: TokenHex::new("ab".repeat(TOKEN_LEN)),
        kit_only,
    }
}

#[test]
fn recovery_box_kit_only_wire_is_exact() {
    let line = serde_json::to_string(&request(true)).unwrap();
    assert_eq!(
        line,
        format!(
            r#"{{"op":"recovery_box_kit_only","vault":"vault-7","token":"{}","kit_only":true}}"#,
            "ab".repeat(TOKEN_LEN)
        )
    );
    let back: RecoveryBoxKitOnly = serde_json::from_str(&line).unwrap();
    back.validate().unwrap();
    assert!(back.kit_only);
}

#[test]
fn recovery_box_kit_only_refuses_bad_shapes() {
    let mut wrong_op = request(false);
    wrong_op.op = "ledger_update".to_owned();
    assert!(wrong_op.validate().is_err());
    let mut bad_vault = request(false);
    bad_vault.vault = "Vault_7".to_owned();
    assert!(bad_vault.validate().is_err());
    let mut short_token = request(false);
    short_token.token = TokenHex::new("ab".to_owned());
    assert!(short_token.validate().is_err());
    let extra = format!(
        r#"{{"op":"recovery_box_kit_only","vault":"vault-7","token":"{}","kit_only":true,"placement_generation":3}}"#,
        "ab".repeat(TOKEN_LEN)
    );
    assert!(serde_json::from_str::<RecoveryBoxKitOnly>(&extra).is_err());
    assert!(!format!("{:?}", request(true)).contains(&"ab".repeat(TOKEN_LEN)));
}

#[test]
fn recovery_box_kit_only_ack_shapes() {
    let held: RecoveryBoxKitOnlyAck = serde_json::from_str(r#"{"held":true}"#).unwrap();
    assert!(held.well_formed());
    assert_eq!(serde_json::to_string(&held).unwrap(), r#"{"held":true}"#);
    let refused: RecoveryBoxKitOnlyAck =
        serde_json::from_str(r#"{"held":false,"error":"stale_generation"}"#).unwrap();
    assert!(refused.well_formed());
    for line in [
        r#"{"held":false}"#,
        r#"{"held":true,"error":"refused"}"#,
        r#"{"held":false,"error":"Not A Code"}"#,
    ] {
        let ack: RecoveryBoxKitOnlyAck = serde_json::from_str(line).unwrap();
        assert!(!ack.well_formed(), "{line}");
    }
    // a supervisor before the op answers a ledger ack: not this ack
    assert!(
        serde_json::from_str::<RecoveryBoxKitOnlyAck>(
            r#"{"ok":false,"error":"unknown variant","report":null,"offset":null,"committed":false}"#
        )
        .is_err()
    );
    let long = "a".repeat(RECOVERY_BOX_REFUSAL_MAX + 1);
    assert!(!valid_recovery_box_refusal_code(&long));
}
