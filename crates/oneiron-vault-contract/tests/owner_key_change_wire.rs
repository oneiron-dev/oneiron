//! One owner key change's wire on the supervisor socket (Engine ruling
//! 21 Nov 06:00): the request's exact line and its shape checks, and the ack
//! a vault may read. A supervisor built before the op answers a ledger ack,
//! which is not one, and neither is the recovery box's ack.

use oneiron_vault_contract::{
    OWNER_KEY_CHANGE_AT_MAX, OWNER_KEY_CHANGE_OP, OWNER_KEY_CHANGE_REFUSAL_MAX,
    OwnerKeyChangeReport, OwnerKeyChangeReportAck, TOKEN_LEN, TokenHex,
    valid_owner_key_change_refusal_code,
};

fn request() -> OwnerKeyChangeReport {
    OwnerKeyChangeReport {
        op: OWNER_KEY_CHANGE_OP.to_owned(),
        vault: "vault-7".to_owned(),
        token: TokenHex::new("ab".repeat(TOKEN_LEN)),
        entry: "ce".repeat(32),
        change: "enrolled".to_owned(),
        key: "passkey".to_owned(),
        at: 1_764_110_000,
    }
}

#[test]
fn owner_key_change_wire_is_exact() {
    let line = serde_json::to_string(&request()).unwrap();
    assert_eq!(
        line,
        format!(
            r#"{{"op":"owner_key_change","vault":"vault-7","token":"{}","entry":"{}","change":"enrolled","key":"passkey","at":1764110000}}"#,
            "ab".repeat(TOKEN_LEN),
            "ce".repeat(32),
        )
    );
    let back: OwnerKeyChangeReport = serde_json::from_str(&line).unwrap();
    back.validate().unwrap();
    assert_eq!(back.entry, "ce".repeat(32));
}

#[test]
fn owner_key_change_refuses_bad_shapes() {
    let mut wrong_op = request();
    wrong_op.op = "ledger_update".to_owned();
    assert!(wrong_op.validate().is_err());
    let mut bad_vault = request();
    bad_vault.vault = "Vault_7".to_owned();
    assert!(bad_vault.validate().is_err());
    let mut short_token = request();
    short_token.token = TokenHex::new("ab".to_owned());
    assert!(short_token.validate().is_err());
    for entry in [
        "ce".repeat(31),
        "ce".repeat(33),
        "CE".repeat(32),
        "zz".repeat(32),
    ] {
        let mut bad_entry = request();
        bad_entry.entry = entry;
        assert!(bad_entry.validate().is_err());
    }
    let mut bad_change = request();
    bad_change.change = "vouched".to_owned();
    assert!(bad_change.validate().is_err());
    let mut bad_key = request();
    bad_key.key = "machine".to_owned();
    assert!(bad_key.validate().is_err());
    let mut bad_at = request();
    bad_at.at = OWNER_KEY_CHANGE_AT_MAX + 1;
    assert!(bad_at.validate().is_err());
    let mut at_max = request();
    at_max.at = OWNER_KEY_CHANGE_AT_MAX;
    at_max.validate().unwrap();
    let extra = format!(
        r#"{{"op":"owner_key_change","vault":"vault-7","token":"{}","entry":"{}","change":"enrolled","key":"passkey","at":1,"placement_generation":3}}"#,
        "ab".repeat(TOKEN_LEN),
        "ce".repeat(32),
    );
    assert!(serde_json::from_str::<OwnerKeyChangeReport>(&extra).is_err());
    assert!(!format!("{:?}", request()).contains(&"ab".repeat(TOKEN_LEN)));
}

#[test]
fn owner_key_change_ack_shapes() {
    let reported: OwnerKeyChangeReportAck = serde_json::from_str(r#"{"reported":true}"#).unwrap();
    assert!(reported.well_formed());
    assert_eq!(
        serde_json::to_string(&reported).unwrap(),
        r#"{"reported":true}"#
    );
    let refused: OwnerKeyChangeReportAck =
        serde_json::from_str(r#"{"reported":false,"error":"stale_generation"}"#).unwrap();
    assert!(refused.well_formed());
    for line in [
        r#"{"reported":false}"#,
        r#"{"reported":true,"error":"refused"}"#,
        r#"{"reported":false,"error":"Not A Code"}"#,
    ] {
        let ack: OwnerKeyChangeReportAck = serde_json::from_str(line).unwrap();
        assert!(!ack.well_formed(), "{line}");
    }
    // a supervisor before the op answers a ledger ack: not this ack
    assert!(
        serde_json::from_str::<OwnerKeyChangeReportAck>(
            r#"{"ok":false,"error":"unknown variant","report":null,"offset":null,"committed":false}"#
        )
        .is_err()
    );
    // the recovery box's ack is not this ack either
    assert!(serde_json::from_str::<OwnerKeyChangeReportAck>(r#"{"held":true}"#).is_err());
    assert!(
        serde_json::from_str::<OwnerKeyChangeReportAck>(
            r#"{"held":false,"error":"stale_generation"}"#
        )
        .is_err()
    );
    let long = "a".repeat(OWNER_KEY_CHANGE_REFUSAL_MAX + 1);
    assert!(!valid_owner_key_change_refusal_code(&long));
}
