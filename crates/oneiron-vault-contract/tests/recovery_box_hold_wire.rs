//! The kit-only hold's wire on the supervisor socket (Fable pass 27 R7;
//! Engine RULING WAYBACK-BOX-HOLD-RELAY = A, 16 Nov 01:02): the request's
//! exact line and its shape checks, and the ack a vault may read. A
//! supervisor built before the op answers a ledger ack, which is not one.

use oneiron_vault_contract::{
    RECOVERY_BOX_CANCEL_OP, RECOVERY_BOX_KIT_ONLY_OP, RECOVERY_BOX_REFUSAL_MAX,
    RECOVERY_BOX_WAIT_MAX_SECS, RECOVERY_BOX_WAIT_OP, RecoveryBoxCancel, RecoveryBoxCancelAck,
    RecoveryBoxCancelledBy, RecoveryBoxKitOnly, RecoveryBoxKitOnlyAck, RecoveryBoxWait, TOKEN_LEN,
    TokenHex, valid_recovery_box_refusal_code,
};

/// The owner and device key the cancels in these tests name.
fn canceller() -> RecoveryBoxCancelledBy {
    RecoveryBoxCancelledBy {
        person: "12".repeat(16),
        device_key: "cd".repeat(32),
    }
}

fn cancel(release_receipt: Option<u64>) -> RecoveryBoxCancel {
    RecoveryBoxCancel {
        op: RECOVERY_BOX_CANCEL_OP.to_owned(),
        vault: "vault-7".to_owned(),
        token: TokenHex::new("ab".repeat(TOKEN_LEN)),
        cancelled_by: canceller(),
        release_receipt,
    }
}

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

#[test]
fn recovery_box_wait_and_cancel_wires_are_exact() {
    let wait = RecoveryBoxWait {
        op: RECOVERY_BOX_WAIT_OP.to_owned(),
        vault: "vault-7".to_owned(),
        token: TokenHex::new("ab".repeat(TOKEN_LEN)),
        wait_secs: 86_400,
    };
    wait.validate().unwrap();
    assert_eq!(
        serde_json::to_string(&wait).unwrap(),
        format!(
            r#"{{"op":"recovery_box_wait","vault":"vault-7","token":"{}","wait_secs":86400}}"#,
            "ab".repeat(TOKEN_LEN)
        )
    );
    let wait_line = serde_json::to_string(&wait).unwrap();
    let smuggled = wait_line.replace("\"wait_secs\"", "\"kit_only\":true,\"wait_secs\"");
    assert!(serde_json::from_str::<RecoveryBoxWait>(&smuggled).is_err());
    assert!(!format!("{wait:?}").contains(&"ab".repeat(TOKEN_LEN)));
    let mut over = wait.clone();
    over.wait_secs = RECOVERY_BOX_WAIT_MAX_SECS + 1;
    assert!(over.validate().is_err());
    let mut wrong_op = wait.clone();
    wrong_op.op = RECOVERY_BOX_KIT_ONLY_OP.to_owned();
    assert!(wrong_op.validate().is_err());

    let cancel = cancel(None);
    cancel.validate().unwrap();
    let line = serde_json::to_string(&cancel).unwrap();
    assert_eq!(
        line,
        format!(
            r#"{{"op":"recovery_box_cancel","vault":"vault-7","token":"{}","cancelled_by":{{"person":"{}","device_key":"{}"}}}}"#,
            "ab".repeat(TOKEN_LEN),
            "12".repeat(16),
            "cd".repeat(32)
        )
    );
    let with_wait = line.replacen("\"op\"", "\"wait_secs\":0,\"op\"", 1);
    assert!(serde_json::from_str::<RecoveryBoxCancel>(&with_wait).is_err());
    let mut bad_vault = cancel.clone();
    bad_vault.vault = "Vault_7".to_owned();
    assert!(bad_vault.validate().is_err());
    assert!(!format!("{cancel:?}").contains(&"ab".repeat(TOKEN_LEN)));
}

#[test]
fn recovery_box_cancel_ack_shapes() {
    for (line, cancelled) in [
        (r#"{"held":true,"cancelled":true}"#, true),
        (r#"{"held":true,"cancelled":false}"#, false),
    ] {
        let ack: RecoveryBoxCancelAck = serde_json::from_str(line).unwrap();
        assert!(ack.well_formed(), "{line}");
        assert_eq!(ack.cancelled, Some(cancelled));
        assert_eq!(serde_json::to_string(&ack).unwrap(), line);
    }
    let refused: RecoveryBoxCancelAck =
        serde_json::from_str(r#"{"held":false,"error":"wrong_node"}"#).unwrap();
    assert!(refused.well_formed());
    for line in [
        r#"{"held":true}"#,
        r#"{"held":false}"#,
        r#"{"held":true,"cancelled":true,"error":"refused"}"#,
        r#"{"held":false,"cancelled":false,"error":"refused"}"#,
        r#"{"held":false,"error":"Not A Code"}"#,
    ] {
        let ack: RecoveryBoxCancelAck = serde_json::from_str(line).unwrap();
        assert!(!ack.well_formed(), "{line}");
    }
    assert!(
        serde_json::from_str::<RecoveryBoxCancelAck>(r#"{"held":true,"cancelled":true,"x":1}"#)
            .is_err()
    );
}

#[test]
fn recovery_box_cancel_names_its_canceller_and_may_name_the_release() {
    let named = cancel(Some(41));
    named.validate().unwrap();
    let line = serde_json::to_string(&named).unwrap();
    assert!(line.ends_with(r#"},"release_receipt":41}"#), "{line}");
    let back: RecoveryBoxCancel = serde_json::from_str(&line).unwrap();
    assert_eq!(back.cancelled_by, canceller());
    assert_eq!(back.release_receipt, Some(41));
    let unnamed: RecoveryBoxCancel =
        serde_json::from_str(&serde_json::to_string(&cancel(None)).unwrap()).unwrap();
    assert_eq!(unnamed.release_receipt, None);

    // the canceller is required, and takes no other field
    let token = "ab".repeat(TOKEN_LEN);
    let without = format!(r#"{{"op":"recovery_box_cancel","vault":"vault-7","token":"{token}"}}"#);
    assert!(serde_json::from_str::<RecoveryBoxCancel>(&without).is_err());
    let smuggled = line.replace(r#""device_key""#, r#""role":"owner","device_key""#);
    assert!(serde_json::from_str::<RecoveryBoxCancel>(&smuggled).is_err());

    // reject, never truncate: the exact length, lowercase hex only
    for person in [
        "12".repeat(15),
        "12".repeat(17),
        "AB".repeat(16),
        "zz".repeat(16),
    ] {
        let mut bad = cancel(None);
        bad.cancelled_by.person = person;
        assert!(bad.validate().is_err(), "{:?}", bad.cancelled_by);
    }
    for device_key in [
        "cd".repeat(31),
        "cd".repeat(33),
        "CD".repeat(32),
        "g0".repeat(32),
    ] {
        let mut bad = cancel(None);
        bad.cancelled_by.device_key = device_key;
        assert!(bad.validate().is_err(), "{:?}", bad.cancelled_by);
    }
}
