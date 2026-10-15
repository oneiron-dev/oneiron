//! Generated-lens validation tests: closed enums, URL bans, unsafe atoms, budgets,
//! and size caps.

use super::*;
use proptest::prelude::*;
use serde_json::json;

#[test]
fn generated_ui_rejects_unknown_segment_and_raw_media_url_shapes() {
    let unknown_segment = json!({
        "segment": "open_url",
        "payload": { "url": "https://attacker.example" }
    });
    assert!(
        serde_json::from_value::<GeneratedUiSegment>(unknown_segment).is_err(),
        "segment kind must be a closed enum"
    );

    for segment in [
        json!({
            "segment": "card_start",
            "payload": {
                "protocolVersion": GENERATED_UI_WIRE_VERSION + 1,
                "catalog": "lens_atom_kit",
                "cardId": "card-1",
                "root": "root",
                "nodeCount": 1,
                "fallbackText": "root"
            }
        }),
        json!({
            "segment": "card_element",
            "payload": {
                "protocolVersion": GENERATED_UI_WIRE_VERSION + 1,
                "cardId": "card-1",
                "node": {
                    "id": "root",
                    "atom": {
                        "kind": "throbber",
                        "props": { "label": "loading" }
                    },
                    "fallbackText": "loading"
                }
            }
        }),
        json!({
            "segment": "card_state_update",
            "payload": {
                "protocolVersion": GENERATED_UI_WIRE_VERSION + 1,
                "cardId": "card-1",
                "dataModel": {
                    "root": "root",
                    "nodeCount": 1,
                    "catalog": "lens_atom_kit",
                    "lifecycle": { "phase": "active", "revision": 0 }
                }
            }
        }),
    ] {
        assert!(
            serde_json::from_value::<GeneratedUiSegment>(segment).is_err(),
            "segment payloads must reject unsupported generated-ui wire versions"
        );
    }

    for segment in [
        json!({
            "segment": "card_start",
            "payload": {
                "protocolVersion": GENERATED_UI_WIRE_VERSION,
                "catalog": "lens_atom_kit",
                "cardId": "card-1",
                "root": "root",
                "nodeCount": 0,
                "fallbackText": "root"
            }
        }),
        json!({
            "segment": "card_state_update",
            "payload": {
                "protocolVersion": GENERATED_UI_WIRE_VERSION,
                "cardId": "card-1",
                "dataModel": {
                    "root": "root",
                    "nodeCount": 0,
                    "catalog": "lens_atom_kit",
                    "lifecycle": { "phase": "active", "revision": 0 }
                }
            }
        }),
    ] {
        assert!(
            serde_json::from_value::<GeneratedUiSegment>(segment).is_err(),
            "segment payloads must reject zero nodeCount"
        );
    }

    let zero_node_data_model = json!({
        "root": "root",
        "nodeCount": 0,
        "catalog": "lens_atom_kit",
        "lifecycle": { "phase": "active", "revision": 0 }
    });
    assert!(
        serde_json::from_value::<GeneratedUiDataModel>(zero_node_data_model).is_err(),
        "generated-ui data model must reject zero nodeCount"
    );

    let raw_url_handle = json!({
        "kind": "media",
        "props": {
            "handle": "https://attacker.example/pixel.png",
            "alt": "pixel"
        }
    });
    assert!(
        serde_json::from_value::<LensAtom>(raw_url_handle).is_err(),
        "media handles must be engine-owned tokens, not raw URLs"
    );

    let raw_url_prop = json!({
        "kit_version": LENS_ATOM_KIT_VERSION,
        "apps_contract_version": LENS_APPS_CONTRACT_VERSION,
        "root": {
            "id": "root",
            "fallbackText": "pixel",
            "atom": {
                "kind": "media",
                "props": {
                    "handle": "engine-media-pixel",
                    "url": "https://attacker.example/pixel.png",
                    "alt": "pixel"
                }
            }
        }
    });
    assert!(
        serde_json::from_value::<GeneratedLens>(raw_url_prop).is_err(),
        "media atoms must not accept raw URL leaves"
    );
}

proptest! {
    #[test]
    fn generated_ui_fuzz_rejects_url_shaped_media_handles(
        scheme in "https?",
        host in "[a-z]{1,12}",
        path in "[a-z0-9/_-]{0,24}",
    ) {
        let url = format!("{scheme}://{host}.example/{path}");
        let attempted = json!({
            "kit_version": LENS_ATOM_KIT_VERSION,
            "apps_contract_version": LENS_APPS_CONTRACT_VERSION,
            "root": {
                "id": "root",
                "fallbackText": "remote media",
                "atom": {
                    "kind": "media",
                    "props": {
                        "handle": url,
                        "alt": "remote media"
                    }
                }
            }
        });

        prop_assert!(
            serde_json::from_value::<GeneratedLens>(attempted).is_err(),
            "URL-shaped media handles must be rejected"
        );
    }
}

#[test]
fn unsafe_raw_atom_variants_are_rejected() {
    for kind in [
        "raw_script",
        "script",
        "network_request",
        "storage_read",
        "eval",
    ] {
        let attempted = json!({
            "kit_version": LENS_ATOM_KIT_VERSION,
            "apps_contract_version": LENS_APPS_CONTRACT_VERSION,
            "root": {
                "id": "root",
                "fallbackText": "unsafe atom",
                "atom": {
                    "kind": kind,
                    "props": {
                        "code": "fetch('https://attacker.example')"
                    }
                }
            }
        });

        assert!(
            serde_json::from_value::<GeneratedLens>(attempted).is_err(),
            "unsafe atom kind {kind} should be rejected"
        );
    }
}

#[test]
fn raw_script_network_storage_eval_props_are_rejected() {
    for forbidden_prop in [
        "on_click", "script", "src", "href", "fetch", "storage", "eval",
    ] {
        let attempted = json!({
            "kit_version": LENS_ATOM_KIT_VERSION,
            "apps_contract_version": LENS_APPS_CONTRACT_VERSION,
            "root": {
                "id": "root",
                "fallbackText": "refresh",
                "atom": {
                    "kind": "self_ui",
                    "props": {
                        "control": "button",
                        "props": {
                            "id": "refresh",
                            "label": "Refresh",
                            "action": { "command": "refresh_lens" },
                            forbidden_prop: "javascript:alert(1)"
                        }
                    }
                }
            }
        });

        assert!(
            serde_json::from_value::<GeneratedLens>(attempted).is_err(),
            "raw prop {forbidden_prop} should be rejected"
        );

        let attempted = json!({
            "kit_version": LENS_ATOM_KIT_VERSION,
            "apps_contract_version": LENS_APPS_CONTRACT_VERSION,
            "root": {
                "id": "root",
                "fallbackText": "refresh",
                "atom": {
                    "kind": "self_ui",
                    "props": {
                        "control": "button",
                        "props": {
                            "id": "refresh",
                            "label": "Refresh",
                            "action": { "command": "refresh_lens" }
                        },
                        forbidden_prop: "javascript:alert(1)"
                    }
                }
            }
        });

        assert!(
            serde_json::from_value::<GeneratedLens>(attempted).is_err(),
            "raw self.ui envelope prop {forbidden_prop} should be rejected"
        );

        let attempted = json!({
            "kit_version": LENS_ATOM_KIT_VERSION,
            "apps_contract_version": LENS_APPS_CONTRACT_VERSION,
            "root": {
                "id": "root",
                "fallbackText": "refresh",
                "atom": {
                    "kind": "self_ui",
                    "props": {
                        "control": "button",
                        "props": {
                            "id": "refresh",
                            "label": "Refresh",
                            "action": { "command": "refresh_lens" }
                        }
                    },
                    forbidden_prop: "javascript:alert(1)"
                }
            }
        });

        assert!(
            serde_json::from_value::<GeneratedLens>(attempted).is_err(),
            "raw atom envelope prop {forbidden_prop} should be rejected"
        );
    }
}
