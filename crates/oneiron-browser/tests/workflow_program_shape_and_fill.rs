//! These tests hold the program shape and fill contract
//! (FIX [BROWSER-LIBRARY-PLAIN-FUNCTIONS-HELD-BY-NO-TEST]).
//! They check the site helpers and the slot filler on plain values, without a browser or a store.

use oneiron_browser::{
    BatchStep, BrowserError, ExpectInput, SecretKind, SecretParam, WorkflowProgram, site_of,
};
use serde_json::json;
use std::collections::BTreeMap;

const FORM: &str = "https://shop.example/form";
const SHOP: &str = "shop.example";

/// An ordinary check that requires neither handle resolution nor custody.
fn ready() -> ExpectInput {
    ExpectInput {
        role: Some("heading".to_owned()),
        name: Some("Ready".to_owned()),
        ..Default::default()
    }
}

/// A sound program on the shop site, with no parameters.
fn program() -> WorkflowProgram {
    WorkflowProgram {
        subgoal: "Fill form".to_owned(),
        params: Vec::new(),
        secret_params: Vec::new(),
        steps: vec![BatchStep::Open {
            url: FORM.to_owned(),
        }],
        postcondition: vec![ready()],
    }
}

/// A program whose type step takes its secret slot.
fn secret_type_program() -> WorkflowProgram {
    WorkflowProgram {
        subgoal: "Fill form".to_owned(),
        params: vec!["password".to_owned()],
        secret_params: vec![SecretParam {
            name: "password".to_owned(),
            kind: SecretKind::Password,
        }],
        steps: vec![
            BatchStep::Open {
                url: FORM.to_owned(),
            },
            BatchStep::Type {
                target: "e-field".to_owned(),
                text: None,
                secret: Some("{{password}}".to_owned()),
                clear: false,
            },
        ],
        postcondition: vec![ready()],
    }
}

/// A program whose check takes its secret slot.
fn secret_check_program() -> WorkflowProgram {
    WorkflowProgram {
        subgoal: "Fill form".to_owned(),
        params: vec!["password".to_owned()],
        secret_params: vec![SecretParam {
            name: "password".to_owned(),
            kind: SecretKind::Password,
        }],
        steps: vec![BatchStep::Open {
            url: FORM.to_owned(),
        }],
        postcondition: vec![ExpectInput {
            target: Some("e-verify".to_owned()),
            secret: Some("{{password}}".to_owned()),
            ..Default::default()
        }],
    }
}

#[test]
fn site_trims_lowercases_and_keeps_host_and_port_only_with_uppercase_scheme_taken() {
    assert_eq!(
        site_of("  HTTPS://Shop.Example:8443/form?x=1#frag  "),
        Some("shop.example:8443".to_owned())
    );
    assert_eq!(
        site_of("https://shop.example:8443?q=item#ready"),
        Some("shop.example:8443".to_owned())
    );
    assert_eq!(
        site_of("https://shop.example#ready"),
        Some("shop.example".to_owned())
    );
    assert_eq!(
        site_of("http://SHOP.EXAMPLE:80/path"),
        Some("shop.example:80".to_owned())
    );
}

#[test]
fn site_drops_user_info_before_the_host() {
    assert_eq!(
        site_of("https://user:pw@shop.example/form"),
        Some("shop.example".to_owned())
    );
    assert_eq!(
        site_of("https://user@shop.example:8443/"),
        Some("shop.example:8443".to_owned())
    );
}

#[test]
fn site_is_none_for_a_non_http_scheme_and_for_text_without_a_scheme_separator() {
    assert_eq!(site_of("ftp://shop.example/form"), None);
    assert_eq!(site_of("shop.example/form"), None);
}

#[test]
fn site_is_none_for_an_empty_host_and_for_a_host_with_a_slot() {
    assert_eq!(site_of("https:///form"), None);
    assert_eq!(site_of("https://{{shop}}.example/form"), None);
    assert_eq!(site_of("https://{{name}}/"), None);
}

#[test]
fn a_sound_program_names_the_site_of_the_page_its_first_step_opens() {
    let program = WorkflowProgram {
        steps: vec![
            BatchStep::Open {
                url: FORM.to_owned(),
            },
            BatchStep::Open {
                url: "https://other.example/form".to_owned(),
            },
        ],
        ..program()
    };
    assert_eq!(program.site(), Ok(SHOP.to_owned()));
}

#[test]
fn a_blank_subgoal_is_refused() {
    let program = WorkflowProgram {
        subgoal: "  \t ".to_owned(),
        ..program()
    };
    assert_eq!(
        program.site(),
        Err(BrowserError::Input(
            "a program names its subgoal".to_owned()
        ))
    );
}

#[test]
fn a_parameter_name_outside_lowercase_letters_digits_and_underscore_is_refused() {
    for bad in ["Bad", "9lives", "bad-name", ""] {
        let program = WorkflowProgram {
            params: vec![bad.to_owned()],
            ..program()
        };
        assert_eq!(
            program.site(),
            Err(BrowserError::Input(
                "a program names distinct parameters, each a-z, 0-9 and _ from a letter".to_owned()
            )),
            "param {bad:?}"
        );
    }
}

#[test]
fn a_repeated_parameter_is_refused() {
    let program = WorkflowProgram {
        params: vec!["name".to_owned(), "name".to_owned()],
        ..program()
    };
    assert_eq!(
        program.site(),
        Err(BrowserError::Input(
            "a program names distinct parameters, each a-z, 0-9 and _ from a letter".to_owned()
        ))
    );
}

#[test]
fn a_secret_slot_that_is_no_parameter_is_refused() {
    let program = WorkflowProgram {
        params: vec!["name".to_owned()],
        secret_params: vec![SecretParam {
            name: "other".to_owned(),
            kind: SecretKind::Password,
        }],
        ..program()
    };
    assert_eq!(
        program.site(),
        Err(BrowserError::Input(
            "a program's secret slots are distinct parameters of its own".to_owned()
        ))
    );
}

#[test]
fn a_repeated_secret_slot_is_refused() {
    let program = WorkflowProgram {
        params: vec!["password".to_owned()],
        secret_params: vec![
            SecretParam {
                name: "password".to_owned(),
                kind: SecretKind::Password,
            },
            SecretParam {
                name: "password".to_owned(),
                kind: SecretKind::Password,
            },
        ],
        ..program()
    };
    assert_eq!(
        program.site(),
        Err(BrowserError::Input(
            "a program's secret slots are distinct parameters of its own".to_owned()
        ))
    );
}

#[test]
fn a_program_with_no_step_is_refused() {
    let program = WorkflowProgram {
        steps: Vec::new(),
        ..program()
    };
    assert_eq!(
        program.site(),
        Err(BrowserError::Input(
            "a program holds one or more steps".to_owned()
        ))
    );
}

#[test]
fn a_program_with_no_check_is_refused() {
    let program = WorkflowProgram {
        postcondition: Vec::new(),
        ..program()
    };
    assert_eq!(
        program.site(),
        Err(BrowserError::Input(
            "a program's postcondition holds one or more checks".to_owned()
        ))
    );
}

#[test]
fn a_live_handle_as_a_step_target_is_refused_while_a_locator_passes() {
    let refused = WorkflowProgram {
        steps: vec![
            BatchStep::Open {
                url: FORM.to_owned(),
            },
            BatchStep::Click {
                target: "hab:007".to_owned(),
            },
        ],
        ..program()
    };
    assert_eq!(
        refused.site(),
        Err(BrowserError::Input(
            "a program names its elements by locator; a live handle this session did not mint never joins the library"
                .to_owned()
        ))
    );
    let passed = WorkflowProgram {
        steps: vec![
            BatchStep::Open {
                url: FORM.to_owned(),
            },
            BatchStep::Click {
                target: "e-button".to_owned(),
            },
        ],
        ..program()
    };
    assert_eq!(passed.site(), Ok(SHOP.to_owned()));
}

#[test]
fn a_live_handle_as_a_check_target_is_refused_while_a_locator_passes() {
    let refused = WorkflowProgram {
        postcondition: vec![ExpectInput {
            target: Some("hab:007".to_owned()),
            ..Default::default()
        }],
        ..program()
    };
    assert_eq!(
        refused.site(),
        Err(BrowserError::Input(
            "a program names its elements by locator; a live handle this session did not mint never joins the library"
                .to_owned()
        ))
    );
    let passed = WorkflowProgram {
        postcondition: vec![ExpectInput {
            target: Some("e-button".to_owned()),
            ..Default::default()
        }],
        ..program()
    };
    assert_eq!(passed.site(), Ok(SHOP.to_owned()));
}

#[test]
fn a_first_step_that_opens_no_page_is_refused() {
    let program = WorkflowProgram {
        steps: vec![
            BatchStep::Click {
                target: "e-button".to_owned(),
            },
            BatchStep::Open {
                url: FORM.to_owned(),
            },
        ],
        ..program()
    };
    assert_eq!(
        program.site(),
        Err(BrowserError::Input(
            "a program's first step opens its page".to_owned()
        ))
    );
}

#[test]
fn a_first_page_with_a_slot_host_or_a_non_http_scheme_is_refused() {
    for url in ["https://{{shop}}.example/form", "ftp://shop.example/form"] {
        let program = WorkflowProgram {
            steps: vec![BatchStep::Open {
                url: url.to_owned(),
            }],
            ..program()
        };
        assert_eq!(
            program.site(),
            Err(BrowserError::Input(
                "a program opens an http or https page whose host takes no slot".to_owned()
            )),
            "url {url:?}"
        );
    }
}

#[test]
fn fill_takes_every_slot_trims_names_and_fills_two_slots_in_one_string() {
    let program = WorkflowProgram {
        params: vec!["name".to_owned(), "city".to_owned()],
        steps: vec![
            BatchStep::Open {
                url: "https://shop.example/{{city}}/form".to_owned(),
            },
            BatchStep::Type {
                target: "e-field".to_owned(),
                text: Some("hi {{ name }} from {{city}}".to_owned()),
                secret: None,
                clear: false,
            },
        ],
        postcondition: vec![ExpectInput {
            value: Some("welcome {{name}}".to_owned()),
            ..ready()
        }],
        ..program()
    };
    let args = BTreeMap::from([
        ("city".to_owned(), "paris".to_owned()),
        ("name".to_owned(), "Alice".to_owned()),
    ]);
    let filled = program.fill(&args).map(|(steps, checks)| {
        let steps = serde_json::to_value(&steps).expect("filled steps serialize");
        (steps, checks)
    });
    assert_eq!(
        filled,
        Ok((
            json!([
                {"step": "open", "url": "https://shop.example/paris/form"},
                {"step": "type", "ref": "e-field", "text": "hi Alice from paris", "clear": false},
            ]),
            vec![ExpectInput {
                value: Some("welcome Alice".to_owned()),
                ..ready()
            }],
        ))
    );
}

#[test]
fn fill_refuses_arguments_that_are_not_exactly_the_parameters() {
    let program = WorkflowProgram {
        params: vec!["name".to_owned(), "city".to_owned()],
        ..program()
    };
    let missing = BTreeMap::from([("name".to_owned(), "Alice".to_owned())]);
    assert_eq!(
        program.fill(&missing).err(),
        Some(BrowserError::Input(
            "the program takes exactly the arguments [\"name\", \"city\"]".to_owned()
        ))
    );
    let extra = BTreeMap::from([
        ("city".to_owned(), "paris".to_owned()),
        ("extra".to_owned(), "x".to_owned()),
        ("name".to_owned(), "Alice".to_owned()),
    ]);
    assert_eq!(
        program.fill(&extra).err(),
        Some(BrowserError::Input(
            "the program takes exactly the arguments [\"name\", \"city\"]".to_owned()
        ))
    );
}

#[test]
fn fill_refuses_a_slot_that_names_no_parameter_with_the_slot_name() {
    let program = WorkflowProgram {
        params: vec!["name".to_owned()],
        steps: vec![
            BatchStep::Open {
                url: FORM.to_owned(),
            },
            BatchStep::Type {
                target: "e-field".to_owned(),
                text: Some("hi {{other}}".to_owned()),
                secret: None,
                clear: false,
            },
        ],
        ..program()
    };
    let args = BTreeMap::from([("name".to_owned(), "Alice".to_owned())]);
    assert_eq!(
        program.fill(&args).err(),
        Some(BrowserError::Input(
            "slot {{other}} is no parameter".to_owned()
        ))
    );
}

#[test]
fn fill_refuses_a_slot_that_is_never_closed() {
    let program = WorkflowProgram {
        params: vec!["name".to_owned()],
        steps: vec![
            BatchStep::Open {
                url: FORM.to_owned(),
            },
            BatchStep::Type {
                target: "e-field".to_owned(),
                text: Some("hi {{name".to_owned()),
                secret: None,
                clear: false,
            },
        ],
        ..program()
    };
    let args = BTreeMap::from([("name".to_owned(), "Alice".to_owned())]);
    assert_eq!(
        program.fill(&args).err(),
        Some(BrowserError::Input("a {{ slot is never closed".to_owned()))
    );
}

#[test]
fn fill_takes_an_argument_as_data_without_filling_it_again() {
    let program = WorkflowProgram {
        params: vec!["name".to_owned(), "other".to_owned()],
        steps: vec![
            BatchStep::Open {
                url: FORM.to_owned(),
            },
            BatchStep::Type {
                target: "e-field".to_owned(),
                text: Some("hi {{name}}".to_owned()),
                secret: None,
                clear: false,
            },
        ],
        ..program()
    };
    let args = BTreeMap::from([
        ("name".to_owned(), "{{other}}".to_owned()),
        ("other".to_owned(), "paris".to_owned()),
    ]);
    let filled = program.fill(&args).map(|(steps, checks)| {
        let steps = serde_json::to_value(&steps).expect("filled steps serialize");
        (steps, checks)
    });
    assert_eq!(
        filled,
        Ok((
            json!([
                {"step": "open", "url": FORM},
                {"step": "type", "ref": "e-field", "text": "hi {{other}}", "clear": false},
            ]),
            vec![ready()],
        ))
    );
}

#[test]
fn a_secret_handle_stays_in_a_type_step_secret_arm() {
    let args = BTreeMap::from([("password".to_owned(), "sc1".to_owned())]);
    let filled = secret_type_program().fill(&args).map(|(steps, checks)| {
        let steps = serde_json::to_value(&steps).expect("filled steps serialize");
        (steps, checks)
    });
    assert_eq!(
        filled,
        Ok((
            json!([
                {"step": "open", "url": FORM},
                {"step": "type", "ref": "e-field", "secret": "sc1", "clear": false},
            ]),
            vec![ready()],
        ))
    );
}

#[test]
fn a_secret_plain_value_moves_to_a_type_step_text_arm() {
    let args = BTreeMap::from([("password".to_owned(), "plain value".to_owned())]);
    let filled = secret_type_program().fill(&args).map(|(steps, checks)| {
        let steps = serde_json::to_value(&steps).expect("filled steps serialize");
        (steps, checks)
    });
    assert_eq!(
        filled,
        Ok((
            json!([
                {"step": "open", "url": FORM},
                {"step": "type", "ref": "e-field", "text": "plain value", "clear": false},
            ]),
            vec![ready()],
        ))
    );
}

#[test]
fn a_check_secret_arm_keeps_a_handle_and_moves_plain_text_to_its_value() {
    let kept = BTreeMap::from([("password".to_owned(), "sc1".to_owned())]);
    let filled = secret_check_program().fill(&kept).map(|(steps, checks)| {
        let steps = serde_json::to_value(&steps).expect("filled steps serialize");
        (steps, checks)
    });
    assert_eq!(
        filled,
        Ok((
            json!([{"step": "open", "url": FORM}]),
            vec![ExpectInput {
                target: Some("e-verify".to_owned()),
                secret: Some("sc1".to_owned()),
                ..Default::default()
            }],
        ))
    );
    let moved = BTreeMap::from([("password".to_owned(), "plain value".to_owned())]);
    let filled = secret_check_program().fill(&moved).map(|(steps, checks)| {
        let steps = serde_json::to_value(&steps).expect("filled steps serialize");
        (steps, checks)
    });
    assert_eq!(
        filled,
        Ok((
            json!([{"step": "open", "url": FORM}]),
            vec![ExpectInput {
                target: Some("e-verify".to_owned()),
                value: Some("plain value".to_owned()),
                ..Default::default()
            }],
        ))
    );
}
