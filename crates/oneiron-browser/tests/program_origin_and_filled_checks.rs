//! These tests hold the plain origin and check-filling rules
//! (FIX [BROWSER-LIBRARY-PLAIN-FUNCTIONS-HELD-BY-NO-TEST]).
//! They use the driver feature's public value helpers without starting a browser or a store.
#![cfg(feature = "driver")]

use oneiron_browser::{
    BatchStep, BrowserError, ExpectInput, LibraryRunInput, SecretArg, SecretKind, SecretParam,
    WorkflowProgram, filled_checks, program_origin,
};
use std::collections::BTreeMap;

/// A program whose opening is determined by the supplied batch.
fn program(steps: Vec<BatchStep>) -> WorkflowProgram {
    WorkflowProgram {
        subgoal: "Verify the form".to_owned(),
        params: vec![],
        secret_params: vec![],
        steps,
        postcondition: vec![ExpectInput {
            name: Some("Ready".to_owned()),
            ..Default::default()
        }],
    }
}

/// An opening with the given URL as its input.
fn open(url: &str) -> BatchStep {
    BatchStep::Open {
        url: url.to_owned(),
    }
}

/// A form program with a lone secret slot in its check.
fn secret_check_program() -> WorkflowProgram {
    WorkflowProgram {
        params: vec!["password".to_owned()],
        secret_params: vec![SecretParam {
            name: "password".to_owned(),
            kind: SecretKind::Password,
        }],
        postcondition: vec![ExpectInput {
            target: Some("e-field".to_owned()),
            secret: Some("{{ password }}".to_owned()),
            ..Default::default()
        }],
        ..program(vec![open("https://shop.example/form")])
    }
}

/// A run with a typed password argument and no plain arguments.
fn run_input(password: SecretArg) -> LibraryRunInput {
    LibraryRunInput {
        workflow: "verify-form".to_owned(),
        args: BTreeMap::new(),
        base: None,
        mode: None,
        secret_args: BTreeMap::from([("password".to_owned(), password)]),
    }
}

#[test]
fn the_opening_origin_normalizes_the_host_and_omits_only_the_default_port() {
    for (url, origin) in [
        (
            "HTTPS://Shop.Example:443/form?q=item#ready",
            "https://shop.example",
        ),
        ("http://Shop.Example:8443/form", "http://shop.example:8443"),
    ] {
        let program = program(vec![open(url), open("https://other.example/form")]);
        assert_eq!(program_origin(&program), Some(origin.to_owned()), "{url}");
    }
}

#[test]
fn an_origin_requires_an_opening_as_the_first_step() {
    assert_eq!(program_origin(&program(vec![])), None);

    let program = program(vec![
        BatchStep::Click {
            target: "e-button".to_owned(),
        },
        open("https://shop.example/form"),
    ]);
    assert_eq!(program_origin(&program), None);
}

#[test]
fn an_unparseable_url_or_an_opaque_origin_gives_no_program_origin() {
    for url in ["not a URL", "about:blank"] {
        assert_eq!(program_origin(&program(vec![open(url)])), None, "{url}");
    }
}

#[test]
fn checks_fill_plain_and_typed_arguments_with_typed_values_taking_precedence() {
    let program = WorkflowProgram {
        params: vec!["heading".to_owned(), "password".to_owned()],
        postcondition: vec![ExpectInput {
            target: Some("e-field".to_owned()),
            name: Some("{{heading}}".to_owned()),
            secret: Some("{{password}}".to_owned()),
            ..Default::default()
        }],
        ..secret_check_program()
    };
    let input = LibraryRunInput {
        args: BTreeMap::from([
            ("heading".to_owned(), "Password".to_owned()),
            ("password".to_owned(), "plain fallback".to_owned()),
        ]),
        ..run_input(SecretArg::Text("typed value".to_owned()))
    };
    assert_eq!(
        filled_checks(&program, &input),
        Ok(vec![ExpectInput {
            target: Some("e-field".to_owned()),
            name: Some("Password".to_owned()),
            value: Some("typed value".to_owned()),
            ..Default::default()
        }]),
    );
}

#[test]
fn a_typed_handle_that_names_no_handle_is_refused() {
    let input = run_input(SecretArg::Handle("sc12:abc".to_owned()));
    assert_eq!(
        filled_checks(&secret_check_program(), &input),
        Err(BrowserError::Input(
            "the secret argument password's handle names no handle".to_owned(),
        )),
    );
}

#[test]
fn a_typed_text_argument_fills_the_check_value_even_if_it_looks_like_a_handle() {
    let program = secret_check_program();
    for text in ["plain value", "sc12"] {
        let input = run_input(SecretArg::Text(text.to_owned()));
        assert_eq!(
            filled_checks(&program, &input),
            Ok(vec![ExpectInput {
                target: Some("e-field".to_owned()),
                value: Some(text.to_owned()),
                ..Default::default()
            }]),
            "{text}",
        );
    }
}

#[test]
fn a_typed_handle_fills_the_secret_arm_instead_of_the_check_value() {
    let input = run_input(SecretArg::Handle("sc12:ab".to_owned()));
    assert_eq!(
        filled_checks(&secret_check_program(), &input),
        Ok(vec![ExpectInput {
            target: Some("e-field".to_owned()),
            secret: Some("sc12:ab".to_owned()),
            ..Default::default()
        }]),
    );
}
