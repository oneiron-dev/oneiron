//! FIX-LIST line 212: the `UNAUTHORIZED` suggestion named only the bearer
//! (`Authorization: Bearer`) and omitted the fresh `x-oneiron-binding`
//! holder proof every protected request must carry, so a client that
//! followed the hint alone was refused again. The suggestion now names both.

use oneiron_server::error::ApiError;

#[test]
fn unauthorized_suggestion_names_the_binding_holder_proof() {
    let error = ApiError::unauthorized();
    let suggestions = error.suggestions();
    assert!(
        suggestions
            .iter()
            .any(|suggestion| suggestion.contains("x-oneiron-binding")),
        "the suggestion must name the binding proof, got: {suggestions:?}"
    );
    assert!(
        suggestions
            .iter()
            .any(|suggestion| suggestion.contains("fresh")),
        "the suggestion must say the proof is fresh, got: {suggestions:?}"
    );
}

#[test]
fn unauthorized_suggestion_still_names_the_bearer() {
    let error = ApiError::unauthorized();
    let suggestions = error.suggestions();
    assert!(
        suggestions
            .iter()
            .any(|suggestion| suggestion.contains("Authorization: Bearer")),
        "the suggestion must keep naming the bearer, got: {suggestions:?}"
    );
}
