//! The model licence admission under the owner's choice
//! (`models.install.allow_noncommercial_licences`), read the way every model install reads it,
//! for `tests/model_licence_owner_key.rs`.

use std::borrow::Cow;

use crate::model_artifacts::licence::{LicencePolicy, LicenceTerms, admit_terms};

/// The class a download of a model whose card declares `licence_id` (and, for a conditional
/// licence, names `decision`) is admitted as under `vault`'s owner choice, read now; or the
/// refusal's text.
///
/// # Errors
///
/// The refusal's text, as the install would report it.
pub fn admit_licence(
    vault: &oneiron::Vault,
    licence_id: &str,
    decision: Option<&str>,
) -> Result<&'static str, String> {
    let terms = LicenceTerms {
        id: Cow::Owned(licence_id.to_owned()),
        file: Cow::Borrowed("LICENSE"),
        decision: decision.map(|decision| Cow::Owned(decision.to_owned())),
    };
    admit_terms("door/model", &terms, LicencePolicy::for_vault(vault))
        .map(|class| class.as_str())
        .map_err(|error| error.to_string())
}
