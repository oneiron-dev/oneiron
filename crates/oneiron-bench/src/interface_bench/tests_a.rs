//! Taskgen, config, and memo tests.

#[cfg(test)]
pub(crate) mod tests {
    use super::super::*;
    use std::collections::BTreeMap;

    pub(crate) fn pinned_settings(allowed: &str) -> RunSettings {
        let config = parse_pinned_model_config(allowed).expect("valid pinned config parses");
        let model = pinned_model_for_wire_id(&config, MODEL).expect("covered wire id");
        RunSettings {
            pinned: Some(PinnedRun {
                config,
                wire_models: BTreeMap::from([(MODEL.to_owned(), model)]),
            }),
            ..RunSettings::default()
        }
    }
}
