/// Top-level body keys, or form fields, that pick the model or the route by
/// another way than the one selector: a fallback list, a route or a provider
/// preference.
pub(crate) const ROUTE_OVERRIDES: [&str; 3] = ["models", "route", "provider"];
