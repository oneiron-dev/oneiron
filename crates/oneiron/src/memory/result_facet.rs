/// One of a result's `more` facets: a deterministic read of its body.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ResultFacet {
    /// A range of the body, by bytes or by lines.
    Slice,
    /// The matches of a literal or a regex, with their lines and context.
    Search,
    /// Values picked by a JSON path, or rows of a line table.
    Query,
    /// The body cut into range refs, a page at a time.
    Chunks,
}

impl ResultFacet {
    /// Every facet, in the order a card lists them.
    pub const ALL: [Self; 4] = [Self::Slice, Self::Search, Self::Query, Self::Chunks];

    /// The facet a call names.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|facet| facet.as_str() == name)
    }

    /// The facet's name, as a program calls it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Slice => "slice",
            Self::Search => "search",
            Self::Query => "query",
            Self::Chunks => "chunks",
        }
    }
}
