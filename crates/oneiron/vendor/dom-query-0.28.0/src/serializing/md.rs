mod constants;
mod ext;
mod serializer;
mod text_utils;

use tendril::StrTendril;

use crate::node::NodeRef;

pub fn serialize_md(
    root_node: &NodeRef,
    include_node: bool,
    skip_tags: Option<&[&str]>,
) -> StrTendril {
    serializer::MDSerializer::new(root_node, skip_tags).serialize(include_node)
}
