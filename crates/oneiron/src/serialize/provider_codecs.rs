//! Provider read formats share prepared rows and always null credential-bearing fields.
use serde_json::{Value,json};
use super::pack_entry::PreparedPack;
use crate::context_pack::PackFormat;

pub(super) fn serialize_provider(format: PackFormat, prepared: PreparedPack) -> Vec<u8> {
    let rows=prepared.results.into_iter().chain(prepared.neighbors).flat_map(|(_,rows)|rows);
    let mut messages=Vec::new();
    for row in rows {
        let mut fields=serde_json::Map::from_iter(row.fields);
        if row.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
            fields.values_mut().for_each(|v|*v=Value::Null);
        } else { fields.iter_mut().for_each(|(key,value)|scrub(key,value)); }
        let text=Value::Object(fields).to_string();
        messages.push(match format {
            PackFormat::Gemini=>json!({"role":"user","parts":[{"text":text}]}),
            PackFormat::AnthropicMessages=>json!({"role":"user","content":[{"type":"text","text":text}]}),
            _=>json!({"role":"user","content":text}),
        });
    }
    let body=if format==PackFormat::Gemini {json!({"contents":messages,"secrets_nulled":true})} else {json!({"messages":messages,"secrets_nulled":true})};
    serde_json::to_vec(&body).expect("provider value is serializable")
}
fn scrub(key:&str,value:&mut Value) {
    let lower=key.to_ascii_lowercase();
    if ["secret","password","credential","api_key","access_token","refresh_token","authorization"].iter().any(|needle|lower.contains(needle)) {
        *value=Value::Null;return;
    }
    match value {
        Value::String(text) if crate::batch::secret_scan::scan_file_content("provider-export", text.as_bytes()).is_some()=>*value=Value::Null,
        Value::Array(values)=>values.iter_mut().for_each(|v|scrub("",v)),
        Value::Object(values)=>values.iter_mut().for_each(|(k,v)|scrub(k,v)),
        _=>{}
    }
}


pub(super) fn sanitize_pack(pack: &crate::context_pack::ContextPack) -> crate::context_pack::ContextPack {
    let mut sanitized=pack.clone();
    for entity in sanitized.results.iter_mut().chain(sanitized.neighbors.iter_mut()) {
        if let Some(fields)=entity.fields.as_mut() {
            if entity.entity_type==crate::registry::ENTITY_TYPE_SECRET_CUSTODY { fields.values_mut().for_each(|v|*v=Value::Null); }
            else { fields.iter_mut().for_each(|(key,value)|scrub(key,value)); }
        }
    }
    sanitized
}
