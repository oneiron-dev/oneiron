//! Configured consent explanation. No policy or prompt prose is compiled in.
use super::*;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeConsentRecipe {
    pub version: u32,
    pub template: String,
}
impl CodeConsentRecipe {
    /// Host facts always override similarly named caller variables. Unknown
    /// variables refuse rather than silently dropping an omitted risk fact.
    pub fn explain(
        &self,
        request: &mut CodeConsentRequest,
        supplied: &BTreeMap<String, String>,
    ) -> Result<()> {
        if self.version != 1 || self.template.len() > 16384 {
            return Err(Error::InvalidClaimBody("invalid consent recipe"));
        }
        let mut variables = supplied.clone();
        variables.insert(
            "reached_symbols".into(),
            request.blast_radius.reached_symbols.to_string(),
        );
        variables.insert(
            "reached_entities".into(),
            request.blast_radius.reached_entities.to_string(),
        );
        variables.insert(
            "max_depth".into(),
            request.blast_radius.max_depth.to_string(),
        );
        let mut rest = self.template.as_str();
        let mut output = String::new();
        while let Some(start) = rest.find('{') {
            output.push_str(&rest[..start]);
            let end = rest[start..]
                .find('}')
                .map(|i| i + start)
                .ok_or(Error::InvalidClaimBody("unclosed consent variable"))?;
            let value = variables
                .get(&rest[start + 1..end])
                .ok_or(Error::InvalidClaimBody("missing consent variable"))?;
            if value.len() > 16384 {
                return Err(Error::InvalidClaimBody("oversize consent variable"));
            }
            output.push_str(value);
            rest = &rest[end + 1..];
        }
        output.push_str(rest);
        request.risk_summary = Some(output);
        Ok(())
    }
}
