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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn agent_authored_v1_recipe_runs_with_host_facts() {
        let recipe: CodeConsentRecipe = serde_json::from_str(include_str!(
            "../../../../../examples/code-review/consent-recipe-v1.json"
        ))
        .unwrap();
        let mut request = CodeConsentRequest {
            blast_radius: BlastRadiusWalk {
                reached_symbols: 12,
                reached_entities: 8,
                max_depth: 3,
            },
            risk_summary: None,
        };
        let vars = BTreeMap::from([
            ("purpose".into(), "rename a function".into()),
            ("writes".into(), "src/lib.rs".into()),
            ("egress".into(), "none declared".into()),
            (
                "side_channels".into(),
                "timing and undeclared egress".into(),
            ),
        ]);
        recipe.explain(&mut request, &vars).unwrap();
        let ask = request.ask("Review?");
        let facts: serde_json::Value =
            serde_json::from_str(ask.prompt.lines().last().unwrap()).unwrap();
        assert_eq!(facts["reached_symbols"], 12);
        assert_eq!(facts["risk_summary"], request.risk_summary.unwrap());
        assert!(
            recipe
                .explain(
                    &mut CodeConsentRequest {
                        blast_radius: request.blast_radius,
                        risk_summary: None
                    },
                    &BTreeMap::new()
                )
                .is_err()
        );
    }
}
