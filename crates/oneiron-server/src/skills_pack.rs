use serde::Serialize;

pub(crate) const ARTIFACT_PATH: &str = "oneiron.skills.md";
const MEDIA_TYPE: &str = "text/markdown; profile=agentskills.io";
const CONTENT: &str = include_str!("../../../oneiron.skills.md");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutputMode {
    Markdown,
    Json,
    Path,
}

#[derive(Serialize)]
struct JsonEnvelope<'a> {
    artifact_path: &'static str,
    media_type: &'static str,
    bytes: usize,
    content: &'a str,
}

pub(crate) fn render(mode: OutputMode) -> anyhow::Result<String> {
    match mode {
        OutputMode::Markdown => Ok(CONTENT.to_owned()),
        OutputMode::Path => Ok(format!("{ARTIFACT_PATH}\n")),
        OutputMode::Json => {
            let envelope = JsonEnvelope {
                artifact_path: ARTIFACT_PATH,
                media_type: MEDIA_TYPE,
                bytes: CONTENT.len(),
                content: CONTENT,
            };
            Ok(format!("{}\n", serde_json::to_string_pretty(&envelope)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_markdown_output_is_committed_skills_pack() {
        assert_eq!(render(OutputMode::Markdown).unwrap(), CONTENT);
        assert!(CONTENT.starts_with("---\nname: oneiron-http-memory-api"));
    }

    #[test]
    fn path_output_names_committed_artifact() {
        assert_eq!(render(OutputMode::Path).unwrap(), "oneiron.skills.md\n");
    }

    #[test]
    fn json_output_wraps_pack_without_drift() {
        let output = render(OutputMode::Json).unwrap();
        let envelope: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(envelope["artifact_path"], ARTIFACT_PATH);
        assert_eq!(envelope["media_type"], MEDIA_TYPE);
        assert_eq!(envelope["bytes"], CONTENT.len());
        assert_eq!(envelope["content"], CONTENT);
    }
}
