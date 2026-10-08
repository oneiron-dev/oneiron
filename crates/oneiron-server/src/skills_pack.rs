use serde::Serialize;

pub(crate) const ARTIFACT_PATH: &str = "oneiron.skills.md";
pub(crate) const MEDIA_TYPE: &str = "text/markdown; profile=agentskills.io";
pub(crate) const CONTENT: &str = include_str!("../oneiron.skills.md");

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
