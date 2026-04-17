//! Persona engine. A persona is a YAML file describing how the honeypot should present itself
//! to an attacking client — server name, version, instructions, and a list of fake tools with
//! canned responses.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

use crate::protocol::{ServerInfo, Tool, ToolContent};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Persona {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub instructions: Option<String>,
    pub tools: Vec<PersonaTool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonaTool {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// JSON Schema for tool inputs, passed through verbatim to `tools/list`.
    #[serde(rename = "inputSchema", default = "default_input_schema")]
    pub input_schema: Value,
    /// Canned response text returned from `tools/call`.
    pub response: String,
}

fn default_input_schema() -> Value {
    serde_json::json!({"type": "object", "properties": {}})
}

impl Persona {
    pub fn from_yaml_str(s: &str) -> Result<Self> {
        let p: Persona = serde_yaml::from_str(s).context("parsing persona YAML")?;
        p.validate()?;
        Ok(p)
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("reading persona file {}", path.display()))?;
        Self::from_yaml_str(&body)
    }

    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(anyhow!("persona.name must not be empty"));
        }
        if self.version.trim().is_empty() {
            return Err(anyhow!("persona.version must not be empty"));
        }
        let mut seen: HashMap<&str, ()> = HashMap::new();
        for t in &self.tools {
            if t.name.trim().is_empty() {
                return Err(anyhow!("persona tool name must not be empty"));
            }
            if seen.insert(t.name.as_str(), ()).is_some() {
                return Err(anyhow!("duplicate tool name in persona: {}", t.name));
            }
        }
        Ok(())
    }

    pub fn server_info(&self) -> ServerInfo {
        ServerInfo {
            name: self.name.clone(),
            version: self.version.clone(),
        }
    }

    pub fn mcp_tools(&self) -> Vec<Tool> {
        self.tools
            .iter()
            .map(|t| Tool {
                name: t.name.clone(),
                description: t.description.clone(),
                input_schema: t.input_schema.clone(),
            })
            .collect()
    }

    /// Look up the canned response for a given tool name.
    pub fn response_for(&self, tool_name: &str) -> Option<ToolContent> {
        self.tools
            .iter()
            .find(|t| t.name == tool_name)
            .map(|t| ToolContent::Text {
                text: t.response.clone(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
name: "postgres-admin"
version: "15.4"
instructions: "Postgres admin tools"
tools:
  - name: "query"
    description: "Run SQL"
    inputSchema:
      type: object
      properties:
        sql:
          type: string
    response: "rows=0"
  - name: "list_tables"
    response: "users\norders"
"#;

    #[test]
    fn loads_valid_persona() {
        let p = Persona::from_yaml_str(SAMPLE).unwrap();
        assert_eq!(p.name, "postgres-admin");
        assert_eq!(p.tools.len(), 2);
        assert_eq!(p.mcp_tools()[0].name, "query");
    }

    #[test]
    fn rejects_duplicate_tool_names() {
        let bad = r#"
name: x
version: "1"
tools:
  - name: a
    response: r
  - name: a
    response: r
"#;
        let e = Persona::from_yaml_str(bad).unwrap_err();
        assert!(e.to_string().contains("duplicate"));
    }

    #[test]
    fn response_for_returns_text_content() {
        let p = Persona::from_yaml_str(SAMPLE).unwrap();
        match p.response_for("list_tables") {
            Some(ToolContent::Text { text }) => assert_eq!(text, "users\norders"),
            _ => panic!("expected text content"),
        }
        assert!(p.response_for("nonexistent").is_none());
    }
}
