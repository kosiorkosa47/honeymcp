//! Persona engine. A persona is a YAML file describing how the honeypot should present itself
//! to an attacking client — server name, version, instructions, and a list of fake tools with
//! canned responses.

use anyhow::{anyhow, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::{Arc, OnceLock};

use crate::protocol::{ServerInfo, Tool, ToolContent};

/// Flat map of canary token name -> value, substituted into persona responses
/// wherever the YAML references `{{canary.<name>}}`. Loaded from a gitignored
/// `canaries.yaml` (see `canaries.example.yaml`). Empty is fine: unresolved
/// placeholders fall back to deterministic realistic fakes so the honeypot
/// still presents credible output, it just loses the second-stage "the key
/// was used" alert that a real Thinkst canary provides.
pub type CanaryMap = HashMap<String, String>;

#[derive(Debug, Deserialize)]
struct CanaryFile {
    #[serde(default)]
    canary: CanaryMap,
}

/// Load a canary map from a YAML file with a top-level `canary:` table.
pub fn load_canaries<P: AsRef<Path>>(path: P) -> Result<CanaryMap> {
    let path = path.as_ref();
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("reading canaries file {}", path.display()))?;
    let f: CanaryFile = serde_yaml::from_str(&body).context("parsing canaries YAML")?;
    Ok(f.canary)
}

/// Resolve canaries from, in order: an explicit `--canaries` path, then
/// `$HONEYMCP_CANARIES`, then `./canaries.yaml` if it exists. Returns an
/// empty map (with a warning logged by the caller) when none are found.
pub fn load_canaries_default(explicit: Option<&Path>) -> Result<CanaryMap> {
    if let Some(p) = explicit {
        return load_canaries(p);
    }
    if let Ok(env_path) = std::env::var("HONEYMCP_CANARIES") {
        return load_canaries(env_path);
    }
    let default = Path::new("canaries.yaml");
    if default.exists() {
        return load_canaries(default);
    }
    Ok(CanaryMap::new())
}

fn template_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // {{canary.name}} or {{arg.name}} — names are [a-zA-Z0-9_], optional
        // surrounding whitespace tolerated.
        Regex::new(r"\{\{\s*(canary|arg)\.([a-zA-Z0-9_]+)\s*\}\}").expect("template regex")
    })
}

/// Deterministic, realistic-looking fake for a canary placeholder that has no
/// real value configured. Keyed on the placeholder name so the same name
/// always yields the same fake within and across runs (DefaultHasher uses a
/// fixed seed), which keeps a session's responses internally consistent.
fn fallback_canary(name: &str) -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    name.hash(&mut h);
    let seed = h.finish();
    let lower = name.to_ascii_lowercase();
    if lower.contains("region") {
        return "us-east-1".to_string();
    }
    // "secret" is checked before the access-key branch because names like
    // "aws_secret_access_key" contain "access_key" but should render as a
    // secret blob, not an AKIA id.
    if lower.contains("secret") {
        // 40-char base64-ish secret.
        const ALPH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        let mut s = seed ^ 0x9E3779B97F4A7C15;
        for _ in 0..40 {
            out.push(ALPH[(s % ALPH.len() as u64) as usize] as char);
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
        }
        return out;
    }
    if lower.ends_with("akid") || lower.contains("access_key") || lower.contains("akid") {
        // AWS access key ids are "AKIA" + 16 uppercase base32-ish chars.
        const ALPH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out = String::from("AKIA");
        let mut s = seed;
        for _ in 0..16 {
            out.push(ALPH[(s % ALPH.len() as u64) as usize] as char);
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
        }
        return out;
    }
    "REDACTED".to_string()
}

/// Render a persona response template, substituting `{{canary.x}}` from the
/// canary map (falling back to a realistic fake) and `{{arg.x}}` from the
/// attacker-supplied tool-call arguments (echoing their own input back makes
/// responses feel live and pulls intent into the params we log anyway).
pub fn render_response(template: &str, args: &Value, canaries: &CanaryMap) -> String {
    template_re()
        .replace_all(template, |caps: &regex::Captures| {
            let kind = &caps[1];
            let name = &caps[2];
            match kind {
                "canary" => canaries
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| fallback_canary(name)),
                "arg" => match args.get(name) {
                    Some(Value::String(s)) => s.clone(),
                    Some(other) => other.to_string(),
                    None => String::new(),
                },
                _ => caps[0].to_string(),
            }
        })
        .into_owned()
}

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

    /// Look up the response for a tool name and render its template against the
    /// attacker-supplied `arguments` and the configured canary map. Templates
    /// without any `{{...}}` markers render to their literal text, so existing
    /// static personas are unaffected.
    pub fn response_for(
        &self,
        tool_name: &str,
        args: &Value,
        canaries: &CanaryMap,
    ) -> Option<ToolContent> {
        self.tools
            .iter()
            .find(|t| t.name == tool_name)
            .map(|t| ToolContent::Text {
                text: render_response(&t.response, args, canaries),
            })
    }
}

/// A routed collection of personas served by a single process. The transport
/// maps a URL path segment to a key here: `/<key>/mcp` selects that persona,
/// while bare `/mcp` (no segment) resolves to the default. One process, one
/// database, one dashboard — every event is tagged with the persona that
/// served it so the timeline stays multi-persona aware.
#[derive(Clone, Debug)]
pub struct PersonaSet {
    personas: HashMap<String, Arc<Persona>>,
    default_key: String,
}

impl PersonaSet {
    /// Build from `(key, persona)` pairs with an explicit default key. Errors
    /// on an empty set or a default key that isn't present.
    pub fn new(entries: Vec<(String, Persona)>, default_key: String) -> Result<Self> {
        if entries.is_empty() {
            return Err(anyhow!("persona set must contain at least one persona"));
        }
        let personas: HashMap<String, Arc<Persona>> =
            entries.into_iter().map(|(k, p)| (k, Arc::new(p))).collect();
        if !personas.contains_key(&default_key) {
            return Err(anyhow!("default persona key {default_key:?} not in set"));
        }
        Ok(Self {
            personas,
            default_key,
        })
    }

    /// Single-persona set: the persona is the only entry and the default. Its
    /// route key is the persona name. Keeps single-persona callers and the
    /// stdio transport (which has no routing) trivial.
    pub fn single(persona: Persona) -> Self {
        let key = persona.name.clone();
        let mut personas = HashMap::new();
        personas.insert(key.clone(), Arc::new(persona));
        Self {
            personas,
            default_key: key,
        }
    }

    /// Resolve a route key to a persona, falling back to the default for an
    /// unknown or absent key. Unknown keys deliberately serve the default
    /// rather than 404 — a scanner probing `/random/mcp` still gets a live
    /// honeypot face.
    pub fn resolve(&self, key: Option<&str>) -> &Arc<Persona> {
        key.and_then(|k| self.personas.get(k))
            .unwrap_or_else(|| &self.personas[&self.default_key])
    }

    /// The persona served at bare `/mcp`. Used for the `/stats` + dashboard
    /// server-identity card.
    pub fn default_persona(&self) -> &Arc<Persona> {
        &self.personas[&self.default_key]
    }

    pub fn default_key(&self) -> &str {
        &self.default_key
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.personas.keys().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.personas.len()
    }

    pub fn is_empty(&self) -> bool {
        self.personas.is_empty()
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
        let canaries = CanaryMap::new();
        match p.response_for("list_tables", &Value::Null, &canaries) {
            Some(ToolContent::Text { text }) => assert_eq!(text, "users\norders"),
            _ => panic!("expected text content"),
        }
        assert!(p
            .response_for("nonexistent", &Value::Null, &canaries)
            .is_none());
    }

    #[test]
    fn render_substitutes_canary_and_arg_placeholders() {
        let mut canaries = CanaryMap::new();
        canaries.insert("aws_file_akid".into(), "AKIAREAL01".into());
        let args = serde_json::json!({"role_arn": "arn:aws:iam::1234:role/admin"});
        let tmpl = "key={{canary.aws_file_akid}} role={{ arg.role_arn }} miss={{arg.nope}}";
        let out = render_response(tmpl, &args, &canaries);
        assert_eq!(
            out,
            "key=AKIAREAL01 role=arn:aws:iam::1234:role/admin miss="
        );
    }

    #[test]
    fn render_falls_back_to_realistic_fake_for_unconfigured_canary() {
        let canaries = CanaryMap::new();
        let out = render_response("{{canary.aws_secret_access_key}}", &Value::Null, &canaries);
        // Fallback secret is a 40-char base64-ish blob, deterministic per name.
        assert_eq!(out.len(), 40);
        assert_eq!(
            out,
            render_response("{{canary.aws_secret_access_key}}", &Value::Null, &canaries),
            "fallback must be deterministic"
        );
        let akid = render_response("{{canary.aws_file_akid}}", &Value::Null, &canaries);
        assert!(akid.starts_with("AKIA") && akid.len() == 20, "got {akid}");
        let region = render_response("{{canary.aws_default_region}}", &Value::Null, &canaries);
        assert_eq!(region, "us-east-1");
    }

    #[test]
    fn render_leaves_plain_text_untouched() {
        let canaries = CanaryMap::new();
        assert_eq!(
            render_response("no markers here", &Value::Null, &canaries),
            "no markers here"
        );
    }

    #[test]
    fn loads_canary_map_from_yaml() {
        let yaml = "canary:\n  aws_file_akid: \"AKIATEST\"\n  aws_file_region: \"eu-west-1\"\n";
        let f: CanaryFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(f.canary.get("aws_file_akid").unwrap(), "AKIATEST");
        assert_eq!(f.canary.get("aws_file_region").unwrap(), "eu-west-1");
    }

    fn persona(name: &str) -> Persona {
        Persona::from_yaml_str(&format!(
            "name: {name}\nversion: \"1\"\ntools:\n  - name: t\n    response: r\n"
        ))
        .unwrap()
    }

    #[test]
    fn persona_set_resolves_key_and_falls_back_to_default() {
        let set = PersonaSet::new(
            vec![
                ("aws".into(), persona("aws-admin")),
                ("github".into(), persona("github-admin")),
            ],
            "aws".into(),
        )
        .unwrap();
        assert_eq!(set.resolve(Some("github")).name, "github-admin");
        assert_eq!(set.resolve(Some("aws")).name, "aws-admin");
        // Unknown key and None both resolve to the default persona.
        assert_eq!(set.resolve(Some("nope")).name, "aws-admin");
        assert_eq!(set.resolve(None).name, "aws-admin");
        assert_eq!(set.default_persona().name, "aws-admin");
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn persona_set_single_is_its_own_default() {
        let set = PersonaSet::single(persona("solo"));
        assert_eq!(set.default_key(), "solo");
        assert_eq!(set.resolve(None).name, "solo");
        assert_eq!(set.resolve(Some("anything")).name, "solo");
    }

    #[test]
    fn persona_set_rejects_missing_default_key() {
        let e = PersonaSet::new(vec![("a".into(), persona("a"))], "b".into()).unwrap_err();
        assert!(e.to_string().contains("default persona key"));
    }
}
