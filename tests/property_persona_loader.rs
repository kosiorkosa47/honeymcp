//! Property: the persona YAML loader returns `Result::Err` for any
//! malformed input rather than panicking.
//!
//! Why: an operator who misconfigures their persona file (typo, partial
//! download, wrong YAML version) must get a clear error at startup, not
//! a panic that kills the supervisor a thousand restarts later.

use honeymcp::persona::Persona;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Arbitrary UTF-8 fed straight into serde_yaml. We don't care
    /// whether anything parses — we care that nothing panics.
    #[test]
    fn arbitrary_yaml_never_panics(s in ".{0,4096}") {
        let _ = serde_yaml::from_str::<Persona>(&s);
    }

    /// YAML structures shaped like a persona but with random field
    /// values. These hit the deserializer's per-field code paths in a
    /// way the corpus-shaped test cases above don't.
    #[test]
    fn persona_shaped_yaml_never_panics(
        name in "[a-z0-9-]{0,64}",
        version in ".{0,32}",
        instructions in ".{0,1024}",
        tool_count in 0usize..32,
    ) {
        let mut yaml = format!("name: \"{}\"\nversion: \"{}\"\ninstructions: \"{}\"\ntools:\n",
            name.replace('"', ""),
            version.replace('"', ""),
            instructions.replace('"', "").replace('\n', " "),
        );
        for i in 0..tool_count {
            yaml.push_str(&format!(
                "  - name: \"tool_{}\"\n    description: \"d\"\n    inputSchema:\n      type: object\n    response: \"r\"\n",
                i,
            ));
        }
        let _ = serde_yaml::from_str::<Persona>(&yaml);
    }
}
