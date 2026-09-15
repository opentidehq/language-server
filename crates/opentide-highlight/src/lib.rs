//! Frozen HighlightSpec and semantic-token encoding.
//!
//! Capture rename in `highlights/spec.toml` is a **major** (breaking) change.

use opentide_core::{ByteSpan, LanguageId, Range, span_to_range};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const SPEC_TOML: &str = include_str!("../../../highlights/spec.toml");
pub const KQL_HIGHLIGHTS_SCM: &str = include_str!("../../../highlights/queries/kql/highlights.scm");
pub const SPL_HIGHLIGHTS_SCM: &str = include_str!("../../../highlights/queries/spl/highlights.scm");
pub const TIDE_HIGHLIGHTS_SCM: &str =
    include_str!("../../../highlights/queries/tide/highlights.scm");

#[derive(Debug, Error)]
pub enum HighlightError {
    #[error("highlight spec: {0}")]
    Spec(String),
    #[error("unknown capture '{0}' (not in highlights/spec.toml)")]
    UnknownCapture(String),
}

#[derive(Debug, Clone, Deserialize)]
struct SpecFile {
    meta: SpecMeta,
    captures: BTreeMap<String, CaptureMaps>,
}

#[derive(Debug, Clone, Deserialize)]
struct SpecMeta {
    id: String,
    version: String,
    legend: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CaptureMaps {
    pub tm: String,
    pub monaco: String,
    pub helix: String,
}

#[derive(Debug, Clone)]
pub struct HighlightSpec {
    pub id: String,
    pub version: String,
    pub legend: Vec<String>,
    pub captures: BTreeMap<String, CaptureMaps>,
}

impl HighlightSpec {
    pub fn load() -> Result<Self, HighlightError> {
        let file: SpecFile =
            toml::from_str(SPEC_TOML).map_err(|e| HighlightError::Spec(e.to_string()))?;
        if file.meta.legend.is_empty() {
            return Err(HighlightError::Spec("empty legend".into()));
        }
        for name in &file.meta.legend {
            if !file.captures.contains_key(name) {
                return Err(HighlightError::Spec(format!(
                    "legend entry '{name}' has no [captures] maps"
                )));
            }
        }
        Ok(Self {
            id: file.meta.id,
            version: file.meta.version,
            legend: file.meta.legend,
            captures: file.captures,
        })
    }

    pub fn token_index(&self, capture: &str) -> Result<u32, HighlightError> {
        self.legend
            .iter()
            .position(|n| n == capture)
            .map(|i| i as u32)
            .ok_or_else(|| HighlightError::UnknownCapture(capture.to_string()))
    }

    pub fn contains_capture(&self, capture: &str) -> bool {
        self.captures.contains_key(capture)
    }
}

/// Extract `@capture` names from a tree-sitter highlights.scm file.
pub fn scm_captures(scm: &str) -> BTreeSet<String> {
    let re = Regex::new(r"@([A-Za-z][A-Za-z0-9_.]*)").expect("regex");
    re.captures_iter(scm)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

pub fn assert_scm_subset_of_spec(spec: &HighlightSpec, scm: &str) -> Result<(), HighlightError> {
    for capture in scm_captures(scm) {
        if !spec.contains_capture(&capture) {
            return Err(HighlightError::UnknownCapture(capture));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HighlightToken {
    pub span: ByteSpan,
    pub range: Range,
    pub capture: String,
    pub token_type: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighlightResult {
    pub language_id: String,
    pub tokens: Vec<HighlightToken>,
    pub legend: Vec<String>,
}

/// LSP semantic tokens (delta-encoded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticTokens {
    pub data: Vec<u32>,
    pub legend: Vec<String>,
}

pub fn encode_semantic_tokens(tokens: &[HighlightToken]) -> Vec<u32> {
    let mut data = Vec::with_capacity(tokens.len() * 5);
    let mut prev_line = 0u32;
    let mut prev_char = 0u32;
    for token in tokens {
        let line = token.range.start.line;
        let character = token.range.start.character;
        let delta_line = line.saturating_sub(prev_line);
        let delta_char = if delta_line == 0 {
            character.saturating_sub(prev_char)
        } else {
            character
        };
        let length = token
            .range
            .end
            .character
            .saturating_sub(token.range.start.character)
            .max(1);
        data.extend_from_slice(&[delta_line, delta_char, length, token.token_type, 0]);
        prev_line = line;
        prev_char = character;
    }
    data
}

pub fn tokens_from_spans(
    spec: &HighlightSpec,
    source: &str,
    spans: &[(ByteSpan, &str)],
) -> Result<Vec<HighlightToken>, HighlightError> {
    let mut out = Vec::with_capacity(spans.len());
    for (span, capture) in spans {
        let token_type = spec.token_index(capture)?;
        out.push(HighlightToken {
            span: *span,
            range: span_to_range(source, *span),
            capture: (*capture).to_string(),
            token_type,
        });
    }
    out.sort_by_key(|t| (t.span.start, t.token_type));
    Ok(out)
}

/// Generate TextMate / Monaco / Helix maps from the frozen spec.
pub fn generate_tm_language(language: LanguageId, spec: &HighlightSpec) -> serde_json::Value {
    let patterns: Vec<serde_json::Value> = spec
        .captures
        .iter()
        .map(|(name, maps)| {
            serde_json::json!({
                "name": maps.tm,
                "comment": format!("capture:{name}"),
            })
        })
        .collect();
    serde_json::json!({
        "scopeName": format!("source.{}", language.as_str()),
        "name": format!("OpenTide {}", language),
        "patterns": patterns,
        "opentideHighlightSpec": spec.version,
    })
}

pub fn generate_monaco(spec: &HighlightSpec) -> serde_json::Value {
    let token_map: BTreeMap<&String, &String> =
        spec.captures.iter().map(|(k, v)| (k, &v.monaco)).collect();
    serde_json::json!({
        "tokenLegend": spec.legend,
        "tokenMap": token_map,
    })
}

pub fn generate_helix(spec: &HighlightSpec) -> String {
    let mut out = String::from("# Generated from highlights/spec.toml — do not edit.\n");
    for (name, maps) in &spec.captures {
        out.push_str(&format!("\"{name}\" = \"{}\"\n", maps.helix));
    }
    out
}

pub fn generated_artifacts_stale(
    spec: &HighlightSpec,
    tm: &str,
    monaco: &str,
    helix: &str,
) -> Result<(), String> {
    let expected_tm = serde_json::to_string_pretty(&generate_tm_language(LanguageId::Kql, spec))
        .map_err(|e| e.to_string())?;
    let expected_monaco =
        serde_json::to_string_pretty(&generate_monaco(spec)).map_err(|e| e.to_string())?;
    let expected_helix = generate_helix(spec);
    if tm.trim() != expected_tm.trim() {
        return Err("generated tmLanguage is stale; run opentide-lsp generate-highlights".into());
    }
    if monaco.trim() != expected_monaco.trim() {
        return Err("generated monaco map is stale; run opentide-lsp generate-highlights".into());
    }
    if helix.trim() != expected_helix.trim() {
        return Err("generated helix map is stale; run opentide-lsp generate-highlights".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_loads_and_legend_matches_captures() {
        let spec = HighlightSpec::load().expect("spec");
        assert!(spec.legend.contains(&"keyword".to_string()));
        assert!(spec.contains_capture("tide.keyword"));
        assert!(spec.token_index("keyword").is_ok());
    }

    #[test]
    fn scm_captures_are_subset_of_spec() {
        let spec = HighlightSpec::load().unwrap();
        assert_scm_subset_of_spec(&spec, KQL_HIGHLIGHTS_SCM).unwrap();
        assert_scm_subset_of_spec(&spec, SPL_HIGHLIGHTS_SCM).unwrap();
        assert_scm_subset_of_spec(&spec, TIDE_HIGHLIGHTS_SCM).unwrap();
    }

    #[test]
    fn unknown_scm_capture_fails() {
        let spec = HighlightSpec::load().unwrap();
        let err = assert_scm_subset_of_spec(&spec, "(identifier) @not_a_real_capture").unwrap_err();
        match err {
            HighlightError::UnknownCapture(name) => assert_eq!(name, "not_a_real_capture"),
            other => panic!("{other}"),
        }
    }

    #[test]
    fn semantic_token_encoding_is_delta() {
        let spec = HighlightSpec::load().unwrap();
        let src = "where x";
        let tokens = tokens_from_spans(
            &spec,
            src,
            &[
                (ByteSpan::new(0, 5), "keyword"),
                (ByteSpan::new(6, 7), "variable"),
            ],
        )
        .unwrap();
        let data = encode_semantic_tokens(&tokens);
        assert_eq!(data.len(), 10);
        assert_eq!(data[0], 0);
        assert_eq!(data[5], 0); // same line
    }
}
