//! I/O-free analysis orchestrator. Filesystem lives behind [`WorkspaceHost`].

use opentide_core::{CompletionItem, Diagnostic, LanguageId, Position};
use opentide_highlight::{
    HighlightResult, HighlightSpec, HighlightToken, SemanticTokens, encode_lsp_semantic_tokens,
};
use opentide_kql::Profile;
use opentide_tide::{IndexedObject, TideAnalyzeResult};

/// Host-supplied workspace snapshot. The analysis crate never calls `std::fs`.
pub trait WorkspaceHost {
    fn document(&self, uri: &str) -> Option<String>;
    fn documents(&self) -> Vec<(String, String)>;
}

#[derive(Debug, Clone, Default)]
pub struct MemoryWorkspace {
    pub files: Vec<(String, String)>,
}

impl WorkspaceHost for MemoryWorkspace {
    fn document(&self, uri: &str) -> Option<String> {
        self.files
            .iter()
            .find(|(p, _)| p == uri)
            .map(|(_, s)| s.clone())
    }

    fn documents(&self) -> Vec<(String, String)> {
        self.files.clone()
    }
}

#[derive(Debug, Clone)]
pub struct AnalyzeRequest {
    pub uri: String,
    pub language: LanguageId,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct AnalyzeResponse {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
    pub symbols: Vec<opentide_tide::DocumentSymbol>,
}

pub fn index_workspace(host: &dyn WorkspaceHost) -> Vec<IndexedObject> {
    host.documents()
        .iter()
        .filter_map(|(path, src)| opentide_tide::index_object(path, src))
        .collect()
}

pub fn analyze(host: &dyn WorkspaceHost, request: AnalyzeRequest) -> AnalyzeResponse {
    let workspace = index_workspace(host);
    match request.language {
        LanguageId::Kql => {
            let r = opentide_kql::analyze(&request.text, Profile::Sentinel);
            AnalyzeResponse {
                diagnostics: r.diagnostics,
                tokens: r.tokens,
                symbols: Vec::new(),
            }
        }
        LanguageId::Spl => {
            let r = opentide_spl::analyze(&request.text);
            AnalyzeResponse {
                diagnostics: r.diagnostics,
                tokens: r.tokens,
                symbols: Vec::new(),
            }
        }
        LanguageId::TideYaml => {
            let r: TideAnalyzeResult = opentide_tide::analyze(opentide_tide::AnalyzeInput {
                path: &request.uri,
                source: &request.text,
                workspace: &workspace,
            });
            AnalyzeResponse {
                diagnostics: r.diagnostics,
                tokens: r.tokens,
                symbols: r.symbols,
            }
        }
    }
}

pub fn highlight(language: LanguageId, text: &str) -> HighlightResult {
    let host = MemoryWorkspace {
        files: vec![("memory".into(), text.to_string())],
    };
    let response = analyze(
        &host,
        AnalyzeRequest {
            uri: "memory".into(),
            language,
            text: text.to_string(),
        },
    );
    let spec = HighlightSpec::load().expect("spec");
    HighlightResult {
        language_id: language.as_str().to_string(),
        tokens: response.tokens,
        legend: spec.legend,
    }
}

pub fn semantic_tokens(language: LanguageId, text: &str) -> SemanticTokens {
    let result = highlight(language, text);
    SemanticTokens {
        data: encode_lsp_semantic_tokens(&result.tokens),
        legend: result.legend,
    }
}

pub fn hover(
    host: &dyn WorkspaceHost,
    language: LanguageId,
    text: &str,
    position: Position,
) -> Option<String> {
    match language {
        LanguageId::Kql => opentide_kql::hover(text, position, Profile::Sentinel),
        LanguageId::Spl => opentide_spl::hover(text, position),
        LanguageId::TideYaml => {
            let workspace = index_workspace(host);
            // UUID hover
            let offset = {
                let mut line = 0u32;
                let mut col = 0u32;
                let mut at = text.len();
                for (idx, ch) in text.char_indices() {
                    if line == position.line && col >= position.character {
                        at = idx;
                        break;
                    }
                    if ch == '\n' {
                        line += 1;
                        col = 0;
                    } else {
                        col += 1;
                    }
                }
                at
            };
            let window = text
                .get(offset.saturating_sub(40)..(offset + 40).min(text.len()))
                .unwrap_or("");
            let re = regex::Regex::new(
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            )
            .ok()?;
            let uuid = re.find(window)?.as_str();
            opentide_tide::definition(&workspace, uuid)
                .map(|o| format!("**{}** ({})\n\n`{}`", o.name, o.object_type, o.uuid))
        }
    }
}

pub fn completions(
    host: &dyn WorkspaceHost,
    language: LanguageId,
    text: &str,
    offset: usize,
) -> Vec<CompletionItem> {
    match language {
        LanguageId::Kql => opentide_kql::completions(text, offset, Profile::Sentinel),
        LanguageId::Spl => opentide_spl::completions(text, offset),
        LanguageId::TideYaml => {
            let workspace = index_workspace(host);
            let mut items = Vec::new();
            for (name, uuid) in opentide_tide::completions_for(&workspace, "objective") {
                items.push(CompletionItem {
                    label: name,
                    detail: Some(uuid),
                    kind: "reference".into(),
                });
            }
            for (name, uuid) in opentide_tide::completions_for(&workspace, "threat") {
                items.push(CompletionItem {
                    label: name,
                    detail: Some(uuid),
                    kind: "reference".into(),
                });
            }
            for (field, vocab) in opentide_tide::bundled_vocabs() {
                for key in vocab.keys {
                    items.push(CompletionItem {
                        label: key.name,
                        detail: Some(format!("{field} vocabulary")),
                        kind: "enum".into(),
                    });
                }
            }
            items
        }
    }
}

pub fn compiled_kql(text: &str, tenant: &str) -> String {
    opentide_kql::compile_kql_query(text, &[], tenant)
}

pub fn compiled_spl(text: &str) -> String {
    // Authored text is the compiled form; implicit `| search` is not rewritten.
    text.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_workspace_indexes_objects() {
        let host = MemoryWorkspace {
            files: vec![(
                "objects/rules/a.yaml".into(),
                "name: A\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\n".into(),
            )],
        };
        let idx = index_workspace(&host);
        assert_eq!(idx.len(), 1);
        assert_eq!(idx[0].object_type, "rule");
    }

    #[test]
    fn highlight_kql_returns_legend() {
        let h = highlight(LanguageId::Kql, "SecurityEvent | take 1");
        assert!(!h.legend.is_empty());
        assert!(!h.tokens.is_empty());
    }

    #[test]
    fn hover_and_completions_for_kql() {
        let host = MemoryWorkspace { files: vec![] };
        let items = completions(&host, LanguageId::Kql, "SecurityEvent | ", 16);
        assert!(items.iter().any(|i| i.label == "where"));
        let h = hover(
            &host,
            LanguageId::Kql,
            "SecurityEvent | where EventID == 1",
            Position::new(0, 16),
        );
        assert!(h.unwrap().contains("where"));
    }
}
