//! I/O-free engine for the Lucene classic query syntax, as Elasticsearch's
//! `query_string` reads it (Elastic Security rules with `language: lucene`).
//!
//! Boolean operators are upper case only: a lower-case `and` between two
//! clauses is a search term, so the clause list silently widens. Clauses have
//! no precedence (`a OR b AND c` is `a +b +c`), escapes are dropped one
//! backslash at a time, and a tab or newline inside a range glues tokens.
//! Those are the checks this engine adds after the grammar.

use opentide_core::{
    ByteSpan, CompletionItem, Diagnostic, LanguageId, Position, Range, codes, span_to_range,
};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use opentide_syntax::{first_error, node_span, parse as ts_parse};
use tree_sitter::Node;

const SYNTAX_DOCS: &str = "https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query#query-string-syntax";

pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
}

pub fn analyze(source: &str) -> AnalyzeResult {
    let spec = HighlightSpec::load().expect("highlight spec");
    let Some(tree) = ts_parse(LanguageId::Lucene, source) else {
        return AnalyzeResult {
            diagnostics: vec![Diagnostic::error(
                codes::LUCENE_PARSE_ERROR,
                "failed to initialize the Lucene parser",
                Range::point(0, 0),
            )],
            tokens: Vec::new(),
        };
    };
    let root = tree.root_node();
    let mut diagnostics = Vec::new();
    if let Some(err) = first_error(root) {
        let message = if err.is_missing() {
            format!("Lucene syntax error: missing `{}`", err.kind())
        } else {
            match text(err, source).split_whitespace().next() {
                Some(first) => format!("Lucene syntax error near `{first}`"),
                None => "Lucene syntax error".into(),
            }
        };
        diagnostics.push(Diagnostic::error(
            codes::LUCENE_PARSE_ERROR,
            message,
            range(source, node_span(err)),
        ));
    }
    walk(root, &mut |node| match node.kind() {
        "boolean_query" => {
            lowercase_operators(node, source, &mut diagnostics);
            mixed_operators(node, source, &mut diagnostics);
            kuery_ranges(node, source, &mut diagnostics);
        }
        "field_name" => field_wildcard(node, source, &mut diagnostics),
        "range_query" => range_whitespace(node, source, &mut diagnostics),
        "term" | "wildcard_term" | "phrase" => escapes(node, source, &mut diagnostics),
        _ => {}
    });
    let tokens = highlight(&spec, source);
    AnalyzeResult {
        diagnostics,
        tokens,
    }
}

/// A bare `and`, `or`, or `not` term between two clauses.
fn lowercase_operators(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let mut cursor = node.walk();
    let items: Vec<Node> = node.named_children(&mut cursor).collect();
    for (i, item) in items.iter().enumerate() {
        if i == 0 || i + 1 == items.len() || item.kind() != "term_query" {
            continue;
        }
        let word = text(*item, source);
        let upper = word.to_ascii_uppercase();
        if matches!(upper.as_str(), "AND" | "OR" | "NOT") && word != upper {
            out.push(
                Diagnostic::warning(
                    codes::LUCENE_LOWERCASE_OPERATOR,
                    format!(
                        "`{word}` is a search term in Lucene, not an operator; operators are upper case (`{upper}`)"
                    ),
                    range(source, node_span(*item)),
                )
                .with_suggestion(upper),
            );
        }
    }
}

/// `a OR b AND c` is `a +b +c`: Lucene marks clauses pairwise and has no
/// precedence, so mixing the two at one level is never what it looks like.
fn mixed_operators(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let mut cursor = node.walk();
    let ops: Vec<Node> = node
        .children_by_field_name("operator", &mut cursor)
        .collect();
    let has_and = ops.iter().any(|o| o.kind() == "and");
    let has_or = ops.iter().any(|o| o.kind() == "or");
    if has_and && has_or {
        let first_or = ops
            .iter()
            .find(|o| o.kind() == "or")
            .copied()
            .unwrap_or(node);
        out.push(Diagnostic::warning(
            codes::LUCENE_MIXED_OPERATORS,
            "Lucene has no AND/OR precedence (`a OR b AND c` means `a +b +c`); add parentheses",
            range(source, node_span(first_or)),
        ));
    }
}

/// `field >= 10` is KQL. In Lucene it is three terms; write `field:>=10`.
fn kuery_ranges(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let mut cursor = node.walk();
    let items: Vec<Node> = node.named_children(&mut cursor).collect();
    for pair in items.windows(2) {
        let op = text(pair[1], source);
        if pair[0].kind() == "term_query"
            && pair[1].kind() == "term_query"
            && matches!(op, "<" | "<=" | ">" | ">=")
        {
            out.push(Diagnostic::warning(
                codes::LUCENE_KUERY_SYNTAX,
                format!(
                    "`{} {op}` is KQL; Lucene searches `{op}` as a term. Write `{}:{op}value`",
                    text(pair[0], source),
                    text(pair[0], source)
                ),
                range(source, node_span(pair[1])),
            ));
        }
    }
}

fn field_wildcard(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    if node
        .named_child(0)
        .is_some_and(|c| c.kind() == "wildcard_term")
    {
        let name = text(node, source);
        out.push(
            Diagnostic::error(
                codes::LUCENE_PARSE_ERROR,
                "Lucene rejects `*` or `?` in a field name; escape it (`book.\\*:`)",
                range(source, node_span(node)),
            )
            .with_suggestion(name.replace('*', "\\*").replace('?', "\\?")),
        );
    }
}

/// Lucene's range lexer splits bounds on a space only: `[1 TO<newline>5]`
/// reads `TO<newline>5` as one bound and fails.
fn range_whitespace(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let mut in_phrase = false;
    for (i, c) in text(node, source).char_indices() {
        match c {
            '"' => in_phrase = !in_phrase,
            '\t' | '\n' | '\r' if !in_phrase => {
                let at = node.start_byte() + i;
                out.push(Diagnostic::error(
                    codes::LUCENE_PARSE_ERROR,
                    "Lucene allows only spaces inside a range; a tab or newline joins `TO` to a bound",
                    range(source, ByteSpan::new(at, at + 1)),
                ));
                return;
            }
            _ => {}
        }
    }
}

/// `\uXXXX` needs four hex digits; any other single backslash is dropped, so
/// `"C:\Windows"` searches `C:Windows`.
fn escapes(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let t = text(node, source);
    let bytes = t.as_bytes();
    let phrase = node.kind() == "phrase";
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] != b'\\' {
            i += 1;
            continue;
        }
        let next = bytes[i + 1];
        let at = node.start_byte() + i;
        if next == b'u' {
            let hex = t.get(i + 2..i + 6).unwrap_or("");
            if hex.len() < 4 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                out.push(Diagnostic::error(
                    codes::LUCENE_ESCAPE,
                    "`\\u` must be followed by four hex digits; Lucene rejects the query. Write `\\\\u` for a literal backslash",
                    range(source, ByteSpan::new(at, at + 2)),
                ));
                return;
            }
        } else if phrase && next.is_ascii_alphanumeric() {
            out.push(
                Diagnostic::warning(
                    codes::LUCENE_ESCAPE,
                    format!(
                        "Lucene drops a single backslash: `\\{}` searches `{}`. Write `\\\\` for a literal backslash",
                        next as char, next as char
                    ),
                    range(source, ByteSpan::new(at, at + 2)),
                )
                .with_suggestion(format!("\\\\{}", next as char)),
            );
            return;
        }
        i += 2;
    }
}

fn walk<'t>(node: Node<'t>, f: &mut impl FnMut(Node<'t>)) {
    f(node);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, f);
    }
}

fn range(source: &str, span: ByteSpan) -> Range {
    span_to_range(source, span)
}

fn text<'a>(node: Node, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

fn highlight(spec: &HighlightSpec, source: &str) -> Vec<HighlightToken> {
    let Ok(spans) = opentide_syntax::query_captures(
        LanguageId::Lucene,
        source,
        opentide_highlight::LUCENE_HIGHLIGHTS_SCM,
    ) else {
        return Vec::new();
    };
    let refs: Vec<(ByteSpan, &str)> = spans.iter().map(|(s, c)| (*s, c.as_str())).collect();
    tokens_from_spans(spec, source, &refs).unwrap_or_default()
}

/// Field names a query mentions, for completion.
pub fn fields(source: &str) -> Vec<String> {
    let Some(tree) = ts_parse(LanguageId::Lucene, source) else {
        return Vec::new();
    };
    let mut names = std::collections::BTreeSet::new();
    walk(tree.root_node(), &mut |node| {
        if node.kind() == "field_name" && !node.has_error() {
            names.insert(text(node, source).to_string());
        }
    });
    names.into_iter().collect()
}

const OPERATORS: &[(&str, &str)] = &[
    (
        "AND",
        "Both clauses must match. Also `&&`. Upper case only.",
    ),
    ("&&", "Same as `AND`."),
    ("OR", "Either clause matches. Also `||`. Upper case only."),
    ("||", "Same as `OR`."),
    (
        "NOT",
        "Excludes the clause that follows. Also `!`. Upper case only.",
    ),
    ("!", "Same as `NOT`."),
    ("+", "The clause must match."),
    ("-", "The clause must not match."),
    (
        "TO",
        "Range bounds: `[a TO b]` inclusive, `{a TO b}` exclusive, `*` for an open end.",
    ),
    (
        ":",
        "`field:value`. `_exists_:field` matches documents that have the field.",
    ),
];

pub fn hover(source: &str, position: Position) -> Option<String> {
    let offset = position_to_offset(source, position);
    let tree = ts_parse(LanguageId::Lucene, source)?;
    let node = tree.root_node().descendant_for_byte_range(offset, offset)?;
    let word = text(node, source);
    if node.kind() == "boost" {
        return Some(format!(
            "**`^`** boost\n\nRaises the clause's relevance weight.\n\n[Elastic docs]({SYNTAX_DOCS})"
        ));
    }
    if node.kind() == "fuzzy" {
        return Some(format!(
            "**`~`** fuzzy or proximity\n\nAfter a term, edit distance; after a phrase, word slop.\n\n[Elastic docs]({SYNTAX_DOCS})"
        ));
    }
    OPERATORS
        .iter()
        .find(|(k, _)| *k == word)
        .map(|(k, d)| format!("**`{k}`** (Lucene)\n\n{d}\n\n[Elastic docs]({SYNTAX_DOCS})"))
}

pub fn completions(source: &str, offset: usize) -> Vec<CompletionItem> {
    let before = &source[..offset.min(source.len())];
    let mut items = Vec::new();
    if before.ends_with(char::is_whitespace) && !before.trim().is_empty() {
        for kw in ["AND", "OR", "NOT"] {
            items.push(CompletionItem::new(kw, "keyword"));
        }
    }
    items.extend(
        fields(source)
            .into_iter()
            .map(|f| CompletionItem::new(f, "property")),
    );
    items
}

fn position_to_offset(source: &str, position: Position) -> usize {
    let mut line = 0u32;
    let mut col = 0u32;
    for (idx, ch) in source.char_indices() {
        if line == position.line && col >= position.character {
            return idx;
        }
        if ch == '\n' {
            line += 1;
            col = 0;
        } else {
            col += ch.len_utf16() as u32;
        }
    }
    source.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes_of(src: &str) -> Vec<String> {
        analyze(src)
            .diagnostics
            .into_iter()
            .map(|d| d.code)
            .collect()
    }

    #[test]
    fn classic_syntax_is_clean() {
        let src = "event.category:process AND process.name:(cmd.exe OR \"power shell.exe\"^2) -user.name:SYSTEM AND bytes:[100 TO *} AND name:jo?n*";
        let r = analyze(src);
        assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);
        assert!(r.tokens.iter().any(|t| t.capture == "property"));
    }

    #[test]
    fn lowercase_operators_are_terms() {
        let r = analyze("process.name:cmd.exe and user.name:root");
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::LUCENE_LOWERCASE_OPERATOR)
            .expect("lowercase and");
        assert_eq!(d.suggestion.as_deref(), Some("AND"));
        assert!(
            codes_of("title:and").is_empty(),
            "a value is not an operator"
        );
    }

    #[test]
    fn parse_errors_are_reported() {
        assert!(codes_of("name:(a OR b").contains(&codes::LUCENE_PARSE_ERROR.to_string()));
        assert!(codes_of("bytes:[1 TO]").contains(&codes::LUCENE_PARSE_ERROR.to_string()));
    }

    #[test]
    fn behaviour_checks_from_the_lucene_parser() {
        assert!(codes_of("a OR b AND c").contains(&codes::LUCENE_MIXED_OPERATORS.to_string()));
        assert!(codes_of("(a OR b) AND c").is_empty());
        assert!(codes_of("book.*:x").contains(&codes::LUCENE_PARSE_ERROR.to_string()));
        assert!(codes_of("book.\\*:x").is_empty());
        assert!(codes_of("x:[1 TO\n5]").contains(&codes::LUCENE_PARSE_ERROR.to_string()));
        assert!(codes_of("path:\"c:\\users\\bob\"").contains(&codes::LUCENE_ESCAPE.to_string()));
        assert!(codes_of("path:\"C:\\Windows\"").contains(&codes::LUCENE_ESCAPE.to_string()));
        assert!(codes_of("path:\"C:\\\\Windows\"").is_empty());
        assert!(codes_of("bytes >= 10").contains(&codes::LUCENE_KUERY_SYNTAX.to_string()));
        assert!(codes_of("foo:AND").contains(&codes::LUCENE_PARSE_ERROR.to_string()));
        assert!(codes_of("*").is_empty());
        assert!(codes_of("-foo*").is_empty());
    }

    #[test]
    fn hover_and_completion() {
        let h = hover("a:1 AND b:2", Position::new(0, 5)).expect("hover");
        assert!(h.contains("AND"));
        assert!(completions("a:1 ", 4).iter().any(|i| i.label == "AND"));
    }
}
