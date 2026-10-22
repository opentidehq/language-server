//! I/O-free Kibana Query Language (`kuery`) engine: parse, Kibana's literal
//! rules, Lucene syntax that KQL reads as plain text, highlighting, hover, and
//! completion. `kuery` is Elastic's KQL; Kusto KQL is the `kql` language.
//!
//! The grammar follows Kibana's `kuery/grammar/grammar.peggy`. Two Kibana
//! behaviours sit below the grammar and are checked here: an unquoted literal
//! ends at an unescaped `not` followed by whitespace, and Lucene operators
//! (`[a TO b]`, `_exists_`, `~`, `^`, `/re/`) are searched as literal text.

use opentide_core::{
    ByteSpan, CompletionItem, Diagnostic, LanguageId, Position, Range, Severity, codes,
    span_to_range,
};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use opentide_syntax::{first_error, node_span, parse as ts_parse};
use regex::Regex;
use std::sync::OnceLock;
use tree_sitter::Node;

const KQL_DOCS: &str = "https://www.elastic.co/docs/reference/query-languages/kql";

pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
}

pub fn analyze(source: &str) -> AnalyzeResult {
    let spec = HighlightSpec::load().expect("highlight spec");
    let Some(tree) = ts_parse(LanguageId::Kuery, source) else {
        return AnalyzeResult {
            diagnostics: vec![Diagnostic::error(
                codes::KUERY_PARSE_ERROR,
                "failed to initialize the KQL parser",
                Range::point(0, 0),
            )],
            tokens: Vec::new(),
        };
    };
    let root = tree.root_node();
    let mut diagnostics = Vec::new();
    if let Some(err) = first_error(root) {
        diagnostics.push(Diagnostic::error(
            codes::KUERY_PARSE_ERROR,
            parse_error_message(err, source),
            range(source, node_span(err)),
        ));
    }
    // Kibana compiles the query with trailing whitespace stripped.
    let effective = source.trim_end();
    walk(root, &mut |node| match node.kind() {
        "unquoted_literal" => {
            if let Some(d) = embedded_not(node, source, effective) {
                diagnostics.push(d);
            }
            diagnostics.extend(lucene_syntax(node, source));
            diagnostics.extend(unquoted_escapes(node, source));
        }
        "or" | "and" | "not" => {
            if let Some(d) = keyword_spacing(node, source) {
                diagnostics.push(d);
            }
        }
        "nested_query" => {
            if let Some(d) = exclusive_range(node, source) {
                diagnostics.push(d);
            }
        }
        "quoted_string" => diagnostics.extend(quoted_string(node, source)),
        _ => {}
    });
    let tokens = highlight(&spec, source);
    AnalyzeResult {
        diagnostics,
        tokens,
    }
}

fn parse_error_message(err: Node, source: &str) -> String {
    if err.is_missing() {
        return format!("KQL syntax error: missing `{}`", err.kind());
    }
    match text(err, source).split_whitespace().next() {
        Some(first) => format!("KQL syntax error near `{first}`"),
        None => "KQL syntax error".into(),
    }
}

/// Kibana's `UnquotedCharacter` stops at `!Keyword`, and `Keyword` includes
/// `'not'i Space` with no space required before it. `cannot run` therefore
/// ends the value at `can`, and the query fails.
fn embedded_not(node: Node, source: &str, effective: &str) -> Option<Diagnostic> {
    static NOT_SPACE: OnceLock<Regex> = OnceLock::new();
    let re = NOT_SPACE.get_or_init(|| Regex::new(r"(?i)not[ \t\r\n\u{00A0}]").expect("regex"));
    let start = node.start_byte();
    // The literal plus the whitespace Kibana reads after it, when more follows.
    let mut end = node.end_byte();
    let rest = effective.get(end..).unwrap_or("");
    let ws = rest.len()
        - rest
            .trim_start_matches([' ', '\t', '\r', '\n', '\u{00A0}'])
            .len();
    if ws > 0 && end + ws < effective.len() {
        end += ws.min(1);
    }
    let window = source.get(start..end)?;
    for m in re.find_iter(window) {
        let escaped = m.start() > 0 && window.as_bytes()[m.start() - 1] == b'\\';
        if !escaped {
            let at = start + m.start();
            return Some(
                Diagnostic::error(
                    codes::KUERY_PARSE_ERROR,
                    "Kibana ends an unquoted value at `not ` and rejects the query; quote the value",
                    range(source, ByteSpan::new(at, at + 3)),
                )
                .with_suggestion(format!("\"{}\"", source.get(node.start_byte()..node.end_byte()).unwrap_or(""))),
            );
        }
    }
    None
}

/// Lucene syntax KQL parses as literal text, so the rule silently matches
/// something else. Ranges, `_exists_`, and prefix operators are warnings;
/// regex and fuzzy/boost shapes are hints, because paths and 8.3 names look
/// alike.
fn lucene_syntax(node: Node, source: &str) -> Vec<Diagnostic> {
    let literal = text(node, source);
    let in_field = node.parent().is_some_and(|p| p.kind() == "field");
    let span = node_span(node);
    let diagnostic = |severity: Severity, message: &str| {
        let mut d = Diagnostic::warning(codes::KUERY_LUCENE_SYNTAX, message, range(source, span));
        d.severity = severity;
        d
    };
    let trimmed = literal.trim();
    let found = if in_field {
        if literal == "_exists_" {
            Some(diagnostic(
                Severity::Warning,
                "`_exists_:field` is Lucene; in KQL write `field:*`",
            ))
        } else if literal.starts_with(['+', '-', '!']) {
            Some(diagnostic(
                Severity::Warning,
                "`+`, `-`, and `!` prefixes are Lucene; KQL reads them as part of the field name. Use `not field:value`",
            ))
        } else {
            None
        }
    } else if (trimmed.starts_with('[') || trimmed.starts_with('{'))
        && (trimmed.contains(" TO ") || trimmed.contains(" to "))
    {
        Some(diagnostic(
            Severity::Warning,
            "`[a TO b]` is a Lucene range; KQL searches it as text. Use `field >= a and field <= b`",
        ))
    } else if matches!(trimmed, "&&" | "||") {
        Some(diagnostic(
            Severity::Warning,
            "`&&` and `||` are Lucene; KQL uses `and` and `or`",
        ))
    } else if looks_like_regex(trimmed) {
        Some(diagnostic(
            Severity::Hint,
            "`/regex/` is Lucene; KQL has no regular expressions and searches it as text",
        ))
    } else if fuzzy_or_boost(trimmed) {
        Some(diagnostic(
            Severity::Hint,
            "`~` (fuzzy, proximity) and `^` (boost) are Lucene; KQL searches them as text",
        ))
    } else {
        None
    };
    found.into_iter().collect()
}

/// `/…/` with a regex metacharacter. A plain path such as
/// `/var/lib/tool/` is not one.
fn looks_like_regex(word: &str) -> bool {
    word.len() > 2
        && word.starts_with('/')
        && word.ends_with('/')
        && word[1..word.len() - 1].contains(['^', '$', '+', '?', '|', '[', ']', '\\'])
}

fn is_kql_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n' | '\u{00A0}')
}

/// Kibana's `Or` and `And` need whitespace on both sides and `Not` after it:
/// `not(a:1)` and `a:1 and(b:2)` are syntax errors.
fn keyword_spacing(node: Node, source: &str) -> Option<Diagnostic> {
    let before = source[..node.start_byte()].chars().next_back();
    let after = source[node.end_byte()..].chars().next();
    let needs_before = node.kind() != "not";
    let missing =
        (needs_before && !before.is_some_and(is_kql_space)) || !after.is_some_and(is_kql_space);
    missing.then(|| {
        let word = text(node, source);
        let place = if needs_before { "around" } else { "after" };
        Diagnostic::error(
            codes::KUERY_PARSE_ERROR,
            format!("Kibana needs whitespace {place} `{word}`"),
            range(source, node_span(node)),
        )
    })
}

/// `field:{1 TO 5}` is a Lucene exclusive range; Kibana reads a nested query.
fn exclusive_range(node: Node, source: &str) -> Option<Diagnostic> {
    let query = node.child_by_field_name("query")?;
    let body = text(query, source);
    (query.kind() == "value_expression" && (body.contains(" TO ") || body.contains(" to "))).then(|| {
        Diagnostic::warning(
            codes::KUERY_LUCENE_SYNTAX,
            "`{a TO b}` is a Lucene range; Kibana reads `field:{ ... }` as a nested query. Use `field > a and field < b`",
            range(source, node_span(node)),
        )
    })
}

/// `\not` outside quotes: Kibana reads `\n` first, a newline plus `ot`.
fn unquoted_escapes(node: Node, source: &str) -> Vec<Diagnostic> {
    let t = text(node, source);
    let mut out = Vec::new();
    for (i, _) in t.match_indices("\\not") {
        let at = node.start_byte() + i;
        out.push(
            Diagnostic::warning(
                codes::KUERY_ESCAPE,
                "Kibana reads `\\not` as a newline followed by `ot`; write `\\NOT` or quote the value",
                range(source, ByteSpan::new(at, at + 4)),
            )
            .with_suggestion("\\NOT"),
        );
    }
    out
}

/// Inside quotes Kibana turns `\t`, `\r`, and `\n` into control characters
/// (`"C:\temp"` searches a TAB), and `*` is a literal asterisk.
fn quoted_string(node: Node, source: &str) -> Vec<Diagnostic> {
    let t = text(node, source);
    let bytes = t.as_bytes();
    let mut out = Vec::new();
    let mut i = 1;
    while i + 1 < bytes.len() {
        if bytes[i] == b'\\' {
            let next = bytes[i + 1];
            let followed_by_word = bytes.get(i + 2).is_some_and(|b| b.is_ascii_alphanumeric());
            if matches!(next, b't' | b'r' | b'n') && followed_by_word {
                let at = node.start_byte() + i;
                out.push(
                    Diagnostic::warning(
                        codes::KUERY_ESCAPE,
                        format!(
                            "Kibana turns `\\{}` inside quotes into a control character; write `\\\\{}` for a backslash",
                            next as char, next as char
                        ),
                        range(source, ByteSpan::new(at, at + 2)),
                    )
                    .with_suggestion(format!("\\\\{}", next as char)),
                );
                break;
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    let inner = t.get(1..t.len().saturating_sub(1)).unwrap_or("");
    if inner.contains('*') && inner != "*" {
        let mut d = Diagnostic::warning(
            codes::KUERY_QUOTED_WILDCARD,
            "`*` inside quotes is a literal asterisk in KQL, not a wildcard; drop the quotes and escape spaces to match a pattern",
            range(source, node_span(node)),
        );
        d.severity = opentide_core::Severity::Hint;
        out.push(d);
    }
    out
}

fn fuzzy_or_boost(word: &str) -> bool {
    // `PROGRA~1` and paths are 8.3 short names, not fuzzy terms.
    if word.contains(['\\', '.', '/']) {
        return false;
    }
    if let Some((head, _)) = word.split_once('~') {
        if head.len() <= 6
            && head
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            return false;
        }
    }
    let tail = |sep: char| {
        word.rsplit_once(sep).is_some_and(|(head, n)| {
            !head.is_empty()
                && !head.ends_with('\\')
                && (n.is_empty() || n.chars().all(|c| c.is_ascii_digit() || c == '.'))
        })
    };
    tail('~') || tail('^')
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
        LanguageId::Kuery,
        source,
        opentide_highlight::KUERY_HIGHLIGHTS_SCM,
    ) else {
        return Vec::new();
    };
    let refs: Vec<(ByteSpan, &str)> = spans.iter().map(|(s, c)| (*s, c.as_str())).collect();
    tokens_from_spans(spec, source, &refs).unwrap_or_default()
}

/// Field names a query mentions, for completion and for Tide checks.
pub fn fields(source: &str) -> Vec<String> {
    let Some(tree) = ts_parse(LanguageId::Kuery, source) else {
        return Vec::new();
    };
    let mut names = std::collections::BTreeSet::new();
    walk(tree.root_node(), &mut |node| {
        if node.kind() == "field" && !node.has_error() {
            names.insert(text(node, source).trim_matches('"').to_string());
        }
    });
    names.into_iter().collect()
}

const OPERATORS: &[(&str, &str)] = &[
    (
        "and",
        "Both clauses must match. Case-insensitive; binds tighter than `or`.",
    ),
    ("or", "Either clause matches. Case-insensitive."),
    ("not", "Negates the clause that follows. Case-insensitive."),
    (
        ":",
        "`field:value` matches a value; `field:*` matches documents that have the field; `field:{ ... }` queries a nested field.",
    ),
    ("<", "Range: less than."),
    ("<=", "Range: less than or equal."),
    (">", "Range: greater than."),
    (">=", "Range: greater than or equal."),
];

pub fn hover(source: &str, position: Position) -> Option<String> {
    let offset = position_to_offset(source, position);
    let tree = ts_parse(LanguageId::Kuery, source)?;
    let node = tree.root_node().descendant_for_byte_range(offset, offset)?;
    let word = text(node, source).to_ascii_lowercase();
    OPERATORS
        .iter()
        .find(|(k, _)| *k == word)
        .map(|(k, d)| format!("**`{k}`** (KQL)\n\n{d}\n\n[Elastic docs]({KQL_DOCS})"))
}

pub fn completions(source: &str, offset: usize) -> Vec<CompletionItem> {
    let before = &source[..offset.min(source.len())];
    let mut items = Vec::new();
    let after_value = before
        .trim_end()
        .chars()
        .last()
        .is_some_and(|c| !matches!(c, ':' | '(' | '{' | '<' | '>' | '='));
    if after_value && before.ends_with(char::is_whitespace) {
        for kw in ["and", "or", "not"] {
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
    fn detection_query_is_clean() {
        let src = "event.category:process and process.name:(\"cmd.exe\" or powershell.exe) and not user.name:SYSTEM and event.code >= 4624";
        let r = analyze(src);
        assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);
        assert!(r.tokens.iter().any(|t| t.capture == "property"));
        assert!(r.tokens.iter().any(|t| t.capture == "keyword"));
    }

    #[test]
    fn not_inside_an_unquoted_value_fails_in_kibana() {
        assert!(codes_of("message: cannot run").contains(&codes::KUERY_PARSE_ERROR.to_string()));
        assert!(codes_of("message:knot and x:1").contains(&codes::KUERY_PARSE_ERROR.to_string()));
        assert!(codes_of("message:knot").is_empty());
        assert!(codes_of("message:\"cannot run\"").is_empty());
        // `\not` escapes the keyword, but Kibana reads `\n` first.
        let c = codes_of("message: can\\not run");
        assert!(!c.contains(&codes::KUERY_PARSE_ERROR.to_string()), "{c:?}");
        assert!(c.contains(&codes::KUERY_ESCAPE.to_string()), "{c:?}");
        assert!(codes_of("not message:x").is_empty());
        assert!(codes_of("process.executable:/var/lib/command-not-found/").is_empty());
        assert!(codes_of("file.name:PROGRA~1").is_empty());
    }

    #[test]
    fn lucene_constructs_are_flagged() {
        for src in [
            "bytes:[100 TO 200]",
            "_exists_:host.name",
            "name:jon~2",
            "title:/joh?n/",
            "path:/[a-z]+/",
            "-user.name:root",
        ] {
            assert!(
                codes_of(src).contains(&codes::KUERY_LUCENE_SYNTAX.to_string()),
                "{src}"
            );
        }
    }

    #[test]
    fn kibana_whitespace_and_escape_rules() {
        for src in ["not(a:1)", "a:1 and(b:2)", "(a:1)and(b:2)"] {
            assert!(
                codes_of(src).contains(&codes::KUERY_PARSE_ERROR.to_string()),
                "{src}"
            );
        }
        assert!(codes_of("(a:1) and (b:2)").is_empty());
        assert!(codes_of("x:{1 TO 5}").contains(&codes::KUERY_LUCENE_SYNTAX.to_string()));
        assert!(codes_of("path:\"C:\\temp\\x\"").contains(&codes::KUERY_ESCAPE.to_string()));
        assert!(codes_of("path:\"C:\\\\temp\"").is_empty());
        assert!(codes_of("msg:can\\not").contains(&codes::KUERY_ESCAPE.to_string()));
        let r = analyze("process.name:\"cmd*\"");
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::KUERY_QUOTED_WILDCARD)
            .expect("quoted wildcard");
        assert_eq!(d.severity, opentide_core::Severity::Hint);
        assert!(codes_of("x:\"*\"").is_empty());
    }

    #[test]
    fn keywords_are_case_insensitive() {
        assert!(codes_of("a:1 AND b:2 Or NOT c:3").is_empty());
    }

    #[test]
    fn hover_and_completion() {
        let h = hover("a:1 and b:2", Position::new(0, 5)).expect("hover");
        assert!(h.contains("and"));
        let items = completions("host.name:x ", 12);
        assert!(items.iter().any(|i| i.label == "and"));
        assert!(items.iter().any(|i| i.label == "host.name"));
    }
}
