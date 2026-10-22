//! I/O-free ES|QL engine: parse, catalog diagnostics, highlighting, hover,
//! completion, and signature help for Elastic Security `esql` rules.
//!
//! The catalog is Elastic's generated function and command definitions
//! (`catalogs/esql/`). Names the catalog does not know are diagnostics, not
//! parse errors: Kibana 9.4 and 9.5 drop an unknown command from a
//! non-aggregating rule and run the rest, so the editor has to say so.

pub mod catalog;

pub use catalog::{Catalog, CommandRow, FunctionRow, Lifecycle, StackVersion};

use opentide_core::{
    ByteSpan, CompletionItem, Diagnostic, LanguageId, ParameterInformation, Position, Range,
    Severity, SignatureHelp, SignatureInformation, codes, span_to_range,
};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use opentide_syntax::{first_error, node_span, parse as ts_parse};
use tree_sitter::Node;

pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
}

/// `METADATA` fields an `esql` rule can request. Hover text only.
const METADATA_FIELDS: &[(&str, &str)] = &[
    (
        "_id",
        "Document id. Elastic Security de-duplicates alerts from non-aggregating rules on `_id`.",
    ),
    ("_index", "Index the row came from."),
    ("_version", "Document version."),
    ("_score", "Relevance score, when the query scores."),
    ("_source", "Original document source."),
    ("_ignored", "Fields ignored at index time."),
    ("_index_mode", "Index mode of the backing index."),
    ("_tsid", "Time series id, for time series indices."),
];

pub fn analyze(source: &str) -> AnalyzeResult {
    let spec = HighlightSpec::load().expect("highlight spec");
    let catalog = Catalog::cached();
    let Some(tree) = ts_parse(LanguageId::Esql, source) else {
        return AnalyzeResult {
            diagnostics: vec![Diagnostic::error(
                codes::ESQL_PARSE_ERROR,
                "failed to initialize the ES|QL parser",
                Range::point(0, 0),
            )],
            tokens: Vec::new(),
        };
    };
    let root = tree.root_node();
    let mut diagnostics = Vec::new();
    if let Some(err) = first_error(root) {
        diagnostics.push(Diagnostic::error(
            codes::ESQL_PARSE_ERROR,
            parse_error_message(err, source),
            range(source, node_span(err)),
        ));
    }
    walk(root, &mut |node| {
        if node.kind() == "unknown_command" {
            diagnostics.push(unknown_command(node, source, catalog));
        } else if let Some(name) = command_name(node, source) {
            if let Some(row) = catalog.command(&name) {
                if let Some(d) = availability(
                    &display_name(&name),
                    "command",
                    row.snapshot_only,
                    &Lifecycle::parse(&row.stack),
                    range(source, keyword_span(node)),
                ) {
                    diagnostics.push(d);
                }
            }
        } else if node.kind() == "function_call" {
            if let Some(d) = function_diagnostic(node, source, catalog) {
                diagnostics.push(d);
            }
        } else if node.kind() == "qualified_name" {
            if let Some(d) = reserved_name(node, source) {
                diagnostics.push(d);
            }
        } else if node.kind() == "string" {
            if let Some(d) = string_escape(node, source) {
                diagnostics.push(d);
            }
        } else if node.kind() == "qualified_interval" {
            let value = node.child_by_field_name("value").map(|v| text(v, source));
            if value.is_some_and(|v| !v.bytes().all(|b| b.is_ascii_digit())) {
                diagnostics.push(Diagnostic::error(
                    codes::ESQL_PARSE_ERROR,
                    "a time span needs a whole number (`90 minutes`, not `1.5 hours`)",
                    range(source, node_span(node)),
                ));
            }
        }
    });
    if let Some(d) = metadata_id_advisory(root, source) {
        diagnostics.push(d);
    }
    let tokens = highlight(&spec, source, catalog);
    AnalyzeResult {
        diagnostics,
        tokens,
    }
}

/// Words the expression lexer always reads as keywords. A field with one of
/// these names needs backticks: `` `by` ``.
const EXPRESSION_KEYWORDS: &[&str] = &[
    "and", "asc", "by", "desc", "false", "first", "in", "is", "last", "like", "not", "null",
    "nulls", "on", "or", "rlike", "true", "where", "with",
];

fn reserved_name(node: Node, source: &str) -> Option<Diagnostic> {
    let mut cursor = node.walk();
    let part = node.named_children(&mut cursor).find(|part| {
        part.kind() == "identifier"
            && EXPRESSION_KEYWORDS.contains(&text(*part, source).to_ascii_lowercase().as_str())
    })?;
    let word = text(part, source);
    Some(
        Diagnostic::error(
            codes::ESQL_PARSE_ERROR,
            format!(
                "`{word}` is an ES|QL keyword here; quote a field with that name as `` `{word}` ``"
            ),
            range(source, node_span(part)),
        )
        .with_suggestion(format!("`{word}`")),
    )
}

/// Double-quoted strings allow only `\t \n \r \" \\`; anything else, such as
/// `"C:\Windows"`, fails the lexer. Triple-quoted strings take no escapes.
fn string_escape(node: Node, source: &str) -> Option<Diagnostic> {
    let t = text(node, source);
    if t.starts_with("\"\"\"") {
        return None;
    }
    let bytes = t.as_bytes();
    let mut i = 1;
    while i + 1 < bytes.len() {
        if bytes[i] == b'\\' {
            if !matches!(bytes[i + 1], b't' | b'n' | b'r' | b'"' | b'\\') {
                let at = node.start_byte() + i;
                return Some(
                    Diagnostic::error(
                        codes::ESQL_PARSE_ERROR,
                        format!(
                            "ES|QL strings allow only the escapes \\t \\n \\r \\\" \\\\; `\\{}` fails. Use `\\\\` or a triple-quoted string",
                            bytes[i + 1] as char
                        ),
                        range(source, ByteSpan::new(at, at + 2)),
                    )
                    .with_suggestion(format!("\"\"\"{}\"\"\"", &t[1..t.len().saturating_sub(1)])),
                );
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    None
}

fn parse_error_message(err: Node, source: &str) -> String {
    if err.is_missing() {
        return format!("ES|QL syntax error: missing `{}`", err.kind());
    }
    let text = source
        .get(err.start_byte()..err.end_byte())
        .unwrap_or("")
        .trim();
    let first = text.split_whitespace().next().unwrap_or("");
    if first.is_empty() {
        "ES|QL syntax error".to_string()
    } else {
        format!("ES|QL syntax error near `{first}`")
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

/// Catalog name of a command node: `stats`, `inline stats`, `lookup join`.
pub fn command_name(node: Node, source: &str) -> Option<String> {
    let kind = node.kind();
    let base = kind.strip_suffix("_command")?;
    Some(match base {
        "unknown" => return None,
        "inline_stats" => {
            let first = node.child(0).map(|c| text(c, source).to_ascii_lowercase());
            if first.as_deref() == Some("inlinestats") {
                "inlinestats".into()
            } else {
                "inline stats".into()
            }
        }
        "join" => {
            let join_kind = node
                .child_by_field_name("kind")
                .map(|k| text(k, source).to_ascii_lowercase())
                .unwrap_or_else(|| "lookup".into());
            format!("{join_kind} join")
        }
        "fill_null" => "fillnull".into(),
        other => other.to_string(),
    })
}

fn display_name(name: &str) -> String {
    name.to_ascii_uppercase()
}

/// The command's leading keywords (`LOOKUP JOIN`, `INLINE STATS`).
fn keyword_span(node: Node) -> ByteSpan {
    let start = node.start_byte();
    let mut end = start;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.is_named() {
            break;
        }
        if child.kind() == "|" || child.kind() == "(" {
            break;
        }
        end = child.end_byte();
        if node.kind() != "inline_stats_command" && node.kind() != "join_command" {
            break;
        }
    }
    if node.kind() == "join_command" {
        if let Some(kind) = node.child_by_field_name("kind") {
            end = end.max(kind.end_byte());
            if let Some(join) = kind.next_sibling() {
                end = end.max(join.end_byte());
            }
        }
    }
    ByteSpan::new(start, end.max(start + 1))
}

fn unknown_command(node: Node, source: &str, catalog: &Catalog) -> Diagnostic {
    let name_node = node.child_by_field_name("name").unwrap_or(node);
    let name = text(name_node, source);
    let mut d = Diagnostic::error(
        codes::ESQL_UNKNOWN_COMMAND,
        format!(
            "unknown ES|QL command `{name}`; Elasticsearch rejects it, and Kibana 9.4 and 9.5 run a non-aggregating rule without it"
        ),
        range(source, node_span(name_node)),
    );
    if let Some(s) = catalog.suggest_command(name) {
        d = d.with_suggestion(display_name(&s));
    }
    d
}

fn function_diagnostic(node: Node, source: &str, catalog: &Catalog) -> Option<Diagnostic> {
    let name_node = node.child_by_field_name("name")?;
    if name_node.kind() == "parameter" {
        return None;
    }
    let name = text(name_node, source);
    let span = node_span(name_node);
    match catalog.function(name) {
        Some(row) => availability(
            &format!("{}()", name.to_ascii_uppercase()),
            "function",
            row.snapshot_only,
            &Lifecycle::parse(&row.stack),
            range(source, span),
        ),
        None => {
            let mut d = Diagnostic::error(
                codes::ESQL_UNKNOWN_FUNCTION,
                format!("unknown ES|QL function `{name}`"),
                range(source, span),
            );
            if let Some(s) = catalog.suggest_function(name) {
                d = d.with_suggestion(s.to_ascii_uppercase());
            }
            Some(d)
        }
    }
}

/// Snapshot-only names fail on every release; names first documented at 9.2
/// or later are missing on the 8.19 floor; preview names may change.
fn availability(
    name: &str,
    what: &str,
    snapshot_only: bool,
    lifecycle: &Lifecycle,
    range: Range,
) -> Option<Diagnostic> {
    if snapshot_only {
        return Some(Diagnostic::error(
            codes::ESQL_UNAVAILABLE,
            format!(
                "{what} `{name}` exists only in Elasticsearch snapshot builds; release clusters reject it"
            ),
            range,
        ));
    }
    if let Some(first) = lifecycle.after_floor() {
        let mut d = Diagnostic::warning(
            codes::ESQL_UNAVAILABLE,
            format!(
                "{what} `{name}` needs Elasticsearch {first} or later ({}); an 8.19 cluster rejects it",
                lifecycle.describe()
            ),
            range,
        );
        d.severity = Severity::Information;
        return Some(d);
    }
    if !lifecycle.is_ga() && (lifecycle.preview.is_some() || lifecycle.preview_unversioned) {
        let mut d = Diagnostic::warning(
            codes::ESQL_UNAVAILABLE,
            format!(
                "{what} `{name}` is in technical preview ({}); Elastic may change or remove it",
                lifecycle.describe()
            ),
            range,
        );
        d.severity = Severity::Information;
        return Some(d);
    }
    None
}

/// Non-aggregating `FROM` queries need `METADATA _id` so Elastic Security can
/// de-duplicate alerts ([elastic-1.0] Advisories).
fn metadata_id_advisory(root: Node, source: &str) -> Option<Diagnostic> {
    let query = named_child_of_kind(root, "query")?;
    let source_cmd = query.child_by_field_name("source")?;
    if source_cmd.kind() != "from_command" {
        return None;
    }
    let mut cursor = query.walk();
    let aggregates = query
        .children_by_field_name("command", &mut cursor)
        .any(|c| c.kind() == "stats_command");
    if aggregates {
        return None;
    }
    let metadata = source_cmd.child_by_field_name("metadata");
    let has_id = metadata.is_some_and(|m| {
        let mut c = m.walk();
        m.children_by_field_name("field", &mut c)
            .any(|f| text(f, source) == "_id")
    });
    if has_id {
        return None;
    }
    let span = metadata
        .map(node_span)
        .unwrap_or_else(|| keyword_span(source_cmd));
    Some(
        Diagnostic::warning(
            codes::ESQL_METADATA_ID,
            "non-aggregating ES|QL query lacks `METADATA _id`; before 9.4 Elastic Security cannot de-duplicate its alerts (9.4 and later add it)",
            range(source, span),
        )
        .with_suggestion("METADATA _id, _version, _index"),
    )
}

fn named_child_of_kind<'t>(node: Node<'t>, kind: &str) -> Option<Node<'t>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|c| c.kind() == kind)
}

fn highlight(spec: &HighlightSpec, source: &str, catalog: &Catalog) -> Vec<HighlightToken> {
    let Ok(mut spans) = opentide_syntax::query_captures(
        LanguageId::Esql,
        source,
        opentide_highlight::ESQL_HIGHLIGHTS_SCM,
    ) else {
        return Vec::new();
    };
    for (span, capture) in spans.iter_mut() {
        if capture == "function" {
            let name = source.get(span.start..span.end).unwrap_or("");
            if catalog.function(name).is_some() {
                *capture = "function.builtin".into();
            }
        }
    }
    let refs: Vec<(ByteSpan, &str)> = spans.iter().map(|(s, c)| (*s, c.as_str())).collect();
    tokens_from_spans(spec, source, &refs).unwrap_or_default()
}

// ---- Hover ----------------------------------------------------------------

pub fn hover(source: &str, position: Position) -> Option<String> {
    let offset = position_to_offset(source, position);
    let tree = ts_parse(LanguageId::Esql, source)?;
    let catalog = Catalog::cached();
    let node = tree.root_node().descendant_for_byte_range(offset, offset)?;
    // Function name.
    if let Some(parent) = node.parent() {
        if parent.kind() == "function_call"
            && parent.child_by_field_name("name").map(|n| n.id()) == Some(node.id())
        {
            return catalog.function(text(node, source)).map(function_hover);
        }
        if parent.kind() == "metadata_field" || node.kind() == "metadata_field" {
            let name = text(node, source);
            return METADATA_FIELDS
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(n, d)| format!("**`{n}`** (METADATA field)\n\n{d}"));
        }
    }
    // Command keyword.
    let mut cur = Some(node);
    while let Some(n) = cur {
        if n.kind().ends_with("_command") {
            let span = keyword_span(n);
            if offset >= span.start && offset < span.end {
                if n.kind() == "unknown_command" {
                    return None;
                }
                let name = command_name(n, source)?;
                return catalog.command(&name).map(command_hover);
            }
            break;
        }
        cur = n.parent();
    }
    // Operator.
    if !node.is_named() {
        let symbol = text(node, source);
        if let Some(op) = catalog.operator(symbol) {
            return Some(operator_hover(op));
        }
    }
    None
}

fn command_hover(row: &CommandRow) -> String {
    let mut md = format!("**{}** ({} command)", display_name(&row.name), row.kind);
    if !row.syntax.is_empty() {
        md.push_str(&format!("\n\n```esql\n{}\n```", row.syntax));
    }
    if !row.docs.is_empty() {
        md.push_str(&format!("\n\n{}", row.docs));
    }
    md.push_str(&lifecycle_line(row.snapshot_only, &row.stack));
    if let Some(alias) = &row.alias_of {
        md.push_str(&format!("\n\nSame as `{}`.", display_name(alias)));
    }
    if let Some(c) = &row.citation {
        md.push_str(&format!("\n\n[Elastic docs]({c})"));
    }
    md
}

fn function_hover(row: &FunctionRow) -> String {
    let mut md = format!(
        "**{}** ({} function)\n\n```esql\n{}\n```",
        row.name.to_ascii_uppercase(),
        row.kind,
        row.signature
    );
    if !row.docs.is_empty() {
        md.push_str(&format!("\n\n{}", row.docs));
    }
    if !row.parameters.is_empty() {
        md.push_str("\n\n**Parameters**\n");
        for p in &row.parameters {
            let optional = if p.required { "" } else { " (optional)" };
            md.push_str(&format!(
                "\n- `{}`{optional} _{}_",
                p.name,
                p.types.join(" | ")
            ));
        }
    }
    if !row.returns.is_empty() {
        md.push_str(&format!("\n\n**Returns** _{}_", row.returns.join(" | ")));
    }
    md.push_str(&lifecycle_line(row.snapshot_only, &row.stack));
    if let Some(license) = &row.license {
        md.push_str(&format!("\n\nLicence: {license}."));
    }
    if let Some(c) = &row.citation {
        md.push_str(&format!("\n\n[Elastic docs]({c})"));
    }
    md
}

fn operator_hover(row: &catalog::OperatorRow) -> String {
    let mut md = format!("**`{}`** (operator)\n\n{}", row.operator, row.docs);
    if let Some(c) = &row.citation {
        md.push_str(&format!("\n\n[Elastic docs]({c})"));
    }
    md
}

fn lifecycle_line(snapshot_only: bool, stack: &str) -> String {
    if snapshot_only {
        return "\n\nAvailability: snapshot builds only.".into();
    }
    let lifecycle = Lifecycle::parse(stack);
    let described = lifecycle.describe();
    if described.is_empty() {
        String::new()
    } else {
        format!("\n\nAvailability: {described}.")
    }
}

// ---- Completion -----------------------------------------------------------

pub fn completions(source: &str, offset: usize) -> Vec<CompletionItem> {
    let catalog = Catalog::cached();
    let before = &source[..offset.min(source.len())];
    let segment_start = last_pipe(before).map(|i| i + 1);
    let segment = &before[segment_start.unwrap_or(0)..];
    let trimmed = segment.trim_start();
    let typing_first_word = !trimmed.contains(char::is_whitespace);
    if typing_first_word {
        let source_position = segment_start.is_none();
        return catalog
            .commands
            .iter()
            .filter(|c| !c.snapshot_only && c.alias_of.is_none())
            .filter(|c| {
                if source_position {
                    c.kind == "source" || c.kind == "directive"
                } else {
                    c.kind == "processing"
                }
            })
            .map(|c| {
                CompletionItem::new(display_name(&c.name), "command")
                    .with_detail(c.syntax.lines().next().unwrap_or("").to_string())
                    .with_docs(command_hover(c))
            })
            .collect();
    }
    let command = trimmed
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let lower = trimmed.to_ascii_lowercase();
    if matches!(command.as_str(), "from" | "ts") {
        if lower.split_whitespace().any(|w| w == "metadata") {
            return METADATA_FIELDS
                .iter()
                .map(|(n, d)| CompletionItem::new(*n, "property").with_docs(*d))
                .collect();
        }
        return vec![CompletionItem::new("METADATA", "keyword").with_docs(
            "Request metadata fields. Non-aggregating Elastic Security rules need `METADATA _id`.",
        )];
    }
    let mut items: Vec<CompletionItem> = catalog
        .functions
        .iter()
        .filter(|f| !f.snapshot_only)
        .filter(|f| {
            // Aggregations belong to STATS and INLINE STATS.
            f.kind != "agg" && f.kind != "time_series_agg"
                || matches!(command.as_str(), "stats" | "inline" | "inlinestats")
        })
        .map(|f| {
            CompletionItem::new(f.name.to_ascii_uppercase(), "function")
                .with_detail(f.signature.clone())
                .with_docs(function_hover(f))
        })
        .collect();
    for kw in clause_keywords(&command) {
        items.push(CompletionItem::new(*kw, "keyword"));
    }
    for name in columns_in(source) {
        items.push(CompletionItem::new(name, "property"));
    }
    items
}

fn clause_keywords(command: &str) -> &'static [&'static str] {
    match command {
        "where" | "eval" | "row" => &[
            "AND",
            "OR",
            "NOT",
            "IN",
            "LIKE",
            "RLIKE",
            "IS NULL",
            "IS NOT NULL",
        ],
        "stats" | "inline" | "inlinestats" => &["BY", "WHERE"],
        "sort" => &["ASC", "DESC", "NULLS FIRST", "NULLS LAST"],
        "enrich" => &["ON", "WITH"],
        "rename" => &["AS"],
        "lookup" => &["JOIN", "ON"],
        _ => &[],
    }
}

/// Column names the query already references or creates.
fn columns_in(source: &str) -> Vec<String> {
    let Some(tree) = ts_parse(LanguageId::Esql, source) else {
        return Vec::new();
    };
    let mut names = std::collections::BTreeSet::new();
    walk(tree.root_node(), &mut |node| {
        if matches!(node.kind(), "qualified_name" | "name_pattern") && !node.has_error() {
            let name = text(node, source);
            if !name.contains('*') && !name.is_empty() {
                names.insert(name.to_string());
            }
        }
    });
    names.into_iter().collect()
}

fn last_pipe(before: &str) -> Option<usize> {
    let mut in_string = false;
    let mut last = None;
    let bytes = before.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if in_string => i += 1,
            b'"' => in_string = !in_string,
            b'|' if !in_string => last = Some(i),
            _ => {}
        }
        i += 1;
    }
    last
}

// ---- Signature help -------------------------------------------------------

pub fn signature_help(source: &str, offset: usize) -> Option<SignatureHelp> {
    let before = &source[..offset.min(source.len())];
    let (name, active) = innermost_call(before)?;
    let row = Catalog::cached().function(&name)?;
    let parameters: Vec<ParameterInformation> = row
        .parameters
        .iter()
        .map(|p| ParameterInformation {
            label: p.name.clone(),
            documentation: Some(format!("_{}_", p.types.join(" | "))),
        })
        .collect();
    let active = active.min(parameters.len().saturating_sub(1) as u32);
    Some(SignatureHelp {
        signatures: vec![SignatureInformation {
            label: row.signature.clone(),
            documentation: row.citation.clone().map(|c| format!("[Elastic docs]({c})")),
            parameters,
        }],
        active_signature: 0,
        active_parameter: active,
    })
}

/// Innermost unclosed `name(` before the cursor and the comma count inside it.
fn innermost_call(before: &str) -> Option<(String, u32)> {
    let bytes = before.as_bytes();
    let mut stack: Vec<(usize, u32)> = Vec::new();
    let mut in_string = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if b == b'\\' {
                i += 1;
            } else if b == b'"' {
                in_string = false;
            }
        } else {
            match b {
                b'"' => in_string = true,
                b'(' => stack.push((i, 0)),
                b')' => {
                    stack.pop();
                }
                b',' => {
                    if let Some(top) = stack.last_mut() {
                        top.1 += 1;
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    let (open, commas) = *stack.last()?;
    let name_start = before[..open]
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map(|i| i + 1)
        .unwrap_or(0);
    let name = before[name_start..open].to_string();
    (!name.is_empty()).then_some((name, commas))
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
    fn clean_rule_has_no_diagnostics() {
        let src = "FROM logs-endpoint.events.process-* METADATA _id, _version, _index\n| WHERE process.name == \"cmd.exe\" AND host.os.type == \"windows\"\n| KEEP @timestamp, host.name, process.*\n| LIMIT 100";
        let r = analyze(src);
        assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);
        assert!(r.tokens.iter().any(|t| t.capture == "keyword"));
        assert!(r.tokens.iter().any(|t| t.capture == "type"));
    }

    #[test]
    fn unknown_command_is_named_with_a_suggestion() {
        let r = analyze("FROM logs-* METADATA _id | WEHRE x == 1");
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::ESQL_UNKNOWN_COMMAND)
            .expect("unknown command");
        assert_eq!(d.suggestion.as_deref(), Some("WHERE"));
        assert!(
            !r.diagnostics
                .iter()
                .any(|d| d.code == codes::ESQL_PARSE_ERROR)
        );
    }

    #[test]
    fn unknown_function_is_diagnosed() {
        let c = codes_of("FROM logs-* METADATA _id | EVAL x = STARTSWITH(a, \"b\")");
        assert!(
            c.contains(&codes::ESQL_UNKNOWN_FUNCTION.to_string()),
            "{c:?}"
        );
    }

    #[test]
    fn metadata_id_advisory_only_for_non_aggregating_from() {
        assert!(
            codes_of("FROM logs-* | WHERE a == 1").contains(&codes::ESQL_METADATA_ID.to_string())
        );
        assert!(
            !codes_of("FROM logs-* | STATS c = COUNT(*) BY host.name")
                .contains(&codes::ESQL_METADATA_ID.to_string())
        );
        assert!(
            !codes_of("FROM logs-* METADATA _id | WHERE a == 1")
                .contains(&codes::ESQL_METADATA_ID.to_string())
        );
        assert!(!codes_of("ROW a = 1").contains(&codes::ESQL_METADATA_ID.to_string()));
    }

    #[test]
    fn newer_commands_report_availability() {
        let r = analyze("FROM logs-* METADATA _id | INLINE STATS c = COUNT(*) BY host.name");
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::ESQL_UNAVAILABLE)
            .expect("availability");
        assert_eq!(d.severity, Severity::Information);
        assert!(d.message.contains("9.2"), "{}", d.message);
    }

    #[test]
    fn lexer_rules_from_elasticsearch() {
        let c = codes_of("FROM logs-* METADATA _id | WHERE file.path == \"C:\\Windows\"");
        assert!(c.contains(&codes::ESQL_PARSE_ERROR.to_string()), "{c:?}");
        assert!(
            codes_of("FROM logs-* METADATA _id | WHERE file.path == \"\"\"C:\\Windows\"\"\"")
                .is_empty()
        );
        assert!(codes_of("FROM logs-* METADATA _id | WHERE a == \"x\\ty\"").is_empty());
        assert!(
            codes_of("FROM logs-* METADATA _id | WHERE @timestamp > NOW() - 1.5 hours")
                .contains(&codes::ESQL_PARSE_ERROR.to_string())
        );
        assert!(
            codes_of("FROM logs-* METADATA _id | EVAL s = TO_STR(x)").is_empty(),
            "registered alias"
        );
        assert!(
            codes_of("FROM logs-* METADATA _id | WHERE a =~ \"x\"")
                .contains(&codes::ESQL_PARSE_ERROR.to_string())
        );
    }

    #[test]
    fn expression_keywords_are_reserved() {
        let c = codes_of("FROM logs-* METADATA _id | INLINE STATS BY");
        assert!(c.contains(&codes::ESQL_PARSE_ERROR.to_string()), "{c:?}");
        assert!(codes_of("FROM logs-* METADATA _id | WHERE `by` == 1").is_empty());
        assert!(
            codes_of("FROM logs-* | STATS f = FIRST(x, @timestamp) BY host.name")
                .iter()
                .all(|c| c != codes::ESQL_PARSE_ERROR)
        );
        assert!(codes_of("FROM logs-* METADATA _id | WHERE source.as.number == 1").is_empty());
    }

    #[test]
    fn parse_error_has_a_range() {
        let r = analyze("FROM logs-* | WHERE (a == ");
        assert!(
            r.diagnostics
                .iter()
                .any(|d| d.code == codes::ESQL_PARSE_ERROR)
        );
    }

    #[test]
    fn hover_names_commands_and_functions() {
        let src = "FROM logs-* | WHERE STARTS_WITH(process.name, \"x\")";
        let h = hover(src, Position::new(0, 15)).expect("command hover");
        assert!(h.contains("WHERE"), "{h}");
        let h = hover(src, Position::new(0, 22)).expect("function hover");
        assert!(h.contains("STARTS_WITH"), "{h}");
        assert!(h.contains("elastic.co"), "{h}");
    }

    #[test]
    fn completion_by_position() {
        let items = completions("FROM logs-* | ", 14);
        assert!(items.iter().any(|i| i.label == "WHERE"));
        assert!(!items.iter().any(|i| i.label == "FROM"));
        let items = completions("FR", 2);
        assert!(items.iter().any(|i| i.label == "FROM"));
        let items = completions("FROM logs-* METADATA ", 21);
        assert!(items.iter().any(|i| i.label == "_id"));
        let src = "FROM logs-* | WHERE ";
        let items = completions(src, src.len());
        assert!(items.iter().any(|i| i.label == "STARTS_WITH"));
        assert!(
            !items.iter().any(|i| i.label == "COUNT"),
            "aggregations only in STATS"
        );
    }

    #[test]
    fn signature_help_tracks_the_active_parameter() {
        let src = "FROM logs-* | EVAL x = STARTS_WITH(process.name, ";
        let help = signature_help(src, src.len()).expect("signature");
        assert_eq!(help.active_parameter, 1);
        assert!(help.signatures[0].label.starts_with("STARTS_WITH("));
    }
}
